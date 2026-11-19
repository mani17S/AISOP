"""
AISOP Semantic Knowledge Retriever.

Implements the Cosine Similarity Retrieval Layer (Milestone P2-H3) in accordance with
ADR-001 (Direct Lightweight LLM Abstraction) and ADR-002 (PostgreSQL/pgvector):
- Embeds natural language queries using OllamaEmbedder (768 dimensions).
- Performs cosine similarity search using pgvector's cosine distance operator (<=>).
- Conversion and boundary semantics:
  * min_similarity in [0.0, 1.0] represents cosine similarity (1.0 = identical).
  * Cosine distance = 1.0 - cosine_similarity.
  * When min_similarity > 0.0, the threshold condition (distance <= 1.0 - min_similarity)
    is applied directly in SQL WHERE clause to ensure the query returns up to top_k
    candidates that meet the threshold, preventing premature top-k truncation.
- SQLite fallback: Computes exact cosine similarity in Python for offline test execution.
- Security & trust boundaries: Content returned in RetrievalResult represents untrusted
  reference material. It must never be evaluated as code or system instructions.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from app.core.config import Settings, get_settings
from app.models.knowledge import KnowledgeEmbedding
from app.modules.ai.embeddings.embedder import OllamaEmbedder
from app.schemas.knowledge import RetrievalRequest, RetrievalResult
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


def _cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    """
    Compute cosine similarity between two float vectors.

    similarity = dot(a, b) / (||a|| * ||b||)
    Clamped to [0.0, 1.0].
    """
    if len(vec_a) != len(vec_b) or not vec_a:
        return 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    val = dot / (norm_a * norm_b)
    return max(0.0, min(1.0, val))


class KnowledgeRetriever:
    """
    Executes threshold-bounded semantic retrieval over knowledge embeddings.

    Maintains full chunk provenance (source_document, section_title, doc_version,
    chunk_index, total_chunks, embedding_model, ingested_at).
    """

    def __init__(
        self,
        embedder: OllamaEmbedder | None = None,
        settings: Settings | None = None,
    ) -> None:
        cfg = settings or get_settings()
        self._settings = cfg
        self._embedder = embedder or OllamaEmbedder(cfg)
        self._default_top_k = cfg.RETRIEVAL_TOP_K

    @property
    def embedder(self) -> OllamaEmbedder:
        return self._embedder

    async def retrieve(
        self,
        request: RetrievalRequest,
        session: AsyncSession,
    ) -> list[RetrievalResult]:
        """
        Retrieve the top-k most relevant knowledge chunks matching the query.

        Args:
            request: Validated RetrievalRequest with query, top_k, filters.
            session: Active SQLAlchemy AsyncSession.

        Returns:
            List of RetrievalResult objects sorted by similarity_score descending.
        """
        top_k = request.top_k or self._default_top_k
        min_similarity = request.min_similarity

        # Step 1: Embed query into 768-dim space
        query_vector = await self._embedder.embed(request.query)

        # Step 2: Determine dialect safely across AsyncSession and test adapters
        bind = getattr(session, "bind", None)
        if bind is None and hasattr(session, "get_bind"):
            try:
                bind = session.get_bind()
            except Exception:
                bind = None
        if bind is None and hasattr(session, "_sync"):
            sync_sess = getattr(session, "_sync")
            bind = getattr(sync_sess, "bind", None)
            if bind is None and hasattr(sync_sess, "get_bind"):
                try:
                    bind = sync_sess.get_bind()
                except Exception:
                    bind = None

        dialect_name = getattr(bind, "dialect", None)
        dialect_name_str = getattr(dialect_name, "name", "")
        is_postgres = dialect_name_str == "postgresql"

        now_utc = datetime.now(timezone.utc)

        if is_postgres:
            results = await self._retrieve_postgres(
                query_vector=query_vector,
                top_k=top_k,
                min_similarity=min_similarity,
                source_filter=request.source_document_filter,
                session=session,
                now_utc=now_utc,
            )
        else:
            results = await self._retrieve_sqlite_fallback(
                query_vector=query_vector,
                top_k=top_k,
                min_similarity=min_similarity,
                source_filter=request.source_document_filter,
                session=session,
                now_utc=now_utc,
            )

        logger.info(
            "Knowledge retrieval complete",
            query_length=len(request.query),
            top_k=top_k,
            min_similarity=min_similarity,
            results_found=len(results),
        )

        return results

    async def _retrieve_postgres(
        self,
        query_vector: list[float],
        top_k: int,
        min_similarity: float,
        source_filter: str | None,
        session: AsyncSession,
        now_utc: datetime,
    ) -> list[RetrievalResult]:
        """pgvector-native cosine distance retrieval (<=>)."""
        distance_col = KnowledgeEmbedding.embedding.cosine_distance(query_vector)
        stmt = select(KnowledgeEmbedding, distance_col.label("distance"))

        if source_filter:
            stmt = stmt.where(
                KnowledgeEmbedding.source_document.like(f"{source_filter}%")
            )

        if min_similarity > 0.0:
            # Cosine distance = 1.0 - Cosine similarity
            # similarity >= min_similarity <=> distance <= (1.0 - min_similarity)
            max_distance = round(1.0 - min_similarity, 8)
            stmt = stmt.where(distance_col <= max_distance)

        stmt = stmt.order_by(distance_col.asc()).limit(top_k)

        rows = (await session.execute(stmt)).all()

        results: list[RetrievalResult] = []
        for record, dist in rows:
            dist_val = float(dist)
            # Bound similarity to [0.0, 1.0]
            similarity = max(0.0, min(1.0, 1.0 - dist_val))

            results.append(
                RetrievalResult(
                    id=record.id,
                    source_document=record.source_document,
                    section_title=record.section_title,
                    chunk_index=record.chunk_index,
                    content=record.content,
                    similarity_score=round(similarity, 6),
                    chunk_metadata=record.chunk_metadata or {},
                    retrieved_at=now_utc,
                )
            )

        return results

    async def _retrieve_sqlite_fallback(
        self,
        query_vector: list[float],
        top_k: int,
        min_similarity: float,
        source_filter: str | None,
        session: AsyncSession,
        now_utc: datetime,
    ) -> list[RetrievalResult]:
        """In-memory cosine similarity computation for SQLite unit testing."""
        stmt = select(KnowledgeEmbedding)
        if source_filter:
            stmt = stmt.where(
                KnowledgeEmbedding.source_document.like(f"{source_filter}%")
            )

        records = (await session.execute(stmt)).scalars().all()

        scored: list[tuple[float, KnowledgeEmbedding]] = []
        for rec in records:
            # SQLite stores embedding as JSON or vector representation
            emb = rec.embedding
            if isinstance(emb, list):
                sim = _cosine_similarity(query_vector, emb)
                if sim >= min_similarity:
                    scored.append((sim, rec))

        # Sort descending by similarity
        scored.sort(key=lambda x: x[0], reverse=True)
        top_candidates = scored[:top_k]

        results: list[RetrievalResult] = []
        for sim, record in top_candidates:
            results.append(
                RetrievalResult(
                    id=record.id,
                    source_document=record.source_document,
                    section_title=record.section_title,
                    chunk_index=record.chunk_index,
                    content=record.content,
                    similarity_score=round(sim, 6),
                    chunk_metadata=record.chunk_metadata or {},
                    retrieved_at=now_utc,
                )
            )

        return results
