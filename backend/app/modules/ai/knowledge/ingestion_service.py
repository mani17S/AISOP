"""
AISOP Knowledge Ingestion Service.

Implements the Knowledge Base Ingestion Pipeline (Milestone P2-H3) in accordance with
ADR-001 (Direct Lightweight LLM Abstraction) and ADR-002 (PostgreSQL/pgvector):
- Discovers and loads source documents (.md, .txt, .yaml, .yml) via KnowledgeSourceLoader.
- Deterministically chunks source sections via DocumentChunker.
- Generates 768-dimensional embeddings via OllamaEmbedder into memory before database mutation.
- Safely manages the document lifecycle with version-detection (SHA-256 doc_version):
  * Documents with unchanged versions are skipped idempotently (no wasted embedding calls).
  * Changed documents generate all embeddings in memory first; if embedding fails,
    the existing indexed version remains completely intact and undisturbed.
  * Successful re-ingestion atomically supersedes previous chunks within a database savepoint.
  * Ingestion failures roll back cleanly, preventing ambiguous or partially replaced state.
- Stores provenance (source_document, section_title, doc_version, chunk_index, total_chunks,
  embedding_model, ingested_at) in JSONB chunk_metadata.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import Settings, get_settings
from app.models.knowledge import KnowledgeEmbedding
from app.modules.ai.embeddings.embedder import OllamaEmbedder
from app.modules.ai.knowledge.chunker import DocumentChunker
from app.modules.ai.knowledge.loader import KnowledgeSourceLoader
from app.schemas.knowledge import (
    ChunkError,
    ChunkRecord,
    IngestionResult,
    SourceSection,
)
from loguru import logger
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession


class KnowledgeIngestionService:
    """
    Coordinates knowledge document discovery, chunking, embedding, and atomic persistence.

    Guarantees:
    - Atomicity: Old document chunks are never deleted unless new chunks and embeddings succeed.
    - Idempotency: Documents with unchanged content versions are detected and skipped.
    - Integrity: Fixed 768-dimensional embedding space enforced before persistence.
    """

    def __init__(
        self,
        loader: KnowledgeSourceLoader | None = None,
        chunker: DocumentChunker | None = None,
        embedder: OllamaEmbedder | None = None,
        settings: Settings | None = None,
    ) -> None:
        cfg = settings or get_settings()
        self._settings = cfg
        self._loader = loader or KnowledgeSourceLoader(cfg)
        self._chunker = chunker or DocumentChunker(cfg)
        self._embedder = embedder or OllamaEmbedder(cfg)

    @property
    def loader(self) -> KnowledgeSourceLoader:
        return self._loader

    @property
    def chunker(self) -> DocumentChunker:
        return self._chunker

    @property
    def embedder(self) -> OllamaEmbedder:
        return self._embedder

    async def ingest_document(
        self,
        file_path: Path,
        session: AsyncSession,
        *,
        force_reindex: bool = False,
    ) -> IngestionResult:
        """
        Ingest a single knowledge source file into the knowledge_embeddings table.

        Args:
            file_path: Path to the knowledge source document.
            session: Active SQLAlchemy AsyncSession.
            force_reindex: If True, re-indexes even if doc_version matches existing chunks.

        Returns:
            IngestionResult detailing the outcome.
        """
        start_time = time.perf_counter()

        # Step 1: Load sections and compute source version
        sections: list[SourceSection] = self._loader.load_file(file_path)
        if not sections:
            return IngestionResult(
                source_document=str(file_path),
                status="unchanged",
                total_chunks=0,
                successful_chunks=0,
                skipped_duplicates=0,
                superseded_chunks=0,
                duration_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
            )

        source_document = sections[0].source_document
        doc_version = sections[0].doc_version

        logger.info(
            "Evaluating knowledge document for ingestion",
            source_document=source_document,
            doc_version=doc_version[:12] if doc_version else "none",
        )

        # Step 2: Check existing indexed chunks for this source_document
        stmt = select(KnowledgeEmbedding).where(
            KnowledgeEmbedding.source_document == source_document
        )
        existing_rows = (await session.execute(stmt)).scalars().all()

        # Version-based change detection
        if existing_rows and not force_reindex and doc_version:
            # Check if all existing chunks share the same doc_version
            existing_versions = {
                row.chunk_metadata.get("doc_version")
                for row in existing_rows
                if isinstance(row.chunk_metadata, dict)
            }
            if existing_versions == {doc_version}:
                logger.info(
                    "Document unchanged; skipping re-indexing",
                    source_document=source_document,
                    doc_version=doc_version[:12],
                    indexed_chunks=len(existing_rows),
                )
                duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                return IngestionResult(
                    source_document=source_document,
                    status="unchanged",
                    total_chunks=len(existing_rows),
                    successful_chunks=0,
                    skipped_duplicates=len(existing_rows),
                    superseded_chunks=0,
                    duration_ms=duration_ms,
                )

        # Step 3: Chunk all sections using document-wide continuous 0-based indexing
        chunks: list[ChunkRecord] = self._chunker.chunk_document(sections)

        if not chunks:
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return IngestionResult(
                source_document=source_document,
                status="unchanged",
                total_chunks=0,
                successful_chunks=0,
                skipped_duplicates=0,
                superseded_chunks=0,
                duration_ms=duration_ms,
            )

        # Step 4: In-memory embedding deduplication across identical chunk texts
        # Collect unique text strings to avoid redundant embedding model calls
        # (Preserves every physical chunk occurrence under Option A-Prime)
        unique_texts_to_embed: list[str] = []
        seen_texts: set[str] = set()
        for chunk in chunks:
            if chunk.content not in seen_texts:
                seen_texts.add(chunk.content)
                unique_texts_to_embed.append(chunk.content)

        reused_embeddings_count = len(chunks) - len(unique_texts_to_embed)

        embeddings_by_text: dict[str, list[float]] = {}
        if unique_texts_to_embed:
            try:
                raw_vectors = await self._embedder.embed_batch(unique_texts_to_embed)
                embeddings_by_text = dict(zip(unique_texts_to_embed, raw_vectors))
            except Exception as exc:
                logger.error(
                    "Embedding generation failed; preserving existing indexed version",
                    source_document=source_document,
                    error=str(exc),
                )
                duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                errors = [
                    ChunkError(
                        chunk_index=0,
                        content_hash=chunks[0].content_hash if chunks else "",
                        error_type=type(exc).__name__,
                        error_message=str(exc),
                    )
                ]
                return IngestionResult(
                    source_document=source_document,
                    status="failed",
                    total_chunks=len(chunks),
                    successful_chunks=0,
                    skipped_duplicates=0,
                    superseded_chunks=0,
                    errors=errors,
                    duration_ms=duration_ms,
                )

        # Step 5: Atomic database replacement inside nested savepoint
        superseded_count = len(existing_rows)
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            async with session.begin_nested():
                if existing_rows:
                    await session.execute(
                        delete(KnowledgeEmbedding).where(
                            KnowledgeEmbedding.source_document == source_document
                        )
                    )

                for chunk in chunks:
                    meta = dict(chunk.chunk_metadata)
                    meta["ingested_at"] = now_iso
                    meta["doc_version"] = doc_version

                    record = KnowledgeEmbedding(
                        source_document=chunk.source_document,
                        section_title=chunk.section_title,
                        chunk_index=chunk.chunk_index,
                        content=chunk.content,
                        content_hash=chunk.content_hash,
                        embedding=embeddings_by_text[chunk.content],
                        chunk_metadata=meta,
                    )
                    session.add(record)

                await session.flush()
        except Exception as exc:
            logger.error(
                "Database operation failed during ingestion; rolling back savepoint",
                source_document=source_document,
                error=str(exc),
            )
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            errors = [
                ChunkError(
                    chunk_index=0,
                    content_hash=chunks[0].content_hash if chunks else "",
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
            ]
            return IngestionResult(
                source_document=source_document,
                status="failed",
                total_chunks=len(chunks),
                successful_chunks=0,
                skipped_duplicates=0,
                superseded_chunks=0,
                errors=errors,
                duration_ms=duration_ms,
            )

        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.info(
            "Document ingestion completed successfully",
            source_document=source_document,
            total_chunks=len(chunks),
            successful_chunks=len(chunks),
            reused_embeddings=reused_embeddings_count,
            superseded_chunks=superseded_count,
            duration_ms=duration_ms,
        )

        return IngestionResult(
            source_document=source_document,
            status="success",
            total_chunks=len(chunks),
            successful_chunks=len(chunks),
            skipped_duplicates=reused_embeddings_count,
            superseded_chunks=superseded_count,
            duration_ms=duration_ms,
        )

    async def ingest_directory(
        self,
        session: AsyncSession,
        subdirectory: str | None = None,
        *,
        force_reindex: bool = False,
    ) -> list[IngestionResult]:
        """
        Recursively ingest all accepted documents in knowledge_base/.

        Args:
            session: Active SQLAlchemy AsyncSession.
            subdirectory: Optional subdirectory to restrict scanning.
            force_reindex: If True, re-indexes unchanged documents.

        Returns:
            List of IngestionResult objects.
        """
        scan_root = self._loader.knowledge_base_root
        if subdirectory:
            scan_root = (scan_root / subdirectory).resolve()

        results: list[IngestionResult] = []
        for file_path in sorted(scan_root.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in {".md", ".txt", ".yaml", ".yml"}:
                continue

            try:
                res = await self.ingest_document(
                    file_path, session, force_reindex=force_reindex
                )
                results.append(res)
            except Exception as exc:
                logger.error(
                    "Unhandled exception during document ingestion",
                    file_path=str(file_path),
                    error=str(exc),
                )
                results.append(
                    IngestionResult(
                        source_document=str(file_path),
                        status="failed",
                        total_chunks=0,
                        successful_chunks=0,
                        skipped_duplicates=0,
                        superseded_chunks=0,
                        errors=[
                            ChunkError(
                                chunk_index=0,
                                content_hash="",
                                error_type=type(exc).__name__,
                                error_message=str(exc),
                            )
                        ],
                        duration_ms=0.0,
                    )
                )

        return results
