"""
AISOP Knowledge Base & Vector Embedding ORM Models.

Implements the Knowledge & Retrieval Layer (Milestone P2-H2):
- KnowledgeEmbedding: Curated security knowledge chunk with persistent pgvector embedding.
- Exact-content deduplication via SHA-256 digest on normalized content text.
- Metadata storage using PostgreSQL JSONB with SQLite JSON fallback for testing.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from pgvector.sqlalchemy import Vector
from sqlalchemy import JSON, Index, Integer, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column


class KnowledgeEmbedding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Curated knowledge base chunk with persistent vector embedding for RAG.

    Security note: Stored knowledge content represents retrieved reference context/data,
    not trusted system instructions. Prompt injection defenses and contextual separation
    apply at retrieval and reasoning boundaries.
    """

    __tablename__ = "knowledge_embeddings"

    # Primary key without redundant B-tree index (UUID PK already provides primary-key index)
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    source_document: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    section_title: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    chunk_index: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    content: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    content_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=False, index=True
    )
    embedding: Mapped[list[float]] = mapped_column(
        Vector(768), nullable=False
    )
    # Uses PostgreSQL JSONB natively; falls back to standard JSON for SQLite unit tests
    chunk_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"), nullable=False, default=dict
    )

    __table_args__ = (
        Index(
            "ix_knowledge_embeddings_source_document_chunk_index",
            "source_document",
            "chunk_index",
            unique=True,
        ),
    )

    @staticmethod
    def compute_hash(content: str) -> str:
        """
        Compute deterministic SHA-256 hash for exact-content deduplication.
        Knowledge lifecycle and versioning are tracked via chunk_metadata (source/version).
        """
        return hashlib.sha256(content.strip().encode("utf-8")).hexdigest()


# HNSW Cosine Index (PostgreSQL only; ignored by SQLite)
# Parameters m=16, ef_construction=64 represent an initial recall/latency trade-off
# that will be empirically evaluated later.
Index(
    "ix_knowledge_embeddings_embedding_hnsw",
    KnowledgeEmbedding.embedding,
    postgresql_using="hnsw",
    postgresql_ops={"embedding": "vector_cosine_ops"},
    postgresql_with={"m": 16, "ef_construction": 64},
)
