"""
AISOP Knowledge Base Schemas & Data Contracts.

In accordance with ADR-002 (PostgreSQL/pgvector):
Defines Pydantic v2 contracts for knowledge source ingestion, chunk provenance,
ingestion results, cosine retrieval requests, and auditable retrieval results.

Security note: RetrievalResult content represents untrusted reference material
retrieved from the knowledge base. It must never be evaluated as instructions.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SourceSection(BaseModel):
    """A single logical section extracted from a knowledge source document."""

    model_config = ConfigDict(frozen=True)

    source_document: str = Field(
        description="Relative path from knowledge_base/ root (e.g. 'mitre/T1059.md').",
    )
    section_title: str = Field(
        description="Heading text or filename stem if no heading is present.",
    )
    raw_text: str = Field(
        description="Raw text content of the section before chunking.",
    )
    doc_version: str = Field(
        default="",
        description="SHA-256 digest of the source file content for version tracking.",
    )
    file_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Ancillary metadata extracted from the source file (e.g. YAML frontmatter).",
    )


class ChunkRecord(BaseModel):
    """A deterministic sliding-window chunk ready for embedding and persistence."""

    model_config = ConfigDict(frozen=True)

    source_document: str = Field(
        description="Relative path from knowledge_base/ root.",
    )
    section_title: str = Field(
        description="Section heading or filename stem.",
    )
    content: str = Field(
        description="Chunk text content.",
    )
    content_hash: str = Field(
        description="SHA-256 hex digest of the stripped content (64 hex chars).",
    )
    chunk_index: int = Field(
        ge=0,
        description="0-based position of this chunk within its parent section.",
    )
    total_chunks: int = Field(
        gt=0,
        description="Total number of chunks produced from the parent section.",
    )
    chunk_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Provenance metadata: source_document, section_title, chunk_index, "
            "total_chunks, embedding_model, doc_version, ingested_at."
        ),
    )


class ChunkError(BaseModel):
    """Record of a single chunk-level failure during ingestion."""

    model_config = ConfigDict(frozen=True)

    chunk_index: int = Field(description="0-based chunk index that failed.")
    content_hash: str = Field(description="SHA-256 hash of the failed chunk.")
    error_type: str = Field(description="Exception class name.")
    error_message: str = Field(description="Human-readable failure description.")


class IngestionResult(BaseModel):
    """Summary result returned after ingesting a single source document."""

    model_config = ConfigDict(frozen=True)

    source_document: str = Field(
        description="Relative path of the source document that was processed.",
    )
    status: str = Field(
        default="success",
        description="Ingestion outcome status: 'success', 'unchanged', or 'failed'.",
    )
    total_chunks: int = Field(
        ge=0,
        description="Total number of chunks generated from the document.",
    )
    successful_chunks: int = Field(
        ge=0,
        description="Number of chunks persisted successfully (new inserts).",
    )
    skipped_duplicates: int = Field(
        ge=0,
        description="Number of chunks skipped because content_hash or doc_version already existed.",
    )
    superseded_chunks: int = Field(
        default=0,
        ge=0,
        description="Number of previous-version chunks replaced during re-ingestion.",
    )
    errors: list[ChunkError] = Field(
        default_factory=list,
        description="Per-chunk failures; empty if all chunks processed successfully.",
    )
    duration_ms: float = Field(
        ge=0.0,
        description="Wall-clock duration of the full ingestion run in milliseconds.",
    )


class RetrievalRequest(BaseModel):
    """Request contract for cosine similarity knowledge retrieval."""

    model_config = ConfigDict(frozen=True)

    query: str = Field(
        min_length=3,
        description="Natural-language query to embed and match against the knowledge base.",
    )
    top_k: int = Field(
        default=5,
        gt=0,
        le=20,
        description="Maximum number of results to return (hard upper bound: 20).",
    )
    source_document_filter: str | None = Field(
        default=None,
        description=(
            "Optional prefix filter on source_document "
            "(e.g. 'mitre/' to restrict to MITRE ATT&CK chunks). "
            "Matched via LIKE prefix on the stored relative path."
        ),
    )
    min_similarity: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description=(
            "Optional post-retrieval minimum cosine similarity threshold (0.0-1.0). "
            "Results below this threshold are excluded from the returned list."
        ),
    )


class RetrievalResult(BaseModel):
    """
    A single cosine-similar knowledge chunk returned by the retriever.

    Security note: Content is untrusted reference material sourced from the knowledge base.
    It must NOT be evaluated as code, SQL, shell commands, or system instructions.
    Downstream prompt assembly (P2-H5) is responsible for applying contextual boundaries.
    """

    model_config = ConfigDict(frozen=True)

    id: uuid.UUID = Field(
        description="UUID of the stored KnowledgeEmbedding row; enables exact round-trip lookup.",
    )
    source_document: str = Field(
        description="Relative path from knowledge_base/ root (e.g. 'mitre/T1059.md').",
    )
    section_title: str = Field(
        description="Section heading or filename stem for citation.",
    )
    chunk_index: int = Field(
        ge=0,
        description="0-based document-wide position of this chunk within its source document.",
    )
    content: str = Field(
        description="Raw chunk text content (untrusted reference material).",
    )
    similarity_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Cosine similarity score (1 - cosine distance); 1.0 = identical.",
    )
    chunk_metadata: dict[str, Any] = Field(
        description=(
            "Full provenance chain: chunk_index, total_chunks, ingested_at, "
            "embedding_model, source_document, section_title."
        ),
    )
    retrieved_at: datetime = Field(
        description="UTC timestamp of this retrieval operation.",
    )
