"""
Unit tests for Knowledge Base & Vector Embedding ORM Models (Milestone P2-H2).

Scope:
- Model instantiation, UUID generation, and timestamp mixin fidelity.
- Deterministic SHA-256 hash computation for exact-content deduplication.
- Knowledge chunk metadata JSON handling.
- Basic CRUD and uniqueness constraint enforcement in isolated SQLite session.

Testing note:
SQLite unit tests validate ORM class mapping, lifecycle methods, and relational
schema structure only. PostgreSQL + pgvector remains the authoritative execution
and retrieval environment.
"""

from __future__ import annotations

import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.knowledge import KnowledgeEmbedding


def test_compute_hash_deterministic():
    """Verify compute_hash produces deterministic SHA-256 digests and strips whitespace."""
    content_a = "  Adversaries may abuse PowerShell commands.  \n"
    content_b = "Adversaries may abuse PowerShell commands."
    content_different = "Adversaries may use bash scripts."

    hash_a = KnowledgeEmbedding.compute_hash(content_a)
    hash_b = KnowledgeEmbedding.compute_hash(content_b)
    hash_diff = KnowledgeEmbedding.compute_hash(content_different)

    assert hash_a == hash_b
    assert len(hash_a) == 64
    assert hash_a != hash_diff


def test_knowledge_embedding_instantiation():
    """Verify KnowledgeEmbedding model instantiates with proper attributes."""
    dummy_embedding = [0.01] * 768
    chunk_id = uuid.uuid4()
    chunk = KnowledgeEmbedding(
        id=chunk_id,
        source_document="mitre/attack/T1059.md",
        section_title="T1059 - Command and Scripting Interpreter",
        content="Adversaries may abuse command and script interpreters to execute commands.",
        content_hash=KnowledgeEmbedding.compute_hash("Adversaries may abuse command and script interpreters to execute commands."),
        embedding=dummy_embedding,
        chunk_metadata={"technique_id": "T1059", "tactic": "execution", "version": "v1.0"},
    )

    assert chunk.id == chunk_id
    assert isinstance(chunk.id, uuid.UUID)
    assert chunk.source_document == "mitre/attack/T1059.md"
    assert chunk.section_title == "T1059 - Command and Scripting Interpreter"
    assert len(chunk.embedding) == 768
    assert chunk.chunk_metadata["technique_id"] == "T1059"


@pytest.mark.anyio
async def test_knowledge_embedding_crud_sqlite(db_session):
    """
    Verify KnowledgeEmbedding insert and retrieval lifecycle in SQLite test session.
    Validates automatic UUID generation, column mapping, and JSON metadata serialization.
    """
    dummy_vec = [float(i) / 1000.0 for i in range(768)]
    raw_content = "Process injection via CreateRemoteThread."
    content_hash = KnowledgeEmbedding.compute_hash(raw_content)

    chunk = KnowledgeEmbedding(
        source_document="mitre/attack/T1055.md",
        section_title="T1055 - Process Injection",
        content=raw_content,
        content_hash=content_hash,
        embedding=dummy_vec,
        chunk_metadata={"technique_id": "T1055", "platforms": ["Windows"]},
    )
    db_session.add(chunk)
    await db_session.commit()

    # Query back
    result = await db_session.execute(
        select(KnowledgeEmbedding).where(KnowledgeEmbedding.content_hash == content_hash)
    )
    fetched = result.scalar_one_or_none()
    assert fetched is not None
    assert fetched.id is not None
    assert isinstance(fetched.id, uuid.UUID)
    assert fetched.source_document == "mitre/attack/T1055.md"
    assert fetched.section_title == "T1055 - Process Injection"
    assert fetched.content == raw_content
    assert fetched.chunk_metadata == {"technique_id": "T1055", "platforms": ["Windows"]}
    assert len(fetched.embedding) == 768
    assert fetched.created_at is not None
    assert fetched.updated_at is not None


@pytest.mark.anyio
async def test_knowledge_embedding_unique_content_hash_sqlite(db_session):
    """Verify unique constraint on content_hash prevents duplicate insertion."""
    raw_content = "Shared duplicate knowledge text."
    dup_hash = KnowledgeEmbedding.compute_hash(raw_content)

    chunk1 = KnowledgeEmbedding(
        source_document="doc1.md",
        section_title="Section 1",
        content=raw_content,
        content_hash=dup_hash,
        embedding=[0.0] * 768,
        chunk_metadata={},
    )
    chunk2 = KnowledgeEmbedding(
        source_document="doc2.md",
        section_title="Section 2",
        content=raw_content,
        content_hash=dup_hash,
        embedding=[0.1] * 768,
        chunk_metadata={},
    )

    db_session.add(chunk1)
    await db_session.commit()

    db_session.add(chunk2)
    with pytest.raises(IntegrityError):
        await db_session.commit()

    await db_session.rollback()
