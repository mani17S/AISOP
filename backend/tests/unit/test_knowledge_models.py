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
        chunk_index=0,
        content="Adversaries may abuse command and script interpreters to execute commands.",
        content_hash=KnowledgeEmbedding.compute_hash("Adversaries may abuse command and script interpreters to execute commands."),
        embedding=dummy_embedding,
        chunk_metadata={"technique_id": "T1059", "tactic": "execution", "version": "v1.0"},
    )

    assert chunk.id == chunk_id
    assert isinstance(chunk.id, uuid.UUID)
    assert chunk.source_document == "mitre/attack/T1059.md"
    assert chunk.section_title == "T1059 - Command and Scripting Interpreter"
    assert chunk.chunk_index == 0
    assert len(chunk.embedding) == 768
    assert chunk.chunk_metadata["technique_id"] == "T1059"


@pytest.mark.anyio
async def test_knowledge_embedding_crud_sqlite(db_session):
    """
    Verify KnowledgeEmbedding insert and retrieval lifecycle in SQLite test session.
    Validates automatic UUID generation, column mapping, chunk_index, and JSON metadata serialization.
    """
    dummy_vec = [float(i) / 1000.0 for i in range(768)]
    raw_content = "Process injection via CreateRemoteThread."
    content_hash = KnowledgeEmbedding.compute_hash(raw_content)

    chunk = KnowledgeEmbedding(
        source_document="mitre/attack/T1055.md",
        section_title="T1055 - Process Injection",
        chunk_index=0,
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
    assert fetched.chunk_index == 0
    assert fetched.content == raw_content
    assert fetched.chunk_metadata == {"technique_id": "T1055", "platforms": ["Windows"]}
    assert len(fetched.embedding) == 768
    assert fetched.created_at is not None
    assert fetched.updated_at is not None


@pytest.mark.anyio
async def test_knowledge_embedding_equal_content_hash_permitted_sqlite(db_session):
    """
    Milestone P2-H3 Phase A: Verify non-unique content_hash allows identical text
    across different documents and across different chunk positions in the same document.
    """
    raw_content = "Shared duplicate knowledge text."
    dup_hash = KnowledgeEmbedding.compute_hash(raw_content)

    # Cross-document duplicate content
    chunk_doc1_pos0 = KnowledgeEmbedding(
        source_document="doc1.md",
        section_title="Section 1",
        chunk_index=0,
        content=raw_content,
        content_hash=dup_hash,
        embedding=[0.0] * 768,
        chunk_metadata={},
    )
    chunk_doc2_pos0 = KnowledgeEmbedding(
        source_document="doc2.md",
        section_title="Section 2",
        chunk_index=0,
        content=raw_content,
        content_hash=dup_hash,
        embedding=[0.1] * 768,
        chunk_metadata={},
    )
    # Intra-document duplicate content at a distinct position
    chunk_doc1_pos1 = KnowledgeEmbedding(
        source_document="doc1.md",
        section_title="Section 1 Repeated",
        chunk_index=1,
        content=raw_content,
        content_hash=dup_hash,
        embedding=[0.0] * 768,
        chunk_metadata={},
    )

    db_session.add_all([chunk_doc1_pos0, chunk_doc2_pos0, chunk_doc1_pos1])
    await db_session.commit()

    # Query back all chunks sharing the hash
    result = await db_session.execute(
        select(KnowledgeEmbedding).where(KnowledgeEmbedding.content_hash == dup_hash)
    )
    records = result.scalars().all()
    assert len(records) == 3


@pytest.mark.anyio
async def test_knowledge_embedding_composite_position_uniqueness_sqlite(db_session):
    """
    Milestone P2-H3 Phase A: Verify UNIQUE(source_document, chunk_index) rejects
    inserting two chunks with the same source_document and chunk_index.
    """
    chunk1 = KnowledgeEmbedding(
        source_document="doc_uniq.md",
        section_title="Section A",
        chunk_index=0,
        content="First chunk at index 0.",
        content_hash=KnowledgeEmbedding.compute_hash("First chunk at index 0."),
        embedding=[0.0] * 768,
        chunk_metadata={},
    )
    chunk2 = KnowledgeEmbedding(
        source_document="doc_uniq.md",
        section_title="Section B",
        chunk_index=0,  # Duplicate position in same document
        content="Distinct text at conflicting index 0.",
        content_hash=KnowledgeEmbedding.compute_hash("Distinct text at conflicting index 0."),
        embedding=[0.2] * 768,
        chunk_metadata={},
    )

    db_session.add(chunk1)
    await db_session.commit()

    db_session.add(chunk2)
    with pytest.raises(IntegrityError):
        await db_session.commit()

    await db_session.rollback()


@pytest.mark.anyio
async def test_knowledge_embedding_chunk_index_not_null_sqlite(db_session):
    """
    Milestone P2-H3 Phase A: Verify that chunk_index is NOT NULL and rejecting null values.
    """
    chunk = KnowledgeEmbedding(
        source_document="doc_null.md",
        section_title="Section Null",
        chunk_index=None,  # Invalid null value
        content="Chunk with null index.",
        content_hash=KnowledgeEmbedding.compute_hash("Chunk with null index."),
        embedding=[0.0] * 768,
        chunk_metadata={},
    )
    db_session.add(chunk)
    with pytest.raises(IntegrityError):
        await db_session.commit()

    await db_session.rollback()
