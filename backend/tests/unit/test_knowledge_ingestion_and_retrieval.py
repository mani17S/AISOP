"""
Unit tests for KnowledgeIngestionService and KnowledgeRetriever.

Tests offline using SQLite async session and mocked OllamaEmbedder:
- Changed-document lifecycle (unchanged skip, safe replacement, atomic savepoint rollback).
- Ingestion error safety: embedding failure leaves prior indexed rows completely intact.
- Retrieval ranking, threshold boundary semantics, empty results, source filter.
- Provenance preservation in RetrievalResult.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from app.core.config import Settings
from app.models.knowledge import KnowledgeEmbedding
from app.modules.ai.embeddings.embedder import OllamaEmbedder
from app.modules.ai.embeddings.exceptions import EmbeddingConnectionError
from app.modules.ai.knowledge.chunker import DocumentChunker
from app.modules.ai.knowledge.ingestion_service import KnowledgeIngestionService
from app.modules.ai.knowledge.loader import KnowledgeSourceLoader
from app.modules.ai.knowledge.retriever import KnowledgeRetriever
from app.schemas.knowledge import RetrievalRequest, RetrievalResult
from pydantic import ValidationError
from sqlalchemy import select


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _make_dummy_vector(seed: float = 0.1) -> list[float]:
    """Return a 768-dimensional normalized float vector."""
    vec = [seed] * 768
    norm = sum(x * x for x in vec) ** 0.5
    return [x / norm for x in vec]


@pytest.fixture
def test_doc_file(tmp_path: Path) -> Path:
    kb_dir = tmp_path / "knowledge_base"
    kb_dir.mkdir()
    doc = kb_dir / "mitre_test.md"
    doc.write_text(
        "## Technique T1059\nCommand and Scripting Interpreter.\n"
        "PowerShell is used by adversaries to execute commands.\n",
        encoding="utf-8",
    )
    return doc


@pytest.mark.anyio
async def test_ingestion_service_new_document_and_unchanged_skip(
    db_session, test_doc_file: Path
):
    settings = Settings(
        KNOWLEDGE_BASE_PATH=str(test_doc_file.parent),
        EMBEDDING_DIMENSIONS=768,
    )
    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed_batch.return_value = [_make_dummy_vector(0.1)]

    service = KnowledgeIngestionService(
        embedder=mock_embedder,
        settings=settings,
    )

    # 1. Initial ingestion
    res1 = await service.ingest_document(test_doc_file, db_session)
    assert res1.status == "success"
    assert res1.successful_chunks >= 1
    assert res1.superseded_chunks == 0
    assert mock_embedder.embed_batch.call_count == 1

    # Verify rows in DB
    rows = (await db_session.execute(select(KnowledgeEmbedding))).scalars().all()
    assert len(rows) == res1.successful_chunks

    # 2. Second ingestion with unchanged file -> skips idempotently without calling embedder
    res2 = await service.ingest_document(test_doc_file, db_session)
    assert res2.status == "unchanged"
    assert res2.successful_chunks == 0
    assert res2.skipped_duplicates == len(rows)
    assert mock_embedder.embed_batch.call_count == 1  # Not called again!


@pytest.mark.anyio
async def test_ingestion_service_changed_document_safe_replacement(
    db_session, test_doc_file: Path
):
    settings = Settings(
        KNOWLEDGE_BASE_PATH=str(test_doc_file.parent),
        EMBEDDING_DIMENSIONS=768,
    )
    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed_batch.side_effect = [
        [_make_dummy_vector(0.1)],  # First call
        [
            _make_dummy_vector(0.2),
            _make_dummy_vector(0.3),
        ],  # Second call (modified file)
    ]

    service = KnowledgeIngestionService(
        embedder=mock_embedder,
        settings=settings,
    )

    # Ingest version 1
    res1 = await service.ingest_document(test_doc_file, db_session)
    assert res1.status == "success"
    assert res1.superseded_chunks == 0

    # Modify file content (new doc_version)
    test_doc_file.write_text(
        "## Technique T1059\nUpdated text for PowerShell and Bash.\n\n"
        "## Sub-technique T1059.001\nPowerShell execution details.\n",
        encoding="utf-8",
    )

    # Ingest version 2 -> replaces previous chunks atomically
    res2 = await service.ingest_document(test_doc_file, db_session)
    assert res2.status == "success"
    assert res2.successful_chunks == 2
    assert res2.superseded_chunks == res1.successful_chunks

    # Verify that only version 2 chunks exist in the DB
    rows = (await db_session.execute(select(KnowledgeEmbedding))).scalars().all()
    assert len(rows) == 2
    for r in rows:
        assert r.chunk_metadata["doc_version"] != ""


@pytest.mark.anyio
async def test_ingestion_service_embedding_failure_preserves_old_version(
    db_session, test_doc_file: Path
):
    settings = Settings(
        KNOWLEDGE_BASE_PATH=str(test_doc_file.parent),
        EMBEDDING_DIMENSIONS=768,
    )
    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed_batch.side_effect = [
        [_make_dummy_vector(0.1)],  # Initial ingest succeeds
        EmbeddingConnectionError("Ollama is down"),  # Re-ingest fails at embed step
    ]

    service = KnowledgeIngestionService(
        embedder=mock_embedder,
        settings=settings,
    )

    # Initial ingest
    res1 = await service.ingest_document(test_doc_file, db_session)
    assert res1.status == "success"

    # Modify document
    test_doc_file.write_text("## Changed Heading\nChanged content.\n", encoding="utf-8")

    # Re-ingest fails because Ollama is down
    res2 = await service.ingest_document(test_doc_file, db_session)
    assert res2.status == "failed"
    assert len(res2.errors) == 1
    assert "EmbeddingConnectionError" in res2.errors[0].error_type

    # Crucial guarantee: The original version chunks are STILL active and preserved!
    rows = (await db_session.execute(select(KnowledgeEmbedding))).scalars().all()
    assert len(rows) == res1.successful_chunks
    assert rows[0].section_title == "Technique T1059"


@pytest.mark.anyio
async def test_retriever_ranking_and_threshold_boundaries(db_session):
    # Construct 3 mathematically distinct unit vectors:
    # vec_a: unit vector on axis 0 (query matches this exactly -> similarity = 1.0)
    # vec_b: unit vector on axis 1 (orthogonal -> similarity = 0.0)
    # vec_c: 45-deg linear combination of axis 0 and 1 -> similarity = ~0.7071
    vec_a = [1.0 if i == 0 else 0.0 for i in range(768)]
    vec_b = [1.0 if i == 1 else 0.0 for i in range(768)]
    c_val = 1.0 / (2.0**0.5)
    vec_c = [c_val if i in (0, 1) else 0.0 for i in range(768)]

    doc_a = KnowledgeEmbedding(
        id=uuid.uuid4(),
        source_document="mitre/t1059.md",
        section_title="PowerShell",
        chunk_index=0,
        content="PowerShell execution details",
        content_hash="hash_a",
        embedding=vec_a,
        chunk_metadata={"doc_version": "v1", "source_document": "mitre/t1059.md"},
    )
    doc_b = KnowledgeEmbedding(
        id=uuid.uuid4(),
        source_document="mitre/t1059.md",
        section_title="Bash",
        chunk_index=1,
        content="Unix bash scripting",
        content_hash="hash_b",
        embedding=vec_b,
        chunk_metadata={"doc_version": "v1", "source_document": "mitre/t1059.md"},
    )
    doc_c = KnowledgeEmbedding(
        id=uuid.uuid4(),
        source_document="yara/rules.md",
        section_title="YARA Rules",
        chunk_index=0,
        content="YARA rule syntax",
        content_hash="hash_c",
        embedding=vec_c,
        chunk_metadata={"doc_version": "v1", "source_document": "yara/rules.md"},
    )
    db_session.add_all([doc_a, doc_b, doc_c])
    await db_session.flush()

    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    # Query vector matches vec_a exactly (cosine similarity = 1.0)
    mock_embedder.embed.return_value = vec_a

    retriever = KnowledgeRetriever(embedder=mock_embedder)

    # Test 1: min_similarity = 0.0 -> all 3 returned in ranking order (a=1.0, c=0.707, b=0.0)
    req1 = RetrievalRequest(
        query="powershell command line", top_k=5, min_similarity=0.0
    )
    results1 = await retriever.retrieve(req1, db_session)
    assert len(results1) == 3
    assert results1[0].section_title == "PowerShell"
    assert results1[0].similarity_score == 1.0
    assert results1[0].chunk_index == 0
    assert results1[1].section_title == "YARA Rules"
    assert 0.70 <= results1[1].similarity_score <= 0.72
    assert results1[1].chunk_index == 0
    assert results1[2].section_title == "Bash"
    assert results1[2].similarity_score == 0.0
    assert results1[2].chunk_index == 1

    # Test 2: source_document_filter = "mitre/" -> only doc_a and doc_b returned
    req2 = RetrievalRequest(
        query="powershell",
        top_k=5,
        source_document_filter="mitre/",
        min_similarity=0.0,
    )
    results2 = await retriever.retrieve(req2, db_session)
    assert len(results2) == 2
    for r in results2:
        assert r.source_document.startswith("mitre/")

    # Test 3: min_similarity = 0.8 -> only exact match doc_a returned (0.707 and 0.0 filtered out)
    req3 = RetrievalRequest(query="powershell", top_k=5, min_similarity=0.8)
    results3 = await retriever.retrieve(req3, db_session)
    assert len(results3) == 1
    assert results3[0].id == doc_a.id

    # Test 4: min_similarity = 0.5 -> doc_a (1.0) and doc_c (0.707) returned, doc_b (0.0) excluded
    req4 = RetrievalRequest(query="powershell", top_k=5, min_similarity=0.5)
    results4 = await retriever.retrieve(req4, db_session)
    assert len(results4) == 2
    assert results4[0].id == doc_a.id
    assert results4[1].id == doc_c.id

    # Test 5: query vector orthogonal to all records -> empty list when min_similarity > 0.0
    mock_embedder.embed.return_value = [1.0 if i == 2 else 0.0 for i in range(768)]
    req5 = RetrievalRequest(query="nonexistent", top_k=5, min_similarity=0.5)
    results5 = await retriever.retrieve(req5, db_session)
    assert results5 == []


@pytest.mark.anyio
async def test_ingestion_service_identical_chunks_across_two_documents(
    db_session, tmp_path: Path
):
    """
    Verify Option A-Prime: identical chunk content in two different source documents is
    persisted separately under each document's respective identity and position.
    """
    kb_dir = tmp_path / "knowledge_base"
    kb_dir.mkdir(parents=True, exist_ok=True)
    doc1 = kb_dir / "doc1.md"
    doc2 = kb_dir / "doc2.md"

    shared_heading = "Technique T1059"
    shared_text = "Adversaries may use PowerShell to execute commands."
    doc1.write_text(f"## {shared_heading}\n{shared_text}\n", encoding="utf-8")
    doc2.write_text(f"## {shared_heading}\n{shared_text}\n", encoding="utf-8")

    settings = Settings(KNOWLEDGE_BASE_PATH=str(kb_dir), EMBEDDING_DIMENSIONS=768)
    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed_batch.return_value = [_make_dummy_vector(0.1)]

    service = KnowledgeIngestionService(embedder=mock_embedder, settings=settings)

    res1 = await service.ingest_document(doc1, db_session)
    assert res1.status == "success"
    assert res1.total_chunks == 1
    assert res1.successful_chunks == 1
    assert res1.skipped_duplicates == 0

    res2 = await service.ingest_document(doc2, db_session)
    assert res2.status == "success"
    assert res2.total_chunks == 1
    assert res2.successful_chunks == 1
    assert res2.skipped_duplicates == 0

    # Verify both physical occurrences exist in DB under their distinct source documents
    stmt = select(KnowledgeEmbedding).order_by(KnowledgeEmbedding.source_document)
    rows = (await db_session.execute(stmt)).scalars().all()
    assert len(rows) == 2
    assert rows[0].source_document == "doc1.md"
    assert rows[0].chunk_index == 0
    assert rows[1].source_document == "doc2.md"
    assert rows[1].chunk_index == 0
    assert rows[0].content_hash == rows[1].content_hash


@pytest.mark.anyio
async def test_ingestion_service_multiple_identical_chunks_in_single_document(
    db_session, tmp_path: Path
):
    """
    Verify Option A-Prime: multiple sections with identical text within the same document
    are persisted as distinct physical occurrences with unique chunk_index values (0 and 1),
    while in-memory embedding computation is shared (1 embedding call made).
    """
    kb_dir = tmp_path / "knowledge_base"
    kb_dir.mkdir(parents=True, exist_ok=True)
    doc = kb_dir / "dup_doc.md"

    doc.write_text(
        "## Repeated Section\nRepeated text across sections.\n\n"
        "## Repeated Section\nRepeated text across sections.\n",
        encoding="utf-8",
    )

    settings = Settings(KNOWLEDGE_BASE_PATH=str(kb_dir), EMBEDDING_DIMENSIONS=768)
    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed_batch.return_value = [_make_dummy_vector(0.1)]

    service = KnowledgeIngestionService(embedder=mock_embedder, settings=settings)
    res = await service.ingest_document(doc, db_session)

    assert res.status == "success"
    assert res.total_chunks == 2
    assert res.successful_chunks == 2
    assert res.skipped_duplicates == 1  # 1 redundant embedding computation saved in memory

    # Verify embed_batch was called with only 1 unique text
    assert mock_embedder.embed_batch.call_count == 1
    call_args = mock_embedder.embed_batch.call_args[0][0]
    assert len(call_args) == 1

    # Verify both occurrences exist in DB with unique continuous positions
    stmt = (
        select(KnowledgeEmbedding)
        .where(KnowledgeEmbedding.source_document == "dup_doc.md")
        .order_by(KnowledgeEmbedding.chunk_index)
    )
    rows = (await db_session.execute(stmt)).scalars().all()
    assert len(rows) == 2
    assert rows[0].chunk_index == 0
    assert rows[1].chunk_index == 1
    assert rows[0].content_hash == rows[1].content_hash
    assert rows[0].embedding == rows[1].embedding


@pytest.mark.anyio
async def test_ingestion_service_db_flush_failure_savepoint_rollback(
    db_session, tmp_path: Path
):
    """
    Verify that a database failure during chunk insertion rolls back the savepoint cleanly,
    leaving the previous indexed version completely intact.
    """
    kb_dir = tmp_path / "knowledge_base"
    kb_dir.mkdir(parents=True, exist_ok=True)
    doc = kb_dir / "rollback_doc.md"

    doc.write_text("## Initial\nInitial content version 1.\n", encoding="utf-8")

    settings = Settings(KNOWLEDGE_BASE_PATH=str(kb_dir), EMBEDDING_DIMENSIONS=768)
    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed_batch.return_value = [_make_dummy_vector(0.1)]

    service = KnowledgeIngestionService(embedder=mock_embedder, settings=settings)

    # Ingest version 1
    res1 = await service.ingest_document(doc, db_session)
    assert res1.status == "success"

    # Verify initial row exists
    rows1 = (await db_session.execute(select(KnowledgeEmbedding))).scalars().all()
    assert len(rows1) == 1
    assert rows1[0].section_title == "Initial"

    # Modify doc to version 2
    doc.write_text("## Version 2\nUpdated content version 2.\n", encoding="utf-8")

    # Simulate DB flush failure during replacement
    original_flush = db_session.flush

    async def mock_failing_flush():
        raise RuntimeError("Simulated DB disk failure during flush")

    db_session.flush = mock_failing_flush

    res2 = await service.ingest_document(doc, db_session)
    assert res2.status == "failed"
    assert len(res2.errors) == 1
    assert "Simulated DB disk failure" in res2.errors[0].error_message

    # Restore flush
    db_session.flush = original_flush

    # Verify that version 1 row is STILL INTACT and was NOT deleted!
    rows_after = (await db_session.execute(select(KnowledgeEmbedding))).scalars().all()
    assert len(rows_after) == 1
    assert rows_after[0].section_title == "Initial"


def test_retrieval_request_boundary_validation():
    """Verify RetrievalRequest rejects invalid top_k and out-of-range thresholds."""
    from pydantic import ValidationError

    # Valid boundaries
    req_valid = RetrievalRequest(query="powershell", top_k=1, min_similarity=0.0)
    assert req_valid.top_k == 1
    assert req_valid.min_similarity == 0.0

    req_valid_max = RetrievalRequest(query="powershell", top_k=20, min_similarity=1.0)
    assert req_valid_max.top_k == 20
    assert req_valid_max.min_similarity == 1.0

    # Query too short (< 3 chars)
    with pytest.raises(ValidationError):
        RetrievalRequest(query="ab")

    # top_k <= 0
    with pytest.raises(ValidationError):
        RetrievalRequest(query="powershell", top_k=0)

    # top_k > 20
    with pytest.raises(ValidationError):
        RetrievalRequest(query="powershell", top_k=21)

    # min_similarity < 0.0
    with pytest.raises(ValidationError):
        RetrievalRequest(query="powershell", min_similarity=-0.01)

    # min_similarity > 1.0
    with pytest.raises(ValidationError):
        RetrievalRequest(query="powershell", min_similarity=1.01)


def test_retrieval_result_requires_explicit_chunk_index():
    """Verify RetrievalResult requires explicit chunk_index (no silent fallback to 0)."""
    # 1. Valid construction with explicit chunk_index
    res = RetrievalResult(
        id=uuid.uuid4(),
        source_document="mitre/t1059.md",
        section_title="PowerShell",
        chunk_index=3,
        content="PowerShell execution details",
        similarity_score=0.95,
        chunk_metadata={"chunk_index": 3},
        retrieved_at=datetime.now(timezone.utc),
    )
    assert res.chunk_index == 3

    # 2. Omitting chunk_index must raise ValidationError
    with pytest.raises(ValidationError) as exc_info:
        RetrievalResult(
            id=uuid.uuid4(),
            source_document="mitre/t1059.md",
            section_title="PowerShell",
            # chunk_index intentionally omitted
            content="PowerShell execution details",
            similarity_score=0.95,
            chunk_metadata={},
            retrieved_at=datetime.now(timezone.utc),
        )
    assert "chunk_index" in str(exc_info.value)
