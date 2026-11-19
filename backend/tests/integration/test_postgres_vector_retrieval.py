"""
Integration tests for KnowledgeRetriever and KnowledgeIngestionService with live PostgreSQL & pgvector.

Runs strictly against the containerized PostgreSQL 17 + pgvector service.
Validates:
- pgvector cosine distance (<=>) retrieval, ranking, and limit.
- SQL-level threshold boundaries (WHERE distance <= 1.0 - min_similarity) preventing top-k candidate truncation.
- Document prefix filter (LIKE 'prefix%').
- Atomic document replacement lifecycle on PostgreSQL.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from app.core.config import Settings
from app.models.knowledge import KnowledgeEmbedding
from app.modules.ai.embeddings.embedder import OllamaEmbedder
from app.modules.ai.knowledge.ingestion_service import KnowledgeIngestionService
from app.modules.ai.knowledge.retriever import KnowledgeRetriever
from app.schemas.knowledge import RetrievalRequest
import math
from sqlalchemy import select, text


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.postgres
@pytest.mark.anyio
async def test_postgres_pgvector_retriever_ranking_and_boundaries(postgres_session):
    # Insert 3 records with mathematically distinct unit vectors
    # vec_a: axis 0 (query matches this exactly -> similarity = 1.0, distance = 0.0)
    # vec_b: axis 1 (orthogonal -> similarity = 0.0, distance = 1.0)
    # vec_c: 45-deg angle -> similarity = 0.7071, distance = ~0.2929
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
        content_hash="pg_hash_a",
        embedding=vec_a,
        chunk_metadata={"doc_version": "v1", "source_document": "mitre/t1059.md"},
    )
    doc_b = KnowledgeEmbedding(
        id=uuid.uuid4(),
        source_document="mitre/t1059.md",
        section_title="Bash",
        chunk_index=1,
        content="Unix bash scripting",
        content_hash="pg_hash_b",
        embedding=vec_b,
        chunk_metadata={"doc_version": "v1", "source_document": "mitre/t1059.md"},
    )
    doc_c = KnowledgeEmbedding(
        id=uuid.uuid4(),
        source_document="yara/rules.md",
        section_title="YARA Rules",
        chunk_index=0,
        content="YARA rule syntax",
        content_hash="pg_hash_c",
        embedding=vec_c,
        chunk_metadata={"doc_version": "v1", "source_document": "yara/rules.md"},
    )
    postgres_session.add_all([doc_a, doc_b, doc_c])
    await postgres_session.flush()

    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed.return_value = vec_a

    retriever = KnowledgeRetriever(embedder=mock_embedder)

    # 1. Ranking order verification with min_similarity = 0.0
    req1 = RetrievalRequest(query="powershell", top_k=5, min_similarity=0.0)
    results1 = await retriever.retrieve(req1, postgres_session)
    assert len(results1) == 3
    assert results1[0].id == doc_a.id
    assert results1[0].similarity_score == 1.0
    assert results1[0].chunk_index == 0
    assert results1[1].id == doc_c.id
    assert 0.70 <= results1[1].similarity_score <= 0.72
    assert results1[1].chunk_index == 0
    assert results1[2].id == doc_b.id
    assert results1[2].similarity_score == 0.0
    assert results1[2].chunk_index == 1

    # 2. Source prefix filter
    req2 = RetrievalRequest(
        query="powershell", top_k=5, source_document_filter="mitre/", min_similarity=0.0
    )
    results2 = await retriever.retrieve(req2, postgres_session)
    assert len(results2) == 2
    for r in results2:
        assert r.source_document.startswith("mitre/")

    # 3. Threshold boundary filter at SQL level: min_similarity = 0.8
    # Only doc_a satisfies distance <= 0.2; doc_c (dist ~0.29) and doc_b (dist 1.0) excluded
    req3 = RetrievalRequest(query="powershell", top_k=5, min_similarity=0.8)
    results3 = await retriever.retrieve(req3, postgres_session)
    assert len(results3) == 1
    assert results3[0].id == doc_a.id

    # 4. Threshold boundary filter: min_similarity = 0.5
    # doc_a (1.0) and doc_c (~0.707) satisfy distance <= 0.5
    req4 = RetrievalRequest(query="powershell", top_k=5, min_similarity=0.5)
    results4 = await retriever.retrieve(req4, postgres_session)
    assert len(results4) == 2
    assert results4[0].id == doc_a.id
    assert results4[1].id == doc_c.id


@pytest.mark.postgres
@pytest.mark.anyio
async def test_postgres_ingestion_lifecycle_and_safe_replacement(
    postgres_session, tmp_path: Path
):
    kb_dir = tmp_path / "knowledge_base"
    kb_dir.mkdir()
    doc_file = kb_dir / "technique.md"
    doc_file.write_text(
        "## Technique T1059\nOriginal PowerShell content.\n",
        encoding="utf-8",
    )

    settings = Settings(
        KNOWLEDGE_BASE_PATH=str(kb_dir),
        EMBEDDING_DIMENSIONS=768,
    )

    vec_1 = [1.0 if i == 0 else 0.0 for i in range(768)]
    vec_2 = [1.0 if i == 1 else 0.0 for i in range(768)]

    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed_batch.side_effect = [
        [vec_1],  # Version 1
        [vec_2],  # Version 2
    ]

    service = KnowledgeIngestionService(embedder=mock_embedder, settings=settings)

    # 1. Initial ingestion
    res1 = await service.ingest_document(doc_file, postgres_session)
    assert res1.status == "success"
    assert res1.successful_chunks == 1
    assert res1.superseded_chunks == 0

    rows1 = (await postgres_session.execute(select(KnowledgeEmbedding))).scalars().all()
    assert len(rows1) == 1
    assert rows1[0].section_title == "Technique T1059"

    # 2. Modify file and re-ingest -> safe atomic replacement on PostgreSQL
    doc_file.write_text(
        "## Technique T1059 Updated\nReplacement PowerShell and Python content.\n",
        encoding="utf-8",
    )

    res2 = await service.ingest_document(doc_file, postgres_session)
    assert res2.status == "success"
    assert res2.successful_chunks == 1
    assert res2.superseded_chunks == 1

    rows2 = (await postgres_session.execute(select(KnowledgeEmbedding))).scalars().all()
    assert len(rows2) == 1
    assert rows2[0].section_title == "Technique T1059 Updated"


@pytest.mark.postgres
@pytest.mark.anyio
async def test_postgres_ingestion_cross_document_and_intra_document_deduplication(
    postgres_session, tmp_path: Path
):
    """
    Verify on live PostgreSQL + pgvector that:
    1. Identical chunk content in two different source documents is deduplicated without UniqueViolation.
    2. Repeated sections with identical content in one document are deduplicated.
    """
    kb_dir = tmp_path / "knowledge_base"
    kb_dir.mkdir()
    doc1 = kb_dir / "doc1.md"
    doc2 = kb_dir / "doc2.md"
    doc_repeat = kb_dir / "doc_repeat.md"

    shared_heading = "T1059 Command Execution"
    shared_text = "Adversaries execute commands via interactive command interpreters."
    doc1.write_text(f"## {shared_heading}\n{shared_text}\n", encoding="utf-8")
    doc2.write_text(f"## {shared_heading}\n{shared_text}\n", encoding="utf-8")
    doc_repeat.write_text(
        "## Section One\nUnique repeat test text.\n\n"
        "## Section One\nUnique repeat test text.\n",
        encoding="utf-8",
    )

    settings = Settings(KNOWLEDGE_BASE_PATH=str(kb_dir), EMBEDDING_DIMENSIONS=768)
    vec = [0.01] * 768

    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed_batch.return_value = [vec]

    service = KnowledgeIngestionService(embedder=mock_embedder, settings=settings)

    # 1. Ingest doc1
    res1 = await service.ingest_document(doc1, postgres_session)
    assert res1.status == "success"
    assert res1.successful_chunks == 1
    assert res1.skipped_duplicates == 0

    # 2. Ingest doc2 with identical chunk -> under Option A-Prime, preserved as separate occurrence
    res2 = await service.ingest_document(doc2, postgres_session)
    assert res2.status == "success"
    assert res2.successful_chunks == 1
    assert res2.skipped_duplicates == 0

    # Verify both documents have physical rows in PostgreSQL under Option A-Prime
    rows_doc1 = (
        (
            await postgres_session.execute(
                select(KnowledgeEmbedding).where(
                    KnowledgeEmbedding.source_document == "doc1.md"
                )
            )
        )
        .scalars()
        .all()
    )
    rows_doc2 = (
        (
            await postgres_session.execute(
                select(KnowledgeEmbedding).where(
                    KnowledgeEmbedding.source_document == "doc2.md"
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows_doc1) == 1
    assert len(rows_doc2) == 1
    assert rows_doc1[0].chunk_index == 0
    assert rows_doc2[0].chunk_index == 0
    assert rows_doc1[0].content_hash == rows_doc2[0].content_hash

    # 3. Ingest doc_repeat with two identical sections -> both preserved at distinct chunk_index (0 and 1)
    # with in-memory embedding vector reuse
    res3 = await service.ingest_document(doc_repeat, postgres_session)
    assert res3.status == "success"
    assert res3.total_chunks == 2
    assert res3.successful_chunks == 2
    assert res3.skipped_duplicates == 1  # 1 in-memory embedding reused

    rows_repeat = (
        (
            await postgres_session.execute(
                select(KnowledgeEmbedding)
                .where(KnowledgeEmbedding.source_document == "doc_repeat.md")
                .order_by(KnowledgeEmbedding.chunk_index)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows_repeat) == 2
    assert rows_repeat[0].chunk_index == 0
    assert rows_repeat[1].chunk_index == 1
    assert rows_repeat[0].content_hash == rows_repeat[1].content_hash


@pytest.mark.postgres
@pytest.mark.anyio
async def test_postgres_ingestion_db_error_savepoint_rollback(
    postgres_session, tmp_path: Path
):
    """
    Verify on live PostgreSQL that a database failure during chunk insertion rolls back
    the savepoint cleanly and preserves the previous version intact.
    """
    kb_dir = tmp_path / "knowledge_base"
    kb_dir.mkdir()
    doc = kb_dir / "pg_rollback_doc.md"
    doc.write_text("## Initial\nInitial PG content.\n", encoding="utf-8")

    settings = Settings(KNOWLEDGE_BASE_PATH=str(kb_dir), EMBEDDING_DIMENSIONS=768)
    vec = [0.02] * 768

    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed_batch.return_value = [vec]

    service = KnowledgeIngestionService(embedder=mock_embedder, settings=settings)

    # Ingest version 1
    res1 = await service.ingest_document(doc, postgres_session)
    assert res1.status == "success"

    rows1 = (
        (
            await postgres_session.execute(
                select(KnowledgeEmbedding).where(
                    KnowledgeEmbedding.source_document == "pg_rollback_doc.md"
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows1) == 1
    assert rows1[0].section_title == "Initial"

    # Modify to version 2
    doc.write_text("## Version 2\nUpdated PG content.\n", encoding="utf-8")

    # Simulate DB failure during flush
    original_flush = postgres_session.flush

    async def mock_flush_fail():
        raise RuntimeError("Simulated PostgreSQL connection failure during flush")

    postgres_session.flush = mock_flush_fail

    res2 = await service.ingest_document(doc, postgres_session)
    assert res2.status == "failed"
    assert len(res2.errors) == 1
    assert "Simulated PostgreSQL connection failure" in res2.errors[0].error_message

    postgres_session.flush = original_flush

    # Assert version 1 remains intact in PostgreSQL
    rows_after = (
        (
            await postgres_session.execute(
                select(KnowledgeEmbedding).where(
                    KnowledgeEmbedding.source_document == "pg_rollback_doc.md"
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows_after) == 1
    assert rows_after[0].section_title == "Initial"


@pytest.mark.postgres
@pytest.mark.anyio
async def test_postgres_exact_retrieval_ground_truth_comparison(postgres_session):
    """
    Validates exact-search retrieval ground truth against pgvector.

    Ground-Truth Protocol (P2-H3 Section 4):
    1. Deterministic dataset with known mathematical angles/similarities.
    2. Exact baseline execution via sequential scan (SET LOCAL enable_indexscan = off,
       SET LOCAL enable_bitmapscan = off), avoiding approximate index scans.
    3. Direct comparison of top-k IDs, rank ordering, and floating-point similarities.
    4. Edge case validation: candidate count smaller than k, ties, empty results.
    """
    def make_unit_vec(angle_rad: float) -> list[float]:
        vec = [0.0] * 768
        vec[0] = math.cos(angle_rad)
        vec[1] = math.sin(angle_rad)
        return vec

    query_vec = make_unit_vec(0.0)

    # Deterministic candidates:
    # 0 deg: sim = 1.0 (exact match)
    # 30 deg: sim = cos(30 deg) ~ 0.866025 (tie: doc B1 and doc B2)
    # 45 deg: sim = cos(45 deg) ~ 0.707107
    # 60 deg: sim = cos(60 deg) = 0.500000
    # 90 deg: sim = cos(90 deg) = 0.000000 (orthogonal)
    candidates = [
        ("mitre/t1059.md", 0, "Doc A (0 deg)", make_unit_vec(0.0), 1.0),
        ("mitre/t1059.md", 1, "Doc B1 (30 deg)", make_unit_vec(math.radians(30)), math.cos(math.radians(30))),
        ("mitre/t1059.md", 2, "Doc B2 tie (30 deg)", make_unit_vec(math.radians(30)), math.cos(math.radians(30))),
        ("sigma/rule1.md", 0, "Doc C (45 deg)", make_unit_vec(math.radians(45)), math.cos(math.radians(45))),
        ("sigma/rule2.md", 0, "Doc D (60 deg)", make_unit_vec(math.radians(60)), math.cos(math.radians(60))),
        ("yara/rules.md", 0, "Doc E (90 deg)", make_unit_vec(math.radians(90)), 0.0),
    ]

    for src, idx, title, vec, expected_sim in candidates:
        rec = KnowledgeEmbedding(
            id=uuid.uuid4(),
            source_document=src,
            section_title=title,
            chunk_index=idx,
            content=f"Content for {title}",
            content_hash=f"hash_{title}",
            embedding=vec,
            chunk_metadata={"source_document": src, "chunk_index": idx, "expected_sim": expected_sim},
        )
        postgres_session.add(rec)
    await postgres_session.flush()

    # 1. Establish exact sequential scan ground truth baseline
    async with postgres_session.begin_nested():
        await postgres_session.execute(text("SET LOCAL enable_indexscan = off;"))
        await postgres_session.execute(text("SET LOCAL enable_bitmapscan = off;"))

        # Verify EXPLAIN demonstrates Seq Scan
        explain_res = await postgres_session.execute(
            text("EXPLAIN SELECT id, (embedding <=> :q) AS dist FROM knowledge_embeddings ORDER BY embedding <=> :q LIMIT 6;"),
            {"q": str(query_vec)},
        )
        explain_lines = [r[0] for r in explain_res.fetchall()]
        assert any("Seq Scan" in line for line in explain_lines), f"Expected Seq Scan in baseline, got: {explain_lines}"

        exact_res = await postgres_session.execute(
            text("SELECT id, (embedding <=> :q) AS dist FROM knowledge_embeddings ORDER BY embedding <=> :q LIMIT 6;"),
            {"q": str(query_vec)},
        )
        exact_rows = exact_res.fetchall()

    assert len(exact_rows) == 6
    exact_ids = [r[0] for r in exact_rows]

    # 2. Query via KnowledgeRetriever
    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed.return_value = query_vec
    retriever = KnowledgeRetriever(embedder=mock_embedder)

    res_all = await retriever.retrieve(RetrievalRequest(query="test", top_k=6, min_similarity=0.0), postgres_session)
    assert len(res_all) == 6

    # Verify ID ranking
    retriever_ids = [r.id for r in res_all]
    assert retriever_ids[0] == exact_ids[0], "Top match must be identical!"
    # The two 30-deg vectors form a tie; their set must match exact baseline indices 1 and 2
    assert set(retriever_ids[1:3]) == set(exact_ids[1:3]), "Tied candidates at 30-deg must match exact set!"
    assert retriever_ids[3] == exact_ids[3], "45-deg candidate rank must match!"
    assert retriever_ids[4] == exact_ids[4], "60-deg candidate rank must match!"
    assert retriever_ids[5] == exact_ids[5], "90-deg candidate rank must match!"

    # Verify mathematical similarity scores match 1.0 - distance
    assert math.isclose(res_all[0].similarity_score, 1.0, abs_tol=1e-5)
    assert math.isclose(res_all[1].similarity_score, math.cos(math.radians(30)), abs_tol=1e-5)
    assert math.isclose(res_all[2].similarity_score, math.cos(math.radians(30)), abs_tol=1e-5)
    assert math.isclose(res_all[3].similarity_score, math.cos(math.radians(45)), abs_tol=1e-5)
    assert math.isclose(res_all[4].similarity_score, 0.5, abs_tol=1e-5)
    assert math.isclose(res_all[5].similarity_score, 0.0, abs_tol=1e-5)

    # 3. Handle candidate sets smaller than k without truncation errors
    res_k10 = await retriever.retrieve(RetrievalRequest(query="test", top_k=10, min_similarity=0.80), postgres_session)
    assert len(res_k10) == 3, f"Expected exactly 3 candidates satisfying >= 0.80, got {len(res_k10)}"
    for r in res_k10:
        assert r.similarity_score >= 0.80

    # 4. Handle boundary condition: threshold higher than any candidate
    res_empty = await retriever.retrieve(RetrievalRequest(query="test", top_k=5, min_similarity=0.999), postgres_session)
    assert len(res_empty) == 1
    assert res_empty[0].similarity_score == 1.0
