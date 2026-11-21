"""
Integration tests for AISOP PostgreSQL Lifecycle & Persistence (Milestone P1-H9).

Verifies that AISOP's existing persistence layer (SQLAlchemy 2.0 async engine,
ORM models, and Alembic migrations) functions authoritatively against live PostgreSQL.

Test Suite:
1. test_postgres_connectivity_and_dialect:
   Asserts live PostgreSQL connectivity and prohibits silent SQLite fallback.
2. test_postgres_alembic_upgrade_lifecycle:
   Validates online Alembic migration upgrade to head, inspecting tables, columns,
   indices, foreign keys, and metadata parity.
3. test_postgres_orm_crud_and_datatype_fidelity:
   Validates native PostgreSQL types: UUID, JSON, and TIMESTAMPTZ round-trip fidelity.
4. test_postgres_ingestion_service_deduplication:
   Validates IngestionService batch deduplication, UniqueViolation constraint handling,
   and nested SAVEPOINT rollback recovery on PostgreSQL.
5. test_postgres_foreign_key_cascades:
   Validates ON DELETE CASCADE foreign key integrity between RawEvidence,
   NormalizedEventModel, and ExtractedEntityModel.
6. test_postgres_alembic_downgrade_lifecycle:
   Validates online Alembic migration downgrade to base and clean re-upgrade.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from app.db.base import Base
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.models.knowledge import KnowledgeEmbedding
from app.schemas.ingest import IngestRequest
from app.services.ingestion_service import IngestionService
import sqlalchemy as sa
from sqlalchemy import delete, func, inspect, select
from sqlalchemy.dialects.postgresql import JSON, JSONB, TIMESTAMP, UUID
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

pytestmark = pytest.mark.postgres


@pytest.fixture
def anyio_backend():
    return "asyncio"


# Sample Sysmon Process Creation payload (Event ID 1)
SAMPLE_SYSMON_EVENT: dict[str, Any] = {
    "Event": {
        "System": {
            "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
            "EventID": 1,
            "TimeCreated": {"@SystemTime": "2026-09-17T08:00:00.000000000Z"},
            "Computer": "SEC-OPS-PG-01",
        },
        "EventData": {
            "Data": [
                {"@Name": "RuleName", "#text": "-"},
                {"@Name": "UtcTime", "#text": "2026-09-17 08:00:00.000"},
                {
                    "@Name": "ProcessGuid",
                    "#text": "{11111111-2222-3333-4444-555555555555}",
                },
                {"@Name": "ProcessId", "#text": "4096"},
                {"@Name": "Image", "#text": "C:\\Windows\\System32\\cmd.exe"},
                {"@Name": "CommandLine", "#text": "cmd.exe /c whoami"},
                {"@Name": "CurrentDirectory", "#text": "C:\\Windows\\System32\\"},
                {"@Name": "User", "#text": "CORP\\analyst"},
                {
                    "@Name": "LogonGuid",
                    "#text": "{00000000-1111-2222-3333-444444444444}",
                },
                {"@Name": "LogonId", "#text": "0x3e7"},
                {"@Name": "TerminalSessionId", "#text": "1"},
                {"@Name": "IntegrityLevel", "#text": "High"},
                {
                    "@Name": "Hashes",
                    "#text": "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                },
                {
                    "@Name": "ParentProcessGuid",
                    "#text": "{99999999-8888-7777-6666-555555555555}",
                },
                {"@Name": "ParentProcessId", "#text": "2048"},
                {"@Name": "ParentImage", "#text": "C:\\Windows\\explorer.exe"},
                {"@Name": "ParentCommandLine", "#text": "explorer.exe"},
                {"@Name": "ParentUser", "#text": "CORP\\analyst"},
            ]
        },
    }
}


# ==============================================================================
# 1. Connectivity & Dialect Assertion
# ==============================================================================


@pytest.mark.anyio
async def test_postgres_connectivity_and_dialect(postgres_engine: AsyncEngine):
    """
    Verify live connectivity to PostgreSQL and enforce dialect assertions.
    Silent fallback to SQLite or mock drivers is strictly forbidden.
    """
    async with postgres_engine.connect() as conn:
        dialect_name = conn.dialect.name
        assert (
            dialect_name == "postgresql"
        ), f"Expected dialect 'postgresql', got '{dialect_name}'. Silent fallback is prohibited."

        result = await conn.execute(select(func.version()))
        version_str = result.scalar_one()
        assert (
            "PostgreSQL" in version_str
        ), f"Expected server version string containing 'PostgreSQL', got: {version_str}"


# ==============================================================================
# 2. Alembic Migration Upgrade Lifecycle
# ==============================================================================


def test_postgres_alembic_upgrade_lifecycle(
    postgres_alembic_config: Config, postgres_sync_engine
):
    """
    Execute online Alembic migration upgrade to 'head' against live PostgreSQL.
    Inspect table schemas, native column types, indices, foreign keys, and metadata parity.
    """
    # 1. Apply all pending migrations to head
    command.upgrade(postgres_alembic_config, "head")

    # 2. Inspect live schema via synchronous inspector
    inspector = inspect(postgres_sync_engine)
    table_names = set(inspector.get_table_names())

    expected_tables = {
        "raw_evidence",
        "normalized_events",
        "extracted_entities",
        "knowledge_embeddings",
        "alembic_version",
    }
    assert expected_tables.issubset(
        table_names
    ), f"Missing tables in PostgreSQL: {expected_tables - table_names}"

    # Verify pgvector extension is installed in PostgreSQL
    with postgres_sync_engine.connect() as connection:
        ext_result = connection.execute(
            sa.text("SELECT extname FROM pg_extension WHERE extname = 'vector';")
        ).scalar()
        assert ext_result == "vector", "pgvector extension must be active in PostgreSQL"

    # 3. Check native column types in raw_evidence
    columns_raw = {c["name"]: c for c in inspector.get_columns("raw_evidence")}
    assert "id" in columns_raw
    assert "sha256_hash" in columns_raw
    assert "raw_payload" in columns_raw
    assert "ingested_at" in columns_raw

    # PostgreSQL UUID check
    assert isinstance(columns_raw["id"]["type"], UUID)
    # PostgreSQL JSON / JSONB check
    assert isinstance(columns_raw["raw_payload"]["type"], JSON)
    # PostgreSQL TIMESTAMPTZ check (timezone=True)
    assert isinstance(columns_raw["ingested_at"]["type"], TIMESTAMP)
    assert columns_raw["ingested_at"]["type"].timezone is True

    # Check native column types in knowledge_embeddings
    columns_know = {c["name"]: c for c in inspector.get_columns("knowledge_embeddings")}
    assert isinstance(columns_know["id"]["type"], UUID)
    assert isinstance(columns_know["chunk_metadata"]["type"], JSONB)
    assert isinstance(columns_know["created_at"]["type"], TIMESTAMP)
    assert columns_know["created_at"]["type"].timezone is True
    assert "embedding" in columns_know

    # 4. Check unique indices
    indices_raw = inspector.get_indexes("raw_evidence")
    sha_index = next(
        (idx for idx in indices_raw if idx["name"] == "ix_raw_evidence_sha256_hash"),
        None,
    )
    assert sha_index is not None, "Missing index ix_raw_evidence_sha256_hash"
    assert sha_index["unique"] == 1 or sha_index["unique"] is True

    # Check knowledge_embeddings indexes
    indices_know = inspector.get_indexes("knowledge_embeddings")
    assert any(idx["name"] == "ix_knowledge_embeddings_source_document" for idx in indices_know)
    # Under Option A-Prime, content_hash is a non-unique B-tree lookup index
    assert any(
        idx["name"] == "ix_knowledge_embeddings_content_hash"
        and (idx["unique"] == 0 or idx["unique"] is False)
        for idx in indices_know
    )
    # Composite position (source_document, chunk_index) is UNIQUE
    assert any(
        idx["name"] == "ix_knowledge_embeddings_source_document_chunk_index"
        and (idx["unique"] == 1 or idx["unique"] is True)
        for idx in indices_know
    )
    assert any(idx["name"] == "ix_knowledge_embeddings_embedding_hnsw" for idx in indices_know)

    # 5. Check foreign keys
    fks_events = inspector.get_foreign_keys("normalized_events")
    raw_ev_fk = next(
        (fk for fk in fks_events if fk["referred_table"] == "raw_evidence"),
        None,
    )
    assert (
        raw_ev_fk is not None
    ), "Missing foreign key to raw_evidence in normalized_events"
    assert raw_ev_fk["options"].get("ondelete", "").upper() == "CASCADE"

    # 6. Schema parity: compare Base.metadata against live PostgreSQL database
    with postgres_sync_engine.connect() as connection:
        ctx = MigrationContext.configure(
            connection,
            opts={"compare_type": True, "compare_server_default": True},
        )
        diffs = compare_metadata(ctx, Base.metadata)
        assert (
            diffs == []
        ), f"Unexpected schema drift detected against PostgreSQL: {diffs}"


# ==============================================================================
# 3. ORM CRUD & Native Data Type Fidelity
# ==============================================================================


@pytest.mark.anyio
async def test_postgres_orm_crud_and_datatype_fidelity(
    postgres_session: AsyncSession,
):
    """
    Insert and query records validating PostgreSQL-native data types:
    - Native UUID (stored as native uuid type, returned as uuid.UUID).
    - Native JSON (nested structures, keys, lists preserved).
    - Native TIMESTAMPTZ (preserves exact UTC epoch instant across non-UTC offsets).
    """
    evidence_id = uuid.uuid4()
    event_id = uuid.uuid4()
    entity_id = uuid.uuid4()

    # Non-UTC timezone offset (+05:30) to test timestamptz normalization
    custom_tz = timezone(timedelta(hours=5, minutes=30))
    ingested_time = datetime(2026, 9, 17, 14, 30, 45, 123456, tzinfo=custom_tz)
    event_time = datetime(2026, 9, 17, 9, 0, 0, 0, tzinfo=timezone.utc)

    nested_payload = {
        "event_source": "sysmon_audit",
        "nested_meta": {"priority": 1, "tags": ["prod", "soc", "p1-h9"]},
        "flags": {"is_active": True, "ratio": 0.99},
    }

    # 1. Insert RawEvidence
    raw = RawEvidence(
        id=evidence_id,
        source_type="sysmon",
        source_identifier="PROD-WORKSTATION-01",
        sha256_hash="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        raw_payload=nested_payload,
        ingested_at=ingested_time,
    )
    postgres_session.add(raw)
    await postgres_session.flush()

    # 2. Insert NormalizedEventModel
    norm_event = NormalizedEventModel(
        id=event_id,
        raw_evidence_id=evidence_id,
        event_id="1",
        event_type="process_creation",
        event_timestamp=event_time,
        provider="Microsoft-Windows-Sysmon",
        action="process_started",
        outcome="success",
        severity="informational",
        normalized_payload=nested_payload,
    )
    postgres_session.add(norm_event)
    await postgres_session.flush()

    # 3. Insert ExtractedEntityModel
    entity = ExtractedEntityModel(
        id=entity_id,
        event_id=event_id,
        raw_evidence_id=evidence_id,
        entity_type="ip",
        entity_value="192.168.1.50",
        role="source",
        attributes={"hostname": "PROD-WORKSTATION-01", "port": 443},
    )
    postgres_session.add(entity)
    await postgres_session.commit()

    # 4. Query back and verify fidelity
    res = await postgres_session.execute(
        select(RawEvidence).where(RawEvidence.id == evidence_id)
    )
    fetched_raw = res.scalar_one()

    # Verify native UUID
    assert fetched_raw.id == evidence_id
    assert isinstance(fetched_raw.id, uuid.UUID)

    # Verify native JSON nested payload fidelity
    assert fetched_raw.raw_payload == nested_payload
    assert fetched_raw.raw_payload["nested_meta"]["tags"] == ["prod", "soc", "p1-h9"]

    # Verify TIMESTAMPTZ instant in time equality
    assert fetched_raw.ingested_at == ingested_time
    assert fetched_raw.ingested_at.astimezone(timezone.utc) == ingested_time.astimezone(
        timezone.utc
    )

    # Query normalized event
    res_event = await postgres_session.execute(
        select(NormalizedEventModel).where(NormalizedEventModel.id == event_id)
    )
    fetched_event = res_event.scalar_one()
    assert fetched_event.event_id == "1"
    assert fetched_event.normalized_payload == nested_payload


# ==============================================================================
# 4. Ingestion Service Deduplication & Nested SAVEPOINT Recovery
# ==============================================================================


@pytest.mark.anyio
async def test_postgres_ingestion_service_deduplication(
    postgres_session: AsyncSession,
):
    """
    Verify IngestionService deduplication against live PostgreSQL:
    - Normal ingestion persists RawEvidence, NormalizedEvent, and ExtractedEntities.
    - Subsequent identical batch correctly skips duplicate and increments duplicate_count.
    - Real PostgreSQL UniqueViolation constraint triggers nested SAVEPOINT rollback,
      leaving the parent session healthy and uncorrupted.
    - Intra-batch duplicate deduplication operates accurately.
    """
    service = IngestionService()
    # The disposable database is shared with earlier PostgreSQL tests that may leave rows behind for review, so
    # counts are asserted as deltas against a baseline taken here, never as absolute numbers.
    base_raw = await postgres_session.scalar(select(func.count(RawEvidence.id)))
    base_events = await postgres_session.scalar(select(func.count(NormalizedEventModel.id)))

    # 1. Ingest first submission
    req1 = IngestRequest(
        source_type="sysmon",
        source_identifier="SEC-OPS-PG-01",
        events=[SAMPLE_SYSMON_EVENT],
    )
    resp1 = await service.ingest_batch(postgres_session, req1)
    await postgres_session.commit()

    assert resp1.total_received == 1
    assert resp1.total_normalized == 1
    assert resp1.total_skipped_duplicates == 0
    assert resp1.total_entities_extracted >= 1
    assert len(resp1.errors) == 0

    # Verify database counts
    count_raw = await postgres_session.scalar(select(func.count(RawEvidence.id)))
    count_events = await postgres_session.scalar(
        select(func.count(NormalizedEventModel.id))
    )
    assert count_raw == base_raw + 1
    assert count_events == base_events + 1

    # 2. Ingest exact duplicate in a second batch
    resp2 = await service.ingest_batch(postgres_session, req1)
    await postgres_session.commit()

    assert resp2.total_received == 1
    assert resp2.total_normalized == 0
    assert resp2.total_skipped_duplicates == 1
    assert resp2.total_entities_extracted == 0
    assert len(resp2.existing_evidence_ids) == 1

    # Counts must remain unchanged
    count_raw_after = await postgres_session.scalar(select(func.count(RawEvidence.id)))
    assert count_raw_after == base_raw + 1

    # 3. Direct PostgreSQL UniqueViolation & Nested SAVEPOINT Recovery Test
    # Simulate a concurrent race condition where a duplicate sha256_hash bypasses
    # in-memory cache and triggers PostgreSQL's unique constraint at flush.
    existing_hash = await postgres_session.scalar(
        select(RawEvidence.sha256_hash).where(RawEvidence.source_identifier == "SEC-OPS-PG-01").limit(1)
    )
    duplicate_raw = RawEvidence(
        id=uuid.uuid4(),
        source_type="sysmon",
        source_identifier="RACE-HOST",
        sha256_hash=existing_hash,  # Colliding hash
        raw_payload={"EventID": 1},
        ingested_at=datetime.now(timezone.utc),
    )

    # Begin nested SAVEPOINT
    with pytest.raises(IntegrityError) as exc_info:
        async with postgres_session.begin_nested():
            postgres_session.add(duplicate_raw)
            await postgres_session.flush()

    # Assert that the underlying error was a PostgreSQL UniqueViolation
    assert isinstance(exc_info.value.orig, psycopg.errors.UniqueViolation)
    assert "ix_raw_evidence_sha256_hash" in str(exc_info.value)

    # Verify session remains usable after SAVEPOINT rollback by inserting a valid record
    fresh_id = uuid.uuid4()
    valid_raw = RawEvidence(
        id=fresh_id,
        source_type="sysmon",
        source_identifier="RECOVERY-HOST",
        sha256_hash="1" * 64,
        raw_payload={"EventID": 1, "Status": "recovered"},
        ingested_at=datetime.now(timezone.utc),
    )
    postgres_session.add(valid_raw)
    await postgres_session.commit()

    fetched = await postgres_session.scalar(
        select(RawEvidence).where(RawEvidence.id == fresh_id)
    )
    assert fetched is not None
    assert fetched.source_identifier == "RECOVERY-HOST"

    # 4. Intra-batch duplicate scenario: [EventA, EventA, EventB]
    event_b = dict(SAMPLE_SYSMON_EVENT)
    event_b_modified = {
        "Event": {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": 3,
                "TimeCreated": {"@SystemTime": "2026-09-17T08:05:00.000000000Z"},
                "Computer": "SEC-OPS-PG-01",
            },
            "EventData": {
                "Data": [
                    {"@Name": "Image", "#text": "C:\\Windows\\System32\\curl.exe"},
                    {"@Name": "DestinationIp", "#text": "93.184.216.34"},
                    {"@Name": "DestinationPort", "#text": "443"},
                ]
            },
        }
    }
    # Remove only the rows THIS test created (never other tests' rows, which may be referenced by cases) for a clean intra-batch count
    await postgres_session.execute(
        delete(RawEvidence).where(RawEvidence.source_identifier.in_(["SEC-OPS-PG-01", "RACE-HOST", "RECOVERY-HOST"]))
    )
    await postgres_session.commit()

    req_intra = IngestRequest(
        source_type="sysmon",
        source_identifier="SEC-OPS-PG-01",
        events=[SAMPLE_SYSMON_EVENT, SAMPLE_SYSMON_EVENT, event_b_modified],
    )
    resp_intra = await service.ingest_batch(postgres_session, req_intra)
    await postgres_session.commit()

    assert resp_intra.total_received == 3
    assert resp_intra.total_normalized == 2
    assert resp_intra.total_skipped_duplicates == 1
    assert len(resp_intra.existing_evidence_ids) == 1


# ==============================================================================
# 5. Foreign Key ON DELETE CASCADE
# ==============================================================================


@pytest.mark.anyio
async def test_postgres_foreign_key_cascades(postgres_session: AsyncSession):
    """
    Verify PostgreSQL ON DELETE CASCADE foreign key integrity:
    Deleting a RawEvidence row cascades to delete associated
    NormalizedEventModel and ExtractedEntityModel rows automatically.
    """
    evidence_id = uuid.uuid4()
    event_id = uuid.uuid4()
    entity_id = uuid.uuid4()

    # 1. Insert parent RawEvidence (hash strictly 64 hex chars)
    raw = RawEvidence(
        id=evidence_id,
        source_type="sysmon",
        source_identifier="CASCADE-HOST",
        sha256_hash="c" * 64,
        raw_payload={"EventID": 1},
        ingested_at=datetime.now(timezone.utc),
    )
    postgres_session.add(raw)
    await postgres_session.flush()

    # 2. Insert child NormalizedEventModel
    norm_event = NormalizedEventModel(
        id=event_id,
        raw_evidence_id=evidence_id,
        event_id="1",
        event_type="process_creation",
        event_timestamp=datetime.now(timezone.utc),
        provider="Microsoft-Windows-Sysmon",
        action="process_started",
        outcome="success",
        severity="informational",
        normalized_payload={"image": "test.exe"},
    )
    postgres_session.add(norm_event)
    await postgres_session.flush()

    # 3. Insert child ExtractedEntityModel
    entity = ExtractedEntityModel(
        id=entity_id,
        event_id=event_id,
        raw_evidence_id=evidence_id,
        entity_type="process",
        entity_value="test.exe",
        role="target",
        attributes={},
    )
    postgres_session.add(entity)
    await postgres_session.commit()

    # Confirm all 3 exist
    assert (
        await postgres_session.scalar(
            select(func.count(RawEvidence.id)).where(RawEvidence.id == evidence_id)
        )
        == 1
    )
    assert (
        await postgres_session.scalar(
            select(func.count(NormalizedEventModel.id)).where(
                NormalizedEventModel.id == event_id
            )
        )
        == 1
    )
    assert (
        await postgres_session.scalar(
            select(func.count(ExtractedEntityModel.id)).where(
                ExtractedEntityModel.id == entity_id
            )
        )
        == 1
    )

    # 4. Delete parent RawEvidence record
    await postgres_session.execute(
        delete(RawEvidence).where(RawEvidence.id == evidence_id)
    )
    await postgres_session.commit()

    # 5. Assert child records were cascade-deleted by PostgreSQL
    assert (
        await postgres_session.scalar(
            select(func.count(RawEvidence.id)).where(RawEvidence.id == evidence_id)
        )
        == 0
    )
    assert (
        await postgres_session.scalar(
            select(func.count(NormalizedEventModel.id)).where(
                NormalizedEventModel.id == event_id
            )
        )
        == 0
    )
    assert (
        await postgres_session.scalar(
            select(func.count(ExtractedEntityModel.id)).where(
                ExtractedEntityModel.id == entity_id
            )
        )
        == 0
    )


# ==============================================================================
# 6. Alembic Migration Downgrade Lifecycle
# ==============================================================================


@pytest.mark.skip(
    reason="Stage 7B (D6): `alembic downgrade base` is destructive to the schema and must never run against an existing or shared database. "
    "It is runnable only against a separately created, ephemeral test cluster/database after explicit owner authorization; "
    "the approved Stage 7B target is not such a database."
)
def test_postgres_alembic_downgrade_lifecycle(
    postgres_alembic_config: Config, postgres_sync_engine
):
    """
    Execute online Alembic downgrade to 'base' against live PostgreSQL,
    verify complete removal of tables and version records, then re-upgrade
    to leave database in canonical 'head' state.
    """
    # 1. Downgrade to base
    command.downgrade(postgres_alembic_config, "base")

    # 2. Inspect table names: all application tables must be removed
    inspector = inspect(postgres_sync_engine)
    remaining_tables = set(inspector.get_table_names())

    assert "raw_evidence" not in remaining_tables
    assert "normalized_events" not in remaining_tables
    assert "extracted_entities" not in remaining_tables
    assert "knowledge_embeddings" not in remaining_tables

    # Verify pgvector extension is NOT dropped on downgrade
    with postgres_sync_engine.connect() as conn:
        ext_res = conn.execute(
            sa.text("SELECT extname FROM pg_extension WHERE extname = 'vector';")
        ).scalar()
        assert ext_res == "vector", "pgvector extension must not be dropped during downgrade"

    # 3. Check alembic_version has no current head
    if "alembic_version" in remaining_tables:
        with postgres_sync_engine.connect() as conn:
            from sqlalchemy import text

            version_rows = conn.execute(
                text("SELECT COUNT(*) FROM alembic_version")
            ).scalar()
            assert version_rows == 0

    # 4. Re-upgrade to head so subsequent tests and development environment remain clean
    command.upgrade(postgres_alembic_config, "head")

    inspector_after = inspect(postgres_sync_engine)
    restored_tables = set(inspector_after.get_table_names())
    assert {
        "raw_evidence",
        "normalized_events",
        "extracted_entities",
        "knowledge_embeddings",
    }.issubset(restored_tables)


# ==============================================================================
# 7. pgvector Vector CRUD & Cosine Distance Search (Milestone P2-H2)
# ==============================================================================


@pytest.mark.anyio
async def test_postgres_knowledge_embedding_vector_crud_and_cosine_similarity(
    postgres_session: AsyncSession,
):
    """
    Verify pgvector vector persistence, exact-content deduplication, and cosine
    similarity query against live PostgreSQL with pgvector extension:
    - Insert 768-dimensional vector chunks.
    - Verify cosine distance ordering (<=> operator).
    - Verify content_hash unique constraint raises UniqueViolation on PostgreSQL.
    """
    doc_source = "knowledge/mitre_attack_test.md"

    # Orthogonal unit vectors for deterministic cosine distance calculation
    vec_exact = [1.0] + [0.0] * 767
    vec_orthogonal = [0.0, 1.0] + [0.0] * 766

    content_1 = "Adversaries may use PowerShell to execute malicious commands."
    content_2 = "Adversaries may abuse Windows Management Instrumentation (WMI)."

    chunk_1 = KnowledgeEmbedding(
        source_document=doc_source,
        section_title="T1059.001 - PowerShell",
        chunk_index=0,
        content=content_1,
        content_hash=KnowledgeEmbedding.compute_hash(content_1),
        embedding=vec_exact,
        chunk_metadata={"technique_id": "T1059.001", "tactic": "Execution"},
    )
    chunk_2 = KnowledgeEmbedding(
        source_document=doc_source,
        section_title="T1047 - WMI",
        chunk_index=1,
        content=content_2,
        content_hash=KnowledgeEmbedding.compute_hash(content_2),
        embedding=vec_orthogonal,
        chunk_metadata={"technique_id": "T1047", "tactic": "Execution"},
    )
    postgres_session.add_all([chunk_1, chunk_2])
    await postgres_session.commit()

    # 1. Cosine similarity query matching vec_exact
    # Cosine distance to vec_exact: chunk_1 should have distance 0.0, chunk_2 should have distance 1.0
    query_vec = [1.0] + [0.0] * 767
    stmt = (
        select(
            KnowledgeEmbedding,
            KnowledgeEmbedding.embedding.cosine_distance(query_vec).label("distance"),
        )
        .where(KnowledgeEmbedding.source_document == doc_source)
        .order_by(KnowledgeEmbedding.embedding.cosine_distance(query_vec))
    )
    results = (await postgres_session.execute(stmt)).all()

    assert len(results) == 2
    top_chunk, top_distance = results[0]
    second_chunk, second_distance = results[1]

    assert top_chunk.section_title == "T1059.001 - PowerShell"
    assert pytest.approx(top_distance, abs=1e-4) == 0.0
    assert second_chunk.section_title == "T1047 - WMI"
    assert pytest.approx(second_distance, abs=1e-4) == 1.0

    # 2. Option A-Prime uniqueness enforcement:
    # A) Identical content_hash in a different document or different chunk_index is PERMITTED
    dup_chunk = KnowledgeEmbedding(
        source_document="knowledge/other.md",
        section_title="Duplicate PowerShell Chunk",
        chunk_index=0,
        content=content_1,
        content_hash=KnowledgeEmbedding.compute_hash(content_1),
        embedding=[0.5] * 768,
        chunk_metadata={"status": "duplicate_allowed_in_other_doc"},
    )
    postgres_session.add(dup_chunk)
    await postgres_session.flush()

    # B) Composite uniqueness violation on (source_document, chunk_index) raises UniqueViolation
    colliding_chunk = KnowledgeEmbedding(
        source_document=doc_source,
        section_title="Colliding Position Chunk",
        chunk_index=0,  # Collides with chunk_1 at chunk_index=0
        content="Different content at colliding position",
        content_hash=KnowledgeEmbedding.compute_hash("Different content at colliding position"),
        embedding=[0.5] * 768,
        chunk_metadata={"status": "colliding_position"},
    )
    with pytest.raises(IntegrityError) as exc_info:
        async with postgres_session.begin_nested():
            postgres_session.add(colliding_chunk)
            await postgres_session.flush()

    assert isinstance(exc_info.value.orig, psycopg.errors.UniqueViolation)
    assert "ix_knowledge_embeddings_source_document_chunk_index" in str(exc_info.value)
