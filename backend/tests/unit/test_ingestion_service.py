"""
Unit tests for IngestionService.

Covers all 10 required deduplication scenarios under Milestone P1-H2:
1. First submission persists normally
2. Exact duplicate creates no additional normalized event
3. Exact duplicate creates no additional entities
4. Duplicate response counter increments and existing IDs are referenced
5. Mixed batch correctly handles new + duplicate events
6. Multiple duplicate submissions maintain one authoritative record
7. Different events are NOT incorrectly deduplicated
8. Deterministic key ordering produces the expected duplicate behavior
9. Duplicate processing preserves transaction integrity
10. Concurrency race conflict handling via SAVEPOINT rollback
"""

import pytest
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.evidence.hasher import compute_sha256
from app.schemas.ingest import IngestRequest
from app.services.ingestion_service import IngestionService
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError


@pytest.mark.anyio
async def test_first_submission_persists_normally(db_session):
    """Scenario 1: First ingestion of a telemetry event persists all tiers normally."""
    service = IngestionService()
    event = {
        "EventID": 1,
        "UtcTime": "2026-09-10 10:00:00.000",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "Computer": "HOST-01",
        "User": "CORP\\alice",
        "ProcessId": 1001,
    }
    request = IngestRequest(
        source_type="sysmon", source_identifier="HOST-01", events=[event]
    )

    response = await service.ingest_batch(db_session, request)

    assert response.total_received == 1
    assert response.total_normalized == 1
    assert response.total_skipped_duplicates == 0
    assert response.total_entities_extracted > 0
    assert len(response.errors) == 0

    raw_count = len((await db_session.execute(select(RawEvidence))).scalars().all())
    norm_count = len(
        (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    )
    entity_count = len(
        (await db_session.execute(select(ExtractedEntityModel))).scalars().all()
    )

    assert raw_count == 1
    assert norm_count == 1
    assert entity_count > 0


@pytest.mark.anyio
async def test_exact_duplicate_creates_no_additional_normalized_event(db_session):
    """Scenario 2: Re-submitting identical telemetry does NOT create another NormalizedEventModel."""
    service = IngestionService()
    event = {
        "EventID": 1,
        "UtcTime": "2026-09-10 10:05:00.000",
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe file.txt",
        "Computer": "HOST-01",
        "ProcessId": 2002,
    }
    request = IngestRequest(
        source_type="sysmon", source_identifier="HOST-01", events=[event]
    )

    # Ingest once
    res1 = await service.ingest_batch(db_session, request)
    assert res1.total_normalized == 1

    # Ingest exact duplicate
    res2 = await service.ingest_batch(db_session, request)
    assert res2.total_normalized == 0
    assert res2.total_skipped_duplicates == 1

    # Invariant: NormalizedEventModel count must strictly remain 1
    norm_rows = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    assert len(norm_rows) == 1


@pytest.mark.anyio
async def test_exact_duplicate_creates_no_additional_entities(db_session):
    """Scenario 3: Re-submitting identical telemetry does NOT create duplicate ExtractedEntityModel records."""
    service = IngestionService()
    event = {
        "EventID": 3,
        "UtcTime": "2026-09-10 10:10:00.000",
        "SourceIp": "192.168.1.50",
        "DestinationIp": "198.51.100.10",
        "DestinationPort": 443,
        "Protocol": "tcp",
        "Computer": "HOST-01",
        "ProcessId": 3003,
    }
    request = IngestRequest(
        source_type="sysmon", source_identifier="HOST-01", events=[event]
    )

    # First ingestion
    await service.ingest_batch(db_session, request)
    entity_count_initial = len(
        (await db_session.execute(select(ExtractedEntityModel))).scalars().all()
    )
    assert entity_count_initial > 0

    # Duplicate ingestion
    res2 = await service.ingest_batch(db_session, request)
    assert res2.total_skipped_duplicates == 1

    # Invariant: ExtractedEntityModel count must remain strictly unchanged
    entity_count_after = len(
        (await db_session.execute(select(ExtractedEntityModel))).scalars().all()
    )
    assert entity_count_after == entity_count_initial


@pytest.mark.anyio
async def test_duplicate_response_counter_and_ids(db_session):
    """Scenario 4: Duplicate response increments total_skipped_duplicates and references existing RawEvidence UUID."""
    service = IngestionService()
    event = {
        "EventID": 1,
        "UtcTime": "2026-09-10 10:15:00.000",
        "Image": "C:\\Windows\\System32\\calc.exe",
        "CommandLine": "calc.exe",
        "Computer": "HOST-01",
        "ProcessId": 4004,
    }
    request = IngestRequest(
        source_type="sysmon", source_identifier="HOST-01", events=[event]
    )

    res1 = await service.ingest_batch(db_session, request)
    raw_record = (await db_session.execute(select(RawEvidence))).scalars().first()
    assert raw_record is not None

    res2 = await service.ingest_batch(db_session, request)
    assert res2.total_received == 1
    assert res2.total_normalized == 0
    assert res2.total_skipped_duplicates == 1
    assert len(res2.existing_evidence_ids) == 1
    assert res2.existing_evidence_ids[0] == raw_record.id


@pytest.mark.anyio
async def test_mixed_batch_ingestion_counts(db_session):
    """Scenario 5: Batch containing both new and duplicate events correctly separates counts."""
    service = IngestionService()
    event_a = {
        "EventID": 1,
        "UtcTime": "2026-09-10 11:00:00.000",
        "Image": "proc_a.exe",
        "Computer": "H1",
    }
    event_b = {
        "EventID": 1,
        "UtcTime": "2026-09-10 11:01:00.000",
        "Image": "proc_b.exe",
        "Computer": "H1",
    }
    event_c = {
        "EventID": 1,
        "UtcTime": "2026-09-10 11:02:00.000",
        "Image": "proc_c.exe",
        "Computer": "H1",
    }

    # Ingest Event A and B
    res1 = await service.ingest_batch(
        db_session, IngestRequest(events=[event_a, event_b])
    )
    assert res1.total_received == 2
    assert res1.total_normalized == 2
    assert res1.total_skipped_duplicates == 0

    # Ingest Event B (duplicate) and Event C (new) in a single batch
    res2 = await service.ingest_batch(
        db_session, IngestRequest(events=[event_b, event_c])
    )
    assert res2.total_received == 2
    assert res2.total_normalized == 1
    assert res2.total_skipped_duplicates == 1

    # Database totals: exactly 3 distinct raw events, 3 normalized events
    raw_rows = (await db_session.execute(select(RawEvidence))).scalars().all()
    norm_rows = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    assert len(raw_rows) == 3
    assert len(norm_rows) == 3


@pytest.mark.anyio
async def test_multiple_duplicate_submissions_maintain_single_authoritative_record(
    db_session,
):
    """Scenario 6: Same event submitted 5 times maintains exactly 1 authoritative record across all tables."""
    service = IngestionService()
    event = {
        "EventID": 1,
        "Image": "powershell.exe",
        "CommandLine": "powershell -ep bypass",
        "Computer": "H1",
    }
    request = IngestRequest(events=[event])

    for i in range(5):
        res = await service.ingest_batch(db_session, request)
        if i == 0:
            assert res.total_normalized == 1
            assert res.total_skipped_duplicates == 0
        else:
            assert res.total_normalized == 0
            assert res.total_skipped_duplicates == 1

    raw_rows = (await db_session.execute(select(RawEvidence))).scalars().all()
    norm_rows = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    assert len(raw_rows) == 1
    assert len(norm_rows) == 1


@pytest.mark.anyio
async def test_different_events_not_incorrectly_deduplicated(db_session):
    """Scenario 7: Events differing only by timestamp or PID are NOT deduplicated."""
    service = IngestionService()
    event1 = {
        "EventID": 1,
        "UtcTime": "2026-09-10 12:00:00.000",
        "Image": "cmd.exe",
        "ProcessId": 100,
    }
    event2 = {
        "EventID": 1,
        "UtcTime": "2026-09-10 12:00:01.000",
        "Image": "cmd.exe",
        "ProcessId": 100,
    }
    event3 = {
        "EventID": 1,
        "UtcTime": "2026-09-10 12:00:00.000",
        "Image": "cmd.exe",
        "ProcessId": 200,
    }

    res = await service.ingest_batch(
        db_session, IngestRequest(events=[event1, event2, event3])
    )
    assert res.total_received == 3
    assert res.total_normalized == 3
    assert res.total_skipped_duplicates == 0

    raw_rows = (await db_session.execute(select(RawEvidence))).scalars().all()
    assert len(raw_rows) == 3


@pytest.mark.anyio
async def test_deterministic_key_ordering_deduplication(db_session):
    """Scenario 8: Semantically identical payloads with different JSON key ordering trigger deduplication."""
    service = IngestionService()
    payload_a = {"EventID": 1, "Image": "whoami.exe", "User": "SYSTEM"}
    payload_b = {"User": "SYSTEM", "Image": "whoami.exe", "EventID": 1}

    res1 = await service.ingest_batch(db_session, IngestRequest(events=[payload_a]))
    assert res1.total_normalized == 1
    assert res1.total_skipped_duplicates == 0

    res2 = await service.ingest_batch(db_session, IngestRequest(events=[payload_b]))
    assert res2.total_normalized == 0
    assert res2.total_skipped_duplicates == 1

    raw_rows = (await db_session.execute(select(RawEvidence))).scalars().all()
    assert len(raw_rows) == 1


@pytest.mark.anyio
async def test_duplicate_processing_preserves_transaction_integrity(db_session):
    """Scenario 9: Duplicate processing does not corrupt the transaction; subsequent operations succeed."""
    service = IngestionService()
    event = {"EventID": 1, "Image": "clean.exe", "Computer": "HOST-TX"}

    # Ingest twice with explicit source_identifier
    await service.ingest_batch(
        db_session, IngestRequest(source_identifier="HOST-TX", events=[event])
    )
    await service.ingest_batch(
        db_session, IngestRequest(source_identifier="HOST-TX", events=[event])
    )

    # Verify session is clean and able to execute subsequent reads and writes
    stmt = select(RawEvidence).where(RawEvidence.source_identifier == "HOST-TX")
    result = await db_session.execute(stmt)
    records = result.scalars().all()
    assert len(records) == 1

    # Ingest a new distinct event to ensure writes still work seamlessly
    new_event = {"EventID": 1, "Image": "another.exe", "Computer": "HOST-TX"}
    res3 = await service.ingest_batch(
        db_session, IngestRequest(source_identifier="HOST-TX", events=[new_event])
    )
    assert res3.total_normalized == 1
    assert res3.total_skipped_duplicates == 0


@pytest.mark.anyio
async def test_concurrent_duplicate_savepoint_handling(db_session):
    """
    Scenario 10: Concurrency conflict handling via SAVEPOINT rollback.

    Simulates a race condition where the initial SELECT returned None (as if concurrent),
    but the INSERT encounters an existing record with identical SHA-256 in the database.
    Verifies that the SAVEPOINT rolls back gracefully, retrieves the existing record,
    and converts the conflict into a cleanly skipped duplicate.
    """
    service = IngestionService()
    event = {"EventID": 1, "Image": "race_test.exe", "Computer": "RACE-HOST"}
    sha = compute_sha256(event)

    # Pre-seed the RawEvidence row directly (as if committed by Request A concurrently)
    pre_existing = RawEvidence(
        source_type="sysmon",
        source_identifier="RACE-HOST",
        sha256_hash=sha,
        raw_payload=event,
    )
    db_session.add(pre_existing)
    await db_session.flush()

    # Create a session wrapper that simulates Request B:
    # Its initial SELECT returns None (simulating Request B checking before Request A committed),
    # but its insert flush will trigger the IntegrityError on sha256_hash.
    original_execute = db_session.execute
    first_check_done = False

    async def simulated_race_execute(statement, *args, **kwargs):
        nonlocal first_check_done
        # Intercept the first SELECT RawEvidence check and return empty result
        statement_str = str(statement).lower()
        if "raw_evidence" in statement_str and not first_check_done:
            first_check_done = True

            class EmptyScalarResult:
                def scalars(self):
                    return self

                def first(self):
                    return None

                def all(self):
                    return []

            return EmptyScalarResult()
        return await original_execute(statement, *args, **kwargs)

    # Monkeypatch execute on db_session for this call
    db_session.execute = simulated_race_execute
    try:
        response = await service.ingest_batch(db_session, IngestRequest(events=[event]))
    finally:
        db_session.execute = original_execute

    # The race-handling path must catch the conflict, roll back savepoint, and recover cleanly
    assert response.total_received == 1
    assert response.total_normalized == 0
    assert response.total_skipped_duplicates == 1
    assert len(response.existing_evidence_ids) == 1
    assert response.existing_evidence_ids[0] == pre_existing.id
    assert len(response.errors) == 0

    # Ensure no duplicates were inserted
    all_raw = (await db_session.execute(select(RawEvidence))).scalars().all()
    assert len(all_raw) == 1
    all_norm = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    assert len(all_norm) == 0


@pytest.mark.anyio
async def test_empty_batch_performs_zero_queries_and_returns_zero_counts(
    db_session, sqlite_engine
):
    """P1-H3: Empty batch performs zero DB queries and returns zero counts."""
    from sqlalchemy import event

    service = IngestionService()
    request = IngestRequest(events=[])

    executed_sqls = []

    def capture_sql(conn, cursor, statement, parameters, context, executemany):
        executed_sqls.append(statement)

    event.listen(sqlite_engine, "before_cursor_execute", capture_sql)
    try:
        response = await service.ingest_batch(db_session, request)
    finally:
        event.remove(sqlite_engine, "before_cursor_execute", capture_sql)

    assert response.total_received == 0
    assert response.total_normalized == 0
    assert response.total_skipped_duplicates == 0
    assert response.total_entities_extracted == 0
    assert len(response.existing_evidence_ids) == 0
    assert len(response.errors) == 0
    assert len(executed_sqls) == 0


@pytest.mark.anyio
async def test_intra_batch_duplicates_a_a_a_b_c_c(db_session):
    """P1-H3: Intra-batch duplicates [A, A, A, B, C, C] produce exactly 3 raw records and skip 3 duplicates."""
    service = IngestionService()
    event_a = {
        "EventID": 1,
        "UtcTime": "2026-09-10 13:00:00.000",
        "Image": "app_a.exe",
        "Computer": "HOST-BATCH",
    }
    event_b = {
        "EventID": 1,
        "UtcTime": "2026-09-10 13:00:01.000",
        "Image": "app_b.exe",
        "Computer": "HOST-BATCH",
    }
    event_c = {
        "EventID": 1,
        "UtcTime": "2026-09-10 13:00:02.000",
        "Image": "app_c.exe",
        "Computer": "HOST-BATCH",
    }

    batch = [event_a, event_a, event_a, event_b, event_c, event_c]
    request = IngestRequest(
        source_type="sysmon", source_identifier="HOST-BATCH", events=batch
    )

    response = await service.ingest_batch(db_session, request)

    assert response.total_received == 6
    assert response.total_normalized == 3
    assert response.total_skipped_duplicates == 3
    assert len(response.existing_evidence_ids) == 3

    # Authoritative rows in DB
    raw_rows = (await db_session.execute(select(RawEvidence))).scalars().all()
    norm_rows = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    assert len(raw_rows) == 3
    assert len(norm_rows) == 3

    # Verify existing_evidence_ids reference the newly created raw records for A and C
    hash_to_id = {r.sha256_hash: r.id for r in raw_rows}
    sha_a = compute_sha256(event_a)
    sha_c = compute_sha256(event_c)
    assert response.existing_evidence_ids == [
        hash_to_id[sha_a],
        hash_to_id[sha_a],
        hash_to_id[sha_c],
    ]


@pytest.mark.anyio
async def test_batched_query_count_verification_n20(db_session, sqlite_engine):
    """P1-H3: For N=20 distinct events, exactly 1 batched existence SELECT is executed instead of 20 sequential SELECTs."""
    from sqlalchemy import event

    service = IngestionService()
    events = [
        {
            "EventID": 1,
            "UtcTime": f"2026-09-10 14:00:{i:02d}.000",
            "Image": f"proc_{i}.exe",
            "Computer": "HOST-PERF",
            "ProcessId": 1000 + i,
        }
        for i in range(20)
    ]
    request = IngestRequest(
        source_type="sysmon", source_identifier="HOST-PERF", events=events
    )

    existence_selects = []

    def capture_sql(conn, cursor, statement, parameters, context, executemany):
        statement_lower = statement.lower()
        if (
            "raw_evidence" in statement_lower
            and "select" in statement_lower
            and "sha256_hash" in statement_lower
        ):
            existence_selects.append((statement, parameters))

    event.listen(sqlite_engine, "before_cursor_execute", capture_sql)
    try:
        response = await service.ingest_batch(db_session, request)
    finally:
        event.remove(sqlite_engine, "before_cursor_execute", capture_sql)

    assert response.total_received == 20
    assert response.total_normalized == 20
    assert response.total_skipped_duplicates == 0

    # CRITICAL P1-H3 VERIFICATION:
    # Exactly 1 batched SELECT query executed, containing all 20 hashes in IN clause
    assert len(existence_selects) == 1
    stmt, params = existence_selects[0]
    assert "in (" in stmt.lower() or "in ?" in stmt.lower()
    assert len(params) == 20


@pytest.mark.anyio
async def test_all_duplicate_batch_skips_all_events_with_single_select(
    db_session, sqlite_engine
):
    """P1-H3: Re-submitting N=10 events executes exactly 1 batched existence SELECT and skips all 10."""
    from sqlalchemy import event

    service = IngestionService()
    events = [
        {
            "EventID": 1,
            "UtcTime": f"2026-09-10 15:00:{i:02d}.000",
            "Image": f"dup_proc_{i}.exe",
            "Computer": "HOST-DUP",
        }
        for i in range(10)
    ]
    request = IngestRequest(
        source_type="sysmon", source_identifier="HOST-DUP", events=events
    )

    # Initial ingestion
    res1 = await service.ingest_batch(db_session, request)
    assert res1.total_normalized == 10

    # Duplicate batch ingestion
    existence_selects = []

    def capture_sql(conn, cursor, statement, parameters, context, executemany):
        statement_lower = statement.lower()
        if (
            "raw_evidence" in statement_lower
            and "select" in statement_lower
            and "sha256_hash" in statement_lower
        ):
            existence_selects.append(statement)

    event.listen(sqlite_engine, "before_cursor_execute", capture_sql)
    try:
        res2 = await service.ingest_batch(db_session, request)
    finally:
        event.remove(sqlite_engine, "before_cursor_execute", capture_sql)

    assert res2.total_received == 10
    assert res2.total_normalized == 0
    assert res2.total_skipped_duplicates == 10
    assert len(res2.existing_evidence_ids) == 10
    assert len(existence_selects) == 1

    # Ensure database record counts did not change
    norm_count = len(
        (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    )
    assert norm_count == 10


@pytest.mark.anyio
async def test_chunking_prevents_oversized_in_clauses(db_session, sqlite_engine):
    """P1-H3: Batches exceeding chunk_size are split into ceil(U / chunk_size) queries."""
    from sqlalchemy import event

    # Set chunk_size=5 for easy deterministic verification
    service = IngestionService(chunk_size=5)
    events = [
        {
            "EventID": 1,
            "UtcTime": f"2026-09-10 16:00:{i:02d}.000",
            "Image": f"chunk_proc_{i}.exe",
            "Computer": "HOST-CHUNK",
        }
        for i in range(12)
    ]
    request = IngestRequest(
        source_type="sysmon", source_identifier="HOST-CHUNK", events=events
    )

    chunk_queries = []

    def capture_sql(conn, cursor, statement, parameters, context, executemany):
        statement_lower = statement.lower()
        if (
            "raw_evidence" in statement_lower
            and "select" in statement_lower
            and "sha256_hash" in statement_lower
        ):
            chunk_queries.append((statement, parameters))

    event.listen(sqlite_engine, "before_cursor_execute", capture_sql)
    try:
        response = await service.ingest_batch(db_session, request)
    finally:
        event.remove(sqlite_engine, "before_cursor_execute", capture_sql)

    assert response.total_received == 12
    assert response.total_normalized == 12

    # 12 unique events with chunk_size=5 -> ceil(12 / 5) = 3 queries (sizes 5, 5, 2)
    assert len(chunk_queries) == 3
    assert len(chunk_queries[0][1]) == 5
    assert len(chunk_queries[1][1]) == 5
    assert len(chunk_queries[2][1]) == 2


@pytest.mark.anyio
async def test_chunking_boundary_1001_unique_events(db_session, sqlite_engine):
    """P1-H3: Default chunk_size=1000 correctly handles boundary at 1001 events into 2 queries (1000 + 1)."""
    from sqlalchemy import event

    service = IngestionService(chunk_size=1000)
    # Generate 1001 unique events
    events = [
        {
            "EventID": 1,
            "Image": "test.exe",
            "ProcessId": i,
        }
        for i in range(1001)
    ]
    request = IngestRequest(
        source_type="sysmon", source_identifier="HOST-LARGE", events=events
    )

    chunk_queries = []

    def capture_sql(conn, cursor, statement, parameters, context, executemany):
        statement_lower = statement.lower()
        if (
            "raw_evidence" in statement_lower
            and "select" in statement_lower
            and "sha256_hash" in statement_lower
        ):
            chunk_queries.append((statement, parameters))

    event.listen(sqlite_engine, "before_cursor_execute", capture_sql)
    try:
        response = await service.ingest_batch(db_session, request)
    finally:
        event.remove(sqlite_engine, "before_cursor_execute", capture_sql)

    assert response.total_received == 1001
    assert response.total_normalized == 1001
    # Exactly 2 queries: first has 1000 params, second has 1 param
    assert len(chunk_queries) == 2
    assert len(chunk_queries[0][1]) == 1000
    assert len(chunk_queries[1][1]) == 1


def test_batch_size_boundary_validation():
    """P1-H4: Batch size up to MAX_BATCH_SIZE=2000 is accepted; 2001 is rejected."""
    from pydantic import ValidationError

    # 2000 events is accepted
    events_2000 = [{"EventID": 1, "Image": "test.exe"} for _ in range(2000)]
    req_valid = IngestRequest(events=events_2000)
    assert len(req_valid.events) == 2000

    # 2001 events is rejected
    events_2001 = [{"EventID": 1, "Image": "test.exe"} for _ in range(2001)]
    with pytest.raises(ValidationError) as exc_info:
        IngestRequest(events=events_2001)
    assert "List should have at most 2000 items" in str(exc_info.value)


def test_event_payload_max_bytes_validation():
    """P1-H4: Raw event payload exceeding MAX_EVENT_PAYLOAD_BYTES (64 KB) is rejected."""
    from pydantic import ValidationError

    oversized_event = {"EventID": 1, "LargeData": "A" * 70000}
    with pytest.raises(ValidationError) as exc_info:
        IngestRequest(events=[oversized_event])
    assert "exceeds maximum allowed payload size of 65536 bytes" in str(exc_info.value)

    # Valid size (e.g. 10 KB) succeeds
    valid_event = {"EventID": 1, "Data": "A" * 10000}
    req = IngestRequest(events=[valid_event])
    assert len(req.events) == 1


def test_source_type_and_identifier_validation():
    """P1-H4: source_type and source_identifier enforce length and character bounds."""
    from pydantic import ValidationError

    # Empty source_type rejected
    with pytest.raises(ValidationError):
        IngestRequest(source_type="", events=[])

    # Special characters / SQL injection syntax in source_type rejected
    with pytest.raises(ValidationError):
        IngestRequest(source_type="sysmon; DROP TABLE raw_evidence;", events=[])

    # Overly long source_type (> 50 chars) rejected
    with pytest.raises(ValidationError):
        IngestRequest(source_type="a" * 51, events=[])

    # Valid source_type characters accepted
    valid_req = IngestRequest(source_type="windows_event-2.0", events=[])
    assert valid_req.source_type == "windows_event-2.0"

    # Empty source_identifier rejected
    with pytest.raises(ValidationError):
        IngestRequest(source_identifier="", events=[])

    # Overly long source_identifier (> 255 chars) rejected
    with pytest.raises(ValidationError):
        IngestRequest(source_identifier="b" * 256, events=[])


@pytest.mark.anyio
async def test_atomic_savepoint_rollback_on_child_processing_error(db_session):
    """
    P1-H4: If an unexpected error occurs during child model creation (Event 1),
    the nested savepoint cleanly rolls back that event's RawEvidence insert,
    preventing orphaned raw records, while allowing Event 0 and Event 2 to commit.
    """
    from unittest.mock import patch

    from app.modules.evidence.sysmon_parser import SysmonParser

    service = IngestionService()
    event_0 = {
        "EventID": 1,
        "Image": "good0.exe",
        "Computer": "HOST-ATOM",
        "ProcessId": 100,
    }
    event_1_bad = {
        "EventID": 1,
        "Image": "bad1.exe",
        "Computer": "HOST-ATOM",
        "ProcessId": 200,
    }
    event_2 = {
        "EventID": 1,
        "Image": "good2.exe",
        "Computer": "HOST-ATOM",
        "ProcessId": 300,
    }

    request = IngestRequest(
        source_type="sysmon",
        source_identifier="HOST-ATOM",
        events=[event_0, event_1_bad, event_2],
    )

    # Intercept extract_entities on event_1_bad to simulate an unexpected child processing crash
    from app.services import ingestion_service as ing_module

    orig_extract = ing_module.extract_entities

    def failing_extract(canonical):
        if canonical.process and canonical.process.process_name == "bad1.exe":
            raise RuntimeError("Simulated entity extraction crash")
        return orig_extract(canonical)

    with patch.object(ing_module, "extract_entities", failing_extract):
        response = await service.ingest_batch(db_session, request)

    # IngestResponse must show 3 received, 2 normalized, 1 error
    assert response.total_received == 3
    assert response.total_normalized == 2
    assert response.total_skipped_duplicates == 0
    assert len(response.errors) == 1
    assert response.errors[0].event_index == 1
    assert "Simulated entity extraction crash" in response.errors[0].error

    # CRITICAL ATOMICITY CHECK:
    # Database MUST contain exactly 2 RawEvidence rows (for good0.exe and good2.exe).
    # bad1.exe's RawEvidence must have been completely rolled back by the savepoint!
    raw_rows = (await db_session.execute(select(RawEvidence))).scalars().all()
    assert len(raw_rows) == 2
    raw_payloads = [str(r.raw_payload) for r in raw_rows]
    assert any("good0.exe" in p for p in raw_payloads)
    assert any("good2.exe" in p for p in raw_payloads)
    assert not any("bad1.exe" in p for p in raw_payloads)

    # NormalizedEventModel rows must strictly be 2
    norm_rows = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    assert len(norm_rows) == 2


def test_safe_sample_truncation():
    """P1-H4: _safe_sample safely formats dicts, strings, and non-serializable objects without crashing."""
    from app.services.ingestion_service import _safe_sample

    sample_dict = {"key": "value", "nested": {"a": 1}}
    assert "key" in _safe_sample(sample_dict)

    sample_str = "A" * 200
    res_str = _safe_sample(sample_str, max_len=50)
    assert len(res_str) == 50

    # Object with failing str/repr
    class BrokenObject:
        def __repr__(self):
            raise Exception("Cannot repr")

        def __str__(self):
            raise Exception("Cannot str")

    assert _safe_sample(BrokenObject()) == "<unserializable payload>"
