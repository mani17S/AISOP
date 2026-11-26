"""
Differential tests for the chunked fast path of AlertIngestionService.

The service has two persistence paths that must give identical results: the per-alert path (one savepoint per alert; the reference
and the fallback) and the chunked fast path (pure work first, then one savepoint and three flushes per chunk of
AlertIngestionService.FAST_CHUNK_SIZE alerts). These tests run both against identical fresh SQLite databases and compare the
responses and the stored rows.

Scope limit: SQLite in one session cannot show PostgreSQL concurrency behaviour (real concurrent inserts, lock waits, the unique
constraint under parallel writers). The race handling is exercised here only by simulating a conflicting row; the owner must
measure and test races on PostgreSQL.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Any

import pytest
from app.db.base import Base
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.evidence.hasher import compute_sha256
from app.schemas.alert_ingest import AlertIngestRequest
from app.services.alert_ingestion_service import AlertIngestionService
from loguru import logger
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from tests.conftest import AsyncSessionAdapter

CHUNK = AlertIngestionService.FAST_CHUNK_SIZE
# The generic adapter invents a random id ("siem-" plus 8 hex digits) when the record has no rule id; it is not stable between runs.
RANDOM_ALERT_ID = re.compile(r"siem-[0-9a-f]{8}")
SEVERITIES = ["critical", "high", "medium", "low", "informational"]


# --- helpers ---------------------------------------------------------------------------------------------------------------

def make_alert(i: int) -> dict[str, Any]:
    alert: dict[str, Any] = {
        "source_type": "generic_siem",
        "provider": "Test SIEM",
        "rule_id": f"rule-{i}",
        "rule_name": f"Rule number {i}",
        "description": f"Synthetic alert {i}",
        "severity": SEVERITIES[i % 5],
        "category": "credential_access",
        # every ninth alert has a zone-less time, the rest carry a zone
        "timestamp": f"2026-10-31T09:{i % 60:02d}:12" + ("" if i % 9 == 0 else ".000000Z"),
        "host": f"host-{i % 7}.corp.local",
        "user": f"user{i % 5}",
        "src_ip": f"198.51.100.{i % 250 + 1}",
        "dest_ip": "10.0.2.50",
        "mitre_techniques": ["T1110.003"] if i % 3 == 0 else [],
    }
    if i % 4 == 0:
        alert["entities"] = [{"type": "host", "value": f"extra-host-{i}", "role": "victim"}]
    return alert


def make_request(alerts: list[Any], source_type: str = "generic_siem") -> AlertIngestRequest:
    if all(isinstance(a, dict) for a in alerts):
        return AlertIngestRequest(source_type=source_type, source_identifier="equiv-test", alerts=alerts)
    # Non-dict shapes cannot pass request validation; build the request without it to reach the service directly.
    return AlertIngestRequest.model_construct(source_type=source_type, source_identifier="equiv-test", alerts=alerts)


class FreshDb:
    """An isolated in-memory SQLite database and session, with an INSERT/total statement log."""

    def __init__(self) -> None:
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.connection = self.engine.connect()
        self.sync = sessionmaker(bind=self.connection)()
        self.session = AsyncSessionAdapter(self.sync)
        self.statements: list[str] = []
        self.service_statements: list[str] = []  # frozen right after the service call, before the snapshot queries

        @event.listens_for(self.engine, "before_cursor_execute")
        def _log(conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
            self.statements.append(statement)

    @property
    def inserts(self) -> int:
        return sum(1 for s in self.service_statements if s.lstrip().upper().startswith("INSERT"))

    def close(self) -> None:
        self.sync.close()
        self.connection.close()
        self.engine.dispose()

    def snapshot(self, response: Any) -> dict[str, Any]:
        """Response and stored rows with generated ids and timestamps replaced by stable keys (the SHA-256 of the raw record)."""
        raws = self.sync.execute(select(RawEvidence)).scalars().all()
        events = self.sync.execute(select(NormalizedEventModel)).scalars().all()
        entities = self.sync.execute(select(ExtractedEntityModel)).scalars().all()
        sha_of_raw = {r.id: r.sha256_hash for r in raws}
        sha_of_event = {e.id: sha_of_raw[e.raw_evidence_id] for e in events}

        dumped = response.model_dump(mode="json")
        dumped.pop("batch_id")
        dumped["existing_evidence_ids"] = [sha_of_raw[i] for i in response.existing_evidence_ids]
        dumped["alert_ids"] = [sha_of_event[i] for i in response.alert_ids]

        def payload(e: NormalizedEventModel) -> str:
            p = dict(e.normalized_payload)
            p.pop("id", None)  # random uuid per CanonicalAlert
            p.pop("ingested_at", None)  # wall clock
            return RANDOM_ALERT_ID.sub("siem-RANDOM", json.dumps(p, sort_keys=True, default=str))

        return {
            "response": dumped,
            "raw_insert_order": [r.sha256_hash for r in raws],
            "raw": sorted(
                (r.sha256_hash, r.source_type, r.source_identifier, json.dumps(r.raw_payload, sort_keys=True, default=str)) for r in raws
            ),
            "events": sorted(
                (
                    sha_of_raw[e.raw_evidence_id], RANDOM_ALERT_ID.sub("siem-RANDOM", e.event_id), e.event_type, str(e.event_timestamp), e.provider, e.action,
                    e.outcome, e.severity, payload(e),
                )
                for e in events
            ),
            "entities": sorted(
                (sha_of_event[n.event_id], sha_of_raw[n.raw_evidence_id], n.entity_type, n.entity_value, n.role,
                 json.dumps(n.attributes, sort_keys=True, default=str))
                for n in entities
            ),
        }


def run_service(
    alerts: list[Any],
    source_type: str,
    chunked: bool,
    prefill: list[dict[str, Any]] | None = None,
    hook: Any = None,
) -> tuple[Any, FreshDb]:
    """Run one ingestion on a fresh database. Returns ((snapshot | ('raised', type name)), db). The caller closes the db."""
    db = FreshDb()
    if prefill:
        asyncio.run(AlertIngestionService(chunked=False).ingest_batch(db.session, make_request(prefill, source_type)))
        db.statements.clear()
    if hook is not None:
        hook(db, alerts)
    try:
        response = asyncio.run(AlertIngestionService(chunked=chunked).ingest_batch(db.session, make_request(alerts, source_type)))
    except Exception as exc:  # noqa: BLE001 - a raise must be identical in both paths too
        db.service_statements = list(db.statements)
        return ("raised", type(exc).__name__), db
    db.service_statements = list(db.statements)
    return db.snapshot(response), db


def assert_equivalent(
    alerts: list[Any],
    source_type: str = "generic_siem",
    prefill: list[dict[str, Any]] | None = None,
    hook: Any = None,
) -> dict[str, Any]:
    fast, fast_db = run_service(alerts, source_type, True, prefill, hook)
    ref, ref_db = run_service(alerts, source_type, False, prefill, hook)
    try:
        assert fast == ref
        return fast
    finally:
        fast_db.close()
        ref_db.close()


# --- (a) differential equivalence -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("source_type", ["generic_siem", "auto", "sysmon"])
@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 1, 3 * CHUNK])
def test_valid_batches_are_identical_for_all_sizes_and_source_types(size, source_type):
    alerts = [make_alert(i) for i in range(size)]
    snap = assert_equivalent(alerts, source_type)
    assert snap["response"]["total_received"] == size
    assert snap["response"]["total_normalized"] == size
    assert snap["response"]["errors"] == []
    assert len(snap["response"]["alert_ids"]) == size
    assert len(snap["raw"]) == size and len(snap["events"]) == size


def test_empty_batch_is_identical():
    snap = assert_equivalent([], "generic_siem")
    assert snap["response"]["total_received"] == 0 and snap["raw"] == []


def test_intra_batch_duplicates_within_and_across_chunks_are_identical():
    # 23 distinct alerts repeated: duplicates sit in the same chunk and in later chunks, in a scrambled order.
    alerts = [make_alert((i * 7) % 23) for i in range(CHUNK * 2 + 17)]
    snap = assert_equivalent(alerts)
    assert snap["response"]["total_normalized"] == 23
    assert snap["response"]["total_skipped_duplicates"] == len(alerts) - 23
    assert len(snap["response"]["existing_evidence_ids"]) == 23
    assert len(snap["raw"]) == 23


def test_hashes_that_already_exist_are_identical():
    prefill = [make_alert(i) for i in range(0, 80, 3)]  # 27 alerts already stored
    alerts = [make_alert(i) for i in range(0, 130)]
    snap = assert_equivalent(alerts, prefill=prefill)
    assert snap["response"]["total_skipped_duplicates"] == 27
    assert snap["response"]["total_normalized"] == 130 - 27
    assert len(snap["raw"]) == 130


def _hostile_alerts() -> list[Any]:
    deep: dict[str, Any] = {}
    cursor = deep
    for _ in range(40):
        cursor["n"] = {}
        cursor = cursor["n"]
    hostile: list[Any] = [
        {"unrelated": "no adapter matches this"},
        {},
        {"rule_name": 12345, "timestamp": 99},
        {"rule_name": ["a"], "severity": {"x": 1}, "src_ip": [1, 2], "entities": "not-a-list"},
        {"rule_name": "binary " + "\x00\x01\x02\xff￾" * 200, "timestamp": "2026-10-31T09:55:12Z"},
        {"rule_id": "deep", "rule_name": "deep", "timestamp": "2026-10-31T09:55:12Z", "extra": deep},
        {"rule_id": "big", "rule_name": "x" * 100000, "timestamp": "2026-10-31T09:55:12Z"},
        {"source_type": 5, "rule_name": "r"},
        {"rule_name": "no time at all"},
        {"rule_name": "bad time", "timestamp": "not a time"},
        {"rule_name": "future-only tz", "timestamp": "0001-01-01T00:00:00+14:00"},
    ]
    alerts: list[Any] = []
    for i in range(2 * CHUNK + 5):
        alerts.append(make_alert(i))
        if i % 6 == 0:
            alerts.append(hostile[(i // 6) % len(hostile)])
    alerts.extend(hostile)
    return alerts


@pytest.mark.parametrize("source_type", ["generic_siem", "auto"])
def test_malformed_and_hostile_records_mixed_with_valid_ones_are_identical(source_type):
    alerts = _hostile_alerts()
    snap = assert_equivalent(alerts, source_type)
    assert isinstance(snap, dict), "the batch must not raise"
    assert snap["response"]["errors"], "the hostile records must be reported as errors"
    assert snap["response"]["total_normalized"] >= 2 * CHUNK + 5


def test_non_dict_shapes_are_identical():
    alerts: list[Any] = [make_alert(0), "plain string", 5, None, [1, 2], '{"rule_name": "json text"}', make_alert(1)]
    snap = assert_equivalent(alerts)
    assert isinstance(snap, dict) or snap[0] == "raised"


# --- (b) fallback ------------------------------------------------------------------------------------------------------------

def test_chunk_failure_from_an_integrity_error_falls_back_and_matches_per_alert():
    alerts = [make_alert(i) for i in range(CHUNK + 20)]

    def fail_first_flush_once(db: FreshDb, _alerts: list[Any]) -> None:
        original = db.session.flush
        state = {"armed": True}

        async def flush() -> None:
            if state["armed"]:
                state["armed"] = False
                raise IntegrityError("INSERT", {}, Exception("simulated concurrent duplicate"))
            await original()

        db.session.flush = flush  # type: ignore[method-assign]

    # A transient failure hits the chunk once. The per-alert replay recovers every record, so the result equals a clean per-alert run
    # (the same fault injected into the per-alert path itself would cost one record: it has no chunk to fall back from).
    fast, fast_db = run_service(alerts, "generic_siem", True, hook=fail_first_flush_once)
    clean, clean_db = run_service(alerts, "generic_siem", False)
    try:
        assert fast == clean
        assert fast["response"]["total_normalized"] == len(alerts) and fast["response"]["errors"] == []
    finally:
        fast_db.close()
        clean_db.close()


def test_chunk_failure_from_a_conflicting_existing_row_counts_the_race_as_a_duplicate():
    alerts = [make_alert(i) for i in range(CHUNK + 10)]

    def conflict_after_existence_lookup(db: FreshDb, batch: list[Any]) -> None:
        original = db.session.execute
        state = {"done": False}

        async def execute(statement: Any, *args: Any, **kwargs: Any) -> Any:
            result = await original(statement, *args, **kwargs)
            if not state["done"]:
                state["done"] = True  # the first call is the batched existence lookup
                # A concurrent writer stores alert 10 after the lookup and before our insert.
                db.sync.add(RawEvidence(source_type="generic_siem", source_identifier="other-writer",
                                        sha256_hash=compute_sha256(batch[10]), raw_payload=batch[10]))
                db.sync.flush()
            return result

        db.session.execute = execute  # type: ignore[method-assign]

    snap = assert_equivalent(alerts, hook=conflict_after_existence_lookup)
    response = snap["response"]
    assert response["total_skipped_duplicates"] == 1
    assert response["total_normalized"] == len(alerts) - 1
    assert response["errors"] == []
    assert response["existing_evidence_ids"] == [compute_sha256(alerts[10])]
    assert len(snap["raw"]) == len(alerts)  # nothing lost, nothing duplicated


def test_a_record_that_fails_in_the_database_is_reported_exactly_as_the_per_alert_path_reports_it():
    alerts = [make_alert(i) for i in range(CHUNK + 20)]
    poison_index = 7
    alerts[poison_index]["rule_id"] = "poison"

    def poison_flush(db: FreshDb, _alerts: list[Any]) -> None:
        original = db.session.flush

        async def flush() -> None:
            if any(isinstance(o, RawEvidence) and o.raw_payload.get("rule_id") == "poison" for o in db.sync.new):
                raise IntegrityError("INSERT", {}, Exception("simulated deterministic storage failure"))
            await original()

        db.session.flush = flush  # type: ignore[method-assign]

    snap = assert_equivalent(alerts, hook=poison_flush)
    response = snap["response"]
    assert [e["alert_index"] for e in response["errors"]] == [poison_index]
    assert response["total_normalized"] == len(alerts) - 1
    assert len(snap["raw"]) == len(alerts) - 1
    assert compute_sha256(alerts[poison_index]) not in snap["raw_insert_order"]


# --- (c) statement count -----------------------------------------------------------------------------------------------------

def test_chunked_path_issues_far_fewer_insert_statements_than_the_per_alert_path():
    alerts = [make_alert(i) for i in range(100)]
    _, fast_db = run_service(alerts, "generic_siem", True)
    _, ref_db = run_service(alerts, "generic_siem", False)
    try:
        fast_inserts, ref_inserts = fast_db.inserts, ref_db.inserts
        assert ref_inserts >= 300  # raw, event and entities for each of the 100 alerts
        assert fast_inserts <= ref_inserts / 2
        chunks = -(-len(alerts) // CHUNK)  # ceiling division: the number of database phases
        assert fast_inserts <= 3 * chunks  # at most three statements per chunk
        assert len(fast_db.service_statements) < len(ref_db.service_statements) / 2
    finally:
        fast_db.close()
        ref_db.close()


# --- (d) set-based membership keeps the first-seen order ---------------------------------------------------------------------

def test_many_repeated_existing_hashes_keep_first_seen_order():
    prefill = [make_alert(i) for i in range(12)]
    order = [4, 1, 4, 9, 1, 0, 3, 3, 11, 2, 9, 4, 7, 7, 5, 10, 6, 8, 0, 1]
    alerts = [make_alert(i) for i in order * 8]  # 160 references to 12 existing hashes
    expected_hashes: list[str] = []
    for i in order:
        h = compute_sha256(make_alert(i))
        if h not in expected_hashes:
            expected_hashes.append(h)
    snap = assert_equivalent(alerts, prefill=prefill)
    assert snap["response"]["existing_evidence_ids"] == expected_hashes
    assert snap["response"]["total_skipped_duplicates"] == len(alerts)
    assert snap["response"]["total_normalized"] == 0


# --- (f) failure AFTER the real flush, fallback warning, commit failure ---------------------------------------------------------

FALLBACK_WARNING = "Chunk savepoint failed"


class capture_fallback_warnings:  # noqa: N801 - context manager used like a function
    """Collect the loguru records of the chunk fallback warning."""

    def __enter__(self) -> list[dict[str, Any]]:
        self.records: list[dict[str, Any]] = []
        self._sink_id = logger.add(
            lambda message: self.records.append(message.record) if FALLBACK_WARNING in message.record["message"] else None,
            level="WARNING",
            format="{message}",
        )
        return self.records

    def __exit__(self, *exc_info: object) -> None:
        logger.remove(self._sink_id)


def fail_after_real_flush(nth: int) -> Any:
    """Hook: the real flush runs first (rows really reach the database), then the nth flush call raises once."""

    def hook(db: FreshDb, _alerts: list[Any]) -> None:
        original = db.session.flush
        state = {"calls": 0}

        async def flush() -> None:
            state["calls"] += 1
            await original()
            if state["calls"] == nth:
                raise IntegrityError("INSERT", {}, Exception("simulated failure after the rows were really flushed"))

        db.session.flush = flush  # type: ignore[method-assign]

    return hook


@pytest.mark.parametrize("nth", [2, 3])
def test_failure_after_the_real_flush_is_rolled_back_and_the_fallback_recovers_every_record(nth):
    alerts = [make_alert(i) for i in range(CHUNK + 20)]
    with capture_fallback_warnings() as warnings:
        fast, fast_db = run_service(alerts, "generic_siem", True, hook=fail_after_real_flush(nth))
    clean, clean_db = run_service(alerts, "generic_siem", False)
    try:
        assert fast == clean
        assert fast["response"]["total_normalized"] == len(alerts) and fast["response"]["errors"] == []
        hashes = [compute_sha256(a) for a in alerts]
        assert sorted(fast["raw_insert_order"]) == sorted(hashes)  # exactly one raw row per hash
        assert len(set(fast["raw_insert_order"])) == len(alerts)
        assert not fast_db.sync.new  # no pending object left behind by the rolled-back chunk
        stored = fast_db.sync.execute(select(RawEvidence)).scalars().all()  # strong references: the identity map now holds the stored rows
        assert len(stored) == len(alerts)
        assert sum(1 for o in fast_db.sync.identity_map.values() if isinstance(o, RawEvidence)) == len(stored)
        assert len(warnings) == 1  # the first chunk fell back once; the later chunk took the fast path
        assert (warnings[0]["extra"]["chunk_start"], warnings[0]["extra"]["chunk_end"]) == (0, CHUNK)
    finally:
        fast_db.close()
        clean_db.close()


def test_fallback_warning_carries_the_batch_id_and_no_alert_content_or_exception_text():
    marker = "ALERT-CONTENT-MARKER-7f3a"
    alerts = [make_alert(i) for i in range(CHUNK + 5)]
    for alert in alerts:
        alert["description"] = f"{marker} {alert['description']}"
    db = FreshDb()
    try:
        fail_after_real_flush(2)(db, alerts)
        with capture_fallback_warnings() as warnings:
            response = asyncio.run(AlertIngestionService(chunked=True).ingest_batch(db.session, make_request(alerts)))
        assert len(warnings) == 1
        record = warnings[0]
        assert record["extra"]["batch_id"] == str(response.batch_id)
        assert str(uuid.UUID(record["extra"]["batch_id"])) == record["extra"]["batch_id"]
        assert record["extra"]["error_type"] == "IntegrityError"
        assert record["extra"]["component"] == "alert_ingestion_service"
        logged = record["message"] + json.dumps(record["extra"], default=str)
        assert marker not in logged
        assert "simulated failure" not in logged  # the exception text is never logged
        assert "rule-" not in logged and "198.51.100" not in logged
    finally:
        db.close()


def commit_fails_on_a_real_transaction(db: FreshDb, _alerts: list[Any]) -> None:
    # pysqlite would otherwise let the outermost SAVEPOINT act as the transaction, so a later rollback could not undo it; opening an
    # explicit transaction first makes the rollback below meaningful on SQLite.
    db.sync.execute(text("BEGIN"))

    async def failing_commit() -> None:
        raise RuntimeError("injected commit failure")

    db.session.commit = failing_commit  # type: ignore[method-assign]


def test_commit_failure_after_chunk_successes_behaves_like_the_per_alert_path():
    alerts = [make_alert(i) for i in range(2 * CHUNK + 5)] + [make_alert(0), {"unrelated": "no adapter matches"}]
    outcomes: dict[bool, tuple[str, int]] = {}
    for chunked in (True, False):
        db = FreshDb()
        try:
            commit_fails_on_a_real_transaction(db, alerts)
            with pytest.raises(RuntimeError, match="injected commit failure") as raised:
                asyncio.run(AlertIngestionService(chunked=chunked).ingest_batch(db.session, make_request(alerts)))
            asyncio.run(db.session.rollback())
            stored = len(db.sync.execute(select(RawEvidence)).scalars().all())
            outcomes[chunked] = (type(raised.value).__name__, stored)
        finally:
            db.close()
    assert outcomes[True] == outcomes[False] == ("RuntimeError", 0)


# --- (e) a rejected record never reaches the database ---------------------------------------------------------------------------

def test_a_batch_of_only_rejected_records_issues_only_the_existence_lookup():
    alerts: list[Any] = [
        {"unrelated": "no adapter matches"},
        {},
        {"rule_name": 12345, "timestamp": 99},
        {"rule_name": "bad time", "timestamp": "not a time"},
        {"source_type": 5, "rule_name": "r"},
        {"rule_name": "no time at all"},
    ]
    snap, db = run_service(alerts, "generic_siem", True)
    try:
        assert isinstance(snap, dict)
        assert snap["response"]["errors"], "the records must be rejected"
        assert snap["response"]["total_normalized"] == 0
        assert len(db.service_statements) == 1, db.service_statements
        assert db.service_statements[0].lstrip().upper().startswith("SELECT")
        assert "FROM RAW_EVIDENCE" in db.service_statements[0].upper()
        assert db.sync.execute(select(RawEvidence)).scalars().all() == []
    finally:
        db.close()
