"""
PROPOSED Stage 7B/7C PostgreSQL verification tests (owner review; NOT EXECUTED, NOT AUTHORIZED TO RUN).

Selection: every test is ``@pytest.mark.postgres`` and is therefore excluded by the repository's default expression
``-m "not postgres and not ollama"``. They additionally refuse to start unless the fail-closed target guard in ``tests/conftest.py`` accepts the
environment: exactly host 127.0.0.1, port 5433, database ``aisop_stage7b_verify_disposable``, the launcher-verified container / image / volume /
marker values, a database comment equal to the marker, and the single Alembic head. They never create or alter a database or schema, never run
a migration, never truncate, and never delete anything except rows the test's own session inserted (``OwnedRowTracker``).

Structure: each scenario is a plain coroutine over an ``AsyncSession``-like object, so the same assertions about stored values and transaction
semantics are exercised OFFLINE on SQLite by ``tests/unit/test_stage7c_postgres_scenarios.py``. Only what is PostgreSQL-specific (real concurrency,
``octet_length``, the append-only trigger) is guarded by ``pg=True`` and is therefore UNVERIFIED until an authorized run.

Row ownership: every run uses a fresh ``run`` id embedded in usernames, case numbers AND record bodies (so SHA-256 digests are unique per run and
a re-run never collides with leftovers). Audit rows are append-only and are intentionally left; their case and analyst parents are then left too
(foreign keys RESTRICT). Leftovers are reported by the fixture as a warning, never removed by a wider delete.

Six verification goals: (1) contradiction findings round trip, (2) audit-row size boundary, (3) concurrent unique-hash race, (4) rollback,
(5) case isolation and evidence ownership, (6) sufficiency-v4 persistence and stale-result behaviour.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.rbac import AuthenticatedAnalyst, GlobalRole
from app.models.analyst import Analyst
from app.models.case import CaseAuditEventModel, CaseModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.correlation.workflow import analyze
from app.modules.evidence.hasher import compute_sha256
from app.modules.evidence_domains import scenarios as S
from app.services.domain_evidence_service import IMPORT_ACTION, DomainEvidenceService
from app.services.multisource_investigation_service import PersistenceFailed
from app.services.multisource_investigation_service import (
    MULTISOURCE_ACTION,
    MultiSourceInvestigationService,
    activity_summary,
)
from app.models.case import CaseEvidenceModel
from app.modules.correlation.report import render_incident_report  # noqa: F401  (import check only)
from app.schemas.multisource import MultiSourceSection
from tests.conftest import OwnedRowTracker

pytestmark = pytest.mark.postgres


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ----------------------------------------------------------------------------------------- shared scenario helpers
def new_run() -> str:
    return uuid.uuid4().hex[:10]


def unique(records: list[dict], run: str) -> list[dict]:
    """Copies of the records with the run id inside the body, so their SHA-256 digests never repeat across runs."""
    out = []
    for r in records:
        c = json.loads(json.dumps(r))
        c["data"]["run_id"] = run
        out.append(c)
    return out


def outcome_conflict_records(run: str) -> list[dict]:
    return unique(S.negative_contradiction(), run)


def clean_records(run: str) -> list[dict]:
    return unique(S.scenario_a_identity_cloud(), run)


async def seed(session: Any, run: str, *, cases: int = 1) -> tuple[AuthenticatedAnalyst, list[uuid.UUID]]:
    now = datetime.now(timezone.utc)
    analyst_id = uuid.uuid4()
    username = f"s7b_{run}"[:60]
    session.add(Analyst(id=analyst_id, username=username, email=f"{username}@aisop.local", global_role=GlobalRole.ANALYST_TIER_2.value,
                        is_active=True, created_at=now, updated_at=now))
    case_ids = []
    for i in range(cases):
        cid = uuid.uuid4()
        session.add(CaseModel(id=cid, case_number=f"S7B-{run}-{i}", title=f"Stage 7B verification {run}", description="disposable verification",
                              severity="high", status="open", created_at=now, updated_at=now))
        case_ids.append(cid)
    await session.flush()
    await session.commit()
    return AuthenticatedAnalyst(analyst_id=analyst_id, username=username, global_role=GlobalRole.ANALYST_TIER_2), case_ids


def build_stored_payload(records: list[dict], run: str) -> dict:
    result = analyze(records)
    payload = MultiSourceInvestigationService().build_payload(result, "f" * 64, False)
    payload["created_at"] = datetime.now(timezone.utc).isoformat()
    payload["started_by"] = f"s7b_{run}"
    return json.loads(json.dumps(payload))


async def store_audit(session: Any, analyst: AuthenticatedAnalyst, case_id: uuid.UUID, payload: dict) -> uuid.UUID:
    audit_id = uuid.uuid4()
    session.add(CaseAuditEventModel(id=audit_id, case_id=case_id, actor_analyst_id=analyst.analyst_id, actor_username=analyst.username,
                                    action=MULTISOURCE_ACTION, context_sha256=None, details=payload, created_at=datetime.now(timezone.utc)))
    await session.commit()
    return audit_id


async def stored_details(session: Any, audit_id: uuid.UUID) -> dict:
    return (await session.execute(select(CaseAuditEventModel.details).where(CaseAuditEventModel.id == audit_id))).scalar_one()


async def count(session: Any, model: Any, *where: Any) -> int:
    return (await session.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


# ----------------------------------------------------------------------------------------- scenario 1
async def scenario_findings_round_trip(session: Any, run: str) -> dict:
    """The typed ADR-013 finding fields survive storage unchanged, and no evidence payload text is stored inside a finding."""
    analyst, [case_id] = await seed(session, run)
    records = outcome_conflict_records(run)
    payload = build_stored_payload(records, run)
    audit_id = await store_audit(session, analyst, case_id, payload)
    stored = await stored_details(session, audit_id)
    assert stored == payload                                               # nested structure, numbers, unicode and key order-insensitive equality
    findings = [c for inc in stored["incidents"] for c in inc["contradictions"]] + list(stored.get("contradictions") or [])
    assert findings, "the outcome conflict must be stored as at least one finding"
    f = findings[0]
    assert f["kind"] == "outcome" and f["materiality"] in ("material", "minor", "explained")
    assert f["independence"] in ("independent", "same_source", "unknown") and isinstance(f["affects_verdict"], bool)
    assert isinstance(f["overlap_seconds"], (int, float)) and len(f["evidence_ids"]) == 2 and len(f["times"]) == 2
    blob = json.dumps(findings)
    assert f"hank" not in blob and S.ATTACKER_IP not in blob and run not in blob          # fixed vocabulary, ids, source names and times only
    summary = activity_summary(stored)
    assert summary["summary_only"] is True and summary["verdicts"][0]["verdict"] in ("limited", "sufficient", "insufficient")
    return stored


@pytest.mark.anyio
async def test_s1_contradiction_findings_round_trip_with_typed_fields(postgres_session):
    stored = await scenario_findings_round_trip(postgres_session, new_run())
    assert stored["incidents"][0]["sufficiency"]["rule_version"] == "suff-v5"


# ----------------------------------------------------------------------------------------- scenario 2
async def scenario_large_audit_row(session: Any, run: str, *, pg: bool = False) -> int:
    """A result above one megabyte with multi-byte text is stored and read back byte-for-byte."""
    analyst, [case_id] = await seed(session, run)
    payload = build_stored_payload(outcome_conflict_records(run), run)
    tail = "\n" + ("证据行 \U0001f4a5 evidence line é\n" * 40000)          # about 1.4 MB of UTF-8
    payload["incidents"][0]["report_markdown"] += tail
    size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    assert size > 1_000_000
    audit_id = await store_audit(session, analyst, case_id, payload)
    stored = await stored_details(session, audit_id)
    assert stored["incidents"][0]["report_markdown"] == payload["incidents"][0]["report_markdown"]
    assert stored == payload
    if pg:                                                                    # PostgreSQL-specific: the server-side size of the JSONB value
        octets = (await session.execute(text("SELECT octet_length(details::text) FROM case_audit_events WHERE id = :i"), {"i": audit_id})).scalar_one()
        assert 1_000_000 < octets < 50_000_000
    return size


@pytest.mark.anyio
async def test_s2_audit_row_size_and_serialization_boundary(postgres_session):
    await scenario_large_audit_row(postgres_session, new_run(), pg=True)


# ----------------------------------------------------------------------------------------- scenario 3 (PostgreSQL only)
@pytest.mark.anyio
async def test_s3_concurrent_import_of_one_record_yields_one_raw_row(postgres_engine, postgres_session, monkeypatch):
    """
    Two independent connections import the SAME record into the SAME case. A barrier inside ``_create`` (after both existence checks, before
    either insert) makes both attempt the insert, so the UNIQUE sha256 constraint decides deterministically; no sleeps. The loser must roll back,
    retry once, and take the ordinary duplicate path.
    """
    run = new_run()
    analyst, [case_id] = await seed(postgres_session, run)
    record = unique([S.negative_contradiction()[0]], run)[0]
    digest = compute_sha256(record)

    gate = asyncio.Barrier(2)
    entrants = 0
    original = DomainEvidenceService._create

    async def gated(session, rec, dig, obs, now):
        nonlocal entrants
        entrants += 1
        if entrants <= 2:                                                       # only the first two (one per connection) wait; a retry never does
            await asyncio.wait_for(gate.wait(), timeout=30)
        return await original(session, rec, dig, obs, now)

    monkeypatch.setattr(DomainEvidenceService, "_create", staticmethod(gated))

    factory = async_sessionmaker(bind=postgres_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)
    trackers = [OwnedRowTracker(), OwnedRowTracker()]
    async with factory() as s1, factory() as s2:
        trackers[0].attach(s1.sync_session)
        trackers[1].attach(s2.sync_session)
        svc = DomainEvidenceService()
        r1, r2 = await asyncio.gather(
            svc.import_records(session=s1, case_id=case_id, actor=analyst, records=[record]),
            svc.import_records(session=s2, case_id=case_id, actor=analyst, records=[record]),
        )
    assert entrants == 2                                                         # both reached the insert point: the race really happened
    assert sorted([r1["duplicates"], r2["duplicates"]]) == [0, 1]                # one winner, one idempotent duplicate
    assert r1["evidence"][0]["evidence_id"] == r2["evidence"][0]["evidence_id"]
    async with factory() as check:
        assert await count(check, RawEvidence, RawEvidence.sha256_hash == digest) == 1
        event_id = uuid.UUID(r1["evidence"][0]["evidence_id"])
        assert await count(check, NormalizedEventModel, NormalizedEventModel.id == event_id) == 1
        assert await count(check, CaseEvidenceModel, CaseEvidenceModel.case_id == case_id) == 1
    # owned-row cleanup of the two extra sessions (the main fixture cleans its own); failures are reported, never widened
    import warnings
    for t in trackers:
        deleted, left = t.cleanup(postgres_engine.sync_engine)
        if left:
            warnings.warn(f"s3 cleanup left {left} owned row(s): {sorted(set(t.left_ids))}")


# ----------------------------------------------------------------------------------------- scenario 4
async def scenario_rollback(session: Any, run: str, monkeypatch: Any, *, other_session: Any = None) -> None:
    """A failure after the raw and normalized rows were flushed leaves nothing behind, and the same record can then be imported normally."""
    analyst, [case_id] = await seed(session, run)
    record = unique([S.negative_contradiction()[0]], run)[0]
    digest = compute_sha256(record)
    original = DomainEvidenceService._create

    async def failing(sess, rec, dig, obs, now):
        await original(sess, rec, dig, obs, now)                                 # rows are flushed in the open transaction ...
        raise RuntimeError("simulated failure after insert")                     # ... and then the import fails

    monkeypatch.setattr(DomainEvidenceService, "_create", staticmethod(failing))
    with pytest.raises(PersistenceFailed):
        await DomainEvidenceService().import_records(session=session, case_id=case_id, actor=analyst, records=[record])
    monkeypatch.setattr(DomainEvidenceService, "_create", staticmethod(original))
    check = other_session or session
    assert await count(check, RawEvidence, RawEvidence.sha256_hash == digest) == 0
    assert await count(check, CaseEvidenceModel, CaseEvidenceModel.case_id == case_id) == 0
    assert await count(check, CaseAuditEventModel, CaseAuditEventModel.case_id == case_id, CaseAuditEventModel.action == IMPORT_ACTION) == 0
    ok = await DomainEvidenceService().import_records(session=session, case_id=case_id, actor=analyst, records=[record])
    assert ok["accepted"] == 1 and ok["duplicates"] == 0                        # the failed attempt did not poison the digest
    assert await count(check, RawEvidence, RawEvidence.sha256_hash == digest) == 1


@pytest.mark.anyio
async def test_s4_failed_import_rolls_back_every_row(postgres_engine, postgres_session, monkeypatch):
    factory = async_sessionmaker(bind=postgres_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)
    async with factory() as independent:                                          # a second connection: only committed state is visible to it
        await scenario_rollback(postgres_session, new_run(), monkeypatch, other_session=independent)


# ----------------------------------------------------------------------------------------- scenario 5
async def scenario_case_isolation(session: Any, run: str) -> None:
    """A finding and its evidence belong to one case only; a record shared by digest is stored once but linked per case."""
    analyst, [case_a, case_b] = await seed(session, run, cases=2)
    svc, inv = DomainEvidenceService(), MultiSourceInvestigationService()
    a_records = outcome_conflict_records(run)
    b_records = clean_records(run) + [a_records[0]]                              # B shares ONE record with A
    ia = await svc.import_records(session=session, case_id=case_a, actor=analyst, records=a_records)
    ib = await svc.import_records(session=session, case_id=case_b, actor=analyst, records=b_records)
    shared = compute_sha256(a_records[0])
    assert await count(session, RawEvidence, RawEvidence.sha256_hash == shared) == 1                  # stored once
    ids_a = {e["evidence_id"] for e in ia["evidence"]}
    ids_b = {e["evidence_id"] for e in ib["evidence"]}
    assert len(ids_a & ids_b) == 1 and ib["duplicates"] == 1                                          # the shared record is a duplicate in B
    for cid, ids in ((case_a, ids_a), (case_b, ids_b)):
        linked = {str(x) for x in (await session.execute(select(CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == cid))).scalars().all()}
        assert linked == ids                                                                         # each case sees exactly its own links
    _c, pa = await inv.start(session=session, case_id=case_a, actor=analyst, use_llm=False, force=False, llm_provider=None)
    _c, pb = await inv.start(session=session, case_id=case_b, actor=analyst, use_llm=False, force=False, llm_provider=None)
    codes_a = [c for i in pa["incidents"] for c in i["sufficiency"]["reason_codes"]]
    codes_b = [c for i in pb["incidents"] for c in i["sufficiency"]["reason_codes"]]
    assert "CONTRADICTORY_EVIDENCE:outcome" in codes_a
    assert not any(c.startswith("CONTRADICTORY") for c in codes_b)                                   # A's conflict never appears in B
    ev_a = {e for i in pa["incidents"] for e in i["sufficiency"]["evidence_ids"]}
    ev_b = {e for i in pb["incidents"] for e in i["sufficiency"]["evidence_ids"]}
    assert ev_a <= ids_a and ev_b <= ids_b
    assert pa["evidence_fingerprint"] != pb["evidence_fingerprint"]


@pytest.mark.anyio
async def test_s5_case_isolation_and_evidence_ownership(postgres_session):
    await scenario_case_isolation(postgres_session, new_run())


# ----------------------------------------------------------------------------------------- scenario 6
async def scenario_sufficiency_persistence_and_stale(session: Any, run: str, *, pg: bool = False) -> None:
    """The suff-v4 result is stored and reused; new evidence makes it stale and a new run appends a second record; the first is unchanged."""
    analyst, [case_id] = await seed(session, run)
    svc, inv = DomainEvidenceService(), MultiSourceInvestigationService()
    await svc.import_records(session=session, case_id=case_id, actor=analyst, records=outcome_conflict_records(run))
    created, first = await inv.start(session=session, case_id=case_id, actor=analyst, use_llm=False, force=False, llm_provider=None)
    assert created is True and first["reused"] is False
    inc = first["incidents"][0]["sufficiency"]
    assert inc["rule_version"] == "suff-v5" and "CONTRADICTORY_EVIDENCE:outcome" in inc["reason_codes"] and inc["verdict"] == "limited"
    row = (await session.execute(select(CaseAuditEventModel).where(CaseAuditEventModel.case_id == case_id, CaseAuditEventModel.action == MULTISOURCE_ACTION))).scalars().all()
    assert len(row) == 1
    snapshot = json.loads(json.dumps(row[0].details))
    assert snapshot["incidents"][0]["sufficiency"] == first["incidents"][0]["sufficiency"]              # stored == returned
    created2, again = await inv.start(session=session, case_id=case_id, actor=analyst, use_llm=False, force=False, llm_provider=None)
    assert created2 is False and again["reused"] is True and again["evidence_fingerprint"] == first["evidence_fingerprint"]
    fresh = await inv.get_section(session=session, case_id=case_id, section=MultiSourceSection.SUFFICIENCY)
    assert fresh["stale_evidence"] is False
    # new evidence arrives: the stored result is stale (disclosed), nothing is rewritten
    extra = unique([S.scenario_a_identity_cloud()[0]], run + "x")
    await svc.import_records(session=session, case_id=case_id, actor=analyst, records=extra)
    stale = await inv.get_section(session=session, case_id=case_id, section=MultiSourceSection.SUFFICIENCY)
    assert stale["stale_evidence"] is True
    created3, newer = await inv.start(session=session, case_id=case_id, actor=analyst, use_llm=False, force=False, llm_provider=None)
    assert created3 is True and newer["evidence_fingerprint"] != first["evidence_fingerprint"]
    rows = (await session.execute(select(CaseAuditEventModel).where(CaseAuditEventModel.case_id == case_id, CaseAuditEventModel.action == MULTISOURCE_ACTION))).scalars().all()
    assert len(rows) == 2                                                                              # append, never overwrite
    old = next(r for r in rows if r.details["evidence_fingerprint"] == first["evidence_fingerprint"])
    assert json.loads(json.dumps(old.details))["incidents"][0]["sufficiency"] == snapshot["incidents"][0]["sufficiency"]
    if pg:                                                                                             # append-only trigger (PostgreSQL only)
        with pytest.raises(Exception):
            async with session.begin_nested():
                await session.execute(text("UPDATE case_audit_events SET details = '{}'::jsonb WHERE id = :i"), {"i": old.id})
        await session.rollback()


@pytest.mark.anyio
async def test_s6_sufficiency_v4_persistence_and_stale_result(postgres_session):
    await scenario_sufficiency_persistence_and_stale(postgres_session, new_run(), pg=True)
