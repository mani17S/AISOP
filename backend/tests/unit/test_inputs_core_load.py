"""
Proposal A2 (Investigation_Responsiveness_Profiling section 17.1): the first evidence load of ``start`` is ONE column-only SELECT.

``MultiSourceInvestigationService._load_inputs`` must return exactly what the old two-step path produced:
``_inputs(await _load_rows(...))`` (records, digests, keys, in the same order) and the same fingerprint through
``fingerprint_from_pairs`` (identical to ``fingerprint(rows, use_llm)`` by construction). ``start`` must no longer call ``_load_rows``.

Offline, SQLite harness. SQLite passing does not validate PostgreSQL behaviour or timing (UNVERIFIED).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

import app.services.multisource_investigation_service as svc_mod
from app.models.case import CaseEvidenceModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.correlation.demo_data import intrusion_chain
from app.services.multisource_investigation_service import MultiSourceInvestigationService
from tests.unit.test_case_synthesis_api import seed_analyst_with_token, seed_case_with_lead
from tests.unit.test_multisource_api import (  # noqa: F401  (fixtures and helpers)
    START,
    Keep,
    anyio_backend,
    app_instance,
    auth_settings,
    bearer,
    ingest,
    link_all_events,
    setup,
)

STATUS = "/api/v1/cases/{cid}/investigations/multisource/status"
REVIEW = "/api/v1/cases/{cid}/investigations/multisource/review"
EXPORT = "/api/v1/cases/{cid}/investigations/multisource/export"
T0 = datetime(2026, 11, 7, 9, 0, 0, tzinfo=timezone.utc)
EXTRA = {"source_type": "generic_siem", "rule_id": "R-EXTRA-A2", "rule_name": "extra record", "severity": "low",
         "timestamp": "2026-11-07T09:30:00Z", "host": "x", "user": "y"}


async def seed_items(db_session, case, lead, specs):
    """Directly seed one raw record + normalized event + case link per spec. Insert order is reversed so ORDER BY must do the work.

    spec keys: ts (int minutes after T0), payload (any JSON), hash.
    Returns the event ids in insertion order.
    """
    ids = []
    for spec in reversed(specs):
        raw = RawEvidence(id=uuid.uuid4(), source_type="generic_siem", source_identifier="a2", sha256_hash=spec["hash"],
                          raw_payload=spec["payload"], ingested_at=T0)
        db_session.add(raw)
        await db_session.flush()
        ev = NormalizedEventModel(id=uuid.uuid4(), raw_evidence_id=raw.id, event_id="e", event_type="e",
                                  event_timestamp=T0 + timedelta(minutes=spec["ts"]), provider="x", action="x", outcome="unknown",
                                  severity="low", normalized_payload={})
        db_session.add(ev)
        await db_session.flush()
        db_session.add(CaseEvidenceModel(id=uuid.uuid4(), case_id=case.id, evidence_id=ev.id, linked_by_analyst_id=lead.id))
        ids.append(ev.id)
    await db_session.commit()
    return ids


def make_specs(n, *, tied=False):
    specs = []
    for i in range(n):
        ts = 5 if tied and i % 2 == 0 else i          # several items share the same timestamp: the id tiebreak decides
        specs.append({"ts": ts, "hash": f"{i:02d}" + "a" * 62, "payload": {"rule_id": f"R{i}", "n": i}})
    return specs


async def old_path(db_session, case_id):
    svc = MultiSourceInvestigationService()
    db_session._sync.expire_all()
    rows = await svc._load_rows(db_session, case_id)
    return (*svc._inputs(rows), rows)


async def assert_same(db_session, case_id):
    svc = MultiSourceInvestigationService()
    records, digests, keys, rows = await old_path(db_session, case_id)
    db_session._sync.expire_all()
    n_records, n_digests, n_keys, pairs = await svc._load_inputs(db_session, case_id)
    assert n_records == records and n_digests == digests and n_keys == keys      # same values, same order
    assert [type(r) for r in n_records] == [type(r) for r in records]
    for use_llm in (False, True):
        assert svc.fingerprint_from_pairs(pairs, use_llm) == svc.fingerprint(rows, use_llm)
    return n_records, n_digests, n_keys, pairs


async def new_case(db_session, prefix):
    _token, lead = await seed_analyst_with_token(db_session, prefix=prefix, username=prefix, global_role="analyst_tier_2")
    return await seed_case_with_lead(db_session, lead=lead), lead


# ── (1) differential: _load_inputs equals _inputs(_load_rows(...)) ───────────
@pytest.mark.anyio
@pytest.mark.parametrize("n", [1, 3, 10])
@pytest.mark.parametrize("tied", [False, True])
async def test_load_inputs_equals_the_old_two_step_path(db_session, app_instance, n, tied):
    case, lead = await new_case(db_session, f"a2d{n}{int(tied)}")
    await seed_items(db_session, case, lead, make_specs(n, tied=tied))
    records, digests, keys, pairs = await assert_same(db_session, case.id)
    assert len(records) == len(digests) == len(keys) == len(pairs) == n
    assert all(isinstance(r, dict) for r in records) and all(d for d in digests)


@pytest.mark.anyio
async def test_order_is_timestamp_then_id_with_ties(db_session, app_instance):
    case, lead = await new_case(db_session, "a2ord")
    specs = [{"ts": 5, "hash": f"{i:02d}" + "b" * 62, "payload": {"i": i}} for i in range(6)] + \
            [{"ts": 1, "hash": "ee" + "b" * 62, "payload": {"i": "early"}}, {"ts": 9, "hash": "ff" + "b" * 62, "payload": {"i": "late"}}]
    await seed_items(db_session, case, lead, specs)
    records, _d, keys, _p = await assert_same(db_session, case.id)
    assert records[0] == {"i": "early"} and records[-1] == {"i": "late"}
    tied = keys[1:-1]
    assert len(tied) == 6 and tied == sorted(tied)                      # equal timestamps: ascending event id
    assert len(set(keys)) == 8


@pytest.mark.anyio
async def test_non_dict_payload_gives_record_none_and_the_real_digest(db_session, app_instance):
    case, lead = await new_case(db_session, "a2nd")
    specs = make_specs(4)
    specs[1]["payload"] = ["a", "list", "payload"]
    specs[2]["payload"] = "a string payload"
    await seed_items(db_session, case, lead, specs)
    records, digests, _k, pairs = await assert_same(db_session, case.id)
    assert records.count(None) == 2 and sum(isinstance(r, dict) for r in records) == 2
    for r, d in zip(records, digests):
        assert d is not None and len(d) == 64                           # the digest is kept for an unparseable payload
    assert all(h for _i, h in pairs)


@pytest.mark.anyio
async def test_missing_raw_record_gives_record_none_digest_none_and_the_empty_fingerprint_digest(db_session, app_instance):
    case, lead = await new_case(db_session, "a2miss")
    await seed_items(db_session, case, lead, make_specs(5))
    victim = (await db_session.execute(select(NormalizedEventModel).join(
        CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case.id))).scalars().first()
    vid, raw_id = victim.id, victim.raw_evidence_id
    # SQLite does not enforce the foreign key: remove the raw record so the event has none (outer join semantics).
    await db_session.execute(delete(RawEvidence).where(RawEvidence.id == raw_id))
    await db_session.commit()
    records, digests, keys, pairs = await assert_same(db_session, case.id)
    i = keys.index(vid)
    assert len(keys) == 5 and records[i] is None and digests[i] is None
    assert dict(pairs)[str(vid)] == ""
    assert sum(d is None for d in digests) == 1


@pytest.mark.anyio
async def test_empty_case(db_session, app_instance):
    case, _lead = await new_case(db_session, "a2empty")
    assert await assert_same(db_session, case.id) == ([], [], [], [])


@pytest.mark.anyio
async def test_only_the_cases_own_evidence_is_read(db_session, app_instance):
    case, lead = await new_case(db_session, "a2vis")
    other = await seed_case_with_lead(db_session, lead=lead)
    mine = await seed_items(db_session, case, lead, make_specs(4))
    theirs = await seed_items(db_session, other, lead, [{"ts": 0, "hash": f"{i:02d}" + "c" * 62, "payload": {"o": i}} for i in range(3)])
    shared = mine[0]
    db_session.add(CaseEvidenceModel(id=uuid.uuid4(), case_id=other.id, evidence_id=shared, linked_by_analyst_id=lead.id))
    await db_session.commit()
    svc = MultiSourceInvestigationService()
    _r, _d, keys_mine, _p = await assert_same(db_session, case.id)
    _r, _d, keys_other, _p = await assert_same(db_session, other.id)
    assert set(keys_mine) == set(mine) and set(keys_other) == set(theirs) | {shared}


@pytest.mark.anyio
async def test_python_dedup_by_event_id_keeps_the_first_occurrence():
    eid, other = uuid.uuid4(), uuid.uuid4()

    class _Rows:
        def __init__(self, rows): self._rows = rows
        def all(self): return self._rows

    class _FakeSession:
        def __init__(self, rows): self._rows = rows
        async def execute(self, _stmt): return _Rows(self._rows)

    fake = _FakeSession([(eid, {"first": 1}, "a" * 64), (eid, {"second": 2}, "b" * 64), (other, None, None)])
    records, digests, keys, pairs = await MultiSourceInvestigationService()._load_inputs(fake, uuid.uuid4())
    assert records == [{"first": 1}, None] and digests == ["a" * 64, None] and keys == [eid, other]
    assert pairs == [(str(eid), "a" * 64), (str(other), "")]


# ── (2) end to end through start ─────────────────────────────────────────────
class _Actor:
    username = "a2-actor"

    def __init__(self, analyst_id):
        self.analyst_id = analyst_id


def comparable(payload):
    drop = {"created_at", "investigation_audit_id", "id", "audit_id"}
    return {k: v for k, v in payload.items() if k not in drop}


async def reference_load_inputs(self, session, case_id):
    """The old two-step path: _load_rows + _inputs + the pairs exactly as ``fingerprint`` builds them."""
    rows = await self._load_rows(session, case_id)
    records, digests, keys = self._inputs(rows)
    pairs = [(str(ev.id), (ev.raw_evidence.sha256_hash if ev.raw_evidence else "") or "") for ev in rows]
    return records, digests, keys, pairs


@pytest.mark.anyio
async def test_start_payload_equals_the_payload_of_the_old_two_step_path(db_session, app_instance, monkeypatch):
    use_llm = False
    client, _token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="a2e2e")
    async with Keep(client):
        svc = MultiSourceInvestigationService()
        created, new_payload = await svc.start(session=db_session, case_id=case.id, actor=_Actor(lead.id), use_llm=use_llm, force=True, llm_provider=None)
        assert created is True and new_payload["incidents"]
        monkeypatch.setattr(MultiSourceInvestigationService, "_load_inputs", reference_load_inputs)
        created, old_payload = await svc.start(session=db_session, case_id=case.id, actor=_Actor(lead.id), use_llm=use_llm, force=True, llm_provider=None)
        assert created is True
        assert comparable(new_payload) == comparable(old_payload)
        db_session._sync.expire_all()
        assert new_payload["evidence_fingerprint"] == svc.fingerprint(await svc._load_rows(db_session, case.id), use_llm)


@pytest.mark.anyio
async def test_start_with_odd_stored_evidence_equals_the_old_path(db_session, app_instance, monkeypatch):
    """Non-dict payload and a missing raw record in the case: the stored result is the same as through the old path."""
    case, lead = await new_case(db_session, "a2odd")
    specs = make_specs(5, tied=True)
    specs[1]["payload"] = ["not", "a", "dict"]
    await seed_items(db_session, case, lead, specs)
    victim = (await db_session.execute(select(NormalizedEventModel).join(
        CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case.id))).scalars().first()
    await db_session.execute(delete(RawEvidence).where(RawEvidence.id == victim.raw_evidence_id))
    await db_session.commit()
    svc = MultiSourceInvestigationService()
    _c, new_payload = await svc.start(session=db_session, case_id=case.id, actor=_Actor(lead.id), use_llm=False, force=True, llm_provider=None)
    monkeypatch.setattr(MultiSourceInvestigationService, "_load_inputs", reference_load_inputs)
    _c, old_payload = await svc.start(session=db_session, case_id=case.id, actor=_Actor(lead.id), use_llm=False, force=True, llm_provider=None)
    assert comparable(new_payload) == comparable(old_payload)


@pytest.mark.anyio
async def test_evidence_changed_protection_still_raises(db_session, app_instance, monkeypatch):
    client, _t, lead, case = await setup(db_session, app_instance, intrusion_chain()[:5], prefix="a2raise")
    original = svc_mod.run_workflow

    async def racing(*a, **k):
        result = await original(*a, **k)
        await ingest(client, [EXTRA])
        await link_all_events(db_session, case, lead)
        return result

    monkeypatch.setattr(svc_mod, "run_workflow", racing)
    async with Keep(client):
        with pytest.raises(svc_mod.EvidenceChanged):
            await MultiSourceInvestigationService().start(session=db_session, case_id=case.id, actor=_Actor(lead.id), use_llm=False, force=False, llm_provider=None)


# ── (3) call counts ──────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_start_never_calls_load_rows_and_the_checks_use_the_light_pairs(db_session, app_instance, monkeypatch):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="a2count")
    counts = {"rows": 0, "inputs": 0, "light": 0}
    real = {n: getattr(MultiSourceInvestigationService, n) for n in ("_load_rows", "_load_inputs", "_load_fingerprint_pairs")}

    def counting(name, key):
        async def wrapper(self, session, case_id):
            counts[key] += 1
            return await real[name](self, session, case_id)
        return wrapper

    monkeypatch.setattr(MultiSourceInvestigationService, "_load_rows", counting("_load_rows", "rows"))
    monkeypatch.setattr(MultiSourceInvestigationService, "_load_inputs", counting("_load_inputs", "inputs"))
    monkeypatch.setattr(MultiSourceInvestigationService, "_load_fingerprint_pairs", counting("_load_fingerprint_pairs", "light"))

    def reset():
        counts.update(rows=0, inputs=0, light=0)

    async with Keep(client):
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).status_code == 201
        assert counts == {"rows": 0, "inputs": 1, "light": 1}           # one input load, one light re-check, no ORM load
        reset()
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).status_code == 200   # reused by fingerprint
        assert counts == {"rows": 0, "inputs": 1, "light": 0}
        reset()
        status = (await client.get(STATUS.format(cid=case.id), headers=bearer(token))).json()
        assert counts == {"rows": 0, "inputs": 0, "light": 1}           # get_section
        reset()
        r = await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": status["evidence_fingerprint"]}, headers=bearer(token))
        assert r.status_code == 200 and counts == {"rows": 0, "inputs": 0, "light": 1}                               # review
        reset()
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 200
        assert counts == {"rows": 0, "inputs": 0, "light": 1}           # export_report


# ── (4) the query selects three columns and creates no ORM entities ──────────
@pytest.mark.anyio
async def test_query_selects_three_columns_and_creates_no_orm_entities(db_session, app_instance, monkeypatch):
    case, lead = await new_case(db_session, "a2mat")
    await seed_items(db_session, case, lead, make_specs(10, tied=True))
    cid = case.id
    db_session._sync.expunge_all()
    assert not any(isinstance(o, (NormalizedEventModel, RawEvidence)) for o in db_session._sync.identity_map.values())

    statements = []
    real_execute = db_session.execute

    async def spy(stmt, *a, **k):
        statements.append(stmt)
        return await real_execute(stmt, *a, **k)

    monkeypatch.setattr(db_session, "execute", spy)
    records, digests, keys, pairs = await MultiSourceInvestigationService()._load_inputs(db_session, cid)
    assert len(records) == len(digests) == len(keys) == len(pairs) == 10
    assert len(statements) == 1                                          # one statement for everything
    assert [c.name for c in statements[0].selected_columns] == ["id", "raw_payload", "sha256_hash"]
    sql = " ".join(str(statements[0].compile()).upper().split())
    assert "LEFT OUTER JOIN RAW_EVIDENCE" in sql and "CASE_EVIDENCE" in sql
    assert "ORDER BY NORMALIZED_EVENTS.EVENT_TIMESTAMP ASC, NORMALIZED_EVENTS.ID ASC" in sql
    assert "NORMALIZED_PAYLOAD" not in sql
    assert not any(isinstance(o, (NormalizedEventModel, RawEvidence)) for o in db_session._sync.identity_map.values())
