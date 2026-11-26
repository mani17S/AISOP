"""
Column-only evidence fingerprint (Proposal A, Investigation_Responsiveness_Profiling section 17.1).

The evidence-changed re-check in ``start``, the stale check in ``get_section``, and the checks in ``review`` and ``export_report`` need only
(event id, raw SHA-256) per linked evidence row. ``_load_fingerprint_pairs`` reads exactly that with one column-only SELECT and
``fingerprint_from_pairs`` is the single computation also used by ``fingerprint``, so the value must equal the old ORM-based one.

Offline, SQLite harness (the same fixtures as test_multisource_api). SQLite passing does not validate PostgreSQL behaviour or timing (UNVERIFIED).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

import app.services.multisource_investigation_service as svc_mod
from app.models.case import CaseEvidenceModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.correlation.demo_data import intrusion_chain
from app.services.multisource_investigation_service import MultiSourceInvestigationService
from tests.unit.test_case_synthesis_api import seed_case_with_lead
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

REVIEW = "/api/v1/cases/{cid}/investigations/multisource/review"
STATUS = "/api/v1/cases/{cid}/investigations/multisource/status"
EXPORT = "/api/v1/cases/{cid}/investigations/multisource/export"

EXTRA = {"source_type": "generic_siem", "rule_id": "R-EXTRA-FP", "rule_name": "extra record", "severity": "low",
         "timestamp": "2026-11-07T09:30:00Z", "host": "x", "user": "y"}


async def both(db_session, case_id, use_llm: bool) -> tuple[str, str]:
    """(old ORM-based fingerprint, light column-only fingerprint) for the same case, from a fresh read."""
    svc = MultiSourceInvestigationService()
    db_session._sync.expire_all()
    old = svc.fingerprint(await svc._load_rows(db_session, case_id), use_llm)
    light = svc.fingerprint_from_pairs(await svc._load_fingerprint_pairs(db_session, case_id), use_llm)
    return old, light


# ── (a) differential: the light path equals the old path ─────────────────────
@pytest.mark.anyio
@pytest.mark.parametrize("n", [1, 3, 10])
@pytest.mark.parametrize("use_llm", [False, True])
async def test_light_fingerprint_equals_the_orm_fingerprint(db_session, app_instance, n, use_llm):
    client, _t, _lead, case = await setup(db_session, app_instance, intrusion_chain()[:n], prefix=f"fpd{n}{int(use_llm)}")
    async with Keep(client):
        old, light = await both(db_session, case.id, use_llm)
        assert old == light and len(old) == 64


@pytest.mark.anyio
async def test_empty_case_fingerprints_match(db_session, app_instance):
    client, _t, _lead, case = await setup(db_session, app_instance, [], prefix="fpempty")
    async with Keep(client):
        for use_llm in (False, True):
            old, light = await both(db_session, case.id, use_llm)
            assert old == light


@pytest.mark.anyio
async def test_missing_raw_record_contributes_the_empty_digest_on_both_paths(db_session, app_instance):
    client, _t, _lead, case = await setup(db_session, app_instance, intrusion_chain()[:4], prefix="fpmiss")
    async with Keep(client):
        before = await both(db_session, case.id, False)
        ev = (await db_session.execute(select(NormalizedEventModel).join(
            CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case.id))).scalars().first()
        victim = ev.id
        # SQLite does not enforce the foreign key: remove the raw record so the event has none (LEFT OUTER JOIN semantics).
        db_session._sync.execute(delete(RawEvidence).where(RawEvidence.id == ev.raw_evidence_id))
        db_session._sync.commit()
        svc = MultiSourceInvestigationService()
        pairs = dict(await svc._load_fingerprint_pairs(db_session, case.id))
        assert len(pairs) == 4 and pairs[str(victim)] == ""            # the row is kept, with the empty digest
        for use_llm in (False, True):
            old, light = await both(db_session, case.id, use_llm)
            assert old == light
        assert (await both(db_session, case.id, False))[1] != before[1]


@pytest.mark.anyio
async def test_same_evidence_cannot_be_linked_twice_and_python_dedup_mirrors_unique(db_session, app_instance):
    client, _t, lead, case = await setup(db_session, app_instance, intrusion_chain()[:3], prefix="fpdup")
    async with Keep(client):
        link = (await db_session.execute(select(CaseEvidenceModel).where(CaseEvidenceModel.case_id == case.id))).scalars().first()
        db_session.add(CaseEvidenceModel(id=uuid.uuid4(), case_id=case.id, evidence_id=link.evidence_id, linked_by_analyst_id=lead.id))
        with pytest.raises(IntegrityError):                              # uq_case_evidence_case_evidence
            await db_session.commit()
        await db_session.rollback()

        # If a duplicate row ever came back, the result must still equal the old ``.unique()`` behaviour.
        class _Rows:
            def __init__(self, rows): self._rows = rows
            def all(self): return self._rows

        class _FakeSession:
            def __init__(self, rows): self._rows = rows
            async def execute(self, _stmt): return _Rows(self._rows)

        eid = uuid.uuid4()
        out = await MultiSourceInvestigationService()._load_fingerprint_pairs(_FakeSession([(eid, "a" * 64), (eid, "a" * 64), (uuid.uuid4(), None)]), uuid.uuid4())
        assert len(out) == 2 and out[0] == (str(eid), "a" * 64) and out[1][1] == ""


@pytest.mark.anyio
async def test_only_the_cases_own_evidence_is_read(db_session, app_instance):
    client, _t, lead, case = await setup(db_session, app_instance, intrusion_chain()[:6], prefix="fpvis")
    async with Keep(client):
        other = await seed_case_with_lead(db_session, lead=lead)
        some = (await db_session.execute(select(CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case.id))).scalars().all()[:2]
        for eid in some:                                                  # evidence may be linked to several cases
            db_session.add(CaseEvidenceModel(id=uuid.uuid4(), case_id=other.id, evidence_id=eid, linked_by_analyst_id=lead.id))
        await db_session.commit()
        svc = MultiSourceInvestigationService()
        assert len(await svc._load_fingerprint_pairs(db_session, case.id)) == 6
        assert {p[0] for p in await svc._load_fingerprint_pairs(db_session, other.id)} == {str(e) for e in some}
        for cid in (case.id, other.id):
            old, light = await both(db_session, cid, False)
            assert old == light
        assert (await both(db_session, case.id, False))[1] != (await both(db_session, other.id, False))[1]


# ── (b) sensitivity: the light path changes exactly when the old path does ───
@pytest.mark.anyio
async def test_adding_removing_and_rehashing_evidence_changes_both_fingerprints_alike(db_session, app_instance):
    client, _t, lead, case = await setup(db_session, app_instance, intrusion_chain()[:5], prefix="fpsens")
    async with Keep(client):
        base_old, base_light = await both(db_session, case.id, False)
        assert base_old == base_light

        await ingest(client, [EXTRA])
        await link_all_events(db_session, case, lead)
        added_old, added_light = await both(db_session, case.id, False)
        assert added_old == added_light and added_light != base_light

        link = (await db_session.execute(select(CaseEvidenceModel).where(CaseEvidenceModel.case_id == case.id))).scalars().first()
        await db_session.execute(delete(CaseEvidenceModel).where(CaseEvidenceModel.id == link.id))
        await db_session.commit()
        removed_old, removed_light = await both(db_session, case.id, False)
        assert removed_old == removed_light and removed_light not in (base_light, added_light)

        raw = (await db_session.execute(select(RawEvidence).join(
            NormalizedEventModel, NormalizedEventModel.raw_evidence_id == RawEvidence.id).join(
            CaseEvidenceModel, CaseEvidenceModel.evidence_id == NormalizedEventModel.id).where(CaseEvidenceModel.case_id == case.id))).scalars().first()
        await db_session.execute(update(RawEvidence).where(RawEvidence.id == raw.id).values(sha256_hash="f" * 64))
        await db_session.commit()
        rehashed_old, rehashed_light = await both(db_session, case.id, False)
        assert rehashed_old == rehashed_light and rehashed_light not in (base_light, added_light, removed_light)


def test_fingerprint_from_pairs_is_the_single_computation():
    svc = MultiSourceInvestigationService()

    class _Raw:
        def __init__(self, h): self.sha256_hash = h

    class _Ev:
        def __init__(self, i, raw): self.id, self.raw_evidence = i, raw

    a, b, c = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    rows = [_Ev(a, _Raw("1" * 64)), _Ev(b, None), _Ev(c, _Raw(None))]
    pairs = [(str(a), "1" * 64), (str(b), ""), (str(c), "")]
    for use_llm in (False, True):
        assert svc.fingerprint(rows, use_llm) == svc.fingerprint_from_pairs(pairs, use_llm) == svc.fingerprint_from_pairs(reversed(pairs), use_llm)
    assert svc.fingerprint_from_pairs(pairs, False) != svc.fingerprint_from_pairs(pairs[:-1], False)


# ── (c) behaviour is unchanged ───────────────────────────────────────────────
@pytest.mark.anyio
async def test_evidence_changed_protection_still_raises_and_stores_nothing(db_session, app_instance, monkeypatch):
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain()[:5], prefix="fpraise")
    original = svc_mod.run_workflow

    async def racing(*a, **k):
        result = await original(*a, **k)
        await ingest(client, intrusion_chain()[5:7])
        await link_all_events(db_session, case, lead)
        return result

    monkeypatch.setattr(svc_mod, "run_workflow", racing)
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert r.status_code == 409 and "changed" in r.json()["detail"]
        monkeypatch.setattr(svc_mod, "run_workflow", original)
        assert (await client.get(STATUS.format(cid=case.id), headers=bearer(token))).status_code == 404   # nothing was stored


@pytest.mark.anyio
async def test_evidence_changed_raises_the_service_exception(db_session, app_instance, monkeypatch):
    """Directly on the service: a changed light read after the analysis raises EvidenceChanged."""
    client, _t, lead, case = await setup(db_session, app_instance, intrusion_chain()[:5], prefix="fpexc")
    original = svc_mod.run_workflow

    async def racing(*a, **k):
        result = await original(*a, **k)
        await ingest(client, [EXTRA])
        await link_all_events(db_session, case, lead)
        return result

    monkeypatch.setattr(svc_mod, "run_workflow", racing)
    from app.core.rbac import AuthenticatedAnalyst  # noqa: F401
    async with Keep(client):
        class _Actor:
            username = "t"
            analyst_id = lead.id
        with pytest.raises(svc_mod.EvidenceChanged):
            await MultiSourceInvestigationService().start(session=db_session, case_id=case.id, actor=_Actor(), use_llm=False, force=False, llm_provider=None)


@pytest.mark.anyio
async def test_stale_flag_and_review_follow_the_light_fingerprint(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="fpbeh")
    async with Keep(client):
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).status_code == 201
        status = (await client.get(STATUS.format(cid=case.id), headers=bearer(token))).json()
        fp = status["evidence_fingerprint"]
        assert status["stale_evidence"] is False and status["review"]["state"] == "not_reviewed"

        wrong = "0" * 64
        r = await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": wrong}, headers=bearer(token))
        assert r.status_code == 409
        r = await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": fp}, headers=bearer(token))
        assert r.status_code == 200 and r.json()["state"] == "approved"
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 200

        await ingest(client, [EXTRA])
        await link_all_events(db_session, case, lead)
        after = (await client.get(STATUS.format(cid=case.id), headers=bearer(token))).json()
        assert after["stale_evidence"] is True and after["review"]["state"] == "stale"
        r = await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": fp}, headers=bearer(token))
        assert r.status_code == 409
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 409


# ── (d) the heavy load runs once per start and never for the checks ──────────
@pytest.mark.anyio
async def test_start_loads_inputs_once_and_the_checks_use_only_the_light_query(db_session, app_instance, monkeypatch):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="fpcount")
    counts = {"rows": 0, "inputs": 0, "light": 0}
    real_rows, real_inputs, real_light = (MultiSourceInvestigationService._load_rows, MultiSourceInvestigationService._load_inputs,
                                          MultiSourceInvestigationService._load_fingerprint_pairs)

    async def counting_rows(self, session, case_id):
        counts["rows"] += 1
        return await real_rows(self, session, case_id)

    async def counting_inputs(self, session, case_id):
        counts["inputs"] += 1
        return await real_inputs(self, session, case_id)

    async def counting_light(self, session, case_id):
        counts["light"] += 1
        return await real_light(self, session, case_id)

    monkeypatch.setattr(MultiSourceInvestigationService, "_load_rows", counting_rows)
    monkeypatch.setattr(MultiSourceInvestigationService, "_load_inputs", counting_inputs)
    monkeypatch.setattr(MultiSourceInvestigationService, "_load_fingerprint_pairs", counting_light)

    def reset():
        counts["rows"] = counts["inputs"] = counts["light"] = 0

    async with Keep(client):
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).status_code == 201
        assert counts == {"rows": 0, "inputs": 1, "light": 1}             # first load for the analysis, light re-check after it
        reset()
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).status_code == 200   # reused by fingerprint
        assert counts == {"rows": 0, "inputs": 1, "light": 0}
        reset()
        status = (await client.get(STATUS.format(cid=case.id), headers=bearer(token))).json()
        assert counts == {"rows": 0, "inputs": 0, "light": 1}
        reset()
        r = await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": status["evidence_fingerprint"]}, headers=bearer(token))
        assert r.status_code == 200 and counts == {"rows": 0, "inputs": 0, "light": 1}
        reset()
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 200
        assert counts == {"rows": 0, "inputs": 0, "light": 1}


# ── (e) no entities are materialised; only two columns are selected ──────────
@pytest.mark.anyio
async def test_light_query_selects_two_columns_and_creates_no_orm_entities(db_session, app_instance, monkeypatch):
    client, _t, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="fpmat")
    async with Keep(client):
        cid = case.id
        db_session._sync.expunge_all()
        assert not any(isinstance(o, (NormalizedEventModel, RawEvidence)) for o in db_session._sync.identity_map.values())

        statements = []
        real_execute = db_session.execute

        async def spy(stmt, *a, **k):
            statements.append(stmt)
            return await real_execute(stmt, *a, **k)

        monkeypatch.setattr(db_session, "execute", spy)
        pairs = await MultiSourceInvestigationService()._load_fingerprint_pairs(db_session, cid)
        assert len(pairs) == 10 and all(isinstance(p, tuple) and len(p) == 2 and all(isinstance(x, str) for x in p) for p in pairs)
        assert len(statements) == 1
        assert [c.name for c in statements[0].selected_columns] == ["id", "sha256_hash"]
        sql = str(statements[0].compile()).upper()
        assert "LEFT OUTER JOIN RAW_EVIDENCE" in sql and "CASE_EVIDENCE" in sql and "RAW_PAYLOAD" not in sql and "NORMALIZED_PAYLOAD" not in sql
        assert not any(isinstance(o, (NormalizedEventModel, RawEvidence)) for o in db_session._sync.identity_map.values())
