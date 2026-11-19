"""
Stage 6 (ADR-011): application integration of source-agnostic evidence. Offline, SQLite-backed, no network.

Path under test: POST /api/v1/cases/{id}/evidence/domain (validate, quarantine, preserve raw, dedupe, link, audit)
-> POST /api/v1/cases/{id}/investigations/multisource -> sections graph / evidence / report.

SQLite passing does NOT validate PostgreSQL behaviour of the stored JSON documents (UNVERIFIED, not run here).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import func, select

from app.models.case import CaseAssignmentModel, CaseAuditEventModel, CaseEvidenceModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.evidence.hasher import compute_sha256
from app.modules.evidence_domains import scenarios as S
from app.services.domain_evidence_service import IMPORT_ACTION
from tests.unit.test_case_synthesis_api import (  # noqa: F401  (fixtures and seeding helpers)
    app_instance,
    auth_settings,
    seed_analyst_with_token,
    seed_case_with_lead,
)
from tests.unit.test_multisource_api import Keep, ScriptedProvider, START, bearer, setup

IMPORT = "/api/v1/cases/{cid}/evidence/domain"


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def count(db, model, *where) -> int:
    return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


@pytest.mark.anyio
async def test_import_preserves_raw_payload_hash_links_to_case_and_audits(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, [], prefix="imp")
    recs = S.scenario_a_identity_cloud()
    async with Keep(client):
        r = await client.post(IMPORT.format(cid=case.id), json={"records": recs}, headers=bearer(token))
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["accepted"] == len(recs) and body["quarantined"] == 0 and body["duplicates"] == 0
    raws = (await db_session.execute(select(RawEvidence))).scalars().all()
    assert len(raws) == len(recs)
    stored = {r.sha256_hash: r.raw_payload for r in raws}
    for rec in recs:
        assert stored[compute_sha256(rec)] == rec                                     # payload unchanged, digest is of the submitted record
    assert await count(db_session, CaseEvidenceModel, CaseEvidenceModel.case_id == case.id) == len(recs)
    audit = (await db_session.execute(select(CaseAuditEventModel).where(CaseAuditEventModel.action == IMPORT_ACTION))).scalars().all()
    assert len(audit) == 1 and audit[0].details["accepted"] == len(recs) and audit[0].actor_username == "imp"
    assert "payload" not in str(audit[0].details).lower() and "alice.example" not in str(audit[0].details)   # hashes and counts only
    ev = (await db_session.execute(select(NormalizedEventModel))).scalars().first()
    assert ev.normalized_payload["aisop_domain"] is True and ev.normalized_payload["time_status"] == "valid"


@pytest.mark.anyio
async def test_malformed_records_are_quarantined_and_not_stored(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="quar")
    recs = [r for r in S.malformed_records() if isinstance(r, dict)] + S.negative_unknown_type()
    async with Keep(client):
        r = await client.post(IMPORT.format(cid=case.id), json={"records": recs}, headers=bearer(token))
        body = r.json()
        assert r.status_code == 201 and body["quarantined"] == 4 and body["accepted"] == 1 and body["unclassified"] == 1
        assert {q["reason"] for q in body["quarantined_records"]} == {"SCHEMA_VERSION_UNSUPPORTED", "FIELD_MISSING:source", "FIELD_INVALID:ip", "FIELD_TOO_LONG:user"}
        assert "Traceback" not in r.text
    assert await count(db_session, RawEvidence) == 1                                   # only the unrecognised-but-valid record is kept


@pytest.mark.anyio
async def test_reimport_is_idempotent_and_does_not_duplicate_evidence(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="idem")
    recs = S.scenario_b_network_endpoint()
    async with Keep(client):
        await client.post(IMPORT.format(cid=case.id), json={"records": recs}, headers=bearer(token))
        again = (await client.post(IMPORT.format(cid=case.id), json={"records": recs + recs[:1]}, headers=bearer(token))).json()
    assert again["duplicates"] == len(recs) + 1 and await count(db_session, RawEvidence) == len(recs)
    assert await count(db_session, CaseEvidenceModel, CaseEvidenceModel.case_id == case.id) == len(recs)


@pytest.mark.anyio
async def test_authorization_and_validation(db_session, app_instance):
    client, lead_token, _lead, case = await setup(db_session, app_instance, [], prefix="aut")
    v_token, viewer = await seed_analyst_with_token(db_session, prefix="vw", username="vw", global_role="analyst_tier_1")
    db_session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case.id, analyst_id=viewer.id, case_role="viewer", assigned_at=datetime.now(timezone.utc)))
    o_token, _other = await seed_analyst_with_token(db_session, prefix="ot", username="ot", global_role="analyst_tier_2")
    await db_session.commit()
    body = {"records": S.negative_unknown_type()}
    async with Keep(client):
        assert (await client.post(IMPORT.format(cid=case.id), json=body)).status_code == 401
        assert (await client.post(IMPORT.format(cid=case.id), json=body, headers=bearer(v_token))).status_code == 403
        assert (await client.post(IMPORT.format(cid=case.id), json=body, headers=bearer(o_token))).status_code == 404       # unassigned: anti-enumeration
        assert (await client.post(IMPORT.format(cid=case.id), json={"records": []}, headers=bearer(lead_token))).status_code == 422
        assert (await client.post(IMPORT.format(cid=case.id), json={"records": [{}] * 501}, headers=bearer(lead_token))).status_code == 422
        assert (await client.post(IMPORT.format(cid=case.id), json={"records": "x"}, headers=bearer(lead_token))).status_code == 422
        assert (await client.post(IMPORT.format(cid=case.id), json={"records": [{}], "extra": 1}, headers=bearer(lead_token))).status_code == 422
        assert (await client.post(IMPORT.format(cid=uuid.uuid4()), json=body, headers=bearer(lead_token))).status_code == 404
    assert await count(db_session, RawEvidence) == 0


@pytest.mark.anyio
async def test_end_to_end_non_siem_investigation_through_the_api(db_session, app_instance):
    provider = ScriptedProvider()
    client, token, _lead, case = await setup(db_session, app_instance, [], provider=provider, prefix="e2e6")
    recs = S.scenario_c_email_forensic() + S.negative_bad_times()[:1] + S.negative_unknown_type()
    async with Keep(client):
        assert (await client.post(IMPORT.format(cid=case.id), json={"records": recs}, headers=bearer(token))).status_code == 201
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert r.status_code == 201, r.text
        body = r.json()
        assert provider.calls == 0 and body["workflow_version"] == "multi-source-v2" and body["counts"]["incidents"] == 1
        inc = body["incidents"][0]
        assert {m["technique_id"] for m in inc["mitre"]} == {"T1566.001", "T1566.002", "T1547.001", "T1055"}
        assert inc["analyst_statements"] and inc["analyst_statements"][0]["counts_for_corroboration"] is False
        assert body["observation_counts"]["undated"] == 1 and body["observation_counts"]["by_classification"]["unclassified"] == 1
        assert "alice" not in r.text and "payload" not in r.text.lower().replace("payload-free", "")

        graph = (await client.get(START.format(cid=case.id) + "/graph", headers=bearer(token))).json()
        g = graph["incidents"][0]["graph"]
        assert g["edges"] and all(e["rationale"] and e["supporting_observations"] for e in g["edges"])
        assert any(c["counts_as_corroboration"] for c in g["correlations"]) and graph["stale_evidence"] is False
        assert {u["kind"] for u in g["uncertainties"]} >= {"TOOL_ASSERTED_ONLY"}

        ev = (await client.get(START.format(cid=case.id) + "/evidence", headers=bearer(token))).json()
        by_type = {o["evidence_type"]: o for o in ev["observations"]}
        assert by_type["identity.signin"]["time_status"] == "missing" and by_type["identity.signin"]["on_timeline"] is False
        assert by_type["vendorx.widget_event"]["classification"] == "unclassified"
        assert by_type["analyst.observation"]["trust_class"] == "analyst_observation" and by_type["analyst.observation"]["counts_for_corroboration"] is False
        assert by_type["forensic.memory_finding"]["trust_class"] == "tool_asserted"
        assert all(o["raw_sha256"] and o["source_system"] and o["adapter"] for o in ev["observations"])

        report = (await client.get(START.format(cid=case.id) + "/report", headers=bearer(token))).json()
        assert "4d. Analyst statements" in report["incidents"][0]["report_markdown"]


@pytest.mark.anyio
async def test_undated_evidence_is_stored_without_an_invented_event_time(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="undated")
    async with Keep(client):
        await client.post(IMPORT.format(cid=case.id), json={"records": S.negative_bad_times()}, headers=bearer(token))
        body = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
    assert body["incidents"] == [] and body["batch_sufficiency"]["verdict"] == "insufficient"
    ev = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    assert all(e.normalized_payload["event_time"] is None and e.normalized_payload["event_timestamp_is_ingestion_time"] is True for e in ev)


@pytest.mark.anyio
async def test_repeat_is_reused_new_evidence_is_stale_and_force_appends(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="rep")
    recs = S.scenario_a_identity_cloud()
    async with Keep(client):
        await client.post(IMPORT.format(cid=case.id), json={"records": recs[:5]}, headers=bearer(token))
        first = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        again = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert first.status_code == 201 and again.status_code == 200 and again.json()["reused"] is True
        await client.post(IMPORT.format(cid=case.id), json={"records": recs[5:]}, headers=bearer(token))
        assert (await client.get(START.format(cid=case.id) + "/status", headers=bearer(token))).json()["stale_evidence"] is True
        rerun = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert rerun.status_code == 201 and rerun.json()["counts"]["records_normalized"] == len(recs)
    audits = (await db_session.execute(select(CaseAuditEventModel).where(CaseAuditEventModel.action == "case_multisource_investigation"))).scalars().all()
    assert len(audits) == 2


@pytest.mark.anyio
async def test_case_isolation_no_cross_case_leakage(db_session, app_instance):
    client, token, lead, case_a = await setup(db_session, app_instance, [], prefix="isoc")
    case_b = await seed_case_with_lead(db_session, lead=lead, title="Other case")
    other_token, _o = await seed_analyst_with_token(db_session, prefix="outsider", username="outsider", global_role="analyst_tier_2")
    async with Keep(client):
        await client.post(IMPORT.format(cid=case_a.id), json={"records": S.scenario_a_identity_cloud()}, headers=bearer(token))
        await client.post(IMPORT.format(cid=case_b.id), json={"records": S.negative_unrelated()[:1]}, headers=bearer(token))
        ra = (await client.post(START.format(cid=case_a.id), json={}, headers=bearer(token))).json()
        rb = (await client.post(START.format(cid=case_b.id), json={}, headers=bearer(token))).json()
        assert ra["counts"]["records_normalized"] == 8 and rb["counts"]["records_normalized"] == 1
        ids_a = {o["evidence_id"] for o in (await client.get(START.format(cid=case_a.id) + "/evidence", headers=bearer(token))).json()["observations"]}
        ids_b = {o["evidence_id"] for o in (await client.get(START.format(cid=case_b.id) + "/evidence", headers=bearer(token))).json()["observations"]}
        assert ids_a.isdisjoint(ids_b)
        assert (await client.get(START.format(cid=case_a.id) + "/graph", headers=bearer(other_token))).status_code == 404


@pytest.mark.anyio
async def test_identical_record_in_two_cases_is_one_raw_row_linked_separately(db_session, app_instance):
    client, token, lead, case_a = await setup(db_session, app_instance, [], prefix="shared")
    case_b = await seed_case_with_lead(db_session, lead=lead, title="Second")
    rec = S.negative_unknown_type()
    async with Keep(client):
        await client.post(IMPORT.format(cid=case_a.id), json={"records": rec}, headers=bearer(token))
        await client.post(IMPORT.format(cid=case_b.id), json={"records": rec}, headers=bearer(token))
    assert await count(db_session, RawEvidence) == 1
    assert await count(db_session, CaseEvidenceModel, CaseEvidenceModel.case_id == case_a.id) == 1
    assert await count(db_session, CaseEvidenceModel, CaseEvidenceModel.case_id == case_b.id) == 1


@pytest.mark.anyio
async def test_persistence_failure_stores_nothing_and_leaks_nothing(db_session, app_instance, monkeypatch):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="pfail")
    real_commit = db_session.commit

    async def failing_commit():
        raise RuntimeError("database detail that must not leak")

    monkeypatch.setattr(db_session, "commit", failing_commit)
    async with Keep(client):
        r = await client.post(IMPORT.format(cid=case.id), json={"records": S.scenario_b_network_endpoint()}, headers=bearer(token))
        assert r.status_code == 500 and "must not leak" not in r.text and "nothing was imported" in r.json()["detail"]
    monkeypatch.setattr(db_session, "commit", real_commit)
    assert await count(db_session, RawEvidence) == 0 and await count(db_session, CaseEvidenceModel) == 0
    assert await count(db_session, CaseAuditEventModel, CaseAuditEventModel.action == IMPORT_ACTION) == 0


@pytest.mark.anyio
async def test_closed_case_refuses_import(db_session, app_instance):
    from app.models.case import CaseStatus

    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="closed")
    case.status = CaseStatus.CLOSED.value
    await db_session.commit()
    async with Keep(client):
        r = await client.post(IMPORT.format(cid=case.id), json={"records": S.negative_unknown_type()}, headers=bearer(token))
    assert r.status_code == 409 and await count(db_session, RawEvidence) == 0


@pytest.mark.anyio
async def test_legacy_siem_ingestion_path_and_investigation_still_work_beside_domain_evidence(db_session, app_instance):
    from app.modules.correlation.demo_data import intrusion_chain
    from tests.unit.test_multisource_api import ingest, link_all_events

    client, token, lead, case = await setup(db_session, app_instance, [], prefix="mixed")
    async with Keep(client):
        await ingest(client, intrusion_chain())
        await link_all_events(db_session, case, lead)
        await client.post(IMPORT.format(cid=case.id), json={"records": S.scenario_a_identity_cloud()}, headers=bearer(token))
        body = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
    assert body["counts"]["records_normalized"] == 10 + len(S.scenario_a_identity_cloud())
    assert body["counts"]["incidents"] >= 2
