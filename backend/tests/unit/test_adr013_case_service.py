"""
ADR-013 Revision 2, owner decision D7: the shared detector and the single sufficiency gate also serve ``case_service`` (case synthesis).

Both production paths are exercised through the real HTTP endpoints over SQLite (nothing here validates PostgreSQL):
 * incident path: POST /cases/{id}/investigations/multisource
 * case path:     POST /cases/{id}/investigations/synthesize (stored raw payloads -> observations -> the SAME detector -> the SAME gate)
Parity is asserted on what both paths expose: the verdict and the reason codes (the case path stores them in its audit row).
The case context is built differently (no correlator, no anchor), so assessment HASHES are intentionally not compared.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.api.v1.endpoints.cases import get_case_llm_provider
from app.models.case import CaseAuditEventModel
from app.modules.ai.llm.exceptions import LLMConnectionError
from app.modules.evidence_domains import scenarios as S
from tests.unit.test_case_synthesis_api import (  # noqa: F401  (fixtures and helpers)
    MockCaseLLMProvider,
    app_instance,
    auth_settings,
    build_valid_llm_json,
    seed_analyst_with_token,
    seed_case_with_lead,
)
from tests.unit.test_domain_evidence_api import IMPORT
from tests.unit.test_multisource_api import START, Keep, bearer, setup

env = S.env
IP = S.ATTACKER_IP


@pytest.fixture
def anyio_backend():
    return "asyncio"


def ordering_violation():
    recs = [dict(r) for r in S.scenario_c_email_forensic()]
    for r in recs:
        if r["evidence_type"] == "forensic.file":
            r["event_time"] = "2026-11-05T07:00:00Z"
            r["data"] = dict(r["data"], origin_message_id="<inv-8841@invoice-portal.test>", timestamp_semantics="arrival")
    return recs


def outcome_conflict():
    return S.negative_contradiction()


def identity_conflict():
    return [env("identity.signin", "idp-a", {"user": "alice.example", "ip": IP, "session_id": "s-1", "result": "success",
                                              "canonical_id": "P-100", "canonical_id_issuer": "corp-dir"}, t="2026-11-07T09:00:00Z"),
            env("cloud.api_call", "cloud-a", {"actor": "bob.example", "action": "ListBuckets", "resource": "bucket/x", "source_ip": IP,
                                               "session_id": "s-1", "session_issuer": "idp-a", "canonical_id": "P-200", "canonical_id_issuer": "corp-dir"},
                t="2026-11-07T09:00:30Z")]


def temporal_conflict():
    corr = {"issuer": "gateway-1", "id": "req-77"}
    return [env("cloud.api_call", "ct-a", {"actor": "u4.example", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T09:00:00Z", correlation=corr),
            env("cloud.api_call", "ct-b", {"actor": "u4.example", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T13:00:00Z", correlation=corr)]


class FailingProvider:
    model_name = "llama3.1:8b"

    async def generate(self, request):
        raise LLMConnectionError("down")


async def case_path(client, app_instance, token, case_id, evidence_id, provider=None):
    app_instance.dependency_overrides[get_case_llm_provider] = lambda: (provider or MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=evidence_id)))
    return await client.post(f"/api/v1/cases/{case_id}/investigations/synthesize", json={}, headers=bearer(token))


async def synthesis_audit(db_session, case_id):
    rows = (await db_session.execute(select(CaseAuditEventModel).where(CaseAuditEventModel.case_id == case_id))).scalars().all()
    return [r.details for r in rows if isinstance(r.details, dict) and "sufficiency_reason_codes" in r.details]


@pytest.mark.anyio
@pytest.mark.parametrize("builder, qualified_code", [
    (ordering_violation, "CONTRADICTORY_EVIDENCE:ordering"),
    (outcome_conflict, "CONTRADICTORY_EVIDENCE:outcome"),
    (identity_conflict, "CONTRADICTORY_EVIDENCE:identity"),
    (temporal_conflict, "CONTRADICTORY_EVIDENCE:temporal"),
])
async def test_incident_and_case_paths_give_the_same_verdict_and_contradiction_reason_codes(db_session, app_instance, builder, qualified_code):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix=f"par-{qualified_code[-5:]}")
    async with Keep(client):
        imp = (await client.post(IMPORT.format(cid=case.id), json={"records": builder()}, headers=bearer(token))).json()
        inc = max((await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()["incidents"], key=lambda i: i["event_count"])
        resp = await case_path(client, app_instance, token, case.id, uuid.UUID(imp["evidence"][0]["evidence_id"]))
    assert resp.status_code == 200, resp.text
    audit = (await synthesis_audit(db_session, case.id))[-1]
    # incident path
    assert inc["sufficiency"]["verdict"] == "limited" and qualified_code in inc["sufficiency"]["reason_codes"]
    # case path: same detector, same gate
    assert audit["sufficiency_verdict"] == "limited" and qualified_code in audit["sufficiency_reason_codes"]
    assert audit["sufficiency_rule_version"] == "suff-v5"
    assert sorted(c for c in audit["sufficiency_reason_codes"] if c.startswith("CONTRADICTORY_EVIDENCE")) == \
        sorted(c for c in inc["sufficiency"]["reason_codes"] if c.startswith("CONTRADICTORY_EVIDENCE"))
    assert any(qualified_code in g for g in resp.json()["output"]["uncertainty_and_data_gaps"])      # disclosed in the analyst-facing output


@pytest.mark.anyio
async def test_both_paths_leave_a_non_contradictory_investigation_unchanged(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="par-clean")
    async with Keep(client):
        imp = (await client.post(IMPORT.format(cid=case.id), json={"records": S.scenario_a_identity_cloud()}, headers=bearer(token))).json()
        inc = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()["incidents"][0]
        resp = await case_path(client, app_instance, token, case.id, uuid.UUID(imp["evidence"][0]["evidence_id"]))
    assert resp.status_code == 200
    audit = (await synthesis_audit(db_session, case.id))[-1]
    assert inc["contradictions"] == [] and not any(c.startswith("CONTRADICTORY") for c in inc["sufficiency"]["reason_codes"])
    assert not any(c.startswith("CONTRADICTORY") for c in audit["sufficiency_reason_codes"])


@pytest.mark.anyio
async def test_a_pre_existing_file_without_a_causal_relationship_is_not_a_contradiction_on_either_path(db_session, app_instance):
    recs = [dict(r) for r in S.scenario_c_email_forensic()]
    for r in recs:
        if r["evidence_type"] == "forensic.file":
            r["event_time"] = "2026-11-05T07:00:00Z"                                        # earlier, shared hash, nothing states a causal link
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="par-pre")
    async with Keep(client):
        imp = (await client.post(IMPORT.format(cid=case.id), json={"records": recs}, headers=bearer(token))).json()
        inc = max((await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()["incidents"], key=lambda i: i["event_count"])
        await case_path(client, app_instance, token, case.id, uuid.UUID(imp["evidence"][0]["evidence_id"]))
    audit = (await synthesis_audit(db_session, case.id))[-1]
    assert not any(c.startswith("CONTRADICTORY") for c in inc["sufficiency"]["reason_codes"] + audit["sufficiency_reason_codes"])


@pytest.mark.anyio
async def test_case_isolation_a_contradiction_in_one_case_does_not_appear_in_another(db_session, app_instance):
    client, token, lead, case_a = await setup(db_session, app_instance, [], prefix="iso-a")
    case_b = await seed_case_with_lead(db_session, lead=lead, title="Case B")
    recs = ordering_violation()
    only_mail = [r for r in recs if r["evidence_type"] != "forensic.file"]                   # case B never receives the artefact
    async with Keep(client):
        a = (await client.post(IMPORT.format(cid=case_a.id), json={"records": recs}, headers=bearer(token))).json()
        b = (await client.post(IMPORT.format(cid=case_b.id), json={"records": only_mail}, headers=bearer(token))).json()
        await case_path(client, app_instance, token, case_a.id, uuid.UUID(a["evidence"][0]["evidence_id"]))
        await case_path(client, app_instance, token, case_b.id, uuid.UUID(b["evidence"][0]["evidence_id"]))
    assert any(c.startswith("CONTRADICTORY_EVIDENCE:ordering") for c in (await synthesis_audit(db_session, case_a.id))[-1]["sufficiency_reason_codes"])
    assert not any(c.startswith("CONTRADICTORY") for c in (await synthesis_audit(db_session, case_b.id))[-1]["sufficiency_reason_codes"])


@pytest.mark.anyio
async def test_case_path_authorization_is_unchanged_an_unassigned_analyst_still_gets_404(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="auth-case")
    out_token, _o = await seed_analyst_with_token(db_session, prefix="auth-out", username="auth-out", global_role="analyst_tier_2")
    async with Keep(client):
        await client.post(IMPORT.format(cid=case.id), json={"records": ordering_violation()}, headers=bearer(token))
        app_instance.dependency_overrides[get_case_llm_provider] = lambda: MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=uuid.uuid4()))
        r = await client.post(f"/api/v1/cases/{case.id}/investigations/synthesize", json={}, headers=bearer(out_token))
    assert r.status_code == 404


@pytest.mark.anyio
async def test_case_path_is_deterministic_and_the_llm_cannot_change_the_findings(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="det-case")
    async with Keep(client):
        imp = (await client.post(IMPORT.format(cid=case.id), json={"records": ordering_violation()}, headers=bearer(token))).json()
        eid = uuid.UUID(imp["evidence"][0]["evidence_id"])
        r1 = await case_path(client, app_instance, token, case.id, eid)
        r2 = await case_path(client, app_instance, token, case.id, eid)
        r3 = await case_path(client, app_instance, token, case.id, eid, provider=FailingProvider())      # LLM failure: deterministic fallback
    assert r1.status_code == r2.status_code == r3.status_code == 200
    audits = await synthesis_audit(db_session, case.id)
    assert len(audits) == 3
    # The assessment HASH binds the context hash, and the case path draws a fresh investigation id per call (pre-existing), so hashes differ
    # between calls. The deterministic content must not: verdict, reason codes and the evidence units considered.
    assert len({(a["sufficiency_verdict"], tuple(a["sufficiency_reason_codes"]), tuple(sorted(a["sufficiency_evidence_ids"]))) for a in audits}) == 1
    assert all(a["sufficiency_verdict"] == "limited" and "CONTRADICTORY_EVIDENCE:ordering" in a["sufficiency_reason_codes"] for a in audits)
    assert r3.json()["output"]["model_identifier"] == "deterministic_fallback"


@pytest.mark.anyio
async def test_legacy_siem_only_case_synthesis_is_unaffected(db_session, app_instance):
    """Cases with no source-agnostic evidence produce no candidates: the shared detector skips non-envelope payloads."""
    from app.modules.evidence_domains.contradictions import detect_contradictions, observations_from_stored
    from app.modules.correlation.demo_data import intrusion_chain

    rows = [(uuid.uuid4(), rec, "a" * 64) for rec in intrusion_chain()]
    assert observations_from_stored(rows) == [] and detect_contradictions(observations_from_stored(rows)) == ()
    assert observations_from_stored([(uuid.uuid4(), {"schema": "aisop.evidence/1", "evidence_type": "Bad Type!"}, "b" * 64), (uuid.uuid4(), "text", "c" * 64),
                                     (uuid.uuid4(), ordering_violation()[0], "short")]) == []   # malformed, non-object and bad digests are skipped, never guessed
