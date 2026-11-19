"""
Stage 4 (ADR-010): application integration tests for the case-scoped multi-source investigation API.

Offline, SQLite-backed, no network. Evidence enters through the REAL ingestion endpoint
(POST /api/v1/alerts/ingest) and is linked to cases through the case tables, so the tests exercise the
whole path: ingestion -> preserved raw evidence -> case link -> investigation -> persisted audit record ->
retrieval. The optional LLM path uses a scripted, call-counting provider (real-model behaviour is UNVERIFIED).

SQLite passing does NOT validate PostgreSQL behaviour of the stored JSON document (UNVERIFIED).
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from app.api.v1.endpoints.cases import get_case_llm_provider
from app.models.case import CaseAssignmentModel, CaseAuditEventModel, CaseEvidenceModel, CaseModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.ai.llm.exceptions import LLMConnectionError
from app.modules.correlation.demo_data import SCENARIOS, intrusion_chain
from app.schemas.ai import LLMResponse, TokenUsage
from app.services.multisource_investigation_service import MULTISOURCE_ACTION, MultiSourceInvestigationService
from tests.unit.test_case_synthesis_api import (  # noqa: F401  (fixtures and seeding helpers)
    app_instance,
    auth_settings,
    seed_analyst_with_token,
    seed_case_with_lead,
)

MACHINE = {"Authorization": "Bearer legacy-machine-key-999"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class ScriptedProvider:
    """Deterministic call-counting provider: one observed-fact claim copied from the first cited event."""

    model_name = "llama3.1:8b"

    def __init__(self, raise_exc: Exception | None = None) -> None:
        self.calls = 0
        self.prompts: list[str] = []
        self.raise_exc = raise_exc

    async def generate(self, request):
        self.calls += 1
        prompt = request.messages[1].content
        self.prompts.append(prompt)
        if self.raise_exc:
            raise self.raise_exc
        inv = re.search(r'<investigation_context id="([a-f0-9\-]+)"', prompt).group(1)
        ev = re.search(r'<event uuid="([a-f0-9\-]+)".*?<summary>(.*?)</summary>', prompt, re.S)
        payload = {
            "investigation_id": inv, "generated_at": datetime.now(timezone.utc).isoformat(), "model_identifier": "scripted",
            "investigation_summary": "Scripted summary of the incident based on the supplied evidence.",
            "claims": [{"claim_id": str(uuid.uuid4()), "claim_text": ev.group(2), "category": "observed_fact",
                        "supporting_evidence_ids": [ev.group(1)], "references_exist": True,
                        "grounding_status": "validated_reference", "confidence": 0.9}],
            "mitre_attack_hypotheses": [], "alternative_explanations": ["Authorized administrative activity"],
            "recommended_analyst_actions": ["Review the cited events"], "uncertainty_and_data_gaps": [],
            "overall_grounding_score": 1.0,
        }
        return LLMResponse(content=json.dumps(payload), model=self.model_name, usage=TokenUsage())


async def ingest(client: httpx.AsyncClient, records: list[Any]) -> dict[str, Any]:
    """Ingest through the real endpoint; 'auto' lets the adapter registry detect each record's source."""
    r = await client.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "demo-forwarder",
                                                         "alerts": records}, headers=MACHINE)
    assert r.status_code == 200, r.text
    return r.json()


async def link_all_events(db_session, case: CaseModel, analyst, only_new: bool = True) -> int:
    linked = set((await db_session.execute(select(CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case.id))).scalars().all())
    others = set((await db_session.execute(select(CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id != case.id))).scalars().all())
    events = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    n = 0
    for ev in events:
        if ev.id in linked or ev.id in others:
            continue
        db_session.add(CaseEvidenceModel(id=uuid.uuid4(), case_id=case.id, evidence_id=ev.id, linked_by_analyst_id=analyst.id))
        n += 1
    await db_session.commit()
    return n


async def audit_rows(db_session, case_id) -> list[CaseAuditEventModel]:
    rows = (await db_session.execute(select(CaseAuditEventModel).where(
        CaseAuditEventModel.case_id == case_id, CaseAuditEventModel.action == MULTISOURCE_ACTION))).scalars().all()
    return list(rows)


async def setup(db_session, app_instance, records, *, provider=None, role="analyst_tier_2", prefix="ms"):
    token, lead = await seed_analyst_with_token(db_session, prefix=prefix, username=prefix, global_role=role)
    case = await seed_case_with_lead(db_session, lead=lead)
    if provider is not None:
        app_instance.dependency_overrides[get_case_llm_provider] = lambda: provider
    transport = httpx.ASGITransport(app=app_instance)
    client = httpx.AsyncClient(transport=transport, base_url="http://test")
    if records:
        await ingest(client, records)
        await link_all_events(db_session, case, lead)
    return client, token, lead, case


class Keep:
    """Async context manager that closes an already-used httpx client on exit (it cannot be re-opened)."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    async def __aenter__(self) -> httpx.AsyncClient:
        return self.client

    async def __aexit__(self, *exc: object) -> None:
        await self.client.aclose()


START = "/api/v1/cases/{cid}/investigations/multisource"


# ── authentication, authorization, validation ────────────────────────────────
@pytest.mark.anyio
async def test_unauthenticated_requests_are_rejected(app_instance: FastAPI):
    cid = uuid.uuid4()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_instance), base_url="http://test") as c:
        assert (await c.post(START.format(cid=cid), json={})).status_code == 401
        assert (await c.get(START.format(cid=cid) + "/status")).status_code == 401


@pytest.mark.anyio
async def test_unassigned_analyst_gets_anti_enumeration_404(db_session, app_instance):
    client, _t, _lead, case = await setup(db_session, app_instance, [], prefix="owner")
    other_token, _other = await seed_analyst_with_token(db_session, prefix="other", username="other", global_role="analyst_tier_2")
    async with Keep(client):
        r1 = await client.post(START.format(cid=case.id), json={}, headers=bearer(other_token))
        r2 = await client.get(START.format(cid=case.id) + "/status", headers=bearer(other_token))
        assert r1.status_code == 404 and r2.status_code == 404


@pytest.mark.anyio
async def test_viewer_can_read_but_cannot_start(db_session, app_instance):
    client, lead_token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="lead")
    v_token, viewer = await seed_analyst_with_token(db_session, prefix="viewer", username="viewer", global_role="analyst_tier_1")
    db_session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case.id, analyst_id=viewer.id, case_role="viewer",
                                       assigned_at=datetime.now(timezone.utc)))
    await db_session.commit()
    async with Keep(client):
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(v_token))).status_code == 403
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(lead_token))).status_code == 201
        assert (await client.get(START.format(cid=case.id) + "/status", headers=bearer(v_token))).status_code == 200


@pytest.mark.anyio
async def test_invalid_inputs_are_rejected_with_422(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="val")
    async with Keep(client):
        assert (await client.post("/api/v1/cases/not-a-uuid/investigations/multisource", json={}, headers=bearer(token))).status_code == 422
        assert (await client.post(START.format(cid=case.id), json={"use_llm": "maybe"}, headers=bearer(token))).status_code == 422
        assert (await client.post(START.format(cid=case.id), json={"surprise": 1}, headers=bearer(token))).status_code == 422
        assert (await client.get(START.format(cid=case.id) + "/nonsense", headers=bearer(token))).status_code == 422


@pytest.mark.anyio
async def test_reading_before_any_run_is_a_safe_404(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="norun")
    async with Keep(client):
        r = await client.get(START.format(cid=case.id) + "/report", headers=bearer(token))
        assert r.status_code == 404 and "No multi-source investigation" in r.json()["detail"]


# ── end to end, deterministic (no LLM) ───────────────────────────────────────
@pytest.mark.anyio
async def test_end_to_end_without_llm_ingestion_to_persisted_report(db_session, app_instance):
    provider = ScriptedProvider()
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix="e2e")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] == "completed" and body["use_llm"] is False and body["counts"]["incidents"] == 1
        assert provider.calls == 0                                              # deterministic workflow needs no model
        raw = r.text
        assert "SQBFAFgA" not in raw and "-Enc" not in raw                      # no command lines / raw payloads in the result

        status_ = (await client.get(START.format(cid=case.id) + "/status", headers=bearer(token))).json()
        assert status_["incidents"][0]["verdict"] == "sufficient" and status_["ledger"]["verified"] is True
        assert status_["stale_evidence"] is False and len(status_["sources"]) == 4

        tl = (await client.get(START.format(cid=case.id) + "/timeline", headers=bearer(token))).json()["incidents"][0]["timeline"]
        assert len(tl) == 10 and [t["timestamp"] for t in tl] == sorted(t["timestamp"] for t in tl)
        stored = {str(e.id): e for e in (await db_session.execute(select(NormalizedEventModel))).scalars().all()}
        raws = {r_.id: r_ for r_ in (await db_session.execute(select(RawEvidence))).scalars().all()}
        for t in tl:                                                            # provenance: every row maps to stored evidence
            ev = stored[t["event_id"]]
            assert raws[ev.raw_evidence_id].sha256_hash.startswith(t["raw_sha256_prefix"])

        corr = (await client.get(START.format(cid=case.id) + "/correlation", headers=bearer(token))).json()
        assert corr["incidents"][0]["link_counts"]["strong"] >= 2 and corr["incidents"][0]["links"]
        assert {s["source_type"] for s in corr["sources"]} == {"generic_siem", "windows_security", "sysmon", "firewall_ids"}

        atk = (await client.get(START.format(cid=case.id) + "/attack", headers=bearer(token))).json()["incidents"][0]["mitre"]
        assert sorted(m["technique_id"] for m in atk) == ["T1027", "T1059.001", "T1071", "T1078", "T1110", "T1564.003"]
        assert all(m["rule_id"].startswith("MAP-") and m["limitation"] for m in atk)

        suff = (await client.get(START.format(cid=case.id) + "/sufficiency", headers=bearer(token))).json()["incidents"][0]["sufficiency"]
        assert suff["verdict"] == "sufficient" and suff["counts"]["corroborating"] >= 1

        rep = (await client.get(START.format(cid=case.id) + "/report", headers=bearer(token))).json()["incidents"][0]
        assert "**Verdict: SUFFICIENT**" in rep["report_markdown"] and rep["llm_status"] == "not_requested" and rep["llm"] is None

        rows = await audit_rows(db_session, case.id)                            # audit record in the existing audit table
        assert len(rows) == 1 and rows[0].actor_username == lead.username and rows[0].details["evidence_fingerprint"]
        activity = (await client.get(f"/api/v1/cases/{case.id}/activity", headers=bearer(token))).json()
        assert MULTISOURCE_ACTION in {a["action"] for a in activity}


@pytest.mark.anyio
async def test_repeated_request_is_idempotent_and_force_appends(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="idem")
    async with Keep(client):
        first = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        second = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert first.status_code == 201 and second.status_code == 200 and second.json()["reused"] is True
        assert second.json()["ledger"]["head"] == first.json()["ledger"]["head"]
        assert len(await audit_rows(db_session, case.id)) == 1
        forced = await client.post(START.format(cid=case.id), json={"force": True}, headers=bearer(token))
        assert forced.status_code == 201 and len(await audit_rows(db_session, case.id)) == 2


@pytest.mark.anyio
async def test_new_evidence_marks_the_stored_result_stale_and_a_rerun_is_new(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain()[:6], prefix="stale")
    async with Keep(client):
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).status_code == 201
        await ingest(client, intrusion_chain()[6:])
        await link_all_events(db_session, case, lead)
        assert (await client.get(START.format(cid=case.id) + "/status", headers=bearer(token))).json()["stale_evidence"] is True
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).status_code == 201


@pytest.mark.anyio
async def test_case_isolation_only_linked_evidence_is_investigated(db_session, app_instance):
    client, token, lead, case_a = await setup(db_session, app_instance, intrusion_chain(), prefix="isoa")
    case_b = await seed_case_with_lead(db_session, lead=lead, title="Other case")
    async with Keep(client):
        # evidence ingested after case A was linked belongs to nobody until linked to case B
        await ingest(client, SCENARIOS["06_uncorroborated_single_alert"]["build"]())
        await link_all_events(db_session, case_b, lead)
        ra = (await client.post(START.format(cid=case_a.id), json={}, headers=bearer(token))).json()
        rb = (await client.post(START.format(cid=case_b.id), json={}, headers=bearer(token))).json()
        assert ra["counts"]["records_normalized"] == 10 and rb["counts"]["records_normalized"] == 1
        ids_a = {t["event_id"] for t in ra["incidents"][0]["timeline"]}
        ids_b = {t["event_id"] for t in rb["incidents"][0]["timeline"]}
        assert ids_a.isdisjoint(ids_b)


# ── negative and edge scenarios through the application ──────────────────────
@pytest.mark.anyio
async def test_no_evidence_stores_an_abstention_and_never_calls_the_model(db_session, app_instance):
    provider = ScriptedProvider()
    client, token, _lead, case = await setup(db_session, app_instance, [], provider=provider, prefix="empty")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
        assert r.status_code == 201
        body = r.json()
        assert body["batch_sufficiency"]["verdict"] == "insufficient" and body["batch_sufficiency"]["reason_codes"] == ["NO_EVIDENCE"]
        assert provider.calls == 0 and "Analyst abstention" in body["batch_report_markdown"] and body["incidents"] == []


@pytest.mark.anyio
async def test_unparseable_stored_evidence_is_rejected_with_codes_and_abstains(db_session, app_instance):
    token, lead = await seed_analyst_with_token(db_session, prefix="bad", username="bad", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)
    raw = RawEvidence(id=uuid.uuid4(), source_type="unknown", source_identifier="x", sha256_hash="d" * 64,
                      raw_payload={"foo": "bar"}, ingested_at=datetime.now(timezone.utc))
    db_session.add(raw)
    await db_session.flush()
    ev = NormalizedEventModel(id=uuid.uuid4(), raw_evidence_id=raw.id, event_id="x", event_type="x", event_timestamp=datetime.now(timezone.utc),
                              provider="x", action="x", outcome="unknown", severity="low", normalized_payload={})
    db_session.add(ev)
    db_session.add(CaseEvidenceModel(id=uuid.uuid4(), case_id=case.id, evidence_id=ev.id, linked_by_analyst_id=lead.id))
    await db_session.commit()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_instance), base_url="http://test") as client:
        body = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
        assert body["rejected"][0]["reason"] == "NO_ADAPTER" and body["batch_sufficiency"]["verdict"] == "insufficient"


@pytest.mark.anyio
async def test_duplicates_are_deduplicated_at_ingestion_and_near_duplicates_collapse_in_the_engine(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, SCENARIOS["02_duplicates_near_duplicates"]["build"](), prefix="dup")
    async with Keep(client):
        body = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
        # 14 submitted: 3 exact duplicates were skipped by ingestion (existing dedup), the near-duplicate collapses here
        assert body["counts"]["records_normalized"] == 11 and body["counts"]["duplicates_collapsed"] == 1
        assert body["incidents"][0]["sufficiency"]["verdict"] == "sufficient"


@pytest.mark.anyio
async def test_contradictory_evidence_is_limited_with_a_reason(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, SCENARIOS["03_contradictory_evidence"]["build"](), prefix="con")
    async with Keep(client):
        body = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
        suff = body["incidents"][0]["sufficiency"]
        assert suff["verdict"] == "limited" and "CONTRADICTORY_EVIDENCE" in suff["reason_codes"]
        assert any(r["code"] == "CONTRADICTORY_EVIDENCE" and r["meaning"] for r in suff["reasons"]) and body["counts"]["contradictions"] == 1


@pytest.mark.anyio
async def test_unrelated_noise_and_weak_context_are_kept_apart(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, SCENARIOS["04_unrelated_and_weak_context"]["build"](), prefix="noise")
    async with Keep(client):
        body = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
        main = body["incidents"][0]
        assert main["event_count"] == 11 and sum(1 for t in main["timeline"] if t["membership"] == "weak_context") == 1
        assert len(body["incidents"]) == 4


@pytest.mark.anyio
async def test_single_uncorroborated_alert_is_limited_and_host_user_links_do_not_corroborate(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, SCENARIOS["06_uncorroborated_single_alert"]["build"](), prefix="single")
    async with Keep(client):
        body = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
        s = body["incidents"][0]["sufficiency"]
        assert s["verdict"] == "limited" and "UNCORROBORATED_QUESTION" in s["reason_codes"]
        assert body["incidents"][0]["mitre"] == [] and body["incidents"][0]["asserted_only"] == ["T1071"]


@pytest.mark.anyio
async def test_closed_case_conflicts(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="closed")
    row = (await db_session.execute(select(CaseModel).where(CaseModel.id == case.id))).scalars().first()
    row.status = "closed"
    await db_session.commit()
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert r.status_code == 409 and len(await audit_rows(db_session, case.id)) == 0


@pytest.mark.anyio
async def test_evidence_changing_during_the_run_discards_the_result(db_session, app_instance, monkeypatch):
    import app.services.multisource_investigation_service as svc

    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain()[:5], prefix="race")
    original = svc.run_workflow

    async def racing(*a, **k):
        result = await original(*a, **k)
        await ingest(client, intrusion_chain()[5:7])
        await link_all_events(db_session, case, lead)                       # evidence added while the engine ran
        return result

    monkeypatch.setattr(svc, "run_workflow", racing)
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert r.status_code == 409 and "changed" in r.json()["detail"] and len(await audit_rows(db_session, case.id)) == 0


@pytest.mark.anyio
async def test_audit_write_failure_suppresses_the_result_with_a_generic_error(db_session, app_instance, monkeypatch):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="auditfail")
    real_commit = db_session.commit

    async def failing_commit():
        if any(isinstance(o, CaseAuditEventModel) for o in db_session._sync.new):
            raise RuntimeError("database detail that must not leak")
        await real_commit()

    monkeypatch.setattr(db_session, "commit", failing_commit)
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert r.status_code == 500 and "must not leak" not in r.text and "Audit logging failed" in r.json()["detail"]
    monkeypatch.setattr(db_session, "commit", real_commit)
    assert len(await audit_rows(db_session, case.id)) == 0


# ── optional LLM path: gated and verified ────────────────────────────────────
@pytest.mark.anyio
async def test_llm_path_is_gated_claims_are_verified_and_limited_is_disclosed(db_session, app_instance):
    provider = ScriptedProvider()
    client, token, _lead, case = await setup(db_session, app_instance, SCENARIOS["06_uncorroborated_single_alert"]["build"](), provider=provider, prefix="llm")
    async with Keep(client):
        body = (await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))).json()
        inc = body["incidents"][0]
        assert provider.calls == 1 and inc["llm_status"] == "validated" and "[EVIDENCE LIMITATION - system generated]" in provider.prompts[0]
        assert inc["llm"]["claims"][0]["grounding"] == "validated_reference" and inc["llm"]["claims"][0]["category"] == "observed_fact"
        assert any(g.startswith("EVIDENCE_SUFFICIENCY[suff-v4]=LIMITED") for g in inc["llm"]["uncertainty_and_data_gaps"])
        assert "EVIDENCE_SUFFICIENCY[suff-v4]=LIMITED" in inc["report_markdown"]


@pytest.mark.anyio
async def test_llm_failure_falls_back_without_breaking_the_deterministic_result(db_session, app_instance):
    provider = ScriptedProvider(raise_exc=LLMConnectionError("down"))
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix="llmfail")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
        inc = r.json()["incidents"][0]
        assert r.status_code == 201 and inc["llm_status"] == "fallback:LLMConnectionError"
        assert len(inc["timeline"]) == 10 and len(inc["mitre"]) == 6 and inc["sufficiency"]["verdict"] == "sufficient"


@pytest.mark.anyio
async def test_gate_failure_fails_closed_through_the_api(db_session, app_instance, monkeypatch):
    import app.modules.ai.guardrails.sufficiency_gate as gate

    monkeypatch.setattr(gate, "assess_evidence_sufficiency", lambda _c: (_ for _ in ()).throw(RuntimeError("secret detail")))
    provider = ScriptedProvider()
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix="gatefail")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
        inc = r.json()["incidents"][0]
        assert provider.calls == 0 and inc["llm_status"] == "abstained" and inc["sufficiency"]["reason_codes"] == ["GATE_EVALUATION_ERROR"]
        assert "secret detail" not in r.text


@pytest.mark.anyio
async def test_use_llm_without_a_synthesis_role_is_forbidden_but_deterministic_is_allowed(db_session, app_instance):
    provider = ScriptedProvider()
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix="role", role="ingest")
    async with Keep(client):
        assert (await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))).status_code == 403
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).status_code == 201
    assert provider.calls == 0


@pytest.mark.anyio
async def test_service_fingerprint_depends_on_evidence_and_options(db_session, app_instance):
    client, _t, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="fp")
    svc = MultiSourceInvestigationService()
    rows = await svc._load_rows(db_session, case.id)
    assert svc.fingerprint(rows, False) == svc.fingerprint(list(reversed(rows)), False)
    assert svc.fingerprint(rows, False) != svc.fingerprint(rows, True) != svc.fingerprint(rows[:-1], True)
    await client.aclose()
