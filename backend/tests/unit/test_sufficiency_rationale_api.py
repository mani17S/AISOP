"""
Implementation Sprint 1: the suff-v4 rationale through the real multi-source API, audit document and authorisation.

Offline, in-memory SQLite (the project's isolated unit-test engine), no network, scripted provider only. SQLite passing does NOT validate
PostgreSQL behaviour of the stored document (UNVERIFIED).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import select

from app.models.case import CaseAssignmentModel, CaseEvidenceModel
from app.models.evidence import ExtractedEntityModel
from app.modules.ai.llm.exceptions import LLMConnectionError
from app.modules.correlation.demo_data import SCENARIOS, intrusion_chain
from app.schemas.multisource import MultiSourceSection
from app.services.multisource_investigation_service import MultiSourceInvestigationService
from tests.unit.test_case_synthesis_api import (  # noqa: F401  (fixtures and seeding helpers)
    app_instance,
    auth_settings,
    seed_analyst_with_token,
    seed_case_with_lead,
)
from tests.unit.test_multisource_api import (  # noqa: F401
    START,
    Keep,
    ScriptedProvider,
    anyio_backend,
    audit_rows,
    bearer,
    ingest,
    link_all_events,
    setup,
)

EXISTING_SUFFICIENCY_KEYS = {"verdict", "rule_version", "reason_codes", "reasons", "assessment_sha256", "abstain", "counts", "evidence_ids"}


def all_ids(rationale: dict) -> set[str]:
    ids = {rationale["anchor"]["event_id"]} - {None}
    for u in rationale["units"]:
        ids.add(u["unit"]); ids.update(u["members"])
    for c in rationale["collapsed"]:
        ids.update((c["into"], c["duplicate"]))
    for p in rationale["corroboration"]:
        ids.update((p["unit_a"], p["unit_b"]))
    for e in rationale["exclusions"]:
        ids.add(e["unit"])
    for f in rationale["findings"]:
        ids.update(f["evidence_ids"])
    for c in rationale["contradictions"]:
        ids.update(c["evidence_ids"])
    return ids


@pytest.mark.anyio
async def test_the_rationale_is_additive_and_identical_in_the_response_the_sections_and_the_audit_row(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="rat1")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert r.status_code == 201, r.text
        suff = r.json()["incidents"][0]["sufficiency"]
        assert EXISTING_SUFFICIENCY_KEYS <= set(suff)                                   # every pre-existing field is still there
        rat = suff["rationale"]
        assert rat["schema"] == "suff-rationale-v1" and rat["rule_version"] == "suff-v4" and rat["completeness"] == "complete"
        assert suff["verdict"] == "sufficient" and rat["status"]["verdict"] == suff["verdict"]
        assert rat["status"]["model_call_permitted"] is (not suff["abstain"])           # same pass: same fields as the verdict

        section = (await client.get(START.format(cid=case.id) + "/sufficiency", headers=bearer(token))).json()
        assert section["incidents"][0]["sufficiency"]["rationale"] == rat

        rows = await audit_rows(db_session, case.id)
        assert len(rows) == 1
        assert rows[0].details["incidents"][0]["sufficiency"]["rationale"] == rat       # response and audit cannot drift

        # consistency with the verdict's own counts
        assert len([p for p in rat["corroboration"] if p["kind"] == "corroborating"]) >= 1
        assert len(rat["units"]) == suff["counts"]["evidence_units"]
        assert rat["anchor"]["status"] == "used"


@pytest.mark.anyio
async def test_ordinary_roles_never_receive_entity_values_in_the_response_or_the_audit_document(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="rat2")
    v_token, viewer = await seed_analyst_with_token(db_session, prefix="rat2v", username="rat2v", global_role="analyst_tier_1")
    db_session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case.id, analyst_id=viewer.id, case_role="viewer",
                                       assigned_at=datetime.now(timezone.utc)))
    await db_session.commit()
    values = {v for (v,) in (await db_session.execute(select(ExtractedEntityModel.entity_value))).all() if v and len(v) >= 5}
    assert values                                                                         # the scenario really has entities to leak
    async with Keep(client):
        await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        for tok in (token, v_token):                                                      # lead and viewer alike
            rat = (await client.get(START.format(cid=case.id) + "/sufficiency", headers=bearer(tok))).json()["incidents"][0]["sufficiency"]["rationale"]
            text = json.dumps(rat)
            leaked = [v for v in values if v in text]
            assert leaked == [] and rat["entity_values"] == "withheld"
            assert "payload" not in text.lower()                                          # the project's response-text guard (payload-free results)
            assert all(set(e) == {"type", "strength"} for p in rat["corroboration"] for e in p["shared_entities"])
        stored = json.dumps((await audit_rows(db_session, case.id))[0].details["incidents"][0]["sufficiency"]["rationale"])
        assert [v for v in values if v in stored] == []


@pytest.mark.anyio
async def test_viewer_can_read_the_rationale_and_an_unassigned_analyst_cannot(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="rat3")
    other_token, _other = await seed_analyst_with_token(db_session, prefix="rat3o", username="rat3o", global_role="analyst_tier_2")
    async with Keep(client):
        await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        denied = await client.get(START.format(cid=case.id) + "/sufficiency", headers=bearer(other_token))
        assert denied.status_code == 404 and "rationale" not in denied.text and "suff-rationale" not in denied.text
        assert (await client.get(START.format(cid=case.id) + "/sufficiency")).status_code == 401


@pytest.mark.anyio
async def test_no_identifier_from_another_case_appears_in_the_rationale(db_session, app_instance):
    client, token, lead, case_a = await setup(db_session, app_instance, intrusion_chain(), prefix="rat4")
    case_b = await seed_case_with_lead(db_session, lead=lead, title="Other case")
    async with Keep(client):
        await ingest(client, SCENARIOS["06_uncorroborated_single_alert"]["build"]())
        await link_all_events(db_session, case_b, lead)
        body = (await client.post(START.format(cid=case_a.id), json={}, headers=bearer(token))).json()
        linked_a = {str(i) for (i,) in (await db_session.execute(select(CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case_a.id))).all()}
        linked_b = {str(i) for (i,) in (await db_session.execute(select(CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case_b.id))).all()}
        ids = all_ids(body["incidents"][0]["sufficiency"]["rationale"])
        assert ids and ids <= linked_a and ids.isdisjoint(linked_b)


@pytest.mark.anyio
async def test_an_llm_failure_leaves_the_deterministic_rationale_intact(db_session, app_instance):
    provider = ScriptedProvider(raise_exc=LLMConnectionError("down"))
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix="rat5")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
        inc = r.json()["incidents"][0]
        rat = inc["sufficiency"]["rationale"]
        assert r.status_code == 201 and inc["llm_status"] == "fallback:LLMConnectionError"
        assert rat["completeness"] == "complete" and rat["status"]["llm_status"] == "fallback:LLMConnectionError"
        assert rat["status"]["model_call_permitted"] is True and rat["status"]["deterministic_report_available"] is True
        assert rat["units"] and rat["corroboration"]


@pytest.mark.anyio
async def test_an_abstention_blocks_the_model_but_the_deterministic_report_and_rationale_exist(db_session, app_instance):
    provider = ScriptedProvider()
    records = [x for x in SCENARIOS["05_insufficient_unparseable"]["build"]() if isinstance(x, dict)]   # the ingest schema accepts objects only
    client, token, _lead, case = await setup(db_session, app_instance, records, provider=provider, prefix="rat6")
    async with Keep(client):
        body = (await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))).json()
        batch = body["batch_sufficiency"]
        assert provider.calls == 0 and batch["verdict"] == "insufficient" and body["batch_report_markdown"]
        rat = batch["rationale"]
        assert rat["status"]["model_call_permitted"] is False and rat["status"]["deterministic_report_available"] is True
        assert rat["schema"] == "suff-rationale-v1"


@pytest.mark.anyio
async def test_the_rationale_is_bounded_and_does_not_change_the_verdict_or_the_gate_counts(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="rat7")
    async with Keep(client):
        body = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
        suff = body["incidents"][0]["sufficiency"]
        assert len(json.dumps(suff["rationale"])) < 20_000                                  # bounded; truncation flags exist if exceeded
        assert set(suff["rationale"]["truncated"]) == {"units", "collapsed", "corroboration", "exclusions", "findings", "contradictions"}
        assert suff["verdict"] == "sufficient" and suff["counts"]["corroborating"] >= 1       # same values as before this feature


def test_a_stored_document_without_a_rationale_is_still_served():
    payload = {
        "status": "completed", "created_at": "2026-11-12T10:00:00+00:00", "rule_version": "suff-v4", "batch_sufficiency": None,
        "incidents": [{"incident_id": "i1", "sufficiency": {"verdict": "limited", "reason_codes": [], "reasons": []}, "llm_status": "not_requested", "contradictions": []}],
    }
    view = MultiSourceInvestigationService.section_view(payload, MultiSourceSection.SUFFICIENCY, stale=False)
    assert view["incidents"][0]["sufficiency"]["verdict"] == "limited" and "rationale" not in view["incidents"][0]["sufficiency"]


def test_a_rationale_failure_degrades_only_the_rationale(monkeypatch):
    import app.services.multisource_investigation_service as svc
    from app.modules.ai.guardrails.sufficiency_trace import SufficiencyTrace
    from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency
    from tests.unit.test_sufficiency_rationale import scenarios

    a = evaluate_sufficiency(scenarios()["sufficient_pair"])

    def boom(*_a, **_k):
        raise ValueError("secret detail")

    monkeypatch.setattr(svc, "build_rationale", boom)
    view = MultiSourceInvestigationService._sufficiency_view(a, SufficiencyTrace(stage="complete"), "not_requested")
    assert view["verdict"] == "sufficient" and view["rationale"]["completeness"] == "unavailable"
    assert view["rationale"]["trace_error"] == "ValueError" and "secret detail" not in json.dumps(view)
