"""
Analyst review (human approval record) of a multi-source investigation. Offline, SQLite harness, real API path.

Rules under test: only the case lead can write a review; it is bound to the evidence fingerprint the reviewer saw; it is an append-only
audit row; it becomes "stale" when the case evidence changes; it never changes the investigation; the note is bounded and cleaned.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.case import CaseAssignmentModel, CaseAuditEventModel
from app.modules.correlation.demo_data import intrusion_chain
from tests.unit.test_multisource_api import (  # noqa: F401  (fixtures and helpers)
    START,
    Keep,
    anyio_backend,
    app_instance,
    auth_settings,
    bearer,
    ingest,
    link_all_events,
    seed_analyst_with_token,
    setup,
)

REVIEW = "/api/v1/cases/{cid}/investigations/multisource/review"
STATUS = "/api/v1/cases/{cid}/investigations/multisource/status"


async def run_investigation(client, token, case):
    r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
    assert r.status_code in (200, 201), r.text
    s = await client.get(STATUS.format(cid=case.id), headers=bearer(token))
    assert s.status_code == 200
    return s.json()


@pytest.mark.anyio
async def test_lead_review_flow_not_reviewed_then_approved_and_shown_in_status_and_report(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="rvA")
    async with Keep(client):
        status = await run_investigation(client, token, case)
        assert status["review"]["state"] == "not_reviewed"
        r = await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": status["evidence_fingerprint"], "note": "Checked the timeline against the host log."}, headers=bearer(token))
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "approved" and r.json()["reviewed_by"] == lead.username and r.json()["note"].startswith("Checked")
        after = (await client.get(STATUS.format(cid=case.id), headers=bearer(token))).json()
        assert after["review"]["state"] == "approved"
        report = (await client.get(f"/api/v1/cases/{case.id}/investigations/multisource/report", headers=bearer(token))).json()
        assert report["review"]["state"] == "approved"


@pytest.mark.anyio
async def test_only_the_case_lead_can_review(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="rvB")
    tok_inv, inv = await seed_analyst_with_token(db_session, prefix="rvBi", username="rvBi", global_role="analyst_tier_2")
    tok_view, view = await seed_analyst_with_token(db_session, prefix="rvBv", username="rvBv", global_role="analyst_tier_1")
    tok_out, _ = await seed_analyst_with_token(db_session, prefix="rvBo", username="rvBo", global_role="analyst_tier_2")
    for who, role in ((inv, "investigator"), (view, "viewer")):
        db_session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case.id, analyst_id=who.id, case_role=role, assigned_at=datetime.now(timezone.utc)))
    await db_session.commit()
    async with Keep(client):
        status = await run_investigation(client, token, case)
        body = {"decision": "approved", "evidence_fingerprint": status["evidence_fingerprint"]}
        for t in (tok_inv, tok_view):
            assert (await client.post(REVIEW.format(cid=case.id), json=body, headers=bearer(t))).status_code in (403, 404)
        assert (await client.post(REVIEW.format(cid=case.id), json=body, headers=bearer(tok_out))).status_code in (403, 404)   # not assigned at all
        assert (await client.post(REVIEW.format(cid=case.id), json=body)).status_code in (401, 403)                            # no credentials
        assert (await client.get(STATUS.format(cid=case.id), headers=bearer(token))).json()["review"]["state"] == "not_reviewed"


@pytest.mark.anyio
async def test_review_must_name_the_fingerprint_the_reviewer_saw(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="rvC")
    async with Keep(client):
        status = await run_investigation(client, token, case)
        wrong = "0" * 64
        assert (await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": wrong}, headers=bearer(token))).status_code == 409
        for bad in ({"decision": "maybe", "evidence_fingerprint": status["evidence_fingerprint"]}, {"decision": "approved", "evidence_fingerprint": "short"},
                    {"decision": "approved"}, {"decision": "approved", "evidence_fingerprint": status["evidence_fingerprint"], "note": "x" * 501},
                    {"decision": "approved", "evidence_fingerprint": status["evidence_fingerprint"], "extra": 1}):
            assert (await client.post(REVIEW.format(cid=case.id), json=bad, headers=bearer(token))).status_code == 422
        assert (await client.get(STATUS.format(cid=case.id), headers=bearer(token))).json()["review"]["state"] == "not_reviewed"


@pytest.mark.anyio
async def test_review_without_an_investigation_is_refused(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="rvD")
    async with Keep(client):
        r = await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": "a" * 64}, headers=bearer(token))
        assert r.status_code == 404


@pytest.mark.anyio
async def test_review_goes_stale_when_evidence_changes_and_cannot_be_given_to_the_old_run(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="rvE")
    async with Keep(client):
        status = await run_investigation(client, token, case)
        fp = status["evidence_fingerprint"]
        assert (await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": fp}, headers=bearer(token))).status_code == 200
        extra = {"source_type": "generic_siem", "rule_id": "R-EXTRA-REVIEW", "rule_name": "extra record", "severity": "low", "timestamp": "2026-11-07T09:30:00Z", "host": "x", "user": "y"}
        await ingest(client, [extra])
        await link_all_events(db_session, case, lead)
        after = (await client.get(STATUS.format(cid=case.id), headers=bearer(token))).json()
        assert after["stale_evidence"] is True and after["review"]["state"] == "stale"
        r = await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": fp}, headers=bearer(token))
        assert r.status_code == 409                                                                                          # the evidence moved on


@pytest.mark.anyio
async def test_reviews_are_append_only_audit_rows_the_latest_wins_and_the_note_is_cleaned(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="rvF")
    async with Keep(client):
        status = await run_investigation(client, token, case)
        fp = status["evidence_fingerprint"]
        first = await client.post(REVIEW.format(cid=case.id), json={"decision": "rejected", "evidence_fingerprint": fp, "note": "ok\x07bell\x00nul <b>markup</b>"}, headers=bearer(token))
        assert first.status_code == 200 and first.json()["state"] == "rejected"
        assert "\x07" not in first.json()["note"] and "\x00" not in first.json()["note"]
        second = await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": fp}, headers=bearer(token))
        assert second.status_code == 200 and second.json()["state"] == "approved"
        rows = (await db_session.execute(select(CaseAuditEventModel).where(CaseAuditEventModel.case_id == case.id, CaseAuditEventModel.action == "case_multisource_review"))).scalars().all()
        assert len(rows) == 2                                                                                                # both kept, none edited
        assert (await client.get(STATUS.format(cid=case.id), headers=bearer(token))).json()["review"]["state"] == "approved"
        # the investigation itself is untouched by a review
        inv_rows = (await db_session.execute(select(CaseAuditEventModel).where(CaseAuditEventModel.case_id == case.id, CaseAuditEventModel.action == "case_multisource_investigation"))).scalars().all()
        assert len(inv_rows) == 1
