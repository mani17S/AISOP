"""
Export gate: the multi-source report is released only for a result the case lead APPROVED, with unchanged evidence. Offline, real API path.
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
from tests.unit.test_multisource_review import REVIEW, STATUS, run_investigation

EXPORT = "/api/v1/cases/{cid}/investigations/multisource/export"


@pytest.mark.anyio
async def test_export_refused_until_approved_then_released_with_the_approval_stated_and_audited(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="exA")
    async with Keep(client):
        status = await run_investigation(client, token, case)
        fp = status["evidence_fingerprint"]
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 409                      # not reviewed
        await client.post(REVIEW.format(cid=case.id), json={"decision": "rejected", "evidence_fingerprint": fp}, headers=bearer(token))
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 409                      # rejected
        await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": fp, "note": "Reviewed."}, headers=bearer(token))
        r = await client.get(EXPORT.format(cid=case.id), headers=bearer(token))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["markdown"].startswith("# AISOP investigation report (approved)")
        assert f"Approved by {lead.username}" in body["markdown"] and fp in body["markdown"]
        assert "does not make any claim in the report more certain" in body["markdown"]
        assert body["evidence_fingerprint"] == fp and body["filename"].endswith(".md")
        rows = (await db_session.execute(select(CaseAuditEventModel).where(CaseAuditEventModel.case_id == case.id, CaseAuditEventModel.action == "case_multisource_export"))).scalars().all()
        assert len(rows) == 1 and rows[0].actor_username == lead.username                                                   # the release is audited


@pytest.mark.anyio
async def test_export_refused_again_when_the_evidence_changes_after_approval(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="exB")
    async with Keep(client):
        status = await run_investigation(client, token, case)
        await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": status["evidence_fingerprint"]}, headers=bearer(token))
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 200
        extra = {"source_type": "generic_siem", "rule_id": "R-EXTRA-EXPORT", "rule_name": "extra record", "severity": "low", "timestamp": "2026-11-07T09:30:00Z", "host": "x", "user": "y"}
        await ingest(client, [extra])
        await link_all_events(db_session, case, lead)
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 409                      # approval no longer applies


@pytest.mark.anyio
async def test_export_roles_and_missing_investigation(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="exC")
    tok_view, view = await seed_analyst_with_token(db_session, prefix="exCv", username="exCv", global_role="analyst_tier_1")
    tok_out, _ = await seed_analyst_with_token(db_session, prefix="exCo", username="exCo", global_role="analyst_tier_2")
    db_session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case.id, analyst_id=view.id, case_role="viewer", assigned_at=datetime.now(timezone.utc)))
    await db_session.commit()
    async with Keep(client):
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 404                      # nothing investigated yet
        status = await run_investigation(client, token, case)
        await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": status["evidence_fingerprint"]}, headers=bearer(token))
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(tok_view))).status_code in (403, 404)            # a viewer cannot release
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(tok_out))).status_code in (403, 404)             # unassigned
        assert (await client.get(EXPORT.format(cid=case.id))).status_code in (401, 403)                                      # no credentials
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 200
