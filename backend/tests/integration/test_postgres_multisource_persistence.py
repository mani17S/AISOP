"""
Stage 4/5 (ADR-010): PostgreSQL persistence of a multi-source investigation result in the EXISTING audit table.

Marked ``postgres``: WRITTEN BUT NOT EXECUTED in Stage 5 (PostgreSQL validation needs separate owner authorization).
It requires the guarded disposable-database environment (TEST_DATABASE_URL, ALLOW_DESTRUCTIVE_POSTGRES_TESTS) and is
excluded from the offline suite. Run it only through the approved launcher pattern.

Verifies what SQLite cannot: the multisource-v1 document (nested JSON, unicode, ~hundreds of KB) round-trips through
the JSONB column without loss, the bounded activity summary can be computed from the stored document, and the
append-only trigger still blocks modification and deletion of the row.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select, text

from app.core.rbac import GlobalRole
from app.models.analyst import Analyst
from app.models.case import CaseAuditEventModel, CaseModel
from app.modules.correlation.demo_data import ASSETS, intrusion_chain
from app.modules.correlation.workflow import analyze
from app.services.multisource_investigation_service import (
    MULTISOURCE_ACTION,
    MultiSourceInvestigationService,
    activity_summary,
)

pytestmark = pytest.mark.postgres


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def _seed(session):
    now = datetime.now(timezone.utc)
    analyst_id, case_id = uuid.uuid4(), uuid.uuid4()
    session.add(Analyst(id=analyst_id, username=f"ms_pg_{analyst_id.hex[:6]}", email=f"{analyst_id.hex[:6]}@aisop.local",
                        global_role=GlobalRole.ANALYST_TIER_2.value, is_active=True, created_at=now, updated_at=now))
    session.add(CaseModel(id=case_id, case_number=f"CASE-MS-PG-{case_id.hex[:6]}", title="Multi-source PG audit",
                          description="Stage 5", severity="high", status="open", created_at=now, updated_at=now))
    await session.flush()
    return analyst_id, f"ms_pg_{analyst_id.hex[:6]}", case_id, now


def _payload(extra_text: str = "") -> dict:
    result = analyze(intrusion_chain(), assets=ASSETS)
    payload = MultiSourceInvestigationService.build_payload(MultiSourceInvestigationService(), result, "f" * 64, False)
    payload["created_at"] = datetime.now(timezone.utc).isoformat()
    payload["started_by"] = "ms_pg"
    if extra_text:
        payload["incidents"][0]["report_markdown"] += extra_text
    return json.loads(json.dumps(payload))


@pytest.mark.anyio
async def test_multisource_result_round_trips_through_jsonb_and_summary_is_computable(postgres_session):
    analyst_id, username, case_id, now = await _seed(postgres_session)
    payload = _payload("\né中文\U0001f4a5 unicode tail")
    audit_id = uuid.uuid4()
    postgres_session.add(CaseAuditEventModel(id=audit_id, case_id=case_id, actor_analyst_id=analyst_id, actor_username=username,
                                             action=MULTISOURCE_ACTION, context_sha256=payload["incidents"][0]["context_sha256"],
                                             details=payload, created_at=now))
    await postgres_session.commit()
    stored = (await postgres_session.execute(select(CaseAuditEventModel.details).where(CaseAuditEventModel.id == audit_id))).scalar_one()
    assert stored == payload                                  # no loss of nested structure, numbers or unicode
    summary = activity_summary(stored)
    assert summary["summary_only"] is True and summary["ledger_head"] == payload["ledger"]["head"]
    assert summary["verdicts"][0]["verdict"] == "sufficient"


@pytest.mark.anyio
async def test_large_multisource_result_is_stored_and_read_back_intact(postgres_session):
    analyst_id, username, case_id, now = await _seed(postgres_session)
    payload = _payload("\n" + ("evidence line\n" * 40000))     # ~560 KB, above any normal run but below the stored caps' worst case
    audit_id = uuid.uuid4()
    postgres_session.add(CaseAuditEventModel(id=audit_id, case_id=case_id, actor_analyst_id=analyst_id, actor_username=username,
                                             action=MULTISOURCE_ACTION, context_sha256=None, details=payload, created_at=now))
    await postgres_session.commit()
    stored = (await postgres_session.execute(select(CaseAuditEventModel.details).where(CaseAuditEventModel.id == audit_id))).scalar_one()
    assert stored["incidents"][0]["report_markdown"] == payload["incidents"][0]["report_markdown"]


@pytest.mark.anyio
async def test_multisource_audit_row_is_append_only(postgres_session):
    analyst_id, username, case_id, now = await _seed(postgres_session)
    audit_id = uuid.uuid4()
    postgres_session.add(CaseAuditEventModel(id=audit_id, case_id=case_id, actor_analyst_id=analyst_id, actor_username=username,
                                             action=MULTISOURCE_ACTION, context_sha256=None, details=_payload(), created_at=now))
    await postgres_session.commit()
    with pytest.raises(Exception):
        async with postgres_session.begin_nested():
            await postgres_session.execute(text("UPDATE case_audit_events SET details = '{}'::jsonb WHERE id = :id"), {"id": audit_id})
    with pytest.raises(Exception):
        async with postgres_session.begin_nested():
            await postgres_session.execute(text("DELETE FROM case_audit_events WHERE id = :id"), {"id": audit_id})
