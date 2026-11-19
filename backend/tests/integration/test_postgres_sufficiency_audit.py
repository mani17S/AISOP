"""
Stage 3C (ADR-008): PostgreSQL persistence of a sufficiency abstention in the EXISTING audit schema.

Marked ``postgres``: it requires the guarded disposable-database environment
(TEST_DATABASE_URL, ALLOW_DESTRUCTIVE_POSTGRES_TESTS) like the other PostgreSQL tests and is
excluded from the offline suite. Run it only through the approved launcher pattern against
``aisop_stage3_disposable`` with explicit owner authorization.

Verifies that the fixed-shape sufficiency audit details round-trip through JSONB without a
migration and that the append-only trigger still blocks modification of the row.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select, text

from app.core.rbac import GlobalRole
from app.models.analyst import Analyst
from app.models.case import CaseAuditEventModel, CaseModel
from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency
from tests.unit.test_evidence_sufficiency_gate import make

pytestmark = pytest.mark.postgres


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_abstention_audit_details_round_trip_jsonb_and_are_immutable(postgres_session):
    now = datetime.now(timezone.utc)
    analyst_id, case_id, audit_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    postgres_session.add(Analyst(id=analyst_id, username=f"suff_pg_{analyst_id.hex[:6]}",
                                 email=f"{analyst_id.hex[:6]}@aisop.local", global_role=GlobalRole.ANALYST_TIER_2.value,
                                 is_active=True, created_at=now, updated_at=now))
    postgres_session.add(CaseModel(id=case_id, case_number=f"CASE-SUFF-PG-{case_id.hex[:6]}", title="Sufficiency PG audit",
                                   description="Stage 3C", severity="high", status="open", created_at=now, updated_at=now))
    await postgres_session.flush()

    assessment = evaluate_sufficiency(make([], root=None))
    details = {**assessment.audit_details(), "fallback_reason": "Evidence assessed INSUFFICIENT: NO_EVIDENCE"}
    postgres_session.add(CaseAuditEventModel(id=audit_id, case_id=case_id, actor_analyst_id=analyst_id,
                                             actor_username=f"suff_pg_{analyst_id.hex[:6]}",
                                             action="case_investigation_synthesized",
                                             context_sha256="a" * 64, details=details, created_at=now))
    await postgres_session.commit()

    stored = (await postgres_session.execute(
        select(CaseAuditEventModel.details).where(CaseAuditEventModel.id == audit_id)
    )).scalar_one()
    assert stored == details
    assert stored["abstained"] is True and stored["sufficiency_reason_codes"] == ["NO_EVIDENCE"]

    with pytest.raises(Exception):
        async with postgres_session.begin_nested():
            await postgres_session.execute(
                text("UPDATE case_audit_events SET action = 'tampered' WHERE id = :id"), {"id": audit_id}
            )
