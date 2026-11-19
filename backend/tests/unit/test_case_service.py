"""
Unit tests for AISOP CaseService Foundation.

Milestone: Phase 3 — P3-H2 / Gate D.2.1
Provably offline tests verifying:
- Case lookup by UUID returning immutable CaseSummary
- Anti-enumeration assignment resolution joining cases and case_assignments
- Safe column projection preventing DetachedInstanceError
- Corrupt/unrecognized role handling (fails closed, returns None)
- Predicate is_analyst_assigned
"""

from __future__ import annotations

from typing import Any
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select
from app.core.rbac import (
    AuthenticatedAnalyst,
    AuthenticatedCaseContext,
    CaseRole,
    GlobalRole,
)
from app.models.analyst import Analyst
from app.models.case import (
    CaseAssignmentModel,
    CaseAuditEventModel,
    CaseEvidenceModel,
    CaseModel,
)
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.ai.guardrails import GuardrailDecision
from app.modules.ai.llm.exceptions import LLMConnectionError, LLMTimeoutError
from app.modules.ai.llm.protocol import LLMProvider
from app.schemas.case import CaseInvestigationSynthesizeRequest
from app.schemas.report import IncidentSeverityTier, InvestigationReportBundle
from app.services.case_service import CaseService, CaseSummary


class TestCaseServiceWithMocks:
    """Fast, deterministic unit tests for CaseService using mocked AsyncSession."""

    @pytest.mark.anyio
    async def test_get_case_by_id_found(self):
        case_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        mock_case = MagicMock(spec=CaseModel)
        mock_case.id = case_id
        mock_case.case_number = "CASE-20261025-0001"
        mock_case.title = "Suspicious PowerShell Execution"
        mock_case.description = "Encoded command detected on endpoint"
        mock_case.severity = "high"
        mock_case.status = "open"
        mock_case.created_at = now
        mock_case.updated_at = now
        mock_case.closed_at = None

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.first.return_value = mock_case
        mock_session.execute.return_value = mock_result

        service = CaseService()
        result = await service.get_case_by_id(mock_session, case_id)

        assert isinstance(result, CaseSummary)
        assert result.id == case_id
        assert result.case_number == "CASE-20261025-0001"
        assert result.severity == "high"
        assert result.status == "open"

    @pytest.mark.anyio
    async def test_get_case_by_id_not_found(self):
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.first.return_value = None
        mock_session.execute.return_value = mock_result

        service = CaseService()
        result = await service.get_case_by_id(mock_session, uuid.uuid4())
        assert result is None

    @pytest.mark.anyio
    async def test_get_assignment_context_found(self):
        case_id = uuid.uuid4()
        analyst_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.first.return_value = (case_id, analyst_id, "investigator", now)
        mock_session.execute.return_value = mock_result

        service = CaseService()
        context = await service.get_assignment_context(mock_session, case_id, analyst_id)

        assert isinstance(context, AuthenticatedCaseContext)
        assert context.case_id == case_id
        assert context.analyst_id == analyst_id
        assert context.case_role == CaseRole.INVESTIGATOR
        assert context.assigned_at == now

    @pytest.mark.anyio
    async def test_get_assignment_context_not_assigned_anti_enumeration(self):
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_session.execute.return_value = mock_result

        service = CaseService()
        context = await service.get_assignment_context(mock_session, uuid.uuid4(), uuid.uuid4())
        assert context is None

    @pytest.mark.anyio
    async def test_get_assignment_context_corrupt_role_fails_closed(self):
        case_id = uuid.uuid4()
        analyst_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        # "super_owner" is not a canonical case role
        mock_result.first.return_value = (case_id, analyst_id, "super_owner", now)
        mock_session.execute.return_value = mock_result

        service = CaseService()
        context = await service.get_assignment_context(mock_session, case_id, analyst_id)
        assert context is None

    @pytest.mark.anyio
    async def test_is_analyst_assigned_returns_boolean(self):
        case_id = uuid.uuid4()
        analyst_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        mock_session = AsyncMock()
        mock_result_found = MagicMock()
        mock_result_found.first.return_value = (case_id, analyst_id, "lead", now)
        mock_session.execute.return_value = mock_result_found

        service = CaseService()
        assert await service.is_analyst_assigned(mock_session, case_id, analyst_id) is True

        mock_result_absent = MagicMock()
        mock_result_absent.first.return_value = None
        mock_session.execute.return_value = mock_result_absent
        assert await service.is_analyst_assigned(mock_session, case_id, analyst_id) is False


class TestCaseServiceWithSqliteFixture:
    """Offline integration tests against SQLite in-memory fixture (Option A)."""

    @pytest.mark.anyio
    async def test_real_sqlite_case_and_assignment_lookup(self, db_session):
        service = CaseService()

        # Seed analyst
        analyst_id = uuid.uuid4()
        analyst = Analyst(
            id=analyst_id,
            username="investigator_d21",
            email="investigator_d21@aisop.local",
            global_role="analyst_tier_1",
            is_active=True,
        )
        db_session.add(analyst)

        # Seed case
        case_id = uuid.uuid4()
        case_obj = CaseModel(
            id=case_id,
            case_number="CASE-20261025-A101",
            title="Credential Dumping Incident",
            description="LSASS access attempt detected",
            severity="critical",
            status="open",
        )
        db_session.add(case_obj)

        # Seed assignment
        assignment = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case_id,
            analyst_id=analyst_id,
            case_role="investigator",
        )
        db_session.add(assignment)
        await db_session.commit()

        # 1. Look up case by ID
        case_summary = await service.get_case_by_id(db_session, case_id)
        assert case_summary is not None
        assert case_summary.id == case_id
        assert case_summary.case_number == "CASE-20261025-A101"
        assert case_summary.status == "open"

        # 2. Look up assignment for assigned analyst
        ctx = await service.get_assignment_context(db_session, case_id, analyst_id)
        assert ctx is not None
        assert ctx.case_id == case_id
        assert ctx.analyst_id == analyst_id
        assert ctx.case_role == CaseRole.INVESTIGATOR

        # 3. Look up assignment for unassigned analyst (anti-enumeration check)
        unassigned_id = uuid.uuid4()
        unassigned_ctx = await service.get_assignment_context(db_session, case_id, unassigned_id)
        assert unassigned_ctx is None

        # 4. Look up assignment on non-existent case (anti-enumeration check)
        non_existent_case_id = uuid.uuid4()
        absent_ctx = await service.get_assignment_context(db_session, non_existent_case_id, analyst_id)
        assert absent_ctx is None


class MockTimeoutLLMProvider(LLMProvider):
    """Deterministic in-memory mock LLM provider simulating inference timeout."""

    def __init__(self, model: str = "llama3.1:8b", timeout_seconds: int = 120):
        self._model = model
        self.timeout_seconds = timeout_seconds

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, request: Any) -> Any:
        raise LLMTimeoutError(f"Local Ollama inference timed out after {self.timeout_seconds}s")

    async def health(self) -> Any:
        return {"status": "mock"}


class MockConnectionErrorLLMProvider(LLMProvider):
    """Deterministic in-memory mock LLM provider simulating connection failure."""

    def __init__(self, model: str = "llama3.1:8b"):
        self._model = model

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, request: Any) -> Any:
        raise LLMConnectionError("Failed to connect to local Ollama service at localhost:11434")

    async def health(self) -> Any:
        return {"status": "mock"}


class TestCaseServiceFallbackContract:
    """
    AISOP Gate D.2.5.28 — Offline Fallback & Timeout Contract Verification (Contract B).
    Guarantees:
    - Pure offline unit testing using in-memory SQLite db_session.
    - Zero invocation of Ollama, zero network sockets, zero writes to PostgreSQL.
    - Verified separation of live LLM success from deterministic fallback path.
    - Verified audit provenance:
      - 'model_name' records actual producing component ('deterministic_fallback').
      - 'target_model' records requested model ('llama3.1:8b').
      - 'fallback_reason' explicitly captures failure cause (e.g. timeout / connection failure).
    """

    @pytest.mark.anyio
    async def test_case_reports_synthesis_timeout_fallback_contract(self, db_session):
        service = CaseService()
        now = datetime.now(timezone.utc)

        # 1. Seed Analyst
        analyst_id = uuid.uuid4()
        analyst = Analyst(
            id=analyst_id,
            username="fallback_analyst_01",
            email="fallback_analyst_01@aisop.local",
            global_role=GlobalRole.ANALYST_TIER_2.value,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        db_session.add(analyst)

        # 2. Seed Case
        case_id = uuid.uuid4()
        case_obj = CaseModel(
            id=case_id,
            case_number="CASE-20261027-FB01",
            title="Timeout Fallback Verification Case",
            description="Testing fallback behavior on LLM timeout",
            severity="high",
            status="open",
            created_at=now,
            updated_at=now,
        )
        db_session.add(case_obj)

        # 3. Seed Lead Assignment
        assignment = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case_id,
            analyst_id=analyst_id,
            case_role=CaseRole.LEAD.value,
            assigned_at=now,
        )
        db_session.add(assignment)

        # 4. Seed Raw Evidence and Normalized Event
        raw_ev = RawEvidence(
            id=uuid.uuid4(),
            source_type="sysmon",
            source_identifier="host-timeout-01",
            raw_payload={"Event": {"System": {"EventID": 1}}},
            sha256_hash="f" * 64,
            ingested_at=now,
        )
        db_session.add(raw_ev)

        norm_ev = NormalizedEventModel(
            id=uuid.uuid4(),
            raw_evidence_id=raw_ev.id,
            event_id="1",
            event_type="ProcessCreate",
            event_timestamp=now,
            action="cmd.exe /c whoami",
            outcome="success",
            severity="medium",
            provider="Microsoft-Windows-Sysmon",
            normalized_payload={"process": "cmd.exe"},
        )
        db_session.add(norm_ev)

        # 5. Seed Case Evidence Association
        case_ev = CaseEvidenceModel(
            id=uuid.uuid4(),
            case_id=case_id,
            evidence_id=norm_ev.id,
            linked_by_analyst_id=analyst_id,
            linked_at=now,
        )
        db_session.add(case_ev)
        await db_session.commit()

        actor_user = AuthenticatedAnalyst(
            analyst_id=analyst_id,
            username=analyst.username,
            global_role=GlobalRole.ANALYST_TIER_2,
            is_active=True,
        )

        mock_provider = MockTimeoutLLMProvider(model="llama3.1:8b", timeout_seconds=120)

        # 6. Execute report synthesis with mocked timeout
        bundle = await service.synthesize_case_reports(
            session=db_session,
            case_id=case_id,
            actor=actor_user,
            request=CaseInvestigationSynthesizeRequest(),
            llm_provider=mock_provider,
        )

        # 7. Verify Contract B: Fallback is active, explicit, and carries disclaimers
        assert bundle is not None
        assert isinstance(bundle, InvestigationReportBundle)
        assert bundle.is_fallback_active is True, "Fallback must be marked active on timeout"
        assert bundle.provenance is not None
        assert bundle.provenance.is_inconclusive_or_fallback is True
        assert bundle.provenance.model_identifier == "deterministic_fallback"
        assert bundle.provenance.overall_grounding_score == 0.0

        # Executive brief verification
        assert bundle.executive_brief.is_inconclusive_or_fallback is True
        assert bundle.executive_brief.incident_severity == IncidentSeverityTier.INCONCLUSIVE
        assert "unavailable" in bundle.executive_brief.executive_summary.lower()
        assert len(bundle.executive_brief.governance_disclaimer) > 0
        assert any("SYNTHESIS_FAILURE" in u for u in bundle.executive_brief.uncertainties_and_limitations)

        # Technical report verification
        assert bundle.technical_report.is_inconclusive_or_fallback is True
        assert len(bundle.technical_report.investigation_timeline) == 1
        assert bundle.technical_report.investigation_timeline[0].event_uuid == norm_ev.id

        # Detection report verification
        assert bundle.detection_report.is_inconclusive_or_fallback is True

        # Markdown renderings exist
        assert len(bundle.markdown_executive) > 0
        assert len(bundle.markdown_technical) > 0
        assert len(bundle.markdown_detection) > 0

        # 8. Verify Audit Provenance in SQLite session:
        # - model_name = 'deterministic_fallback' (actual producing component)
        # - target_model = 'llama3.1:8b' (requested model)
        # - decision = 'reject_to_fallback'
        # - is_valid = False
        # - fallback_reason documents timeout
        stmt = select(CaseAuditEventModel).where(
            CaseAuditEventModel.case_id == case_id,
            CaseAuditEventModel.action == "case_report_synthesized",
        )
        audit_events = (await db_session.execute(stmt)).scalars().all()
        assert len(audit_events) == 1
        audit_ev = audit_events[0]
        assert audit_ev.actor_analyst_id == analyst_id
        assert audit_ev.actor_username == analyst.username
        assert audit_ev.context_sha256 == bundle.context_sha256
        assert audit_ev.details is not None
        assert audit_ev.details.get("model_name") == "deterministic_fallback"
        assert audit_ev.details.get("target_model") == "llama3.1:8b"
        assert audit_ev.details.get("is_valid") is False
        assert audit_ev.details.get("decision") == GuardrailDecision.REJECT_TO_FALLBACK.value
        assert "fallback_reason" in audit_ev.details
        assert "timed out" in audit_ev.details["fallback_reason"].lower()

    @pytest.mark.anyio
    async def test_case_reports_synthesis_connection_error_fallback_contract(self, db_session):
        service = CaseService()
        now = datetime.now(timezone.utc)

        # 1. Seed Analyst, Case, Assignment, Evidence
        analyst_id = uuid.uuid4()
        analyst = Analyst(
            id=analyst_id,
            username="fallback_analyst_02",
            email="fallback_analyst_02@aisop.local",
            global_role=GlobalRole.ANALYST_TIER_2.value,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        db_session.add(analyst)

        case_id = uuid.uuid4()
        case_obj = CaseModel(
            id=case_id,
            case_number="CASE-20261027-FB02",
            title="Connection Error Fallback Verification Case",
            description="Testing fallback behavior on LLM connection failure",
            severity="medium",
            status="open",
            created_at=now,
            updated_at=now,
        )
        db_session.add(case_obj)

        assignment = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case_id,
            analyst_id=analyst_id,
            case_role=CaseRole.LEAD.value,
            assigned_at=now,
        )
        db_session.add(assignment)

        raw_ev = RawEvidence(
            id=uuid.uuid4(),
            source_type="sysmon",
            source_identifier="host-conn-01",
            raw_payload={"Event": {"System": {"EventID": 3}}},
            sha256_hash="7" * 64,
            ingested_at=now,
        )
        db_session.add(raw_ev)

        norm_ev = NormalizedEventModel(
            id=uuid.uuid4(),
            raw_evidence_id=raw_ev.id,
            event_id="3",
            event_type="NetworkConnect",
            event_timestamp=now,
            action="connected",
            outcome="success",
            severity="low",
            provider="Microsoft-Windows-Sysmon",
            normalized_payload={"destination": "10.0.0.1"},
        )
        db_session.add(norm_ev)

        case_ev = CaseEvidenceModel(
            id=uuid.uuid4(),
            case_id=case_id,
            evidence_id=norm_ev.id,
            linked_by_analyst_id=analyst_id,
            linked_at=now,
        )
        db_session.add(case_ev)
        await db_session.commit()

        actor_user = AuthenticatedAnalyst(
            analyst_id=analyst_id,
            username=analyst.username,
            global_role=GlobalRole.ANALYST_TIER_2,
            is_active=True,
        )

        mock_provider = MockConnectionErrorLLMProvider(model="llama3.1:8b")

        # 2. Execute report synthesis with mocked connection error
        bundle = await service.synthesize_case_reports(
            session=db_session,
            case_id=case_id,
            actor=actor_user,
            request=CaseInvestigationSynthesizeRequest(),
            llm_provider=mock_provider,
        )

        # 3. Verify Contract B
        assert bundle.is_fallback_active is True
        assert bundle.provenance.model_identifier == "deterministic_fallback"

        # 4. Verify Audit Details
        stmt = select(CaseAuditEventModel).where(
            CaseAuditEventModel.case_id == case_id,
            CaseAuditEventModel.action == "case_report_synthesized",
        )
        audit_events = (await db_session.execute(stmt)).scalars().all()
        assert len(audit_events) == 1
        audit_ev = audit_events[0]
        assert audit_ev.details.get("model_name") == "deterministic_fallback"
        assert audit_ev.details.get("target_model") == "llama3.1:8b"
        assert audit_ev.details.get("is_valid") is False
        assert audit_ev.details.get("decision") == GuardrailDecision.REJECT_TO_FALLBACK.value
        assert "fallback_reason" in audit_ev.details
        assert "unavailable" in audit_ev.details["fallback_reason"].lower()
