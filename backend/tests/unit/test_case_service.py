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

import itertools
from typing import Any
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import event, select
from sqlalchemy.dialects import postgresql
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



def _fx(verdict, rule="suff-v5"):
    return {"sufficiency": {"verdict": verdict, "rule_version": rule, "reason_codes": []}}


#: Every stored-result shape the reducer distinguishes (worst-of, batch-only, malformed, unknown verdict, truncation true and false).
_SUFFICIENCY_FIXTURES = {
    "worst_of": {"incidents": [_fx("sufficient", "a"), _fx("insufficient", "b"), _fx("limited", "c")], "truncation": {"incidents_total": 3}},
    "single": {"incidents": [_fx("sufficient")], "truncation": {"incidents_total": 1}},
    "batch_only": {"incidents": [], "batch_sufficiency": {"verdict": "limited", "rule_version": "suff-v5"}, "truncation": {"incidents_total": 0}},
    "batch_only_no_incidents_key": {"batch_sufficiency": {"verdict": "insufficient", "rule_version": "suff-v5"}},
    "truncated_true": {"incidents": [_fx("limited")] * 25, "truncation": {"incidents_total": 31, "incidents_listed": 25}},
    "truncated_false": {"incidents": [_fx("limited")] * 2, "truncation": {"incidents_total": 2}},
    "truncation_unknown": {"incidents": [_fx("limited")]},
    "rule_version_not_a_string": {"incidents": [{"sufficiency": {"verdict": "limited", "rule_version": 5}}], "truncation": {"incidents_total": 1}},
    "unknown_verdict": {"incidents": [{"sufficiency": {"verdict": "probably_fine"}}], "truncation": {"incidents_total": 1}},
    "one_incident_without_sufficiency": {"incidents": [{"sufficiency": {"verdict": "sufficient"}}, {"no": "sufficiency"}], "truncation": {"incidents_total": 2}},
    "incidents_not_a_list": {"incidents": "not-a-list"},
    "no_batch_assessment": {"incidents": [], "batch_sufficiency": None},
    "empty": {},
}


_CASE_SEQ = itertools.count(1000)


class _StatementCounter:
    """Counts the SQL statements a block sends to the SQLite connection bound to the test session."""

    def __init__(self, db_session):
        self._conn = db_session._sync.get_bind()
        self.statements: list[str] = []

    def _record(self, conn, cursor, statement, parameters, context, executemany):
        self.statements.append(statement)

    def __enter__(self):
        event.listen(self._conn, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc):
        event.remove(self._conn, "before_cursor_execute", self._record)


class TestCaseSufficiencyReadModel:
    """Cases API shows the verdict already stored by the gate in case_audit_events; nothing is recomputed (no LLM, no gate call)."""

    @staticmethod
    async def _seed(db_session, runs):
        """One case with a lead; ``runs`` is a list of (created_at, details) for action case_multisource_investigation."""
        analyst = Analyst(id=uuid.uuid4(), username=f"u{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@aisop.local",
                          global_role="analyst_tier_1", is_active=True)
        case = CaseModel(id=uuid.uuid4(), case_number="CASE-20261125-S001", title="Sufficiency read", severity="high", status="open")
        db_session.add_all([analyst, case])
        await db_session.flush()
        db_session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case.id, analyst_id=analyst.id, case_role="lead"))
        for at, details in runs:
            db_session.add(CaseAuditEventModel(id=uuid.uuid4(), case_id=case.id, actor_analyst_id=analyst.id, actor_username=analyst.username,
                                               action="case_multisource_investigation", details=details, created_at=at))
        await db_session.commit()
        return analyst, case

    @staticmethod
    def _inc(verdict, rule="suff-v5"):
        return {"sufficiency": {"verdict": verdict, "rule_version": rule, "reason_codes": []}}

    @staticmethod
    def _t(minute):
        return datetime(2026, 11, 25, 10, minute, tzinfo=timezone.utc)

    @pytest.mark.anyio
    async def test_null_when_no_run_exists(self, db_session):
        analyst, case = await self._seed(db_session, [])
        detail = await CaseService().get_case_detail(db_session, case.id)
        assert (detail.sufficiency_verdict, detail.sufficiency_rule_version,
                detail.sufficiency_assessed_at, detail.sufficiency_incidents_truncated) == (None, None, None, None)

    @pytest.mark.anyio
    async def test_latest_run_wins(self, db_session):
        old = {"incidents": [self._inc("insufficient", "old")], "truncation": {"incidents_total": 1}}
        new = {"incidents": [self._inc("sufficient", "suff-v5")], "truncation": {"incidents_total": 1}}
        analyst, case = await self._seed(db_session, [(self._t(5), new), (self._t(1), old)])
        detail = await CaseService().get_case_detail(db_session, case.id)
        assert detail.sufficiency_verdict.value == "sufficient" and detail.sufficiency_rule_version == "suff-v5"
        assert detail.sufficiency_assessed_at.replace(tzinfo=timezone.utc) == self._t(5)
        assert detail.sufficiency_incidents_truncated is False

    @pytest.mark.anyio
    async def test_worst_verdict_across_incidents_and_its_rule_version(self, db_session):
        d = {"incidents": [self._inc("sufficient", "a"), self._inc("insufficient", "b"), self._inc("limited", "c")],
             "truncation": {"incidents_total": 3}}
        analyst, case = await self._seed(db_session, [(self._t(1), d)])
        detail = await CaseService().get_case_detail(db_session, case.id)
        assert detail.sufficiency_verdict.value == "insufficient" and detail.sufficiency_rule_version == "b"

    @pytest.mark.anyio
    async def test_batch_sufficiency_used_only_when_no_incident_formed(self, db_session):
        d = {"incidents": [], "batch_sufficiency": {"verdict": "limited", "rule_version": "suff-v5"}, "truncation": {"incidents_total": 0}}
        analyst, case = await self._seed(db_session, [(self._t(1), d)])
        detail = await CaseService().get_case_detail(db_session, case.id)
        assert detail.sufficiency_verdict.value == "limited" and detail.sufficiency_incidents_truncated is False

    @pytest.mark.anyio
    @pytest.mark.parametrize("details", [
        {"incidents": [{"sufficiency": {"verdict": "probably_fine"}}], "truncation": {"incidents_total": 1}},
        {"incidents": [{"sufficiency": {"verdict": "sufficient"}}, {"no": "sufficiency"}], "truncation": {"incidents_total": 2}},
        {"incidents": "not-a-list"},
        {"incidents": [], "batch_sufficiency": None},
        {},
    ])
    async def test_malformed_or_unknown_verdict_gives_none(self, db_session, details):
        analyst, case = await self._seed(db_session, [(self._t(1), details)])
        detail = await CaseService().get_case_detail(db_session, case.id)
        assert (detail.sufficiency_verdict, detail.sufficiency_rule_version,
                detail.sufficiency_assessed_at, detail.sufficiency_incidents_truncated) == (None, None, None, None)

    @pytest.mark.anyio
    async def test_truncation_flag_when_more_incidents_formed_than_stored(self, db_session):
        d = {"incidents": [self._inc("limited")] * 25, "truncation": {"incidents_total": 31, "incidents_listed": 25}}
        analyst, case = await self._seed(db_session, [(self._t(1), d)])
        detail = await CaseService().get_case_detail(db_session, case.id)
        assert detail.sufficiency_incidents_truncated is True

    @pytest.mark.anyio
    async def test_list_returns_verdict_for_assigned_case_in_one_batch(self, db_session):
        d = {"incidents": [self._inc("limited")], "truncation": {"incidents_total": 1}}
        analyst, case = await self._seed(db_session, [(self._t(1), d)])
        items, total = await CaseService().list_cases_for_analyst(db_session, analyst.id)
        assert total == 1 and items[0].id == case.id
        assert items[0].sufficiency_verdict.value == "limited"
        assert items[0].model_dump(mode="json")["sufficiency_verdict"] == "limited"

    # ---- Optimisation 2: the case-verdict lookup reads the compact verdict_summary, not the whole stored result ----

    @staticmethod
    def _with_summary(d):
        from app.services.multisource_investigation_service import _compact_verdict

        return {**d, "verdict_summary": _compact_verdict(d)}

    @staticmethod
    async def _seed_cases(db_session, specs):
        """One case per entry of ``specs`` (the details of its single run, at the same minute); returns the case ids in order."""
        analyst = Analyst(id=uuid.uuid4(), username=f"u{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@aisop.local",
                          global_role="analyst_tier_1", is_active=True)
        db_session.add(analyst)
        cases = [CaseModel(id=uuid.uuid4(), case_number=f"CASE-20261125-{next(_CASE_SEQ):04d}", title=f"verdict {i}", severity="high", status="open")
                 for i in range(len(specs))]
        db_session.add_all(cases)
        await db_session.flush()
        for case, details in zip(cases, specs):
            db_session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case.id, analyst_id=analyst.id, case_role="lead"))
            db_session.add(CaseAuditEventModel(id=uuid.uuid4(), case_id=case.id, actor_analyst_id=analyst.id, actor_username=analyst.username,
                                               action="case_multisource_investigation", details=details,
                                               created_at=datetime(2026, 11, 25, 10, 1, tzinfo=timezone.utc)))
        await db_session.commit()
        return [c.id for c in cases]

    @pytest.fixture(autouse=True)
    def _fresh_memo(self):
        import app.services.multisource_investigation_service as svc

        svc._LEGACY_MEMO.clear()
        yield
        svc._LEGACY_MEMO.clear()

    @pytest.mark.anyio
    @pytest.mark.parametrize("name", sorted(_SUFFICIENCY_FIXTURES))
    async def test_summary_row_gives_the_same_fields_as_the_full_row(self, db_session, name):
        from app.services.multisource_investigation_service import case_sufficiency_summaries

        d = _SUFFICIENCY_FIXTURES[name]
        old_id, new_id = await self._seed_cases(db_session, [d, self._with_summary(d)])
        out = await case_sufficiency_summaries(db_session, [old_id, new_id])
        assert out.get(old_id) == out.get(new_id)
        assert (old_id in out) == (name in {"worst_of", "single", "batch_only", "batch_only_no_incidents_key", "truncated_true",
                                            "truncated_false", "truncation_unknown", "rule_version_not_a_string"})

    @pytest.mark.anyio
    async def test_compact_verdict_shape_and_unsummarisable_marker(self):
        from app.services.multisource_investigation_service import _compact_verdict

        assert _compact_verdict(_SUFFICIENCY_FIXTURES["worst_of"]) == {"schema": 1, "verdict": "insufficient", "rule_version": "b", "truncated": False}
        assert _compact_verdict(_SUFFICIENCY_FIXTURES["truncated_true"])["truncated"] is True
        assert _compact_verdict(_SUFFICIENCY_FIXTURES["truncation_unknown"])["truncated"] is None
        for name in ("unknown_verdict", "incidents_not_a_list", "empty"):
            assert _compact_verdict(_SUFFICIENCY_FIXTURES[name]) == {"schema": 1, "verdict": None, "rule_version": None, "truncated": None}

    @pytest.mark.anyio
    async def test_summary_is_what_the_read_path_uses_and_rows_without_it_fall_back(self, db_session):
        from app.services.multisource_investigation_service import case_sufficiency_summaries

        d = _SUFFICIENCY_FIXTURES["single"]
        lie = {**d, "verdict_summary": {"schema": 1, "verdict": "insufficient", "rule_version": "from-summary", "truncated": False}}
        summarised, legacy = await self._seed_cases(db_session, [lie, d])
        out = await case_sufficiency_summaries(db_session, [summarised, legacy])
        assert out[summarised]["sufficiency_verdict"].value == "insufficient" and out[summarised]["sufficiency_rule_version"] == "from-summary"
        assert out[legacy]["sufficiency_verdict"].value == "sufficient"

    @pytest.mark.anyio
    async def test_statement_counts_new_rows_mixed_page_and_memo(self, db_session):
        import app.services.multisource_investigation_service as svc

        names = ["worst_of", "single", "batch_only", "truncated_true", "empty", "unknown_verdict"]
        all_old = await self._seed_cases(db_session, [_SUFFICIENCY_FIXTURES[n] for n in names])
        mixed = await self._seed_cases(db_session, [self._with_summary(_SUFFICIENCY_FIXTURES[n]) if i % 2 else _SUFFICIENCY_FIXTURES[n]
                                                    for i, n in enumerate(names)])
        all_new = await self._seed_cases(db_session, [self._with_summary(_SUFFICIENCY_FIXTURES[n]) for n in names])
        with _StatementCounter(db_session) as new_only:
            out_new = await svc.case_sufficiency_summaries(db_session, all_new)
        assert len(new_only.statements) == 1
        with _StatementCounter(db_session) as first:
            out_mixed = await svc.case_sufficiency_summaries(db_session, mixed)
        assert len(first.statements) == 2
        with _StatementCounter(db_session) as second:
            out_mixed_again = await svc.case_sufficiency_summaries(db_session, mixed)
        assert len(second.statements) == 1                              # the memo answers the legacy rows: no Query B
        svc._LEGACY_MEMO.clear()
        out_old = await svc.case_sufficiency_summaries(db_session, all_old)

        def by_pos(out, ids):
            return [out.get(i) for i in ids]

        assert by_pos(out_mixed, mixed) == by_pos(out_old, all_old) == by_pos(out_new, all_new) == by_pos(out_mixed_again, mixed)
        assert sum(v is not None for v in by_pos(out_old, all_old)) == 4

    @pytest.mark.anyio
    async def test_unsummarisable_marker_is_not_assessed_and_does_not_fall_back(self, db_session):
        import app.services.multisource_investigation_service as svc

        marker = {"schema": 1, "verdict": None, "rule_version": None, "truncated": None}
        (cid,) = await self._seed_cases(db_session, [{**_SUFFICIENCY_FIXTURES["single"], "verdict_summary": marker}])
        with _StatementCounter(db_session) as cnt:
            out = await svc.case_sufficiency_summaries(db_session, [cid])
        assert out == {} and len(cnt.statements) == 1

    @pytest.mark.anyio
    @pytest.mark.parametrize("bad", [
        {"schema": 2, "verdict": "insufficient", "rule_version": "x", "truncated": False},
        {"schema": True, "verdict": "insufficient", "rule_version": "x", "truncated": False},
        {"schema": 1, "verdict": "insufficient", "rule_version": 5, "truncated": False},
        {"schema": 1, "verdict": "insufficient", "rule_version": "x", "truncated": "no"},
        {"schema": 1, "verdict": "probably_fine", "rule_version": "x", "truncated": False},
        {"schema": 1, "verdict": ["insufficient"], "rule_version": "x", "truncated": False},
        {"schema": 1, "verdict": "insufficient"},
        "insufficient",
        [],
    ])
    async def test_invalid_summary_falls_back_to_the_full_row(self, db_session, bad):
        import app.services.multisource_investigation_service as svc

        (cid,) = await self._seed_cases(db_session, [{**_SUFFICIENCY_FIXTURES["single"], "verdict_summary": bad}])
        with _StatementCounter(db_session) as cnt:
            out = await svc.case_sufficiency_summaries(db_session, [cid])
        assert len(cnt.statements) == 2 and out[cid]["sufficiency_verdict"].value == "sufficient"

    @pytest.mark.anyio
    async def test_legacy_memo_is_bounded_and_evicts_oldest(self, monkeypatch):
        import app.services.multisource_investigation_service as svc

        monkeypatch.setattr(svc, "_LEGACY_MEMO_MAX", 2)
        a, b, c = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        for key in (a, b, c):
            svc._remember_legacy(key, None)
        assert list(svc._LEGACY_MEMO) == [b, c]

    @pytest.mark.anyio
    async def test_gate_is_never_called_on_the_read_path_or_in_compact_verdict(self, db_session, monkeypatch):
        import app.modules.ai.guardrails.sufficiency_gate as gate
        import app.modules.correlation.workflow as wf
        import app.services.case_service as cs
        import app.services.multisource_investigation_service as svc

        calls: list[int] = []

        def boom(*a, **k):
            calls.append(1)
            raise AssertionError("evaluate_sufficiency must not run on the read path")

        for mod in (gate, wf, cs):
            monkeypatch.setattr(mod, "evaluate_sufficiency", boom)
        ids = await self._seed_cases(db_session, [_SUFFICIENCY_FIXTURES["worst_of"], self._with_summary(_SUFFICIENCY_FIXTURES["worst_of"])])
        out = await svc.case_sufficiency_summaries(db_session, ids)
        assert len(out) == 2 and svc._compact_verdict(_SUFFICIENCY_FIXTURES["worst_of"])["verdict"] == "insufficient"
        assert (await CaseService().get_case_detail(db_session, ids[1])).sufficiency_verdict.value == "insufficient"
        assert calls == []

    @pytest.mark.anyio
    @pytest.mark.parametrize("cap", [None, 1])
    async def test_build_payload_carries_the_verdict_summary_without_calling_the_gate(self, monkeypatch, cap):
        import app.modules.ai.guardrails.sufficiency_gate as gate
        import app.modules.correlation.workflow as wf
        import app.services.case_service as cs
        import app.services.multisource_investigation_service as svc
        from app.modules.correlation import demo_data as dd
        from app.schemas.multisource import MultiSourceSection

        if cap is not None:
            monkeypatch.setattr(svc, "MAX_STORED_INCIDENTS", cap)
        result = await wf.run_workflow(dd.intrusion_chain() + dd.uncorroborated_single_alert(), None)
        calls: list[int] = []

        def boom(*a, **k):
            calls.append(1)
            raise AssertionError("build_payload must not call the gate")

        for mod in (gate, wf, cs):
            monkeypatch.setattr(mod, "evaluate_sufficiency", boom)
        payload = svc.MultiSourceInvestigationService().build_payload(result, "f" * 64, False)
        core = svc._verdict_core(payload)
        assert core is not None and calls == []
        assert payload["verdict_summary"] == {"schema": 1, "verdict": core["verdict"].value, "rule_version": core["rule_version"],
                                              "truncated": core["truncated"]}
        if cap == 1:
            assert len(payload["incidents"]) == 1 and payload["verdict_summary"]["truncated"] is True
        # The additive key does not leak into the explicit-dictionary views.
        for section in MultiSourceSection:
            assert "verdict_summary" not in svc.MultiSourceInvestigationService.section_view(payload, section, False)
        assert "verdict_summary" not in svc.activity_summary(payload)

    @pytest.mark.anyio
    async def test_json_path_round_trips_a_dict_and_a_missing_key_is_none(self, db_session):
        from app.services.multisource_investigation_service import _latest_verdict_query

        d = _SUFFICIENCY_FIXTURES["single"]
        with_key, without = await self._seed_cases(db_session, [self._with_summary(d), d])
        rows = {r[0]: r[3] for r in (await db_session.execute(_latest_verdict_query([with_key, without]))).all()}
        assert rows[with_key] == {"schema": 1, "verdict": "sufficient", "rule_version": "suff-v5", "truncated": False}
        assert rows[without] is None

    @pytest.mark.anyio
    async def test_postgresql_query_a_reads_details_only_through_the_json_path(self):
        import re

        from app.services.multisource_investigation_service import _latest_verdict_query

        stmt = _latest_verdict_query([uuid.uuid4()])
        sql = str(stmt.compile(dialect=postgresql.dialect()))
        assert "case_audit_events.details" in sql
        assert not re.search(r"case_audit_events\.details(?!\[)", sql), sql        # subscript form (PostgreSQL 14+)
        older = postgresql.dialect()
        older._supports_jsonb_subscripting = False                                # server older than 14: arrow form
        sql13 = str(stmt.compile(dialect=older))
        assert "case_audit_events.details ->" in sql13
        assert not re.search(r"case_audit_events\.details(?! ->)", sql13), sql13

    @pytest.mark.anyio
    async def test_query_a_transfers_about_a_hundred_bytes_per_new_row(self, db_session):
        import json

        from app.services.multisource_investigation_service import _latest_verdict_query

        pad = "x" * 600_000
        specs = [self._with_summary({**_SUFFICIENCY_FIXTURES["single"], "report_markdown": pad}) for _ in range(20)]
        ids = await self._seed_cases(db_session, specs)
        assert len(json.dumps(specs[0])) > 600_000
        rows = (await db_session.execute(_latest_verdict_query(ids))).all()
        assert len(rows) == 20
        for _case_id, _audit_id, _created_at, summary in rows:
            assert len(json.dumps(summary)) < 1024
