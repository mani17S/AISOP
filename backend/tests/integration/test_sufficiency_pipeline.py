"""
Stage 3C (ADR-008): service-level integration tests for the pre-model sufficiency gate.

Offline (in-memory SQLite ``db_session``): a call-counting mock provider proves that
INSUFFICIENT and gate-failure paths never invoke the model, that LIMITED evidence reaches
the model with a fixed-text limitation notice, and that abstentions are recorded in the
existing audit schema (no migration) with fixed-vocabulary details.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.core.rbac import AuthenticatedAnalyst, CaseRole, GlobalRole
from app.models.analyst import Analyst
from app.models.case import CaseAssignmentModel, CaseAuditEventModel, CaseEvidenceModel, CaseModel
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.ai.guardrails import GuardrailDecision
from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency
from app.schemas.case import CaseInvestigationSynthesizeRequest
from app.schemas.investigation import InvestigationSynthesizeRequest
from app.schemas.sufficiency import SufficiencyVerdict
from app.services.case_service import CaseService
from app.services.investigation_service import InvestigationPipelineService
from tests.integration.test_investigation_pipeline import MockLLMProvider, seed_test_event

T_START = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
T_END = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _request() -> InvestigationSynthesizeRequest:
    return InvestigationSynthesizeRequest(time_window_start=T_START, time_window_end=T_END)


def _user_prompt(provider: MockLLMProvider) -> str:
    return provider.calls[0].messages[1].content


# ── Non-case investigation pipeline ───────────────────────────────────────────
@pytest.mark.anyio
async def test_zero_evidence_abstains_without_any_model_call(db_session):
    provider = MockLLMProvider()
    result, context = await InvestigationPipelineService(llm_provider=provider).synthesize_investigation_with_context(
        db_session, _request()
    )
    assert provider.calls == []
    assert result.decision == GuardrailDecision.REJECT_TO_FALLBACK and result.is_valid is False
    assert result.output.model_identifier == "deterministic_fallback" and result.output.claims == []
    assert "abstention" in result.output.investigation_summary.lower()
    assert any(f.startswith("ABSTENTION:") and "NO_EVIDENCE" in f for f in result.output.uncertainty_and_data_gaps)
    assert evaluate_sufficiency(context).verdict == SufficiencyVerdict.INSUFFICIENT


@pytest.mark.anyio
async def test_gate_failure_fails_closed_and_never_calls_the_model(db_session, monkeypatch):
    import app.modules.ai.guardrails.sufficiency_gate as gate

    def boom(_ctx):
        raise RuntimeError("internal gate failure with sensitive-looking detail")

    monkeypatch.setattr(gate, "assess_evidence_sufficiency", boom)
    await seed_test_event(db_session, event_time=datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc))
    provider = MockLLMProvider()
    result, _ = await InvestigationPipelineService(llm_provider=provider).synthesize_investigation_with_context(
        db_session, _request()
    )
    assert provider.calls == []
    assert result.output.model_identifier == "deterministic_fallback"
    blob = result.output.investigation_summary + " ".join(result.output.uncertainty_and_data_gaps)
    assert "GATE_EVALUATION_ERROR" in blob and "sensitive-looking" not in blob


@pytest.mark.anyio
async def test_insufficient_verdict_from_the_gate_blocks_the_provider(db_session, monkeypatch):
    import app.services.investigation_service as svc
    from app.modules.ai.guardrails.sufficiency_gate import _error_assessment

    await seed_test_event(db_session, event_time=datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc))
    monkeypatch.setattr(svc, "evaluate_sufficiency", lambda ctx: _error_assessment(ctx))
    provider = MockLLMProvider()
    result, _ = await InvestigationPipelineService(llm_provider=provider).synthesize_investigation_with_context(
        db_session, _request()
    )
    assert provider.calls == [] and result.is_valid is False


@pytest.mark.anyio
async def test_limited_evidence_reaches_the_model_with_a_fixed_limitation_note(db_session):
    await seed_test_event(db_session, event_time=datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc))
    provider = MockLLMProvider()
    _result, context = await InvestigationPipelineService(llm_provider=provider).synthesize_investigation_with_context(
        db_session, _request()
    )
    assessment = evaluate_sufficiency(context)
    assert assessment.verdict == SufficiencyVerdict.LIMITED
    assert len(provider.calls) >= 1
    prompt = _user_prompt(provider)
    assert "[EVIDENCE LIMITATION - system generated]" in prompt
    assert "UNCORROBORATED_QUESTION" in prompt


@pytest.mark.anyio
async def test_entity_linked_evidence_is_sufficient_and_the_prompt_is_unchanged(db_session):
    raw1, ev1 = await seed_test_event(db_session, event_time=datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc))
    raw2, ev2 = await seed_test_event(db_session, event_time=datetime(2026, 10, 23, 10, 5, 0, tzinfo=timezone.utc),
                                      sha256_hash="e" * 64)
    # Stage 5 (suff-v3): a second event of the SAME kind on the same host is a repeated observation, not corroboration;
    # the corroborating event is a different kind of observation (a network connection) sharing the domain.
    ev2.event_id, ev2.event_type = "3", "network_connection"
    for ev, raw in ((ev1, raw1), (ev2, raw2)):
        db_session.add(ExtractedEntityModel(
            id=uuid.uuid4(), event_id=ev.id, raw_evidence_id=raw.id,
            entity_type="domain", entity_value="c2.badcdn.example", role="destination", attributes={},
        ))
        db_session.add(ExtractedEntityModel(
            id=uuid.uuid4(), event_id=ev.id, raw_evidence_id=raw.id,
            entity_type="process", entity_value="powershell.exe", role="child", attributes={},
        ))
    await db_session.commit()
    provider = MockLLMProvider()
    _result, context = await InvestigationPipelineService(llm_provider=provider).synthesize_investigation_with_context(
        db_session, _request()
    )
    assessment = evaluate_sufficiency(context)
    assert assessment.verdict == SufficiencyVerdict.SUFFICIENT, assessment.reason_codes
    assert len(provider.calls) >= 1
    assert "EVIDENCE LIMITATION" not in _user_prompt(provider)


# ── Case investigation path with audit persistence ────────────────────────────
async def _seed_case(db_session, *, with_evidence: bool):
    now = datetime.now(timezone.utc)
    analyst_id, case_id = uuid.uuid4(), uuid.uuid4()
    db_session.add(Analyst(id=analyst_id, username=f"suff_{analyst_id.hex[:6]}", email=f"{analyst_id.hex[:6]}@aisop.local",
                           global_role=GlobalRole.ANALYST_TIER_2.value, is_active=True, created_at=now, updated_at=now))
    db_session.add(CaseModel(id=case_id, case_number=f"CASE-SUFF-{case_id.hex[:6]}", title="Sufficiency audit case",
                             description="Stage 3C", severity="high", status="open", created_at=now, updated_at=now))
    db_session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case_id, analyst_id=analyst_id,
                                       case_role=CaseRole.LEAD.value, assigned_at=now))
    if with_evidence:
        raw = RawEvidence(id=uuid.uuid4(), source_type="sysmon", source_identifier="host-suff-01",
                          raw_payload={"Event": {"System": {"EventID": 1}}}, sha256_hash="f" * 64, ingested_at=now)
        db_session.add(raw)
        ev = NormalizedEventModel(id=uuid.uuid4(), raw_evidence_id=raw.id, event_id="1", event_type="process_creation",
                                  event_timestamp=now, action="start", outcome="success", severity="medium",
                                  provider="sysmon", normalized_payload={"process": "cmd.exe"})
        db_session.add(ev)
        db_session.add(CaseEvidenceModel(id=uuid.uuid4(), case_id=case_id, evidence_id=ev.id,
                                         linked_by_analyst_id=analyst_id, linked_at=now))
    await db_session.commit()
    actor = AuthenticatedAnalyst(analyst_id=analyst_id, username=f"suff_{analyst_id.hex[:6]}",
                                 global_role=GlobalRole.ANALYST_TIER_2, is_active=True)
    return case_id, actor


async def _audit(db_session, case_id):
    rows = (await db_session.execute(select(CaseAuditEventModel).where(CaseAuditEventModel.case_id == case_id))).scalars().all()
    return [r for r in rows if r.action == "case_investigation_synthesized"]


@pytest.mark.anyio
async def test_case_without_evidence_abstains_and_is_audited_without_a_migration(db_session):
    case_id, actor = await _seed_case(db_session, with_evidence=False)
    provider = MockLLMProvider()
    result, _ = await CaseService().synthesize_case_investigation(
        session=db_session, case_id=case_id, actor=actor,
        request=CaseInvestigationSynthesizeRequest(), llm_provider=provider,
    )
    assert provider.calls == []
    assert result.output.model_identifier == "deterministic_fallback"
    audit = await _audit(db_session, case_id)
    assert len(audit) == 1
    d = audit[0].details
    assert d["abstained"] is True and d["sufficiency_verdict"] == "insufficient"
    assert d["sufficiency_reason_codes"] == ["NO_EVIDENCE"]
    assert len(d["sufficiency_assessment_sha256"]) == 64
    assert d["fallback_reason"].startswith("Evidence assessed INSUFFICIENT")


@pytest.mark.anyio
async def test_case_with_limited_evidence_calls_the_model_and_audits_the_verdict(db_session):
    case_id, actor = await _seed_case(db_session, with_evidence=True)
    provider = MockLLMProvider()
    await CaseService().synthesize_case_investigation(
        session=db_session, case_id=case_id, actor=actor,
        request=CaseInvestigationSynthesizeRequest(), llm_provider=provider,
    )
    assert len(provider.calls) >= 1
    d = (await _audit(db_session, case_id))[0].details
    assert d["sufficiency_verdict"] == "limited" and d["abstained"] is False
    assert "UNCORROBORATED_QUESTION" in d["sufficiency_reason_codes"]


@pytest.mark.anyio
async def test_case_gate_failure_fails_closed_and_is_audited(db_session, monkeypatch):
    import app.modules.ai.guardrails.sufficiency_gate as gate

    def boom(_ctx):
        raise RuntimeError("detail that must not be persisted")

    monkeypatch.setattr(gate, "assess_evidence_sufficiency", boom)
    case_id, actor = await _seed_case(db_session, with_evidence=True)
    provider = MockLLMProvider()
    await CaseService().synthesize_case_investigation(
        session=db_session, case_id=case_id, actor=actor,
        request=CaseInvestigationSynthesizeRequest(), llm_provider=provider,
    )
    assert provider.calls == []
    d = (await _audit(db_session, case_id))[0].details
    assert d["abstained"] is True and d["sufficiency_reason_codes"] == ["GATE_EVALUATION_ERROR"]
    assert "must not be persisted" not in str(d)
