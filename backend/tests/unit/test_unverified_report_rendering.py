"""T1-B: unverified (`is_server_verified` False / no context) report rendering. Offline, deterministic, no I/O."""

from __future__ import annotations

import json
import uuid

from app.modules.ai.guardrails.validator import GuardrailDecision
from app.modules.ai.reporting.synthesizer import DeterministicReportSynthesizer
from app.schemas.investigation import ClaimCategory, FactualClaimItem, GroundingStatus, MitreAttackHypothesis
from app.schemas.report import IncidentSeverityTier
from tests.unit.test_deterministic_report_synthesizer import (
    _make_sample_context,
    _make_sample_validation_result,
)

BANNER = "UNVERIFIED SUBMITTED REPORT - REPORT VERIFICATION FAILED"
CANARY_HOST = "CANARY-HOST-7731"
CANARY_GAP = "CANARY_GAP_7731: client supplied gap"
CANARY_ACTION = "CANARY action 7731 review logs"
CANARY_TECH = "CANARY Technique 7731"
CANARY_REASON = "CANARY reasoning 7731"
CANARY_CLAIM = "CANARY claim 7731 hostile activity confirmed"


def _build(verified, with_context=True, fallback=False):
    inv, ev = uuid.uuid4(), uuid.uuid4()
    ctx = _make_sample_context(inv, ev)
    ctx = ctx.model_copy(update={"target_hosts": [CANARY_HOST]})
    claims = [
        FactualClaimItem(
            claim_id=uuid.uuid4(),
            claim_text=CANARY_CLAIM,
            category=ClaimCategory.OBSERVED_FACT,
            supporting_evidence_ids=[ev],
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
            confidence=0.95,
            analyst_notes=None,
        )
    ]
    hyps = [
        MitreAttackHypothesis(
            technique_id="T1059.001",
            technique_name=CANARY_TECH,
            tactics=["Execution"],
            supporting_event_uuids=[ev],
            confidence=0.90,
            reasoning=CANARY_REASON,
        )
    ]
    vr = _make_sample_validation_result(
        inv, ev, ctx.reproducibility.context_sha256,
        claims=claims, hypotheses=hyps, actions=[CANARY_ACTION], uncertainty_gaps=[CANARY_GAP],
        decision=GuardrailDecision.REJECT_TO_FALLBACK if fallback else GuardrailDecision.PASS,
        is_valid=not fallback,
    )
    bundle = DeterministicReportSynthesizer().synthesize_bundle(
        vr, ctx if with_context else None, is_server_verified=verified
    )
    return bundle


def test_unverified_withholds_analytics_and_severity():
    b = _build(False)
    assert b.executive_brief.incident_severity == IncidentSeverityTier.INCONCLUSIVE
    assert b.executive_brief.severity_justification.startswith("REPORT_VERIFICATION_FAILED")
    assert b.executive_brief.business_risk_statement.startswith("Not assessed")
    d = b.detection_report
    assert d.mitre_coverage_targets == []
    assert d.validated_observables == []
    assert len(d.candidate_detection_hypotheses) == 1 and "WITHHELD" in d.candidate_detection_hypotheses[0]
    assert len(d.candidate_hunting_pseudocode) == 1 and "WITHHELD" in d.candidate_hunting_pseudocode[0]
    assert "T1059.001" not in "".join(d.candidate_detection_hypotheses + d.candidate_hunting_pseudocode)
    assert b.executive_brief.evidenced_affected_assets and CANARY_HOST not in b.executive_brief.evidenced_affected_assets[0]
    assert b.technical_report.investigation_timeline == []
    assert b.technical_report.threat_intelligence_enrichment == []
    assert b.executive_brief.key_confirmed_findings == []


def test_unverified_client_gaps_withheld_and_server_gap_kept():
    b = _build(False)
    gaps = b.executive_brief.uncertainties_and_limitations
    assert not any("CANARY_GAP_7731" in g for g in gaps)
    assert any(g.startswith("REPORT_VERIFICATION_FAILED") for g in gaps)
    assert b.technical_report.investigation_gaps == gaps


def test_unverified_labels_and_prefixes():
    b = _build(False)
    assert b.executive_brief.executive_summary.startswith("[SUBMITTED MATERIAL - NOT VERIFIED BY AISOP]")
    assert b.technical_report.technical_narrative.startswith("[SUBMITTED MATERIAL - NOT VERIFIED BY AISOP]")
    assert all(a.startswith("[UNVERIFIED SUGGESTION]") for a in b.technical_report.recommended_analyst_actions)
    for m in b.technical_report.mitre_attack_mappings:
        assert m["verification_state"] == "SUBMITTED_NOT_VERIFIED"
    assert b.technical_report.model_identifier == "ollama/llama3.1:8b"


def test_unverified_reason_field_and_banner_in_all_markdown():
    b = _build(False)
    assert b.provenance.analytics_withheld_reason.startswith("REPORT_VERIFICATION_FAILED")
    assert b.detection_report.analytics_withheld_reason == b.provenance.analytics_withheld_reason
    assert b.provenance.is_verified_investigation is False
    for md in (b.markdown_executive, b.markdown_technical, b.markdown_detection):
        assert md.startswith(BANNER)
    assert "not an AISOP guardrail decision" not in b.markdown_executive  # flag not set here


def test_unverified_fallback_flag_labelled_not_asserted_as_guardrail():
    b = _build(False, fallback=True)
    assert b.executive_brief.is_inconclusive_or_fallback is True
    assert "not an AISOP guardrail decision" in b.markdown_executive
    assert "rejected by safety guardrails" not in b.markdown_executive
    assert "rejected by safety guardrails" not in b.markdown_technical


def test_unverified_no_context_detached_path():
    b = _build(False, with_context=False)
    assert b.provenance.is_detached_format_mode is True
    assert "detached" in b.executive_brief.severity_justification
    assert any(g.startswith("TELEMETRY_UNAVAILABLE") for g in b.executive_brief.uncertainties_and_limitations)
    assert b.markdown_technical.startswith(BANNER)


def test_unverified_markdown_shows_no_submitted_analytics():
    b = _build(False)
    for md in (b.markdown_executive, b.markdown_technical, b.markdown_detection):
        assert CANARY_HOST not in md
        assert CANARY_GAP not in md
    assert "T1059.001" not in b.markdown_detection


def test_verified_path_unchanged_and_field_absent():
    b = _build(True)
    assert b.provenance.analytics_withheld_reason is None
    dumped = json.dumps(b.model_dump(mode="json"))
    assert "analytics_withheld_reason" not in dumped
    assert "verification_state" not in dumped
    assert BANNER not in b.markdown_executive + b.markdown_technical + b.markdown_detection
    assert CANARY_HOST in b.executive_brief.evidenced_affected_assets
    assert "T1059.001" in b.detection_report.mitre_coverage_targets
    assert any(CANARY_GAP == g for g in b.executive_brief.uncertainties_and_limitations)
    assert not b.executive_brief.executive_summary.startswith("[SUBMITTED")
    assert not any(a.startswith("[UNVERIFIED SUGGESTION]") for a in b.technical_report.recommended_analyst_actions)


def test_unverified_json_contains_reason_key():
    b = _build(False)
    d = b.model_dump(mode="json")
    assert d["provenance"]["analytics_withheld_reason"].startswith("REPORT_VERIFICATION_FAILED")
    assert d["detection_report"]["analytics_withheld_reason"].startswith("REPORT_VERIFICATION_FAILED")


def test_unverified_output_is_deterministic():
    inv, ev = uuid.uuid4(), uuid.uuid4()
    ctx = _make_sample_context(inv, ev)
    vr = _make_sample_validation_result(inv, ev, ctx.reproducibility.context_sha256)
    s = DeterministicReportSynthesizer()
    a = s.synthesize_bundle(vr, ctx, is_server_verified=False)
    c = s.synthesize_bundle(vr, ctx, is_server_verified=False)
    assert a.model_dump(mode="json") == c.model_dump(mode="json")
