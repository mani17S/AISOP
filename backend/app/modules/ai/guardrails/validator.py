"""
AISOP Output Guardrails and Claim Grounding Validator.

Implements P2-H4 Task 2.4:
- 3-Tier Claim Grounding (Tier 1: Reference Existence, Tier 2: Information Containment, Tier 3: Review Flagging).
- Context and Hash Immutability Verification.
- Epistemic Category Consistency (observed_fact vs external_intelligence vs inference vs unknown).
- Outcome Polarization Contradiction Detection.
- MITRE ATT&CK Technique Validation and Behavioral Evidence Grounding.
- Advisory Action Safety (prohibited command execution scrubbing).
- Fail-Safe Tri-State Disposition (PASS, REMEDIATED, REJECT_TO_FALLBACK).
- Deterministic Auditability and Reproducibility.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
import re
from typing import Any, Callable, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.modules.ai.context_builder.hasher import compute_context_sha256
from app.modules.ai.response_parser.parser import InvestigationResponseParser
from app.modules.ai.guardrails.sufficiency_gate import evidence_clusters_for_context
from app.modules.ai.guardrails.claim_verifier import verify_claim
from app.schemas.contradiction import Materiality
from app.modules.evidence.independence import independent_groups
from app.schemas.sufficiency import EvidenceSufficiencyAssessment, SufficiencyVerdict
from app.modules.ai.guardrails import attack_policy as _attack
from app.modules.ai.guardrails.attack_policy import AttackReferenceSource
from app.schemas.investigation import (
    ClaimCategory,
    ContextTIThreatState,
    FactualClaimItem,
    GroundingStatus,
    InvestigationContext,
    MitreAttackHypothesis,
    StructuredInvestigationOutput,
)


class GuardrailDecision(StrEnum):
    """Overall disposition of guardrail validation."""
    PASS = "pass"
    REMEDIATED = "remediated"
    REJECT_TO_FALLBACK = "reject_to_fallback"


class ViolationSeverity(StrEnum):
    """Severity classification of guardrail violations."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class GuardrailViolation(BaseModel):
    """Immutable audit record of a detected guardrail violation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Field(description="Identifier of the triggered guardrail rule")
    severity: ViolationSeverity = Field(description="Violation severity level")
    target_field: str = Field(description="Affected schema field or path")
    description: str = Field(description="Detailed explanation of the violation")
    remediation_applied: Optional[str] = Field(default=None, description="Remediation applied if any")


class InvestigationValidationResult(BaseModel):
    """Immutable, auditable output contract for the guardrail validation pipeline."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: GuardrailDecision = Field(description="Final guardrail disposition")
    is_valid: bool = Field(description="True if output is acceptable for human analyst review")
    output: StructuredInvestigationOutput = Field(description="Validated or remediated report")
    violations: list[GuardrailViolation] = Field(default_factory=list, description="Ordered audit violations")
    context_sha256: str = Field(description="Verified forensic context SHA-256 digest")
    validated_at_utc: datetime = Field(description="UTC validation timestamp")


# ── REGEX PATTERNS ───────────────────────────────────────────────────────────
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_EXECUTABLE_RE = re.compile(r"\b[\w\-\.]+\.(?:exe|dll|ps1|bat|cmd|sh|vbs|py|sys|scr)\b", re.IGNORECASE)
_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_DANGEROUS_COMMAND_RE = re.compile(
    r"(?i)\b(?:iex|invoke-expression|invoke-restmethod|invoke-webrequest|downloadstring|"
    r"curl\s+[^\n|]*?\|\s*(?:bash|sh)|wget\s+[^\n|]*?\|\s*(?:bash|sh)|"
    r"powershell(?:\.exe)?\s+-[^\n]*?(?:enc|encodedcommand)|format\s+[a-z]:|"
    r"rm\s+-rf|drop\s+table|delete\s+from\s+\w+|mkfs\b|dd\s+if=)",
)

_SUCCESS_WORDS_RE = re.compile(
    r"\b(?:successfully|succeeded|achieved code execution|execution succeeded|"
    r"login succeeded|authenticated successfully|access granted|allowed)\b",
    re.IGNORECASE,
)
_FAILURE_WORDS_RE = re.compile(
    r"\b(?:failed to|was blocked|was denied|blocked by|prevented|execution failed|"
    r"login failed|access denied|terminated)\b",
    re.IGNORECASE,
)

# ── CREDENTIAL & SECRET LEAKAGE PATTERNS (OWASP GenAI LLM02) ─────────────────
_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"), "[REDACTED_JWT_TOKEN]"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\b(?:aisop_[a-zA-Z0-9]{16,}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"(?i)\b(password|passwd|secret|api_key|access_token)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?"), r"\1=[REDACTED_SECRET]"),
]


def _sanitize_secrets(text: str) -> tuple[str, list[str]]:
    """
    Scrub sensitive credentials, tokens, and private keys from LLM output.
    Returns: (sanitized_text, list_of_redaction_descriptions)
    """
    redactions: list[str] = []
    sanitized = text
    for pattern, repl in _SECRET_PATTERNS:
        matches = pattern.findall(sanitized)
        if matches:
            redactions.append(f"Redacted {len(matches)} secret pattern(s)")
            sanitized = pattern.sub(repl, sanitized)
    return sanitized, redactions


_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "in", "on", "at", "to", "for", "of", "with",
    "by", "from", "as", "is", "was", "were", "are", "be", "been", "has", "have",
    "had", "it", "this", "that", "these", "those", "not", "no", "observed",
    "detected", "event", "user", "host", "system", "process", "activity"
})


def _extract_candidate_observables(text: str) -> set[str]:
    """Extract candidate observable tokens (IPs, hashes, executable names) from text."""
    observables: set[str] = set()
    for ip in _IPV4_RE.findall(text):
        try:
            ipaddress.ip_address(ip)
            observables.add(ip.lower())
        except ValueError:
            pass
    for h in _HASH_RE.findall(text):
        if len(h) in (32, 40, 64):
            observables.add(h.lower())
    for exe in _EXECUTABLE_RE.findall(text):
        observables.add(exe.lower())
    return observables


def _extract_content_tokens(text: str) -> set[str]:
    """Extract lowercased non-stopword tokens of length >= 3 from text."""
    words = re.findall(r"\b[a-zA-Z0-9_\-\.]{3,}\b", text.lower())
    return {w for w in words if w not in _STOPWORDS}


def _attach_claim_verification(claims: list[Any], context: Any, sufficiency: Any) -> list[Any]:
    """
    Task 1: attach ``ClaimVerification`` to every claim that carries structured assertions; claims without assertions are returned untouched
    (so historical claims and their digests are unchanged). Never raises: a failure leaves the claims exactly as they were.
    """
    try:
        if not any(c.assertions for c in claims):
            return claims
        try:
            clusters: Any = evidence_clusters_for_context(context)
        except Exception:  # noqa: BLE001 - distinct_evidence assertions then report CLUSTERS_UNAVAILABLE (not_verifiable)
            clusters = None
        contested: frozenset[str] = frozenset()
        if sufficiency is not None:
            contested = frozenset(
                str(i) for f in getattr(sufficiency, "contradictions", []) if f.materiality == Materiality.MATERIAL for i in f.evidence_ids
            )
        return [
            c.model_copy(update={"verification": verify_claim(c, context, clusters=clusters, contested_event_ids=contested)}) if c.assertions else c
            for c in claims
        ]
    except Exception:  # noqa: BLE001
        return claims


class InvestigationOutputValidator:
    """
    Authoritative, deterministic output validator and guardrail enforcement engine.
    """

    def __init__(
        self,
        clock: Optional[Callable[[], datetime]] = None,
        strict_mode: bool = False,
        attack_reference: AttackReferenceSource = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._strict_mode = strict_mode
        # Optional local ATT&CK reference (injected, never loaded here). None = not configured: behaviour is unchanged
        # except that successor-technique claims always need structured evidence (4E).
        self._attack_state, self._attack_catalogue = _attack.resolve_reference(attack_reference)

    @property
    def attack_reference_state(self) -> str:
        """'available', 'unavailable' (requested but not loaded) or 'not_configured'. Explicit, never 'valid'."""
        return self._attack_state.value

    def validate(
        self,
        output: StructuredInvestigationOutput,
        context: InvestigationContext,
        sufficiency: "EvidenceSufficiencyAssessment | None" = None,
    ) -> InvestigationValidationResult:
        """
        Validate and guardrail StructuredInvestigationOutput against immutable InvestigationContext.

        ``sufficiency`` (Stage 3C, ADR-008) is the optional pre-model evidence-sufficiency
        assessment. When its verdict is LIMITED, inference claims that rest on fewer than two
        distinct cited events are demoted to ANALYST_REVIEW_REQUIRED so partial support is not
        presented as a definitive conclusion. When None, behaviour is unchanged.
        """
        validation_time = self._clock()
        violations: list[GuardrailViolation] = []
        is_fallback_required = False
        fallback_reason = ""

        # ── 1. CONTEXT INTEGRITY & ID MATCHING ───────────────────────────────
        if output.investigation_id != context.investigation_id:
            violations.append(
                GuardrailViolation(
                    rule_id="SEC-GR-ID-MISMATCH",
                    severity=ViolationSeverity.CRITICAL,
                    target_field="investigation_id",
                    description=(
                        f"Returned investigation_id '{output.investigation_id}' does not match "
                        f"context.investigation_id '{context.investigation_id}'"
                    ),
                    remediation_applied="Triggered deterministic fallback",
                )
            )
            is_fallback_required = True
            fallback_reason = "Investigation ID mismatch"

        expected_hash = compute_context_sha256(context)
        if context.reproducibility.context_sha256 != expected_hash:
            violations.append(
                GuardrailViolation(
                    rule_id="SEC-GR-HASH-MISMATCH",
                    severity=ViolationSeverity.CRITICAL,
                    target_field="context_sha256",
                    description="InvestigationContext SHA-256 digest fails cryptographic verification",
                    remediation_applied="Triggered deterministic fallback",
                )
            )
            is_fallback_required = True
            fallback_reason = "Forensic context hash integrity failure"

        if is_fallback_required:
            fallback_output = InvestigationResponseParser().build_deterministic_fallback(
                context, fallback_reason
            )
            return InvestigationValidationResult(
                decision=GuardrailDecision.REJECT_TO_FALLBACK,
                is_valid=False,
                output=fallback_output,
                violations=violations,
                context_sha256=context.reproducibility.context_sha256,
                validated_at_utc=validation_time,
            )

        # ── 2. PRE-BUILD EVIDENCE LOOKUP TABLES ──────────────────────────────
        events_by_uuid = {e.event_uuid: e for e in context.events}
        context_event_uuids = set(events_by_uuid.keys())

        # Collect event text tokens and candidate observables per event UUID
        event_tokens: dict[uuid.UUID, set[str]] = {}
        event_observables: dict[uuid.UUID, set[str]] = {}
        for ev in context.events:
            combined_text = f"{ev.summary} {ev.action} {ev.outcome} {ev.source_identifier}"
            for k, v in ev.attributes.items():
                combined_text += f" {k} {v}"
            # Also attach associated entities
            for ent in context.entities:
                if ev.event_uuid in ent.associated_event_uuids:
                    combined_text += f" {ent.entity_value} {ent.entity_type}"

            event_tokens[ev.event_uuid] = _extract_content_tokens(combined_text)
            event_observables[ev.event_uuid] = _extract_candidate_observables(combined_text)

        # Collect threat intel observables
        ti_by_observable = {ti.observable.lower(): ti for ti in context.threat_intel}

        # ── 3. CLAIMS GROUNDING & CATEGORY VALIDATION ────────────────────────
        remediated_claims: list[FactualClaimItem] = []
        # Evidence clusters (duplicates / same raw record / near-duplicates count once), used by
        # the LIMITED-evidence rule 3E. Only computed when that rule can apply.
        limited_clusters: dict[uuid.UUID, int] = (
            evidence_clusters_for_context(context)
            if sufficiency is not None and sufficiency.verdict == SufficiencyVerdict.LIMITED
            else {}
        )

        for idx, claim in enumerate(output.claims):
            claim_field = f"claims[{idx}]"
            claim_text = claim.claim_text
            clean_text, secret_redactions = _sanitize_secrets(claim_text)
            if secret_redactions:
                claim_text = clean_text
                violations.append(
                    GuardrailViolation(
                        rule_id="SEC-GR-CREDENTIAL-LEAKAGE",
                        severity=ViolationSeverity.HIGH,
                        target_field=f"{claim_field}.claim_text",
                        description=f"Detected sensitive credential or secret pattern in claim text: {secret_redactions}",
                        remediation_applied="Redacted sensitive secret pattern to [REDACTED_*]",
                    )
                )

            category = claim.category
            grounding_status = claim.grounding_status
            confidence = claim.confidence
            supporting_ids = list(claim.supporting_evidence_ids)
            analyst_notes = claim.analyst_notes or ""

            # 3A. Tier 1: Reference Existence
            valid_supporting_ids = [u for u in supporting_ids if u in context_event_uuids]
            invalid_ids_count = len(supporting_ids) - len(valid_supporting_ids)
            has_invalid_ids = invalid_ids_count > 0
            is_empty_ids = len(supporting_ids) == 0

            # A claim with no supporting evidence is only a violation if it claims references exist,
            # or is marked anything other than UNSUPPORTED, or has non-zero confidence.
            is_unsupported_compliant = (
                is_empty_ids
                and not has_invalid_ids
                and claim.references_exist is False
                and claim.grounding_status == GroundingStatus.UNSUPPORTED
                and claim.confidence == 0.0
            )

            if (has_invalid_ids or is_empty_ids) and not is_unsupported_compliant:
                grounding_status = GroundingStatus.UNSUPPORTED
                confidence = 0.0
                references_exist = False
                if "[UNSUPPORTED:" not in analyst_notes:
                    analyst_notes = (analyst_notes + " [UNSUPPORTED: Nonexistent or empty evidence UUIDs]").strip()
                desc = (
                    f"Claim cites {invalid_ids_count} nonexistent event UUID(s)"
                    if has_invalid_ids
                    else "Claim has empty supporting evidence IDs with non-zero confidence or invalid status"
                )
                violations.append(
                    GuardrailViolation(
                        rule_id="SEC-GR-TIER1-REF-MISSING",
                        severity=ViolationSeverity.HIGH,
                        target_field=f"{claim_field}.supporting_evidence_ids",
                        description=desc,
                        remediation_applied="Demoted to UNSUPPORTED, confidence zeroed",
                    )
                )
                supporting_ids = valid_supporting_ids
            else:
                references_exist = bool(valid_supporting_ids)

            # 3B. Outcome Polarization Contradiction Check
            if references_exist and supporting_ids:
                has_contradiction = False
                for u in supporting_ids:
                    ev = events_by_uuid[u]
                    is_ev_failure = ev.outcome.lower() in ("failure", "failed") or ev.action.lower() in (
                        "blocked", "denied", "prevented"
                    )
                    is_ev_success = ev.outcome.lower() in ("success", "succeeded") or ev.action.lower() in (
                        "allowed", "start", "spawn"
                    )

                    if is_ev_failure and _SUCCESS_WORDS_RE.search(claim_text):
                        has_contradiction = True
                        break
                    if is_ev_success and _FAILURE_WORDS_RE.search(claim_text):
                        has_contradiction = True
                        break

                if has_contradiction:
                    if claim.grounding_status != GroundingStatus.CONTRADICTED or claim.confidence > 0.0:
                        grounding_status = GroundingStatus.CONTRADICTED
                        confidence = 0.0
                        if "[CONTRADICTED:" not in analyst_notes:
                            analyst_notes = (analyst_notes + " [CONTRADICTED: Telemetry outcome directly contradicts claim assertion]").strip()
                        violations.append(
                            GuardrailViolation(
                                rule_id="SEC-GR-CONTRADICTED-OUTCOME",
                                severity=ViolationSeverity.HIGH,
                                target_field=f"{claim_field}.claim_text",
                                description="Claim asserts outcome polarized opposite to cited event outcome/action",
                                remediation_applied="Set status to CONTRADICTED, confidence zeroed",
                            )
                        )
                    else:
                        grounding_status = GroundingStatus.CONTRADICTED
                        confidence = 0.0

            # 3C. Tier 2: Information Containment (for non-contradicted, references_exist OBSERVED_FACT claims)
            if references_exist and grounding_status != GroundingStatus.CONTRADICTED and category == ClaimCategory.OBSERVED_FACT:
                claim_observables = _extract_candidate_observables(claim_text)
                claim_tokens = _extract_content_tokens(claim_text)

                cited_observables = set().union(*(event_observables.get(u, set()) for u in supporting_ids))
                cited_tokens = set().union(*(event_tokens.get(u, set()) for u in supporting_ids))

                # Check observable containment (IPs, hashes, executable names asserted in text must appear in evidence)
                missing_observables = claim_observables - cited_observables
                # Check general substantive evidence overlap
                token_overlap = claim_tokens.intersection(cited_tokens)

                if missing_observables:
                    if claim.grounding_status == GroundingStatus.VALIDATED_REFERENCE or claim.confidence > 0.30:
                        grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                        confidence = min(confidence, 0.30)
                        if "[TIER 2 REVIEW REQUIRED:" not in analyst_notes:
                            analyst_notes = (
                                analyst_notes + f" [TIER 2 REVIEW REQUIRED: Observables {sorted(missing_observables)} not in cited evidence]"
                            ).strip()
                        violations.append(
                            GuardrailViolation(
                                rule_id="SEC-GR-TIER2-CONTAINMENT-FAILED",
                                severity=ViolationSeverity.HIGH,
                                target_field=f"{claim_field}.claim_text",
                                description=f"Claim asserts observables {sorted(missing_observables)} not found in cited event telemetry",
                                remediation_applied="Demoted from VALIDATED_REFERENCE, confidence capped to <= 0.30",
                            )
                        )
                    else:
                        grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                        confidence = min(confidence, 0.30)
                elif not token_overlap:
                    if claim.grounding_status == GroundingStatus.VALIDATED_REFERENCE or claim.confidence > 0.30:
                        grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                        confidence = min(confidence, 0.30)
                        if "[TIER 2 REVIEW REQUIRED:" not in analyst_notes:
                            analyst_notes = (analyst_notes + " [TIER 2 REVIEW REQUIRED: Substantive claim text has zero token match with cited event]").strip()
                        violations.append(
                            GuardrailViolation(
                                rule_id="SEC-GR-TIER2-NO-EVIDENCE-MATCH",
                                severity=ViolationSeverity.HIGH,
                                target_field=f"{claim_field}.claim_text",
                                description="Claim cites valid event UUID but shares zero substantive entities or terms with the event",
                                remediation_applied="Demoted from VALIDATED_REFERENCE, confidence capped to <= 0.30",
                            )
                        )
                    else:
                        grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                        confidence = min(confidence, 0.30)

            # 3D. Epistemic Category Consistency Rules
            if category == ClaimCategory.INFERENCE:
                # An inference cannot be a VALIDATED_REFERENCE
                if claim.grounding_status == GroundingStatus.VALIDATED_REFERENCE:
                    grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                    confidence = min(confidence, 0.70)
                    if "[INFERENCE:" not in analyst_notes:
                        analyst_notes = (analyst_notes + " [INFERENCE: Analytical deductions require human analyst review; confidence capped to 0.70]").strip()
                    violations.append(
                        GuardrailViolation(
                            rule_id="SEC-GR-CATEGORY-INFERENCE-CAPPED",
                            severity=ViolationSeverity.MEDIUM,
                            target_field=f"{claim_field}.category",
                            description="Inference claims cannot be marked VALIDATED_REFERENCE; require review",
                            remediation_applied="Demoted to ANALYST_REVIEW_REQUIRED, confidence capped <= 0.70",
                        )
                    )
                elif claim.confidence > 0.70:
                    confidence = 0.70
                    violations.append(
                        GuardrailViolation(
                            rule_id="SEC-GR-INFERENCE-CONFIDENCE-CAPPED",
                            severity=ViolationSeverity.LOW,
                            target_field=f"{claim_field}.confidence",
                            description="Inference claim confidence exceeds maximum policy threshold of 0.70",
                            remediation_applied="Capped confidence to 0.70",
                        )
                    )

            elif category == ClaimCategory.EXTERNAL_INTELLIGENCE:
                # Cross-reference with context.threat_intel
                claim_obs = _extract_candidate_observables(claim_text)
                matched_ti = [ti_by_observable[o] for o in claim_obs if o in ti_by_observable]

                if not matched_ti:
                    # Unbacked external threat intelligence
                    if claim.grounding_status == GroundingStatus.VALIDATED_REFERENCE or claim.confidence > 0.40:
                        grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                        confidence = min(confidence, 0.40)
                        if "[UNBACKED TI:" not in analyst_notes:
                            analyst_notes = (analyst_notes + " [UNBACKED TI: No matching threat intelligence finding in context]").strip()
                        violations.append(
                            GuardrailViolation(
                                rule_id="SEC-GR-TI-UNBACKED",
                                severity=ViolationSeverity.HIGH,
                                target_field=f"{claim_field}.category",
                                description="Claim asserts external intelligence but observable is missing from context threat intel",
                                remediation_applied="Demoted to ANALYST_REVIEW_REQUIRED, confidence capped <= 0.40",
                            )
                        )
                    else:
                        grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                        confidence = min(confidence, 0.40)
                else:
                    for ti in matched_ti:
                        if ti.threat_state == ContextTIThreatState.SHIELDED_INTERNAL:
                            if claim.grounding_status == GroundingStatus.VALIDATED_REFERENCE or claim.confidence > 0.30:
                                grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                                confidence = min(confidence, 0.30)
                                if "[SHIELDED TI:" not in analyst_notes:
                                    analyst_notes = (analyst_notes + f" [SHIELDED TI: Observable '{ti.observable}' is internal/RFC1918]").strip()
                                violations.append(
                                    GuardrailViolation(
                                        rule_id="SEC-GR-TI-SHIELDED-INTERNAL",
                                        severity=ViolationSeverity.HIGH,
                                        target_field=f"{claim_field}.claim_text",
                                        description=f"External intelligence cited for shielded internal observable '{ti.observable}'",
                                        remediation_applied="Demoted to ANALYST_REVIEW_REQUIRED, confidence capped <= 0.30",
                                    )
                                )
                            else:
                                grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                                confidence = min(confidence, 0.30)
                        elif ti.threat_state in (ContextTIThreatState.STALE, ContextTIThreatState.ENGINE_UNAVAILABLE):
                            if claim.grounding_status == GroundingStatus.VALIDATED_REFERENCE or claim.confidence > 0.40:
                                grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                                confidence = min(confidence, 0.40)
                                if "[DEGRADED TI:" not in analyst_notes:
                                    analyst_notes = (analyst_notes + f" [DEGRADED TI: Observable '{ti.observable}' threat state is {ti.threat_state.value}]").strip()
                                violations.append(
                                    GuardrailViolation(
                                        rule_id="SEC-GR-TI-DEGRADED",
                                        severity=ViolationSeverity.MEDIUM,
                                        target_field=f"{claim_field}.claim_text",
                                        description=f"External intelligence cited for degraded/stale observable '{ti.observable}'",
                                        remediation_applied="Demoted to ANALYST_REVIEW_REQUIRED, confidence capped <= 0.40",
                                    )
                                )
                            else:
                                grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                                confidence = min(confidence, 0.40)

            elif category == ClaimCategory.UNKNOWN:
                if claim.grounding_status == GroundingStatus.VALIDATED_REFERENCE or claim.confidence > 0.20:
                    grounding_status = GroundingStatus.UNSUPPORTED
                    confidence = min(confidence, 0.20)
                    if "[UNKNOWN CATEGORY:" not in analyst_notes:
                        analyst_notes = (analyst_notes + " [UNKNOWN CATEGORY: Unsupported by definition]").strip()
                    violations.append(
                        GuardrailViolation(
                            rule_id="SEC-GR-CATEGORY-UNKNOWN-UNSUPPORTED",
                            severity=ViolationSeverity.MEDIUM,
                            target_field=f"{claim_field}.category",
                            description="Unknown category claim cannot be marked VALIDATED_REFERENCE",
                            remediation_applied="Demoted to UNSUPPORTED, confidence capped <= 0.20",
                        )
                    )
                else:
                    grounding_status = GroundingStatus.UNSUPPORTED
                    confidence = min(confidence, 0.20)

            # 3E. Limited-evidence enforcement (Stage 3C, ADR-008): partial support must not
            # become a definitive inference.
            if (
                sufficiency is not None
                and sufficiency.verdict == SufficiencyVerdict.LIMITED
                and category == ClaimCategory.INFERENCE
                and independent_groups(supporting_ids, limited_clusters) < 2
                and grounding_status != GroundingStatus.UNSUPPORTED
                and grounding_status != GroundingStatus.CONTRADICTED
            ):
                if grounding_status != GroundingStatus.ANALYST_REVIEW_REQUIRED or confidence > 0.30:
                    grounding_status = GroundingStatus.ANALYST_REVIEW_REQUIRED
                    confidence = min(confidence, 0.30)
                    if "[LIMITED EVIDENCE:" not in analyst_notes:
                        analyst_notes = (
                            analyst_notes
                            + " [LIMITED EVIDENCE: Inference rests on fewer than two independent evidence clusters (duplicates, same-record and near-duplicate events count once); analyst review required]"
                        ).strip()
                    violations.append(
                        GuardrailViolation(
                            rule_id="SEC-GR-LIMITED-EVIDENCE-INFERENCE",
                            severity=ViolationSeverity.MEDIUM,
                            target_field=f"{claim_field}.category",
                            description="Inference claim under LIMITED evidence sufficiency cites fewer than two independent evidence clusters",
                            remediation_applied="Demoted to ANALYST_REVIEW_REQUIRED, confidence capped <= 0.30",
                        )
                    )

            # Reconstruct clean immutable FactualClaimItem
            remediated_claim = FactualClaimItem(
                claim_id=claim.claim_id,
                claim_text=claim_text,
                category=category,
                supporting_evidence_ids=supporting_ids,
                references_exist=references_exist,
                grounding_status=grounding_status,
                confidence=round(confidence, 4),
                analyst_notes=analyst_notes or None,
                assertions=claim.assertions,  # Task 1: carried through unchanged; verified after the loop
            )
            remediated_claims.append(remediated_claim)

        # ── 3E. DETERMINISTIC CLAIM-TO-EVIDENCE VERIFICATION (Task 1, claim-assertion-v1) ────────────
        # Independent of the legacy lexical grounding above (which is left untouched): only claims that carry structured assertions are
        # verified, against the exact cited fields of THIS context. The model never judges its own claims. Failure here never fails validation.
        remediated_claims = _attach_claim_verification(remediated_claims, context, sufficiency)

        # ── 4. MITRE ATT&CK HYPOTHESES VALIDATION ────────────────────────────
        remediated_hypotheses: list[MitreAttackHypothesis] = []
        for idx, hyp in enumerate(output.mitre_attack_hypotheses):
            tech_id = hyp.technique_id.strip()
            hyp_confidence = hyp.confidence
            reasoning = hyp.reasoning
            hyp_uuids = [u for u in hyp.supporting_event_uuids if u in context_event_uuids]
            hyp_field = f"mitre_attack_hypotheses[{idx}]"

            # 4A. Syntax Validation
            if not _MITRE_TECHNIQUE_RE.match(tech_id):
                if hyp.confidence > 0.0 or "[INVALID_TECHNIQUE_SYNTAX]" not in hyp.reasoning:
                    hyp_confidence = 0.0
                    if "[INVALID_TECHNIQUE_SYNTAX]" not in reasoning:
                        reasoning = (reasoning + " [INVALID_TECHNIQUE_SYNTAX]").strip()
                    violations.append(
                        GuardrailViolation(
                            rule_id="SEC-GR-MITRE-SYNTAX",
                            severity=ViolationSeverity.HIGH,
                            target_field=f"{hyp_field}.technique_id",
                            description=f"Invalid MITRE ATT&CK technique ID syntax: {tech_id!r}",
                            remediation_applied="Confidence zeroed",
                        )
                    )

            # 4B. Supporting Events Check
            if not hyp_uuids:
                if hyp.confidence > 0.20 or "[UNSUPPORTED_SPECULATION:" not in hyp.reasoning:
                    hyp_confidence = min(hyp_confidence, 0.20)
                    if "[UNSUPPORTED_SPECULATION:" not in reasoning:
                        reasoning = (reasoning + " [UNSUPPORTED_SPECULATION: No valid supporting events cited]").strip()
                    violations.append(
                        GuardrailViolation(
                            rule_id="SEC-GR-MITRE-NO-SUPPORTING-EVENTS",
                            severity=ViolationSeverity.MEDIUM,
                            target_field=f"{hyp_field}.supporting_event_uuids",
                            description="MITRE hypothesis cites zero valid supporting events from context",
                            remediation_applied="Confidence capped <= 0.20",
                        )
                    )

            # 4C. Anti-T1562 Prompt Injection Check (legacy keyword guard). Kept unchanged whenever no pinned ATT&CK catalogue is
            # available; when one is available, the catalogue lifecycle check (4E) governs the revoked identifiers instead.
            if self._attack_state != _attack.ReferenceState.AVAILABLE and (tech_id == "T1562" or tech_id.startswith("T1562.")):
                has_defense_tampering = False
                for u in hyp_uuids:
                    ev = events_by_uuid[u]
                    ev_text = f"{ev.summary} {ev.action} {str(ev.attributes)}".lower()
                    # An inert echo or print is NOT proof of defense tampering
                    is_inert_echo = "echo " in ev_text or "print " in ev_text
                    genuine_tampering_keywords = (
                        "sc stop", "net stop", "stop-service", "set-mppreference",
                        "wevtutil cl", "taskkill", "reg add", "disableantispyware"
                    )
                    if not is_inert_echo and any(kw in ev_text for kw in genuine_tampering_keywords):
                        has_defense_tampering = True
                        break

                if not has_defense_tampering:
                    if hyp.confidence > 0.0 or "UNSUPPORTED_T1562" not in hyp.reasoning:
                        hyp_confidence = 0.0
                        if "UNSUPPORTED_T1562" not in reasoning:
                            reasoning = (
                                reasoning + " [UNSUPPORTED_T1562: Telemetry text or prompt injection without verified defense tampering cannot substantiate T1562]"
                            ).strip()
                        violations.append(
                            GuardrailViolation(
                                rule_id="SEC-GR-MITRE-UNSUPPORTED-T1562",
                                severity=ViolationSeverity.HIGH,
                                target_field=f"{hyp_field}.technique_id",
                                description="T1562 hypothesis proposed without supporting defense-tampering telemetry events",
                                remediation_applied="Confidence zeroed",
                            )
                        )

            # 4E. ATT&CK taxonomy lifecycle and successor-claim evidence (deterministic; catalogue optional).
            # Taxonomy status, evidence support and the model's own claim are kept distinct. A catalogue successor is only a
            # suggestion and never replaces the identifier; nothing here marks an incident benign.
            # The assessment is computed for EVERY hypothesis so each one carries its own taxonomy status (INVALID included);
            # the status is attached when the hypothesis is rebuilt below and always overwrites anything the model supplied.
            attack = _attack.assess_attack_technique(
                tech_id,
                [events_by_uuid[u] for u in hyp_uuids],
                self._attack_catalogue,
                reference_state=self._attack_state,
            )
            if _MITRE_TECHNIQUE_RE.match(tech_id):
                attack_target = f"{hyp_field}.technique_id"
                if attack.taxonomy_status in _attack.OBSOLETE_STATES:
                    # Revoked/deprecated: not accepted as a current mapping. This is a TAXONOMY finding only: evidence confidence
                    # is NOT changed here (the status travels in ``taxonomy``; consumers that accept mappings read it). The
                    # identifier, name and tactics are preserved exactly as received; the successor is a suggestion only.
                    if _attack.MARK_OBSOLETE not in hyp.reasoning:
                        if _attack.MARK_OBSOLETE not in reasoning:
                            reasoning = (reasoning + " " + _attack.obsolete_tag(attack)).strip()
                        violations.append(
                            GuardrailViolation(
                                rule_id=_attack.RULE_OBSOLETE,
                                severity=ViolationSeverity.MEDIUM,
                                target_field=attack_target,
                                description=_attack.obsolete_description(attack),
                                remediation_applied=(
                                    "Annotated and taxonomy status attached; evidence confidence unchanged; identifier preserved "
                                    "as received; catalogue successor(s) suggested only, never substituted"
                                ),
                            )
                        )
                elif attack.taxonomy_status in _attack.UNVALIDATED_STATES:
                    if _attack.MARK_UNVALIDATED not in hyp.reasoning:
                        reasoning = (reasoning + " " + _attack.unvalidated_tag(attack)).strip()
                        violations.append(
                            GuardrailViolation(
                                rule_id=_attack.RULE_UNVALIDATED,
                                severity=ViolationSeverity.LOW,
                                target_field=attack_target,
                                description=(
                                    f"Technique {tech_id} is well-formed but is not a current Enterprise technique in the pinned "
                                    f"ATT&CK {attack.catalogue_release} catalogue: inconclusive, not benign"
                                ),
                                remediation_applied="Annotated as unvalidated; confidence unchanged",
                            )
                        )
                elif attack.taxonomy_status == _attack.TaxonomyState.CATALOGUE_UNAVAILABLE:
                    if _attack.MARK_UNAVAILABLE not in hyp.reasoning:
                        reasoning = (reasoning + " " + _attack.unavailable_tag(attack)).strip()
                        violations.append(
                            GuardrailViolation(
                                rule_id=_attack.RULE_UNAVAILABLE,
                                severity=ViolationSeverity.LOW,
                                target_field=attack_target,
                                description=(
                                    f"The pinned ATT&CK reference could not be loaded, so {tech_id} is not taxonomy-validated: "
                                    "inconclusive, not benign"
                                ),
                                remediation_applied="Annotated as taxonomy-unavailable; confidence unchanged",
                            )
                        )
                if attack.evidence_status == _attack.EvidenceStatus.UNSUPPORTED:
                    # A current successor technique is accepted only with the structured evidence its contract requires.
                    if hyp.confidence > 0.0 or _attack.MARK_UNSUPPORTED not in hyp.reasoning:
                        hyp_confidence = 0.0
                        if _attack.MARK_UNSUPPORTED not in reasoning:
                            reasoning = (reasoning + " " + _attack.unsupported_tag(attack)).strip()
                        violations.append(
                            GuardrailViolation(
                                rule_id=_attack.RULE_UNSUPPORTED,
                                severity=ViolationSeverity.HIGH,
                                target_field=attack_target,
                                description=_attack.unsupported_description(attack),
                                remediation_applied="Confidence zeroed",
                            )
                        )

            # 4D. T1078 Valid Accounts Authentication Compatibility Check
            if tech_id == "T1078" or tech_id.startswith("T1078."):
                has_successful_access = False
                all_cited_are_failed_logons = bool(hyp_uuids)

                for u in hyp_uuids:
                    ev = events_by_uuid[u]
                    ev_outcome = ev.outcome.lower()
                    ev_action = ev.action.lower()
                    is_failure = (
                        ev_outcome in ("failure", "failed")
                        or ev_action in ("blocked", "denied", "prevented", "logon_attempt")
                        or ev.event_id in ("4625",)
                    )
                    is_success = (
                        ev_outcome in ("success", "succeeded")
                        or ev_action in ("logon", "login", "allowed", "start", "spawn", "execute", "connect")
                        or ev.event_id in ("4624",)
                    )
                    if is_success:
                        has_successful_access = True
                    if not (is_failure and not is_success):
                        all_cited_are_failed_logons = False

                if all_cited_are_failed_logons and not has_successful_access:
                    note = "[TENTATIVE_LEAD: Authentication failure cannot substantiate valid account abuse]"
                    if hyp_confidence > 0.35 or note not in reasoning:
                        hyp_confidence = min(hyp_confidence, 0.35)
                        if note not in reasoning:
                            reasoning = (reasoning + f" {note}").strip()
                        violations.append(
                            GuardrailViolation(
                                rule_id="SEC-GR-MITRE-T1078-FAILED-LOGON",
                                severity=ViolationSeverity.HIGH,
                                target_field=f"{hyp_field}.technique_id",
                                description="T1078 hypothesis supported solely by failed authentication events without evidence of successful access",
                                remediation_applied="Confidence capped <= 0.35 and marked as tentative lead",
                            )
                        )

            remediated_hypotheses.append(
                MitreAttackHypothesis(
                    technique_id=tech_id,
                    technique_name=hyp.technique_name,
                    tactics=hyp.tactics,
                    supporting_event_uuids=hyp_uuids,
                    confidence=round(hyp_confidence, 4),
                    reasoning=reasoning,
                    taxonomy=attack.taxonomy,
                )
            )

        # ── 5. RECOMMENDED ACTIONS SAFETY & SECRET SANITIZATION ──────────────
        remediated_actions: list[str] = []
        for idx, act in enumerate(output.recommended_analyst_actions):
            clean_act, act_secrets = _sanitize_secrets(act)
            if act_secrets:
                violations.append(
                    GuardrailViolation(
                        rule_id="SEC-GR-CREDENTIAL-LEAKAGE",
                        severity=ViolationSeverity.HIGH,
                        target_field=f"recommended_analyst_actions[{idx}]",
                        description="Detected sensitive credential or secret pattern in recommended analyst action",
                        remediation_applied="Redacted sensitive secret pattern to [REDACTED_*]",
                    )
                )
                act = clean_act

            if _DANGEROUS_COMMAND_RE.search(act):
                sanitized = "[SANITIZED: Prohibited executable command syntax detected and stripped; review host telemetry directly]"
                remediated_actions.append(sanitized)
                violations.append(
                    GuardrailViolation(
                        rule_id="SEC-GR-DANGEROUS-ACTION",
                        severity=ViolationSeverity.HIGH,
                        target_field=f"recommended_analyst_actions[{idx}]",
                        description=f"Action contained potentially executable or destructive command syntax: {act[:100]!r}",
                        remediation_applied="Replaced with safe advisory guidance",
                    )
                )
            else:
                remediated_actions.append(act)

        if not remediated_actions:
            remediated_actions.append("Review raw telemetry and audit logs directly for the target hosts.")

        # ── 6. UNCERTAINTY, ANTI-BENIGN & SUMMARY SECRET SANITIZATION ────────
        remediated_flags = list(output.uncertainty_and_data_gaps)
        summary = output.investigation_summary

        clean_summary, summary_secrets = _sanitize_secrets(summary)
        if summary_secrets:
            summary = clean_summary
            violations.append(
                GuardrailViolation(
                    rule_id="SEC-GR-CREDENTIAL-LEAKAGE",
                    severity=ViolationSeverity.HIGH,
                    target_field="investigation_summary",
                    description="Detected sensitive credential or secret pattern in investigation summary",
                    remediation_applied="Redacted sensitive secret pattern to [REDACTED_*]",
                )
            )

        remediated_explanations: list[str] = []
        for idx, exp in enumerate(output.alternative_explanations):
            clean_exp, exp_secrets = _sanitize_secrets(exp)
            if exp_secrets:
                violations.append(
                    GuardrailViolation(
                        rule_id="SEC-GR-CREDENTIAL-LEAKAGE",
                        severity=ViolationSeverity.HIGH,
                        target_field=f"alternative_explanations[{idx}]",
                        description="Detected sensitive credential or secret pattern in alternative explanation",
                        remediation_applied="Redacted sensitive secret pattern to [REDACTED_*]",
                    )
                )
                remediated_explanations.append(clean_exp)
            else:
                remediated_explanations.append(exp)

        if context.budget_metrics.context_truncated:
            if not any("TRUNCAT" in f for f in remediated_flags):
                remediated_flags.append(
                    "CONTEXT_TRUNCATED: Telemetry was omitted due to budget constraints; analysis scope is incomplete"
                )
                violations.append(
                    GuardrailViolation(
                        rule_id="SEC-GR-TRUNCATION-DISCLOSURE-MISSING",
                        severity=ViolationSeverity.LOW,
                        target_field="uncertainty_and_data_gaps",
                        description="Context was truncated but output omitted explicit truncation disclosure",
                        remediation_applied="Appended truncation disclosure",
                    )
                )

            # Anti-benign check under truncated telemetry
            if any(term in summary.lower() for term in ("benign", "clean", "false positive", "no threats")):
                if "[DISCLOSURE: Telemetry context was truncated" not in summary:
                    summary = (
                        summary.strip()
                        + " [DISCLOSURE: Telemetry context was truncated; absence of observed attack indicators does not establish benign status]"
                    )
                    violations.append(
                        GuardrailViolation(
                            rule_id="SEC-GR-ANTI-BENIGN-TRUNCATED",
                            severity=ViolationSeverity.HIGH,
                            target_field="investigation_summary",
                            description="Summary claimed benign verdict despite context truncation; incomplete evidence cannot prove benign",
                            remediation_applied="Annotated summary with explicit non-benign disclosure",
                        )
                    )


        # ── 7. RECALIBRATE GROUNDING SCORE & VALIDATE MODEL ──────────────────
        if remediated_claims:
            validated_count = sum(
                1 for c in remediated_claims if c.grounding_status == GroundingStatus.VALIDATED_REFERENCE
            )
            overall_grounding_score = round(validated_count / len(remediated_claims), 4)
        else:
            overall_grounding_score = 0.0

        remediated_output = StructuredInvestigationOutput(
            investigation_id=output.investigation_id,
            generated_at=output.generated_at,
            model_identifier=output.model_identifier,
            investigation_summary=summary,
            claims=remediated_claims,
            mitre_attack_hypotheses=remediated_hypotheses,
            alternative_explanations=remediated_explanations,
            recommended_analyst_actions=remediated_actions,
            uncertainty_and_data_gaps=sorted(set(remediated_flags)),
            overall_grounding_score=overall_grounding_score,
        )

        # ── 8. FINAL DISPOSITION EVALUATION ──────────────────────────────────
        # Check if output is completely ungrounded while asserting severe incident
        has_critical = any(v.severity == ViolationSeverity.CRITICAL for v in violations)
        total_claims = len(remediated_claims)
        all_claims_ungrounded = total_claims > 0 and overall_grounding_score == 0.0

        if has_critical or (all_claims_ungrounded and self._strict_mode):
            fallback_reason = "All factual claims failed evidence grounding or critical violation occurred"
            violations.append(
                GuardrailViolation(
                    rule_id="SEC-GR-UNGROUNDED-NARRATIVE",
                    severity=ViolationSeverity.CRITICAL,
                    target_field="claims",
                    description=fallback_reason,
                    remediation_applied="Triggered deterministic fallback",
                )
            )
            fallback_output = InvestigationResponseParser().build_deterministic_fallback(
                context, fallback_reason
            )
            return InvestigationValidationResult(
                decision=GuardrailDecision.REJECT_TO_FALLBACK,
                is_valid=False,
                output=fallback_output,
                violations=violations,
                context_sha256=context.reproducibility.context_sha256,
                validated_at_utc=validation_time,
            )

        has_modifications = bool(violations)
        decision = GuardrailDecision.REMEDIATED if has_modifications else GuardrailDecision.PASS

        return InvestigationValidationResult(
            decision=decision,
            is_valid=True,
            output=remediated_output,
            violations=violations,
            context_sha256=context.reproducibility.context_sha256,
            validated_at_utc=validation_time,
        )
