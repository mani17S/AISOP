"""
AISOP Deterministic Report Synthesizer and Markdown Renderer.

Implements Milestone P2-H6: Role-Tailored Structured Investigation Reporting.
- Executive Brief (CISO & leadership view).
- Technical Incident Response Report (SOC & forensic investigator view).
- Detection Engineering Report (detection engineering & threat hunting view).

Core Invariants:
1. Zero Secondary LLM Calls: All synthesis is 100% deterministic Python.
2. Epistemic Segregation: Confirmed facts are strictly separated from hypotheses and refuted claims.
3. Cryptographic Binding & Integrity: Bound contexts are validated against context_sha256 using AISOP-CJSON-1.0.
4. Detached-Format Resilience: Clean disclosures and safe sentinels when context is not provided.
5. Injection Defense & Context-Aware Escaping: Untrusted text cannot hijack Markdown structure, headings, or tables.
6. Command Sanitization: Prohibited shell code is neutralized into safe advisory text.
7. Anti-Benign Axiom: Incomplete or truncated telemetry never produces a "clean" or "benign" conclusion.
8. Byte-Level Determinism: Standardized UTC timestamps, stable tie-breaking sorts, Unix newlines, and trailing newline.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import html
import ipaddress
import re
from typing import Any, Optional, Sequence
import uuid

from app.schemas.report_terminology import (
    CLAIMS_VALIDATED_DEFINITION,
    MODEL_REPORTED_CONFIDENCE_DEFINITION,
)
from app.modules.ai.context_builder.hasher import compute_context_sha256
from app.modules.ai.guardrails.validator import (
    GuardrailDecision,
    InvestigationValidationResult,
)
from app.schemas.investigation import (
    ClaimCategory,
    ContextEventItem,
    GroundingStatus,
    InvestigationContext,
    MitreAttackHypothesis,
)
from app.schemas.report import (
    DetectionEngineeringReport,
    DetectionObservableItem,
    ExecutiveBrief,
    IncidentSeverityTier,
    InvestigationReportBundle,
    ReportBundleProvenance,
    TechnicalIncidentReport,
    TechnicalReportClaim,
    TimelineEventSummary,
)


# ── REGEX PATTERNS FOR EXTRACTION AND DEFENSE ─────────────────────────────────

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_EXECUTABLE_RE = re.compile(
    r"\b[\w\-\.]+\.(?:exe|dll|ps1|bat|cmd|sh|vbs|py|sys|scr)\b", re.IGNORECASE
)
_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_DANGEROUS_COMMAND_RE = re.compile(
    r"(?i)\b(?:iex|invoke-expression|invoke-restmethod|invoke-webrequest|downloadstring|"
    r"curl\s+[^\n|]*?\|\s*(?:bash|sh)|wget\s+[^\n|]*?\|\s*(?:bash|sh)|"
    r"powershell(?:\.exe)?\s+-[^\n]*?(?:enc|encodedcommand)|format\s+[a-z]:|"
    r"rm\s+-rf|drop\s+table|delete\s+from\s+\w+|mkfs\b|dd\s+if=)",
)

_MARKDOWN_CONTROL_START_RE = re.compile(
    r"^(?:#{1,6}\s+|>\s*|[-*+]\s+|\d+\.\s+|---|___|\*\*\*|\[!CAUTION\]|\[!WARNING\]|\[!NOTE\]|\[!IMPORTANT\]|\[!TIP\])"
)

_UNSAFE_LINK_TARGET_RE = re.compile(
    r"\[([^\]]*)\]\(\s*(?:javascript|data|vbscript):([^\)]*)\)",
    re.IGNORECASE,
)

_SUCCESSFUL_OUTCOMES = frozenset({"success", "succeeded", "successful"})
_BLOCKED_OUTCOMES = frozenset({"blocked", "denied", "prevented", "rejected", "quarantined"})
_FAILURE_OUTCOMES = frozenset({"failure", "failed"})
_UNKNOWN_OUTCOMES = frozenset({"unknown", "unspecified", "unavailable", "pending", ""})

_BLOCKED_ACTIONS = frozenset({"blocked", "denied", "prevented", "quarantined", "isolated"})


def _is_unlinked_or_missing_hash(sha256_str: Optional[str]) -> bool:
    """
    Deterministic predicate: returns True if raw evidence hash is None, empty,
    whitespace, malformed (not 64 hex characters), or the 64-zero sentinel ('0' * 64).

    Scope & Semantics:
    - Returns True: Telemetry lacks cryptographic binding to raw source evidence.
      This indicates an ingestion limitation, detached mode, or unlinked database record.
      It does NOT prove that tampering occurred, and does NOT imply the event payload is fabricated.
    - Returns False: Telemetry possesses a structurally valid, non-zero SHA-256 hex digest.
    """
    if not sha256_str:
        return True
    clean = sha256_str.strip().lower()
    if clean == ("0" * 64) or clean == "":
        return True
    return len(clean) != 64 or not all(c in "0123456789abcdef" for c in clean)


#: Taxonomy states (``MitreAttackHypothesis.taxonomy``) that make a technique id unacceptable as a CURRENT mapping.
#: Evidence confidence is independent of taxonomy; these helpers only keep such hypotheses out of the consumers that
#: ACCEPT a mapping (coverage targets, detection/hunting ideas, severity contribution), exactly as the former zeroed
#: confidence did. They change no threshold, tactic set or severity tier.
_OBSOLETE_TAXONOMY_VALUES = frozenset({"REVOKED", "DEPRECATED"})
_NOTABLE_TAXONOMY_VALUES = frozenset({"REVOKED", "DEPRECATED", "UNKNOWN", "WRONG_DOMAIN", "CATALOGUE_UNAVAILABLE"})


def _is_obsolete_taxonomy(hyp: Any) -> bool:
    tax = getattr(hyp, "taxonomy", None)
    return tax is not None and tax.state.value in _OBSOLETE_TAXONOMY_VALUES


# Named predicates for the sites that read the status above. Each is the EXACT former inline condition (behaviour-preserving
# refactor, backlog item 1); they are deliberately separate because the consumers' present conditions differ. Their names state
# today's rule, not an intended future policy.
def _is_coverage_target(hyp: Any) -> bool:
    """Coverage targets: any positive confidence, except a revoked/deprecated id."""
    return hyp.confidence > 0.0 and not _is_obsolete_taxonomy(hyp)


def _is_material_hypothesis(hyp: Any) -> bool:
    """Severity's material-event set: confidence >= 0.40, except a revoked/deprecated id."""
    return hyp.confidence >= 0.40 and not _is_obsolete_taxonomy(hyp)


def _mapping_offered_as_current(hyp: Any) -> bool:
    """Detection ideas and hunting pseudocode: the confidence SHOWN in the report mapping (rounded to 4 places) is >= 0.40,
    except for a revoked/deprecated id. Rounding first is deliberate and differs from ``_is_material_hypothesis``
    (raw value): a raw 0.39996 is 0.4 in the mapping. Reads the hypothesis, not the display key ``taxonomy_state``."""
    return round(hyp.confidence, 4) >= 0.40 and not _is_obsolete_taxonomy(hyp)


def _taxonomy_view(hyp: Any) -> dict[str, Any]:
    """Additive report keys; empty for absent/default/current states, so existing reports are unchanged."""
    tax = getattr(hyp, "taxonomy", None)
    if tax is None or tax.state.value not in _NOTABLE_TAXONOMY_VALUES:
        return {}
    view: dict[str, Any] = {"taxonomy_state": tax.state.value}
    if tax.successors:
        view["taxonomy_successors"] = [s.attack_id for s in tax.successors]
    return view


def _taxonomy_suffix(mapping: dict[str, Any]) -> str:
    state = mapping.get("taxonomy_state")
    if state is None:
        return ""
    succ = mapping.get("taxonomy_successors")
    extra = f"; catalogue successor suggestion (not evidence): {', '.join(succ)}" if succ else ""
    return f" [taxonomy: {state}{extra}]"


class ContextIntegrityError(ValueError):
    """Raised when supplied InvestigationContext fails cryptographic binding verification."""


# ── SANITIZATION & ESCAPING HELPERS ──────────────────────────────────────────

def _sanitize_table_cell(text: str) -> str:
    """
    Sanitize untrusted text for safe inclusion within a Markdown table cell.
    - Neutralizes unsafe link protocols (javascript:, data:, vbscript:).
    - HTML-escapes raw markup to prevent HTML tag injection (<img onerror>, <svg onload>, <object>).
    - Replaces pipe characters to prevent breaking table column alignment.
    - Normalizes newlines to <br> to preserve tabular row integrity.
    """
    if not text:
        return "—"
    cleaned = _UNSAFE_LINK_TARGET_RE.sub(r"[\1](#blocked-unsafe-link)", text)
    cleaned = html.escape(cleaned, quote=True)
    cleaned = cleaned.replace("|", r"\|")
    cleaned = cleaned.replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")
    return cleaned.strip() or "—"


def _neutralize_markdown_structural_hijacking(text: str) -> str:
    """
    Neutralize untrusted text to prevent hijacking Markdown headers, blockquotes, alerts, or lists.
    - Neutralizes unsafe link protocols (javascript:, data:, vbscript:).
    - Line-by-line structural token neutralizing with leading backslash (preserving indentation).
    - HTML-escapes raw markup to prevent HTML tag injection (<img onerror>, <svg onload>, <object>, <script>).
    """
    if not text:
        return ""
    # 1. Neutralize unsafe Markdown link targets
    sanitized = _UNSAFE_LINK_TARGET_RE.sub(r"[\1](#blocked-unsafe-link)", text)
    # 2. Line-by-line structural token neutralizing
    lines = sanitized.split("\n")
    neutralized_lines = []
    for line in lines:
        stripped = line.strip()
        if _MARKDOWN_CONTROL_START_RE.match(stripped):
            indent_len = len(line) - len(line.lstrip())
            indent = line[:indent_len]
            content = line[indent_len:]
            neutralized_lines.append(f"{indent}\\{content}")
        else:
            neutralized_lines.append(line)
    neutralized_text = "\n".join(neutralized_lines)
    # 3. Standard HTML escaping of raw tags and markup
    return html.escape(neutralized_text, quote=False)


def _sanitize_inline_code(text: str) -> str:
    """Format string inside inline backticks, safely handling internal backticks."""
    if not text:
        return "`—`"
    max_run = 0
    current_run = 0
    for ch in text:
        if ch == "`":
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 0
    if max_run > 0:
        delimiter = "`" * (max_run + 1)
        return f"{delimiter} {text} {delimiter}"
    return f"`{text}`"


def _sanitize_action_text(action: str) -> str:
    """Scrub dangerous executable commands from advisory recommendations."""
    if _DANGEROUS_COMMAND_RE.search(action):
        return (
            "[SANITIZED ADVISORY: Potential executable command syntax removed; "
            "inspect host telemetry directly]"
        )
    return action.strip()


def _extract_observables_from_text(text: str) -> set[tuple[str, str]]:
    """Extract candidate observables (ipv4, sha256, executable) from unstructured text."""
    found: set[tuple[str, str]] = set()
    for ip in _IPV4_RE.findall(text):
        try:
            ipaddress.ip_address(ip)
            found.add(("ipv4", ip.lower()))
        except ValueError:
            pass
    for h in _SHA256_RE.findall(text):
        found.add(("sha256", h.lower()))
    for exe in _EXECUTABLE_RE.findall(text):
        found.add(("executable", exe.lower()))
    return found


# ── CRYPTOGRAPHIC CONTEXT BINDING ────────────────────────────────────────────

def verify_context_binding(
    validation_result: InvestigationValidationResult,
    context: InvestigationContext,
) -> None:
    """
    Verify the cryptographic consistency and identity binding between InvestigationValidationResult
    and a client-supplied InvestigationContext.

    Asserts:
    1. Investigation ID equality.
    2. Recomputed canonical SHA-256 equals validation_result.context_sha256.
    3. Context reproducibility context_sha256 equals validation_result.context_sha256.

    Raises ContextIntegrityError on any mismatch.
    """
    if str(context.investigation_id) != str(validation_result.output.investigation_id):
        raise ContextIntegrityError(
            f"Investigation ID mismatch: context has '{context.investigation_id}' but "
            f"validation_result has '{validation_result.output.investigation_id}'"
        )

    computed_sha = compute_context_sha256(context)
    if computed_sha != validation_result.context_sha256:
        raise ContextIntegrityError(
            f"Context cryptographic digest mismatch: recomputed '{computed_sha}' does not match "
            f"expected '{validation_result.context_sha256}' from validation result"
        )

    if context.reproducibility.context_sha256 != validation_result.context_sha256:
        raise ContextIntegrityError(
            f"Context reproducibility digest mismatch: '{context.reproducibility.context_sha256}' "
            f"does not match expected '{validation_result.context_sha256}'"
        )


# ── DETERMINISTIC REPORT SYNTHESIZER ─────────────────────────────────────────


# ── Unverified-report rendering (T1-B): fixed, deterministic text; none of it contains submitted data ──────────────
# Applies only when the report is not server-verified (digest mismatch, no case ID, or no context): the route passes
# ``is_server_verified=False``, or a direct call supplies neither a flag nor a context. Verified/server-built output is unchanged.
_ANALYTICS_WITHHELD_REASON = (
    "REPORT_VERIFICATION_FAILED: analytical outputs were withheld because the submitted report could not be verified "
    "against a server-stored record for this case."
)
_UNVERIFIED_BANNER_LINES = (
    "UNVERIFIED SUBMITTED REPORT - REPORT VERIFICATION FAILED",
    "This report could not be verified against a server-stored record for this case. Content below is submitted material that "
    "AISOP has not verified. Analytical outputs derived from submitted content (incident severity, ATT&CK coverage, detection "
    "ideas, hunting guidance, affected assets, threat intelligence, observables and timeline) are withheld or not assessed.",
)
_SUBMITTED_MATERIAL_PREFIX = "[SUBMITTED MATERIAL - NOT VERIFIED BY AISOP]"
_UNVERIFIED_SUGGESTION_PREFIX = "[UNVERIFIED SUGGESTION]"
_SUBMITTED_NOT_VERIFIED = "SUBMITTED_NOT_VERIFIED"
_UNVERIFIED_SEVERITY_JUSTIFICATION = (
    "REPORT_VERIFICATION_FAILED: Inconclusive incident severity. The submitted report could not be verified against a "
    "server-stored record for this case, so no incident severity is assessed from its content. This reflects failed report "
    "verification, not an assessment that evidence is insufficient or that the activity is benign or hostile."
)
_UNVERIFIED_SEVERITY_DETACHED_SUFFIX = " The submitted report is also detached-format: no bound telemetry context was supplied."
_UNVERIFIED_BUSINESS_RISK = "Not assessed: report verification failed. No operational risk statement is made from unverified submitted content."
_WITHHELD_ASSETS_NOTICE = "WITHHELD: report verification failed; affected assets are not asserted from an unverified submitted report."
_WITHHELD_TI_CONTEXT = "Threat intelligence context withheld: report verification failed; submitted threat-intelligence content is not presented."
_WITHHELD_TIMELINE_DISCLOSURE = (
    "Telemetry timeline withheld: report verification failed; submitted events are not presented as a verified timeline."
)
_WITHHELD_DETECTION_NOTICE = (
    "WITHHELD: report verification failed; candidate detection hypotheses are not generated from an unverified submitted report."
)
_WITHHELD_HUNTING_NOTICE = (
    "// WITHHELD: report verification failed; hunting guidance is not generated from an unverified submitted report."
)
_VERIFICATION_FAILURE_GAP = (
    "REPORT_VERIFICATION_FAILED: The submitted report could not be verified against a server-stored record; analytical outputs "
    "derived from submitted content were withheld."
)


def _unverified_caution_lines(fallback_flag_submitted: bool) -> list[str]:
    """Caution block for an unverified report; never attributes a guardrail decision to AISOP for a client-derived flag."""
    lines = [
        "> [!CAUTION]",
        "> **INVESTIGATION STATUS: INCONCLUSIVE / REPORT VERIFICATION FAILED**",
        "> This status reflects failed verification of the submitted report; it is not an assessment of evidence sufficiency.",
    ]
    if fallback_flag_submitted:
        lines.append(
            "> The submitted report also carries a fallback or invalid-result flag. That flag came from the submitted content and "
            "is not an AISOP guardrail decision."
        )
    lines.append("")
    return lines


def _verification_markdown_lines(claim: Any) -> list[str]:
    """One bounded line per claim that carries a persisted claim-verification-v1 result (fixed enum/reason codes only; nothing for historical claims)."""
    v = getattr(claim, "verification", None)
    if v is None:
        return []
    return [
        f"   - **Assertion verification (listed assertions only; AI claim, not analyst-confirmed):** `{v.outcome.value}` "
        f"({v.assertions_evaluated}/{v.assertions_total} evaluated; reason `{v.reason}`)"
    ]


class DeterministicReportSynthesizer:
    """
    Pure Python, deterministic report synthesizer producing role-tailored investigation views.
    Executes zero LLM calls.
    """

    GOVERNANCE_DISCLAIMER: str = (
        "GOVERNANCE NOTICE: This report is an AI-assisted investigative artifact generated under "
        "strict human-in-the-loop oversight in compliance with AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001. "
        "All security conclusions and recommendations are advisory. Automated execution of containment "
        "or remediation actions is prohibited. Operational authorization by a human SOC analyst is required."
    )

    DETECTION_DISCLAIMER: str = (
        "DETECTION ENGINEERING NOTICE: Candidate hunting queries and behavioral hypotheses are advisory "
        "and non-executable. Detection logic must be validated against organizational baselines to eliminate "
        "false positives prior to production SIEM/EDR rule deployment."
    )

    def synthesize_bundle(
        self,
        validation_result: InvestigationValidationResult,
        context: Optional[InvestigationContext] = None,
        events: Optional[Sequence[ContextEventItem]] = None,
        override_timestamp: Optional[datetime] = None,
        is_server_verified: Optional[bool] = None,
    ) -> InvestigationReportBundle:
        """
        Synthesize the full report bundle (Executive Brief, Technical IR Report, Detection Eng Report)
        along with byte-deterministic Markdown representations.
        """
        if is_server_verified is None:
            effective_verified = (context is not None) or bool(events)
        else:
            effective_verified = bool(is_server_verified)

        is_detached = context is None and not events
        is_fallback_active = (
            validation_result.decision == GuardrailDecision.REJECT_TO_FALLBACK
            or not validation_result.is_valid
            or validation_result.output.overall_grounding_score == 0.0
        )
        # T1-B: a report that is not server-verified never presents submitted content as AISOP analytics (see the constants above).
        withhold_analytics = not effective_verified

        # 1. Deterministic Timestamp Sourcing (Never calls datetime.now())
        generated_at = override_timestamp or validation_result.validated_at_utc

        # 2. Epistemic Partitioning of Output Claims
        confirmed_claims: list[TechnicalReportClaim] = []
        inferences: list[TechnicalReportClaim] = []
        refuted_or_unsupported: list[TechnicalReportClaim] = []

        # Sort claims deterministically by confidence DESC, tie-break by claim_id ASC
        sorted_raw_claims = sorted(
            validation_result.output.claims,
            key=lambda c: (-c.confidence, str(c.claim_id)),
        )

        if not effective_verified:
            # UNVERIFIED INPUT: Demote all claims to unverified inferences.
            # Fabricated validation results cannot produce confirmed findings.
            for c in sorted_raw_claims:
                claim_repr = TechnicalReportClaim(
                    claim_id=c.claim_id,
                    claim_text=f"[UNVERIFIED] {c.claim_text}",
                    category=ClaimCategory.INFERENCE.value,
                    grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED.value,
                    confidence=round(min(c.confidence, 0.40), 4),
                    supporting_event_uuids=[],
                    analyst_notes="Unverified input: lacks server-side case investigation provenance.",
                )
                inferences.append(claim_repr)
        else:
            for c in sorted_raw_claims:
                claim_repr = TechnicalReportClaim(
                    claim_id=c.claim_id,
                    claim_text=c.claim_text,
                    category=c.category.value if hasattr(c.category, "value") else str(c.category),
                    grounding_status=c.grounding_status.value if hasattr(c.grounding_status, "value") else str(c.grounding_status),
                    confidence=round(c.confidence, 4),
                    supporting_event_uuids=sorted(c.supporting_evidence_ids),
                    analyst_notes=c.analyst_notes,
                    # Carried only when the caller established server-side provenance (audit-digest-bound output); the unverified branch above never carries it.
                    verification=c.verification if is_server_verified is True else None,
                )
                if c.grounding_status == GroundingStatus.VALIDATED_REFERENCE:
                    confirmed_claims.append(claim_repr)
                elif c.grounding_status in (GroundingStatus.ANALYST_REVIEW_REQUIRED,) or c.category == ClaimCategory.INFERENCE:
                    inferences.append(claim_repr)
                else:
                    refuted_or_unsupported.append(claim_repr)

        # 3. Chronological Investigation Timeline
        timeline_items: list[TimelineEventSummary] = []
        timeline_disclosure: Optional[str] = None
        source_events = (context.events if context is not None else events) or []

        if source_events and withhold_analytics:
            timeline_disclosure = _WITHHELD_TIMELINE_DISCLOSURE
        elif source_events:
            sorted_events = sorted(source_events, key=lambda e: (e.timestamp_utc, str(e.event_uuid)))
            for ev in sorted_events:
                timeline_items.append(
                    TimelineEventSummary(
                        event_uuid=ev.event_uuid,
                        timestamp_utc=ev.timestamp_utc,
                        source_identifier=ev.source_identifier,
                        event_type=ev.event_type,
                        action=ev.action,
                        outcome=ev.outcome,
                        raw_evidence_sha256=ev.raw_evidence_sha256,
                        summary=ev.summary,
                    )
                )
        else:
            timeline_disclosure = (
                "Telemetry event timeline unavailable in detached-format mode "
                "(requires bound InvestigationContext or event stream)."
            )

        # 4. Evidenced Affected Assets Determination
        affected_assets: list[str] = []
        if withhold_analytics and (context is not None or source_events):
            affected_assets = [_WITHHELD_ASSETS_NOTICE]
        elif context and context.target_hosts:
            affected_assets = sorted(set(context.target_hosts))
        elif source_events:
            affected_assets = sorted(set(e.source_identifier for e in source_events if e.source_identifier))
        else:
            affected_assets = ["Unspecified / Host telemetry not provided in detached mode"]

        # 5. MITRE ATT&CK Hypotheses Processing
        mitre_mappings: list[dict[str, Any]] = []
        offered_mappings: list[dict[str, Any]] = []  # the mapping dicts of hypotheses offered as current (same order, same objects)
        mitre_targets: list[str] = []
        sorted_hypotheses = sorted(
            validation_result.output.mitre_attack_hypotheses,
            key=lambda m: (-m.confidence, m.technique_id),
        )
        for hyp in sorted_hypotheses:
            if not withhold_analytics and _is_coverage_target(hyp):
                mitre_targets.append(hyp.technique_id)
            mapping = {
                "technique_id": hyp.technique_id,
                "technique_name": hyp.technique_name,
                "tactics": sorted(hyp.tactics),
                "supporting_event_uuids": [str(u) for u in sorted(hyp.supporting_event_uuids)],
                "confidence": round(hyp.confidence, 4),
                "reasoning": hyp.reasoning,
                **_taxonomy_view(hyp),
            }
            if withhold_analytics:
                mapping["verification_state"] = _SUBMITTED_NOT_VERIFIED  # unverified mode only; the mapping stays submitted material
            mitre_mappings.append(mapping)
            if not withhold_analytics and _mapping_offered_as_current(hyp):
                offered_mappings.append(mapping)
        mitre_targets = sorted(set(mitre_targets))

        # 6. Observables & IOCs Extraction (Distinguishing bound vs claim-extracted)
        observables: list[DetectionObservableItem] = []
        seen_obs_keys: set[tuple[str, str]] = set()

        if withhold_analytics:
            pass  # D4: observables derived from submitted entities or claims are withheld
        elif context and context.entities:
            for ent in context.entities:
                obs_key = (ent.entity_type, ent.entity_value.lower())
                if obs_key not in seen_obs_keys:
                    seen_obs_keys.add(obs_key)
                    observables.append(
                        DetectionObservableItem(
                            observable_type=ent.entity_type,
                            observable_value=ent.entity_value,
                            provenance_type="bound_telemetry",
                            provenance_event_uuids=sorted(ent.associated_event_uuids),
                            provenance_claim_ids=[],
                            is_malicious_asserted=False,
                        )
                    )
        else:
            # Detached extraction from verified claims
            for claim in confirmed_claims:
                extracted = _extract_observables_from_text(claim.claim_text)
                for obs_type, obs_val in extracted:
                    obs_key = (obs_type, obs_val)
                    if obs_key not in seen_obs_keys:
                        seen_obs_keys.add(obs_key)
                        observables.append(
                            DetectionObservableItem(
                                observable_type=obs_type,
                                observable_value=obs_val,
                                provenance_type="claim_text_extraction",
                                provenance_event_uuids=[],
                                provenance_claim_ids=[claim.claim_id],
                                is_malicious_asserted=False,
                            )
                        )

        # Sort observables deterministically
        observables.sort(key=lambda o: (o.observable_type, o.observable_value))

        # 7. Threat Intelligence Enrichment Processing
        ti_enrichments: list[dict[str, Any]] = []
        ti_context_summary = "External threat intelligence not enriched"
        if withhold_analytics and context is not None:
            ti_context_summary = _WITHHELD_TI_CONTEXT  # D4: submitted threat-intelligence content is not presented
        elif context and context.threat_intel:
            for ti in context.threat_intel:
                ti_enrichments.append({
                    "observable": ti.observable,
                    "observable_type": ti.observable_type,
                    "verdict": ti.verdict.value if hasattr(ti.verdict, "value") else str(ti.verdict),
                    "threat_state": ti.threat_state.value if hasattr(ti.threat_state, "value") else str(ti.threat_state),
                    "is_shielded": ti.is_shielded,
                    "confidence": round(ti.confidence, 4),
                    "source_feeds": sorted(ti.source_feeds),
                })
            ti_context_summary = f"{len(ti_enrichments)} observable(s) enriched against local threat intelligence feeds."
        elif is_detached:
            ti_context_summary = "Threat intelligence lookup details unavailable in detached-format mode."

        # 8. Gaps and Uncertainties Normalization (Evaluated prior to severity)
        # D7: submitted gap texts are withheld when unverified; server-computed gaps and the verification-failure gap are kept.
        gaps_list = [] if withhold_analytics else sorted(set(validation_result.output.uncertainty_and_data_gaps))
        if withhold_analytics:
            gaps_list.append(_VERIFICATION_FAILURE_GAP)
        if context and context.budget_metrics.context_truncated:
            trunc_msg = "CONTEXT_TRUNCATED: Telemetry was omitted due to budget constraints; scope is partial."
            if trunc_msg not in gaps_list:
                gaps_list.append(trunc_msg)
        if is_detached:
            detached_msg = (
                "TELEMETRY_UNAVAILABLE: Telemetry context is detached; baseline and forensic events cannot be evaluated."
            )
            if detached_msg not in gaps_list:
                gaps_list.append(detached_msg)
        gaps_list.sort()

        # 9. Deterministic Severity & Business Risk Evaluation (Evidence-Grounded)
        if withhold_analytics:
            # D2: INCONCLUSIVE because report verification failed (distinct from insufficient evidence); severity is not derived from submitted data.
            incident_severity = IncidentSeverityTier.INCONCLUSIVE
            severity_justification = _UNVERIFIED_SEVERITY_JUSTIFICATION + (
                _UNVERIFIED_SEVERITY_DETACHED_SUFFIX if is_detached else ""
            )
            business_risk = _UNVERIFIED_BUSINESS_RISK
        else:
            incident_severity, severity_justification = self._determine_severity(
                validation_result=validation_result,
                confirmed_claims=confirmed_claims,
                mitre_mappings=mitre_mappings,
                is_fallback=is_fallback_active,
                context=context,
                verified_events=source_events,
                is_detached=is_detached,
                gaps_list=gaps_list,
            )
            business_risk = self._determine_business_risk(incident_severity)

        # 10. Sanitized Advisory Actions
        sanitized_actions = [
            _sanitize_action_text(act)
            for act in validation_result.output.recommended_analyst_actions
        ]
        if withhold_analytics:
            sanitized_actions = [f"{_UNVERIFIED_SUGGESTION_PREFIX} {act}" for act in sanitized_actions]
        if not sanitized_actions:
            sanitized_actions = ["Review raw telemetry and host logs directly for the target hosts."]

        # ── BUILD STRUCTURED MODELS ──────────────────────────────────────────

        # Executive Brief
        exec_summary_text = _neutralize_markdown_structural_hijacking(
            validation_result.output.investigation_summary
        )
        if withhold_analytics:
            exec_summary_text = f"{_SUBMITTED_MATERIAL_PREFIX} {exec_summary_text}"
        exec_brief = ExecutiveBrief(
            investigation_id=validation_result.output.investigation_id,
            generated_at_utc=generated_at,
            title="AISOP Executive Security Brief",
            incident_severity=incident_severity,
            severity_justification=severity_justification,
            is_inconclusive_or_fallback=is_fallback_active,
            executive_summary=exec_summary_text,
            evidenced_affected_assets=affected_assets,
            key_confirmed_findings=[c.claim_text for c in confirmed_claims],
            threat_intelligence_context=ti_context_summary,
            business_risk_statement=business_risk,
            uncertainties_and_limitations=gaps_list,
            governance_disclaimer=self.GOVERNANCE_DISCLAIMER,
        )

        # Technical Incident Response Report
        tech_report = TechnicalIncidentReport(
            investigation_id=validation_result.output.investigation_id,
            generated_at_utc=generated_at,
            is_inconclusive_or_fallback=is_fallback_active,
            technical_narrative=exec_summary_text,
            investigation_timeline=timeline_items,
            timeline_status_disclosure=timeline_disclosure,
            confirmed_findings=confirmed_claims,
            hypotheses_and_inferences=inferences,
            unsupported_or_contradicted_claims=refuted_or_unsupported,
            mitre_attack_mappings=mitre_mappings,
            threat_intelligence_enrichment=ti_enrichments,
            investigation_gaps=gaps_list,
            recommended_analyst_actions=sanitized_actions,
            context_sha256=validation_result.context_sha256,
            model_identifier=validation_result.output.model_identifier,
            overall_grounding_score=validation_result.output.overall_grounding_score,
            governance_disclaimer=self.GOVERNANCE_DISCLAIMER,
        )

        # Detection Engineering Report
        candidate_hypotheses = [
            f"Detect behavioral execution of {m['technique_id']} ({m['technique_name']}) in endpoint activity."
            for m in offered_mappings
        ]
        if withhold_analytics:
            candidate_hypotheses = [_WITHHELD_DETECTION_NOTICE]
        elif not candidate_hypotheses:
            candidate_hypotheses = ["No candidate detection hypotheses substantiated by validated evidence."]

        if withhold_analytics:
            hunting_pseudocode = [_WITHHELD_HUNTING_NOTICE]
        else:
            hunting_pseudocode = self._generate_hunting_guidance(offered_mappings, observables)

        detection_report = DetectionEngineeringReport(
            investigation_id=validation_result.output.investigation_id,
            generated_at_utc=generated_at,
            is_inconclusive_or_fallback=is_fallback_active,
            validated_observables=observables,
            mitre_coverage_targets=mitre_targets,
            candidate_detection_hypotheses=candidate_hypotheses,
            recommended_log_sources=["Sysmon Process Creation (Event ID 1)", "Network Connections (Event ID 3)"],
            candidate_hunting_pseudocode=hunting_pseudocode,
            false_positive_considerations=[
                "Routine system administration scripts and scheduled tasks.",
                "Legitimate software updaters and endpoint management agents.",
                "Developer workstations with local build and test execution.",
            ],
            governance_disclaimer=self.DETECTION_DISCLAIMER,
            analytics_withheld_reason=_ANALYTICS_WITHHELD_REASON if withhold_analytics else None,
        )

        # Provenance
        provenance = ReportBundleProvenance(
            investigation_id=validation_result.output.investigation_id,
            context_sha256=validation_result.context_sha256,
            is_detached_format_mode=is_detached,
            is_inconclusive_or_fallback=is_fallback_active,
            overall_grounding_score=validation_result.output.overall_grounding_score,
            model_identifier=validation_result.output.model_identifier,
            is_verified_investigation=effective_verified,
            analytics_withheld_reason=_ANALYTICS_WITHHELD_REASON if withhold_analytics else None,
        )

        # ── RENDER DETERMINISTIC MARKDOWN ────────────────────────────────────
        md_exec = self._render_markdown_executive(exec_brief, unverified=withhold_analytics)
        md_tech = self._render_markdown_technical(tech_report, unverified=withhold_analytics)
        md_det = self._render_markdown_detection(detection_report, unverified=withhold_analytics)

        return InvestigationReportBundle(
            investigation_id=validation_result.output.investigation_id,
            generated_at_utc=generated_at,
            context_sha256=validation_result.context_sha256,
            is_fallback_active=is_fallback_active,
            provenance=provenance,
            executive_brief=exec_brief,
            technical_report=tech_report,
            detection_report=detection_report,
            markdown_executive=md_exec,
            markdown_technical=md_tech,
            markdown_detection=md_det,
        )

    # ── SEVERITY & RISK LOGIC ────────────────────────────────────────────────

    def _determine_severity(
        self,
        validation_result: InvestigationValidationResult,
        confirmed_claims: list[TechnicalReportClaim],
        mitre_mappings: list[dict[str, Any]],
        is_fallback: bool,
        context: Optional[InvestigationContext] = None,
        verified_events: Sequence[ContextEventItem] = (),
        is_detached: bool = False,
        gaps_list: Optional[list[str]] = None,
    ) -> tuple[IncidentSeverityTier, str]:
        """
        Evaluate incident severity using evidence-grounded deterministic rules.

        Invariants:
        1. Substring claim text matching is prohibited (SEC-AUDIT-001).
        2. LLM-generated MITRE tactics alone cannot elevate severity without verified events.
        3. Event citations must exist in verified_events.
        4. Structured event outcomes (outcome, action) distinguish successful from blocked/failed.
        5. Detached mode and truncated context always resolve to INCONCLUSIVE (SEC-AUDIT-002).
        6. When required evidence cannot establish an outcome, return INCONCLUSIVE.
        7. An unknown outcome on an auxiliary event never downgrades an independently confirmed hostile finding.
        8. A missing caller root anchor cannot silently certify a benign baseline.
        """
        def _add_gap(msg: str) -> None:
            if gaps_list is not None and msg not in gaps_list:
                gaps_list.append(msg)

        if is_detached or not verified_events:
            return (
                IncidentSeverityTier.INCONCLUSIVE,
                "Inconclusive incident severity: Telemetry context is unavailable in detached-format mode; baseline activity and adversary outcomes cannot be evaluated without verified evidence.",
            )

        if is_fallback:
            return (
                IncidentSeverityTier.INCONCLUSIVE,
                "Inconclusive incident severity: Analysis rejected by safety guardrails or failed factual grounding; deterministic fallback active.",
            )

        # Check for truncated context before evaluating severity
        is_truncated = False
        if context and context.budget_metrics and context.budget_metrics.context_truncated:
            is_truncated = True
        for gap in (gaps_list or []):
            gap_lower = gap.lower()
            if "truncated" in gap_lower or "budget" in gap_lower or "omitted" in gap_lower:
                is_truncated = True

        if is_truncated:
            return (
                IncidentSeverityTier.INCONCLUSIVE,
                "Inconclusive incident severity: Telemetry context was truncated due to budget constraints; absence of high-severity alerts cannot substantiate an informational or benign status.",
            )

        # Index verified events by event_uuid
        events_by_id: dict[uuid.UUID, ContextEventItem] = {e.event_uuid: e for e in verified_events}
        root_id: Optional[uuid.UUID] = None
        if context:
            repro = getattr(context, "reproducibility", None)
            if repro and hasattr(repro, "root_event_id"):
                root_id = repro.root_event_id
            elif hasattr(context, "root_event_id"):
                root_id = getattr(context, "root_event_id", None)

        # Check if caller-specified root anchor was replaced by fallback
        has_root_fallback = any("ROOT_ANCHOR_FALLBACK_APPLIED" in gap for gap in (gaps_list or []))
        if context and hasattr(context, "uncertainty_flags") and context.uncertainty_flags:
            has_root_fallback = has_root_fallback or any("ROOT_ANCHOR_FALLBACK_APPLIED" in flag for flag in context.uncertainty_flags)

        # Collect material event references deterministically from claims and hypotheses
        material_claim_event_uuids: set[uuid.UUID] = {
            ev_uuid
            for c in confirmed_claims
            for ev_uuid in c.supporting_event_uuids
            if ev_uuid in events_by_id
        }
        material_hyp_event_uuids: set[uuid.UUID] = {
            ev_uuid
            for h in validation_result.output.mitre_attack_hypotheses
            if _is_material_hypothesis(h)
            for ev_uuid in h.supporting_event_uuids
            if ev_uuid in events_by_id
        }
        all_material_event_uuids: set[uuid.UUID] = material_claim_event_uuids | material_hyp_event_uuids
        if root_id and root_id in events_by_id:
            all_material_event_uuids.add(root_id)

        high_impact_tactics = {"Impact", "Exfiltration", "Lateral Movement", "Credential Access"}
        execution_tactics = {"Execution", "Defense Evasion", "Privilege Escalation", "Persistence"}
        recon_tactics = {"Reconnaissance", "Discovery", "Initial Access"}

        has_successful_high_impact = False
        has_blocked_high_impact = False
        has_unknown_high_impact = False
        high_impact_has_provenance_gap = False

        has_successful_execution = False
        has_blocked_execution = False
        has_unknown_execution = False
        execution_has_provenance_gap = False

        has_successful_recon = False
        has_blocked_recon = False
        has_unknown_recon = False
        recon_has_provenance_gap = False

        for hyp in validation_result.output.mitre_attack_hypotheses:
            if hyp.confidence < 0.40:
                continue
            if _is_obsolete_taxonomy(hyp):
                continue  # a revoked/deprecated id is not an accepted mapping (formerly enforced by zeroed confidence)

            # Only cite valid events present in the verified context
            valid_events = [events_by_id[u] for u in hyp.supporting_event_uuids if u in events_by_id]
            if not valid_events:
                # Unverified / ungrounded hypothesis -> cannot elevate severity
                continue

            is_high_impact = any(t in high_impact_tactics for t in hyp.tactics) and hyp.confidence >= 0.60
            is_exec = any(t in execution_tactics for t in hyp.tactics) and hyp.confidence >= 0.50
            is_recon = any(t in recon_tactics for t in hyp.tactics) and hyp.confidence >= 0.40

            for ev in valid_events:
                outcome_str = (ev.outcome or "").strip().lower()
                action_str = (ev.action or "").strip().lower()
                ev_unlinked = _is_unlinked_or_missing_hash(ev.raw_evidence_sha256)

                ev_blocked = (action_str in _BLOCKED_ACTIONS) or (outcome_str in _BLOCKED_OUTCOMES)
                ev_success = (outcome_str in _SUCCESSFUL_OUTCOMES) and (action_str not in _BLOCKED_ACTIONS)
                ev_unknown = (outcome_str in _UNKNOWN_OUTCOMES) and (not ev_blocked)

                if is_high_impact:
                    if ev_success:
                        has_successful_high_impact = True
                        if ev_unlinked:
                            high_impact_has_provenance_gap = True
                    elif ev_blocked:
                        has_blocked_high_impact = True
                    elif ev_unknown:
                        has_unknown_high_impact = True

                if is_exec:
                    if ev_success:
                        has_successful_execution = True
                        if ev_unlinked:
                            execution_has_provenance_gap = True
                    elif ev_blocked:
                        has_blocked_execution = True
                    elif ev_unknown:
                        has_unknown_execution = True

                if is_recon:
                    if ev_success:
                        has_successful_recon = True
                        if ev_unlinked:
                            recon_has_provenance_gap = True
                    elif ev_blocked:
                        has_blocked_recon = True
                    elif ev_unknown:
                        has_unknown_recon = True

        # Uncited unknown-outcome events in scope are treated as indeterminate
        has_indeterminate_unknown = any(
            (e.outcome or "").strip().lower() in _UNKNOWN_OUTCOMES
            for e in verified_events
            if e.event_uuid not in all_material_event_uuids
        )

        def _apply_hostile_disclosures(base_justification: str, has_gap: bool) -> str:
            j = base_justification
            if has_gap:
                j += " [PROVENANCE_LIMITATION: Hostile finding is supported by telemetry events lacking cryptographic raw-evidence hashes; raw source integrity unverified.]"
                _add_gap("PROVENANCE_LIMITATION: Hostile finding is supported by telemetry events lacking cryptographic raw-evidence hashes; raw source integrity unverified.")
            if has_indeterminate_unknown:
                j += " [UNRESOLVED_INDETERMINATE_OUTCOME: Telemetry event(s) record unknown outcomes with indeterminate causal relation; forensic scope remains partially unverified.]"
                _add_gap("UNRESOLVED_INDETERMINATE_OUTCOME: Telemetry event(s) record unknown outcomes with indeterminate causal relation; forensic scope remains partially unverified.")
            if has_root_fallback:
                j += " [ROOT_SELECTION_LIMITATION: Caller-specified root anchor was absent and replaced by fallback; primary alert pivot remains unverified.]"
                _add_gap("ROOT_SELECTION_LIMITATION: Caller-specified root anchor was absent and replaced by fallback; primary alert pivot remains unverified.")
            if not confirmed_claims:
                j += " [EPISTEMIC_NOTE: Severity established via validated MITRE telemetry correlation despite zero confirmed factual claim statements.]"
            return j

        # 1. Critical: Validated structured telemetry confirms successful high-impact adversary action
        if has_successful_high_impact:
            justification = _apply_hostile_disclosures(
                "Critical incident severity: Validated structured telemetry confirms successful adversary activity associated with high-impact tactics (lateral movement, credential access, exfiltration, or impact).",
                high_impact_has_provenance_gap,
            )
            if gaps_list is not None:
                gaps_list.sort()
            return (IncidentSeverityTier.CRITICAL, justification)

        # 2. High: Validated structured telemetry confirms successful hostile execution or defense evasion
        if has_successful_execution:
            justification = _apply_hostile_disclosures(
                "High incident severity: Validated structured telemetry confirms successful hostile execution, privilege escalation, or defense evasion on target endpoint.",
                execution_has_provenance_gap,
            )
            if has_unknown_high_impact:
                justification += " [UNRESOLVED_HIGH_IMPACT_SUSPECTED: Telemetry records potential high-impact activity (lateral movement, credential access, impact), but outcome remains unknown; escalating containment recommended.]"
                _add_gap("UNRESOLVED_HIGH_IMPACT_SUSPECTED: Telemetry records potential high-impact activity (lateral movement, credential access, impact), but outcome remains unknown; escalating containment recommended.")
            if gaps_list is not None:
                gaps_list.sort()
            return (IncidentSeverityTier.HIGH, justification)

        # 3. Inconclusive: High-impact or execution activity observed, but event outcome status is unknown
        if has_unknown_high_impact or has_unknown_execution:
            return (
                IncidentSeverityTier.INCONCLUSIVE,
                "Inconclusive incident severity: Telemetry records potential high-risk or execution activity, but event outcome is unknown or unavailable in telemetry.",
            )

        # 4. Medium: High-impact or execution activity attempted, but blocked/denied by security controls
        if has_blocked_high_impact or has_blocked_execution:
            justification = _apply_hostile_disclosures(
                "Medium incident severity: High-risk or execution activity was detected, but structured telemetry confirms the action was blocked or denied by security controls.",
                False,
            )
            if gaps_list is not None:
                gaps_list.sort()
            return (IncidentSeverityTier.MEDIUM, justification)

        # 5. Medium: Validated anomalous discovery or reconnaissance succeeded
        if has_successful_recon:
            justification = _apply_hostile_disclosures(
                "Medium incident severity: Validated telemetry indicates anomalous discovery or reconnaissance; immediate hostile actions were partially restricted or unobserved.",
                recon_has_provenance_gap,
            )
            if gaps_list is not None:
                gaps_list.sort()
            return (IncidentSeverityTier.MEDIUM, justification)

        # 6. Inconclusive: Recon observed but outcome is unknown
        if has_unknown_recon:
            return (
                IncidentSeverityTier.INCONCLUSIVE,
                "Inconclusive incident severity: Reconnaissance activity observed, but event outcome status is unknown in telemetry.",
            )

        # 7. Low: Recon blocked or minor policy variation
        if has_blocked_recon:
            justification = _apply_hostile_disclosures(
                "Low incident severity: Reconnaissance or discovery activity was detected but blocked or denied by security controls.",
                False,
            )
            if gaps_list is not None:
                gaps_list.sort()
            return (IncidentSeverityTier.LOW, justification)

        # ── 8. NON-HOSTILE BASELINE & ANTI-BENIGN AXIOM EVALUATION ────────────
        # Reached ONLY when zero hostile tactics succeeded, blocked, or were unknown.

        # Rule 8a: Non-hostile activity requires at least one verified claim
        if not confirmed_claims:
            return (
                IncidentSeverityTier.INCONCLUSIVE,
                "Inconclusive incident severity: Zero claims achieved verified evidence grounding in available telemetry.",
            )

        # Rule 8b: Any unknown outcome prevents an informational baseline
        if any((e.outcome or "").strip().lower() in _UNKNOWN_OUTCOMES for e in verified_events):
            return (
                IncidentSeverityTier.INCONCLUSIVE,
                "Inconclusive incident severity: Event outcomes are unknown or missing in telemetry; baseline safety cannot be verified.",
            )

        # Rule 8c: Caller-specified root anchor fallback prevents certifying benign baseline
        if has_root_fallback:
            return (
                IncidentSeverityTier.INCONCLUSIVE,
                "Inconclusive incident severity: Caller-specified root anchor event was absent from telemetry context; baseline safety cannot be verified.",
            )

        # Rule 8d: Root anchor event presence and raw provenance validation
        if root_id is not None:
            if root_id not in events_by_id:
                return (
                    IncidentSeverityTier.INCONCLUSIVE,
                    "Inconclusive incident severity: Root anchor event is absent from telemetry context; baseline safety cannot be verified.",
                )
            if _is_unlinked_or_missing_hash(events_by_id[root_id].raw_evidence_sha256):
                return (
                    IncidentSeverityTier.INCONCLUSIVE,
                    "Inconclusive incident severity: Root anchor event lacks cryptographic raw-evidence provenance; baseline benign status cannot be certified.",
                )

        # Rule 8e: Material baseline claims supported by unlinked events prevent benign certification
        for claim_uuid in material_claim_event_uuids:
            if _is_unlinked_or_missing_hash(events_by_id[claim_uuid].raw_evidence_sha256):
                return (
                    IncidentSeverityTier.INCONCLUSIVE,
                    "Inconclusive incident severity: Material telemetry supporting confirmed claims lacks cryptographic raw-evidence provenance; baseline safety cannot be verified.",
                )

        # Rule 8f: Uncited auxiliary events with elevated severity prevent an informational baseline
        for ev in verified_events:
            if ev.event_uuid not in all_material_event_uuids:
                if (ev.severity or "").strip().lower() in ("critical", "high", "medium"):
                    return (
                        IncidentSeverityTier.INCONCLUSIVE,
                        "Inconclusive incident severity: Telemetry contains elevated-severity auxiliary events not reconciled in factual claims or MITRE hypotheses; baseline safety cannot be verified.",
                    )

        # Rule 8g: Demonstrably immaterial auxiliary events with unlinked hashes require explicit disclosure
        has_immaterial_unlinked = any(
            _is_unlinked_or_missing_hash(ev.raw_evidence_sha256)
            for ev in verified_events
            if ev.event_uuid not in all_material_event_uuids
        )
        justification = (
            "Informational incident severity: Validated activity is consistent with baseline administrative "
            "actions without evidence of hostile compromise."
        )
        if has_immaterial_unlinked:
            justification += (
                " [PROVENANCE_LIMITATION: 1 or more unlinked auxiliary events lack raw evidence hashes; "
                "activity verified immaterial to findings.]"
            )
            _add_gap("PROVENANCE_LIMITATION: 1 or more unlinked auxiliary events lack raw evidence hashes; activity verified immaterial to findings.")

        # 9. Informational: Verified baseline administrative activity without hostile tactics
        if gaps_list is not None:
            gaps_list.sort()
        return (
            IncidentSeverityTier.INFORMATIONAL,
            justification,
        )

    def _determine_business_risk(self, severity: IncidentSeverityTier) -> str:
        """Map incident severity tier to calibrated advisory business-risk statement."""
        mapping = {
            IncidentSeverityTier.CRITICAL: (
                "Elevated Operational Risk: Validated evidence indicates active adversary execution or potential data compromise. "
                "Immediate analyst triage, host containment scoping, and forensic preservation are required."
            ),
            IncidentSeverityTier.HIGH: (
                "Moderate-to-High Operational Risk: Unauthorized execution or defense evasion confirmed on endpoint. "
                "Verification of lateral movement scope is necessary."
            ),
            IncidentSeverityTier.MEDIUM: (
                "Moderate Operational Risk: Suspicious reconnaissance or connection attempts observed; hostile actions "
                "were restricted or inconclusive."
            ),
            IncidentSeverityTier.LOW: (
                "Minimal Operational Risk: Observed activity represents low-risk anomaly or minor policy variation."
            ),
            IncidentSeverityTier.INFORMATIONAL: (
                "Routine Operational Baseline: Activity consistent with standard endpoint baselines or administrative workflows."
            ),
            IncidentSeverityTier.INCONCLUSIVE: (
                "Indeterminate Operational Risk: Telemetry is insufficient, truncated, or failed evidence grounding. "
                "Business impact cannot be evaluated from available data alone; manual analyst review required."
            ),
        }
        text = mapping.get(severity, mapping[IncidentSeverityTier.INCONCLUSIVE])
        return (
            f"{text}\n\n"
            "Note: Technical severity does not equate to organizational business loss. "
            "Asset criticality and regulatory scope must be evaluated by the Incident Commander."
        )

    def _generate_hunting_guidance(
        self,
        offered_mappings: list[dict[str, Any]],
        observables: list[DetectionObservableItem],
    ) -> list[str]:
        """Generate structured pseudocode hunting queries based on validated evidence.

        ``offered_mappings`` are the report mapping dicts already selected by ``_mapping_offered_as_current`` (the caller decides
        eligibility from the hypothesis); this method no longer re-derives it from the ``taxonomy_state`` display key.
        """
        guidance: list[str] = []
        for m in offered_mappings:
            guidance.append(
                f"// Target: {m['technique_id']} ({m['technique_name']})\n"
                f"event_type == 'process_creation' AND action IN ('start', 'spawn') "
                f"AND tags CONTAINS '{m['technique_id']}'"
            )
        if not guidance:
            guidance.append("// No active hunting pseudocode generated for inconclusive or zero-tactic investigations.")
        return guidance

    # ── MARKDOWN RENDERERS ───────────────────────────────────────────────────

    def _render_markdown_executive(self, report: ExecutiveBrief, unverified: bool = False) -> str:
        """Render deterministic Markdown for the Executive Brief."""
        lines: list[str] = []
        if unverified:
            lines.extend(_UNVERIFIED_BANNER_LINES)
            lines.append("")
        lines.append(f"# {report.title}")
        lines.append("")
        sub = " (submitted, not verified)" if unverified else ""
        lines.append(f"**Investigation ID{sub}:** `{report.investigation_id}`  ")
        lines.append(f"**Generated (UTC){sub}:** `{report.generated_at_utc.strftime('%Y-%m-%dT%H:%M:%SZ')}`  ")
        lines.append(f"**Assessed Severity:** **{report.incident_severity.value.upper()}**  ")
        lines.append("")

        if unverified:
            lines.extend(_unverified_caution_lines(report.is_inconclusive_or_fallback))
        elif report.is_inconclusive_or_fallback:
            lines.append("> [!CAUTION]")
            lines.append("> **INVESTIGATION STATUS: INCONCLUSIVE / DETERMINISTIC FALLBACK ACTIVE**")
            lines.append("> AI analysis was rejected by safety guardrails or failed factual grounding.")
            lines.append("> Findings below reflect deterministic fallback data only.")
            lines.append("")
        elif report.incident_severity == IncidentSeverityTier.INCONCLUSIVE:
            lines.append("> [!CAUTION]")
            lines.append("> **INVESTIGATION STATUS: INCONCLUSIVE / VERIFICATION REQUIRED**")
            lines.append("> Telemetry evidence is insufficient, truncated, ungrounded, or detached.")
            lines.append("> Findings below are advisory and cannot confirm compromise or baseline safety.")
            lines.append("")

        lines.append("## Executive Summary")
        lines.append(report.executive_summary)
        lines.append("")

        lines.append("## Assessed Severity & Justification")
        lines.append(f"**Rating:** `{report.incident_severity.value.upper()}`")
        lines.append(report.severity_justification)
        lines.append("")

        lines.append("## Evidenced Affected Assets")
        if report.evidenced_affected_assets:
            for asset in report.evidenced_affected_assets:
                lines.append(f"- {_sanitize_inline_code(asset)}")
        else:
            lines.append("- Unspecified / Host telemetry not attributed")
        lines.append("")

        lines.append("## Key Confirmed Findings")
        if report.key_confirmed_findings:
            for finding in report.key_confirmed_findings:
                lines.append(f"- {_neutralize_markdown_structural_hijacking(finding)}")
        elif unverified:
            lines.append("- Not assessed: report verification failed.")
        else:
            lines.append("- No confirmed factual claims verified in telemetry.")
        lines.append("")

        lines.append("## Business Risk Assessment")
        lines.append(report.business_risk_statement)
        lines.append("")

        lines.append("## Threat Intelligence Context")
        lines.append(report.threat_intelligence_context)
        lines.append("")

        if report.uncertainties_and_limitations:
            lines.append("## Disclosed Gaps and Uncertainties")
            for gap in report.uncertainties_and_limitations:
                lines.append(f"- {_neutralize_markdown_structural_hijacking(gap)}")
            lines.append("")

        lines.append("---")
        lines.append(report.governance_disclaimer)
        lines.append("")

        return "\n".join(lines)

    def _render_markdown_technical(self, report: TechnicalIncidentReport, unverified: bool = False) -> str:
        """Render deterministic Markdown for the Technical Incident Response Report."""
        lines: list[str] = []
        if unverified:
            lines.extend(_UNVERIFIED_BANNER_LINES)
            lines.append("")
        lines.append("# AISOP Technical Incident Response Report")
        lines.append("")
        sub = " (submitted, not verified)" if unverified else ""
        lines.append(f"**Investigation ID{sub}:** `{report.investigation_id}`  ")
        lines.append(f"**Context SHA-256{sub}:** `{report.context_sha256}`  ")
        lines.append(f"**Generated (UTC){sub}:** `{report.generated_at_utc.strftime('%Y-%m-%dT%H:%M:%SZ')}`  ")
        lines.append(f"**Claims validated{sub}:** `{report.overall_grounding_score * 100:.1f}%`  ")
        lines.append(f"**Inference Model{sub}:** `{report.model_identifier}`  ")
        lines.append("")
        lines.append(f"> {CLAIMS_VALIDATED_DEFINITION}")
        lines.append(f"> {MODEL_REPORTED_CONFIDENCE_DEFINITION}")
        lines.append("")

        if unverified:
            lines.extend(_unverified_caution_lines(report.is_inconclusive_or_fallback))
        elif report.is_inconclusive_or_fallback:
            lines.append("> [!CAUTION]")
            lines.append("> **INVESTIGATION STATUS: INCONCLUSIVE / DETERMINISTIC FALLBACK ACTIVE**")
            lines.append("> AI analysis was rejected by safety guardrails or failed factual grounding.")
            lines.append("")

        lines.append("## Incident Narrative")
        lines.append(report.technical_narrative)
        lines.append("")

        lines.append("## Investigation Telemetry Timeline")
        if report.investigation_timeline:
            lines.append("| Timestamp (UTC) | Source / Host | Event Type | Action | Outcome | Event UUID | Raw SHA-256 |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for item in report.investigation_timeline:
                ts_str = item.timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
                short_hash = f"{item.raw_evidence_sha256[:12]}..." if len(item.raw_evidence_sha256) == 64 else item.raw_evidence_sha256
                lines.append(
                    f"| {ts_str} "
                    f"| {_sanitize_table_cell(item.source_identifier)} "
                    f"| {_sanitize_table_cell(item.event_type)} "
                    f"| {_sanitize_table_cell(item.action)} "
                    f"| {_sanitize_table_cell(item.outcome)} "
                    f"| `{item.event_uuid}` "
                    f"| `{short_hash}` |"
                )
        else:
            lines.append(f"*{report.timeline_status_disclosure or 'Timeline unavailable.'}*")
        lines.append("")

        lines.append("## Evidence-Linked Findings (AI-generated; legacy grounding: VALIDATED_REFERENCE; not analyst-confirmed)")
        if report.confirmed_findings:
            for idx, c in enumerate(report.confirmed_findings, start=1):
                uuids_str = ", ".join(f"`{u}`" for u in c.supporting_event_uuids) or "None"
                lines.append(f"{idx}. {_neutralize_markdown_structural_hijacking(c.claim_text)}")
                lines.append(f"   - **Model-reported confidence:** `{c.confidence:.2f}` | **Citations:** {uuids_str}")
                lines.extend(_verification_markdown_lines(c))
        elif unverified:
            lines.append("- Not assessed: report verification failed.")
        else:
            lines.append("- No claims passed the legacy grounding check against the cited telemetry.")
        lines.append("")

        lines.append("## Analytical Inferences & Hypotheses (Review Required)")
        if report.hypotheses_and_inferences:
            for idx, c in enumerate(report.hypotheses_and_inferences, start=1):
                notes = f" — *Notes: {c.analyst_notes}*" if c.analyst_notes else ""
                lines.append(f"{idx}. {_neutralize_markdown_structural_hijacking(c.claim_text)}")
                lines.append(f"   - **Status:** `{c.grounding_status}` | **Model-reported confidence:** `{c.confidence:.2f}`{notes}")
                lines.extend(_verification_markdown_lines(c))
        else:
            lines.append("- No inferences recorded.")
        lines.append("")

        lines.append("## Audit: Refuted or Unsupported Claims")
        if report.unsupported_or_contradicted_claims:
            for idx, c in enumerate(report.unsupported_or_contradicted_claims, start=1):
                notes = f" — *Reason: {c.analyst_notes}*" if c.analyst_notes else ""
                lines.append(f"{idx}. {_neutralize_markdown_structural_hijacking(c.claim_text)}")
                lines.append(f"   - **Disposition:** `{c.grounding_status.upper()}`{notes}")
                lines.extend(_verification_markdown_lines(c))
        else:
            lines.append("- Zero unsupported or contradicted claims generated by model.")
        lines.append("")

        lines.append("## MITRE ATT&CK Mapping Matrix (submitted, not verified)" if unverified else "## MITRE ATT&CK Mapping Matrix")
        if report.mitre_attack_mappings:
            lines.append("| Technique ID | Name | Tactics | Model-reported confidence | Evidence Citations |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for m in report.mitre_attack_mappings:
                tactics_str = ", ".join(m["tactics"]) or "—"
                citations_str = ", ".join(f"`{u[:8]}...`" for u in m["supporting_event_uuids"]) or "None"
                lines.append(
                    f"| `{m['technique_id']}` "
                    f"| {_sanitize_table_cell(m['technique_name'] + _taxonomy_suffix(m))} "
                    f"| {_sanitize_table_cell(tactics_str)} "
                    f"| `{m['confidence']:.2f}` "
                    f"| {citations_str} |"
                )
        else:
            lines.append("- No MITRE ATT&CK techniques mapped.")
        lines.append("")

        lines.append(
            "## Recommended Analyst Actions (Advisory Only; unverified suggestions)"
            if unverified
            else "## Recommended Analyst Actions (Advisory Only)"
        )
        if report.recommended_analyst_actions:
            for idx, act in enumerate(report.recommended_analyst_actions, start=1):
                lines.append(f"{idx}. {_neutralize_markdown_structural_hijacking(act)}")
        else:
            lines.append("- Review raw audit logs directly.")
        lines.append("")

        if report.investigation_gaps:
            lines.append("## Investigation Gaps & Missing Evidence")
            for gap in report.investigation_gaps:
                lines.append(f"- {_neutralize_markdown_structural_hijacking(gap)}")
            lines.append("")

        lines.append("---")
        lines.append(report.governance_disclaimer)
        lines.append("")

        return "\n".join(lines)

    def _render_markdown_detection(self, report: DetectionEngineeringReport, unverified: bool = False) -> str:
        """Render deterministic Markdown for the Detection Engineering Report."""
        lines: list[str] = []
        if unverified:
            lines.extend(_UNVERIFIED_BANNER_LINES)
            lines.append("")
        lines.append("# AISOP Detection Engineering & Hunting Report")
        lines.append("")
        sub = " (submitted, not verified)" if unverified else ""
        lines.append(f"**Investigation ID{sub}:** `{report.investigation_id}`  ")
        lines.append(f"**Generated (UTC){sub}:** `{report.generated_at_utc.strftime('%Y-%m-%dT%H:%M:%SZ')}`  ")
        lines.append("")

        if unverified:
            lines.extend(_unverified_caution_lines(report.is_inconclusive_or_fallback))
            if report.analytics_withheld_reason:
                lines.append(f"**Analytics withheld:** {report.analytics_withheld_reason}")
                lines.append("")
        elif report.is_inconclusive_or_fallback:
            lines.append("> [!CAUTION]")
            lines.append("> **INVESTIGATION STATUS: INCONCLUSIVE / DETERMINISTIC FALLBACK ACTIVE**")
            lines.append("> Threat intelligence and observables below are unverified due to fallback disposition.")
            lines.append("")

        lines.append("## Validated Observables & Provenance")
        if report.validated_observables:
            lines.append("| Type | Observable Value | Provenance Mode | Provenance Citations |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for obs in report.validated_observables:
                cites = (
                    ", ".join(f"`{u}`" for u in obs.provenance_event_uuids)
                    if obs.provenance_event_uuids
                    else ", ".join(f"claim:`{u}`" for u in obs.provenance_claim_ids)
                ) or "None"
                lines.append(
                    f"| `{obs.observable_type}` "
                    f"| {_sanitize_inline_code(obs.observable_value)} "
                    f"| `{obs.provenance_type}` "
                    f"| {cites} |"
                )
        elif unverified:
            lines.append("- Withheld: report verification failed.")
        else:
            lines.append("- No observables extracted from validated telemetry.")
        lines.append("")

        lines.append("## Target MITRE ATT&CK Techniques")
        if report.mitre_coverage_targets:
            for tech in report.mitre_coverage_targets:
                lines.append(f"- `{tech}`")
        elif unverified:
            lines.append("- Withheld: report verification failed.")
        else:
            lines.append("- No techniques targeted.")
        lines.append("")

        lines.append("## Candidate Detection Hypotheses")
        for hyp in report.candidate_detection_hypotheses:
            lines.append(f"- {_neutralize_markdown_structural_hijacking(hyp)}")
        lines.append("")

        lines.append("## Advisory Hunting Pseudocode")
        for code in report.candidate_hunting_pseudocode:
            lines.append("```sql")
            lines.append(code)
            lines.append("```")
            lines.append("")

        lines.append("## False-Positive Considerations")
        for fp in report.false_positive_considerations:
            lines.append(f"- {_neutralize_markdown_structural_hijacking(fp)}")
        lines.append("")

        lines.append("---")
        lines.append(report.governance_disclaimer)
        lines.append("")

        return "\n".join(lines)


__all__ = [
    "ContextIntegrityError",
    "verify_context_binding",
    "DeterministicReportSynthesizer",
]
