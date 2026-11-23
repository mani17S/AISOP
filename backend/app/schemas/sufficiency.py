"""
AISOP Evidence-Sufficiency Assessment Schemas (Stage 3C, ADR-008).

Immutable, auditable contract produced by the deterministic pre-model
sufficiency gate. The assessment is derived only from an InvestigationContext;
it never contains evidence payload text, summaries, attributes or secrets, only
fixed-vocabulary reason codes, counts and event UUID references.

This module deliberately does NOT modify InvestigationContext or
StructuredInvestigationOutput (their SHA-256 hash semantics are unchanged).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.contradiction import ContradictionFinding, Materiality

#: Version of the deterministic rule table. Bump on any rule/threshold change.
SUFFICIENCY_RULE_VERSION = "suff-v4"  # v4 (ADR-013 Rev 2): contradiction findings from independent sources; see schemas/contradiction.py


class SufficiencyVerdict(StrEnum):
    """Outcome of the pre-model evidence-sufficiency gate."""

    SUFFICIENT = "sufficient"
    LIMITED = "limited"
    INSUFFICIENT = "insufficient"


class ReasonCode(StrEnum):
    """Fixed vocabulary of sufficiency reason codes (never free text)."""

    NO_EVIDENCE = "NO_EVIDENCE"
    NO_RELEVANT_EVIDENCE = "NO_RELEVANT_EVIDENCE"
    EVIDENCE_TRUNCATED = "EVIDENCE_TRUNCATED"
    ROOT_ABSENT = "ROOT_ABSENT"
    ROOT_PROVENANCE_MISSING = "ROOT_PROVENANCE_MISSING"
    PROVENANCE_UNVERIFIED_ALL = "PROVENANCE_UNVERIFIED_ALL"
    PROVENANCE_PARTIAL = "PROVENANCE_PARTIAL"
    UNCORROBORATED_QUESTION = "UNCORROBORATED_QUESTION"
    TEMPORAL_ANOMALY = "TEMPORAL_ANOMALY"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    DUPLICATE_EVIDENCE_COLLAPSED = "DUPLICATE_EVIDENCE_COLLAPSED"
    WEAK_LINK_ONLY = "WEAK_LINK_ONLY"
    REPEATED_OBSERVATION_ONLY = "REPEATED_OBSERVATION_ONLY"
    SAME_VANTAGE_ONLY = "SAME_VANTAGE_ONLY"
    IRRELEVANT_EVIDENCE_EXCLUDED = "IRRELEVANT_EVIDENCE_EXCLUDED"
    GATE_EVALUATION_ERROR = "GATE_EVALUATION_ERROR"


class FindingEffect(StrEnum):
    """How a finding influences the verdict."""

    INSUFFICIENT = "insufficient"
    LIMITED = "limited"
    DISCLOSURE = "disclosure"


class SufficiencyFinding(BaseModel):
    """One fired rule: code, effect and the event UUIDs it refers to."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: ReasonCode
    effect: FindingEffect
    #: Optional fixed-vocabulary qualifier, e.g. the missing entity type ("process").
    qualifier: Optional[str] = Field(default=None, max_length=64, pattern=r"^[a-z_]*$")
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Event UUID strings (taken from the context only, never from model output)",
    )

    @property
    def coded(self) -> str:
        return f"{self.code.value}:{self.qualifier}" if self.qualifier else self.code.value


class EvidenceSufficiencyAssessment(BaseModel):
    """Deterministic, hashable pre-model evidence-sufficiency assessment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: SufficiencyVerdict
    rule_version: str = Field(default=SUFFICIENCY_RULE_VERSION)
    findings: list[SufficiencyFinding] = Field(default_factory=list)
    reason_codes: list[str] = Field(
        default_factory=list,
        description="Sorted unique coded reasons (CODE or CODE:qualifier)",
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Event UUID strings of the effective (de-duplicated) evidence considered",
    )
    total_events: int = Field(ge=0, default=0)
    effective_events: int = Field(ge=0, default=0)
    relevant_events: int = Field(ge=0, default=0)
    attested_events: int = Field(ge=0, default=0)
    corroborating_events: int = Field(ge=0, default=0)
    contradictions: list[ContradictionFinding] = Field(
        default_factory=list,
        description="ADR-013: contradiction findings (fixed vocabulary, evidence ids only) with the gate's relation and materiality decision",
    )
    context_sha256: Optional[str] = Field(default=None)
    assessment_sha256: str = Field(
        description="SHA-256 of the canonical JSON of this assessment without this field"
    )

    @property
    def abstain(self) -> bool:
        """True when no model invocation is permitted."""
        return self.verdict == SufficiencyVerdict.INSUFFICIENT

    @property
    def has_unresolved_material_contradiction(self) -> bool:
        """
        True when a MATERIAL contradiction was found. Detection Engineering boundary (owner decision 5, ADR-013): an assessment for which
        this is True must NOT be treated as a validated finding; it may only be offered as an investigation lead with the contradiction
        disclosed. The future findings interface (ADR-012 module 1) must call this property before offering a finding.
        """
        return any(c.materiality == Materiality.MATERIAL for c in self.contradictions)

    def audit_details(self) -> dict[str, Any]:
        """Fixed-shape, payload-free dictionary for the case audit `details` JSON."""
        return {
            "sufficiency_verdict": self.verdict.value,
            "sufficiency_rule_version": self.rule_version,
            "sufficiency_reason_codes": list(self.reason_codes),
            "sufficiency_evidence_ids": list(self.evidence_ids)[:50],
            "sufficiency_assessment_sha256": self.assessment_sha256,
            "abstained": self.abstain,
        }

    def disclosure_flags(self) -> list[str]:
        """Coded, fixed-vocabulary strings suitable for uncertainty_and_data_gaps."""
        if not self.reason_codes and self.verdict == SufficiencyVerdict.SUFFICIENT:
            return []
        flags = [
            f"EVIDENCE_SUFFICIENCY[{self.rule_version}]={self.verdict.value.upper()}: "
            + ", ".join(self.reason_codes)
            if self.reason_codes
            else f"EVIDENCE_SUFFICIENCY[{self.rule_version}]={self.verdict.value.upper()}"
        ]
        return flags

    def limitation_note(self) -> Optional[str]:
        """Trusted, fixed-text instruction for the prompt when the verdict is LIMITED."""
        if self.verdict != SufficiencyVerdict.LIMITED:
            return None
        return (
            "[EVIDENCE LIMITATION - system generated]: The deterministic evidence-sufficiency "
            f"check ({self.rule_version}) classified this evidence as LIMITED with reason codes: "
            + ", ".join(self.reason_codes)
            + ". Make only bounded statements that are directly supported by the cited events, "
            "do not state definitive conclusions, and disclose the missing evidence in "
            "uncertainty_and_data_gaps."
        )
