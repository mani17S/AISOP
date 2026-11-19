"""
AISOP Role-Tailored Structured Investigation Reporting Schemas.

Defines typed, immutable Pydantic V2 contracts for:
1. Executive Brief (non-technical leadership summary, assessed risk, evidenced assets).
2. Technical Incident Response Report (chronological timeline, confirmed findings, audit of refuted claims, MITRE ATT&CK, gaps).
3. Detection Engineering Report (observables with provenance, hunting pseudocode, false-positive considerations).
4. InvestigationReportBundle (consolidated structured views and deterministic Markdown).
5. ReportFormatRequest (input contract for offline or re-rendered formatting with cryptographic context binding).

Security & Architectural Invariants:
1. All models are immutable (frozen=True) with strict unknown-field prohibition (extra="forbid").
2. Evidence attributes and claim texts are treated as UNTRUSTED DATA.
3. Timestamps are timezone-aware and normalized to UTC.
4. Epistemic segregation: Confirmed observations are strictly separated from hypotheses and refuted claims.
5. Zero LLM Inference: Reporting contracts are purely deterministic presentations of validated investigation results.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
import re
from typing import Any, Optional, Self
import uuid

from pydantic import BaseModel, ConfigDict, Field, SerializerFunctionWrapHandler, field_validator, model_serializer, model_validator

from app.modules.ai.guardrails.validator import InvestigationValidationResult
from app.schemas.claim_verification import ClaimVerification
from app.schemas.investigation import InvestigationContext


def _validate_and_normalize_utc(dt: datetime, field_name: str) -> datetime:
    """Enforce timezone-awareness and normalize datetime to UTC."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"{field_name} must be timezone-aware (e.g. UTC)")
    return dt.astimezone(timezone.utc)


class IncidentSeverityTier(StrEnum):
    """Assessed incident severity classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    INCONCLUSIVE = "inconclusive"


class ReportAudience(StrEnum):
    """Target audience categorization for generated reports."""

    EXECUTIVE = "executive"
    TECHNICAL_IR = "technical_ir"
    DETECTION_ENGINEERING = "detection_engineering"


class ExecutiveBrief(BaseModel):
    """Executive Brief tailored for CISO, SOC leadership, and non-technical stakeholders."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: uuid.UUID = Field(description="Corresponding investigation UUID")
    generated_at_utc: datetime = Field(description="Deterministic generation timestamp in UTC")
    title: str = Field(min_length=5, description="Executive brief heading")
    incident_severity: IncidentSeverityTier = Field(
        description="Assessed incident severity (inconclusive when ungrounded/truncated)"
    )
    severity_justification: str = Field(
        min_length=10, description="Evidence basis and limitations for assigned severity"
    )
    is_inconclusive_or_fallback: bool = Field(
        description="True if investigation fell back to deterministic fallback or failed grounding"
    )
    executive_summary: str = Field(
        min_length=20, description="High-level non-technical incident narrative"
    )
    evidenced_affected_assets: list[str] = Field(
        default_factory=list, description="Hostnames/assets confirmed by validated telemetry"
    )
    key_confirmed_findings: list[str] = Field(
        default_factory=list, description="Bulleted list of claims with VALIDATED_REFERENCE only"
    )
    threat_intelligence_context: str = Field(
        description="Concise external intelligence summary or unavailable disclosure"
    )
    business_risk_statement: str = Field(
        description="Advisory operational risk statement with human assessment requirement"
    )
    uncertainties_and_limitations: list[str] = Field(
        default_factory=list, description="Explicit disclosures regarding truncation, gaps, or degraded feeds"
    )
    governance_disclaimer: str = Field(
        description="Mandatory human-in-the-loop and anti-autonomous action disclaimer"
    )

    @field_validator("generated_at_utc", mode="after")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        return _validate_and_normalize_utc(v, "generated_at_utc")


class TimelineEventSummary(BaseModel):
    """Ordered event item within the technical investigation timeline."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_uuid: uuid.UUID = Field(description="Database primary key UUID of normalized event")
    timestamp_utc: datetime = Field(description="Event timestamp in UTC")
    source_identifier: str = Field(description="Endpoint hostname or sensor identifier")
    event_type: str = Field(description="Canonical event category (e.g. process_creation)")
    action: str = Field(description="Action verb (e.g. created, connected)")
    outcome: str = Field(description="Observed outcome (success, failure, unknown)")
    raw_evidence_sha256: str = Field(description="SHA-256 digest of raw telemetry or unavailable sentinel")
    summary: str = Field(description="Sanitized event summary")

    @field_validator("timestamp_utc", mode="after")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        return _validate_and_normalize_utc(v, "timestamp_utc")


class TechnicalReportClaim(BaseModel):
    """Claim representation in the Technical Incident Response Report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    claim_id: uuid.UUID = Field(description="Unique claim identifier")
    claim_text: str = Field(min_length=1, description="Specific claim text")
    category: str = Field(description="Epistemic category (observed_fact, inference, external_intelligence, unknown)")
    grounding_status: str = Field(description="Validation status (validated_reference, analyst_review_required, unsupported, contradicted)")
    confidence: float = Field(ge=0.0, le=1.0, description="Model-reported confidence (0.0 to 1.0), only capped by guardrails; not independently measured evidence strength")
    supporting_event_uuids: list[uuid.UUID] = Field(default_factory=list, description="Verified supporting event UUIDs")
    analyst_notes: Optional[str] = Field(default=None, description="Guardrail audit flags or warnings")
    verification: Optional[ClaimVerification] = Field(
        default=None,
        description=(
            "Optional claim-verification-v1 result copied from the server-validated claim (never computed here, never client-trusted). "
            "Absent for historical reports, unverified/detached input and claims without structured assertions. It checks the claim's listed "
            "assertions only; it is not analyst confirmation."
        ),
    )

    @model_serializer(mode="wrap")
    def _omit_absent_verification(self, handler: SerializerFunctionWrapHandler) -> Any:
        """Historical compatibility: a claim without verification serializes byte-identically to the pre-verification shape."""
        data = handler(self)
        if isinstance(data, dict) and data.get("verification") is None:
            data.pop("verification", None)
        return data


class TechnicalIncidentReport(BaseModel):
    """In-depth Technical Incident Response Report for SOC analysts and responders."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: uuid.UUID = Field(description="Investigation UUID")
    generated_at_utc: datetime = Field(description="Deterministic generation timestamp in UTC")
    is_inconclusive_or_fallback: bool = Field(description="True if fallback or inconclusive")
    technical_narrative: str = Field(description="Detailed incident narrative")
    investigation_timeline: list[TimelineEventSummary] = Field(
        default_factory=list, description="Chronologically sorted telemetry timeline"
    )
    timeline_status_disclosure: Optional[str] = Field(
        default=None, description="Disclosure when timeline is unavailable or detached"
    )
    confirmed_findings: list[TechnicalReportClaim] = Field(
        default_factory=list, description="Claims with VALIDATED_REFERENCE status only"
    )
    hypotheses_and_inferences: list[TechnicalReportClaim] = Field(
        default_factory=list, description="Claims requiring analyst review (inferences)"
    )
    unsupported_or_contradicted_claims: list[TechnicalReportClaim] = Field(
        default_factory=list, description="Claims refuted or unsupported by evidence (retained for audit)"
    )
    mitre_attack_mappings: list[dict[str, Any]] = Field(
        default_factory=list, description="Validated ATT&CK techniques with supporting evidence"
    )
    threat_intelligence_enrichment: list[dict[str, Any]] = Field(
        default_factory=list, description="Enriched threat intelligence observables"
    )
    investigation_gaps: list[str] = Field(
        default_factory=list, description="Disclosed missing sensors, omitted telemetry, or data gaps"
    )
    recommended_analyst_actions: list[str] = Field(
        default_factory=list, description="Advisory containment steps with dangerous shell code stripped"
    )
    context_sha256: str = Field(description="Verified forensic SHA-256 context digest")
    model_identifier: str = Field(description="LLM provider and model identifier")
    overall_grounding_score: float = Field(ge=0.0, le=1.0, description="Claims validated: fraction (0.0 to 1.0) of claims whose citations passed configured validation checks; not evidence strength or proof of truth")
    governance_disclaimer: str = Field(description="Mandatory advisory disclaimer")

    @field_validator("generated_at_utc", mode="after")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        return _validate_and_normalize_utc(v, "generated_at_utc")


class DetectionObservableItem(BaseModel):
    """Extracted observable with provenance tracking for detection rule engineering."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observable_type: str = Field(description="Indicator type: ip, domain, sha256, executable, command_line")
    observable_value: str = Field(min_length=1, description="Canonical observable value")
    provenance_type: str = Field(
        description="Provenance classification: bound_telemetry or claim_text_extraction"
    )
    provenance_event_uuids: list[uuid.UUID] = Field(
        default_factory=list, description="Associated event UUIDs where observed"
    )
    provenance_claim_ids: list[uuid.UUID] = Field(
        default_factory=list, description="Associated claim IDs where asserted"
    )
    is_malicious_asserted: bool = Field(
        default=False, description="True if threat intelligence or confirmed finding explicitly asserts maliciousness"
    )
    first_seen_utc: Optional[datetime] = Field(
        default=None, description="Earliest observation timestamp if bound context available"
    )
    last_seen_utc: Optional[datetime] = Field(
        default=None, description="Latest observation timestamp if bound context available"
    )

    @field_validator("first_seen_utc", "last_seen_utc", mode="after")
    @classmethod
    def validate_timestamps(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None:
            return _validate_and_normalize_utc(v, "observable_timestamp")
        return None


class DetectionEngineeringReport(BaseModel):
    """Detection Engineering, Threat Hunting, and Content Development Guidance Report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: uuid.UUID = Field(description="Investigation UUID")
    generated_at_utc: datetime = Field(description="Deterministic generation timestamp in UTC")
    is_inconclusive_or_fallback: bool = Field(description="True if fallback or inconclusive")
    validated_observables: list[DetectionObservableItem] = Field(
        default_factory=list, description="Deduplicated observables with provenance attribution"
    )
    mitre_coverage_targets: list[str] = Field(
        default_factory=list, description="Validated MITRE technique IDs targeted for coverage"
    )
    candidate_detection_hypotheses: list[str] = Field(
        default_factory=list, description="High-level behavioral detection ideas"
    )
    recommended_log_sources: list[str] = Field(
        default_factory=list, description="Required telemetry sensors and event types"
    )
    candidate_hunting_pseudocode: list[str] = Field(
        default_factory=list, description="Advisory pseudo-queries for threat hunting"
    )
    false_positive_considerations: list[str] = Field(
        default_factory=list, description="Benign administrative utilities and baseline factors"
    )
    governance_disclaimer: str = Field(
        description="Mandatory engineering disclaimer requiring local baseline tuning"
    )
    analytics_withheld_reason: Optional[str] = Field(
        default=None,
        description=(
            "Fixed, code-prefixed reason (never submitted data) that analytical outputs were withheld because report verification "
            "failed. Absent (key omitted) for verified and server-built reports, so an empty coverage list is never ambiguous."
        ),
    )

    @field_validator("generated_at_utc", mode="after")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        return _validate_and_normalize_utc(v, "generated_at_utc")

    # No return annotation on purpose: an explicit ``-> Any`` would become the serialization-mode JSON Schema of this whole model.
    @model_serializer(mode="wrap")
    def _omit_absent_analytics_withheld_reason(self, handler: SerializerFunctionWrapHandler):
        """ABSENT_WHEN_NONE: verified/server-built output keeps its prior JSON shape (no new key)."""
        data = handler(self)
        if isinstance(data, dict) and data.get("analytics_withheld_reason") is None:
            data.pop("analytics_withheld_reason", None)
        return data


class ReportBundleProvenance(BaseModel):
    """Cryptographic provenance and context binding verification metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: uuid.UUID = Field(description="Investigation UUID")
    context_sha256: str = Field(description="Forensic context SHA-256 digest")
    is_detached_format_mode: bool = Field(description="True if generated without bound InvestigationContext")
    is_inconclusive_or_fallback: bool = Field(description="True if deterministic fallback active")
    overall_grounding_score: float = Field(ge=0.0, le=1.0, description="Claims validated: fraction (0.0 to 1.0) of claims whose citations passed configured validation checks; not evidence strength or proof of truth")
    model_identifier: str = Field(description="Model identifier")
    is_verified_investigation: bool = Field(
        default=False,
        description="True only if investigation validity is backed by server-side case audit records",
    )
    analytics_withheld_reason: Optional[str] = Field(
        default=None,
        description=(
            "Fixed, code-prefixed reason (never submitted data) that analytical outputs were withheld because report verification "
            "failed. Absent (key omitted) for verified and server-built reports."
        ),
    )

    # No return annotation on purpose: an explicit ``-> Any`` would become the serialization-mode JSON Schema of this whole model.
    @model_serializer(mode="wrap")
    def _omit_absent_analytics_withheld_reason(self, handler: SerializerFunctionWrapHandler):
        """ABSENT_WHEN_NONE: verified/server-built output keeps its prior JSON shape (no new key)."""
        data = handler(self)
        if isinstance(data, dict) and data.get("analytics_withheld_reason") is None:
            data.pop("analytics_withheld_reason", None)
        return data


class InvestigationReportBundle(BaseModel):
    """Consolidated bundle containing all three role-tailored reports and their Markdown renderings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: uuid.UUID = Field(description="Investigation tracking ID")
    generated_at_utc: datetime = Field(description="Deterministic generation timestamp in UTC")
    context_sha256: str = Field(description="Verified context SHA-256 digest")
    is_fallback_active: bool = Field(description="True if fallback or inconclusive")
    provenance: ReportBundleProvenance = Field(description="Provenance and integrity metadata")
    executive_brief: ExecutiveBrief = Field(description="Executive Brief")
    technical_report: TechnicalIncidentReport = Field(description="Technical Incident Response Report")
    detection_report: DetectionEngineeringReport = Field(description="Detection Engineering Report")
    markdown_executive: str = Field(description="Deterministic Markdown representation of Executive Brief")
    markdown_technical: str = Field(description="Deterministic Markdown representation of Technical Report")
    markdown_detection: str = Field(description="Deterministic Markdown representation of Detection Report")

    @field_validator("generated_at_utc", mode="after")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        return _validate_and_normalize_utc(v, "generated_at_utc")


class ReportFormatRequest(BaseModel):
    """Request schema for offline or re-rendered report formatting."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    validation_result: InvestigationValidationResult = Field(
        description="Validated investigation result to render"
    )
    context: Optional[InvestigationContext] = Field(
        default=None,
        description="Optional InvestigationContext for cryptographic binding and timeline generation",
    )
    case_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Optional Case UUID for server-side verified audit binding and authorization",
    )


class ReportExportFormat(StrEnum):
    """Supported export serialization formats."""

    MARKDOWN = "markdown"
    JSON = "json"


class ReportExportView(StrEnum):
    """Specific role-tailored report view or consolidated bundle."""

    BUNDLE = "bundle"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    DETECTION = "detection"


class ReportExportResponse(BaseModel):
    """Exported investigation report container with cryptographic provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: uuid.UUID = Field(description="Case UUID")
    investigation_id: uuid.UUID = Field(description="Investigation UUID")
    format: str = Field(description="Export format (markdown or json)")
    view: str = Field(description="Export view (bundle, executive, technical, detection)")
    filename: str = Field(description="Deterministic filename for export artifact")
    content: str = Field(description="Exported report content string")
    context_sha256: str = Field(description="Cryptographic context SHA-256 digest")
    exported_at_utc: datetime = Field(description="UTC timestamp of export")
    is_server_verified: bool = Field(
        default=True,
        description="True if report provenance is anchored in server-side audit logs",
    )

    @field_validator("exported_at_utc", mode="after")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        return _validate_and_normalize_utc(v, "exported_at_utc")


__all__ = [
    "IncidentSeverityTier",
    "ReportAudience",
    "ExecutiveBrief",
    "TimelineEventSummary",
    "TechnicalReportClaim",
    "TechnicalIncidentReport",
    "DetectionObservableItem",
    "DetectionEngineeringReport",
    "ReportBundleProvenance",
    "InvestigationReportBundle",
    "ReportFormatRequest",
    "ReportExportFormat",
    "ReportExportView",
    "ReportExportResponse",
]
