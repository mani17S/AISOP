"""
AISOP Investigation Contracts and Domain Schemas.

In accordance with P2-H4 Design and Architecture Decision Records (ADR-001, ADR-002):
Defines typed, immutable Pydantic V2 contracts for investigation context assembly,
budgeting, deterministic reproducibility records, structured LLM output generation,
and 3-tier factual claim grounding.

Security & Architectural Invariants:
1. All models are immutable (frozen=True) with strict unknown-field prohibition (extra="forbid").
2. Evidence attributes and retrieved texts represent UNTRUSTED DATA and are kept logically
   distinct from derived claims and authoritative system state.
3. Timestamps must be timezone-aware and are normalized to UTC.
4. SHA-256 digests are validated as exactly 64 hexadecimal characters.
5. Incomplete context and evidence omission (both events and entities) are explicitly recorded
   in BudgetMetrics and uncertainty flags; evidence is never silently dropped.
6. Syntactic and structural validation does not equate to semantic truth or prompt-injection immunity.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
import re
from typing import Any, Optional, Self
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.attack_taxonomy import TechniqueTaxonomyStatus
from app.schemas.claim_verification import ClaimVerification


_SHA256_HEX_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _validate_and_normalize_utc(dt: datetime, field_name: str) -> datetime:
    """Enforce timezone-awareness and normalize datetime to UTC."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"{field_name} must be timezone-aware (e.g. UTC)")
    return dt.astimezone(timezone.utc)


def _validate_sha256_hex(val: str, field_name: str) -> str:
    """Validate 64-character hexadecimal SHA-256 digest."""
    if not _SHA256_HEX_RE.match(val):
        raise ValueError(
            f"{field_name} must be exactly 64 hexadecimal characters, got {val!r}"
        )
    return val.lower()


class InvestigationScopeType(StrEnum):
    """Classification of the investigation scope boundary."""

    SINGLE_EVENT = "single_event"
    INCIDENT_TIMELINE = "incident_timeline"
    ENTITY_CENTRIC = "entity_centric"


class ContextTIVerdict(StrEnum):
    """Threat intelligence verdict categories."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class ContextTIThreatState(StrEnum):
    """Operational state of threat intelligence lookup."""

    SHIELDED_INTERNAL = "shielded_internal"
    ACTIVE = "active"
    STALE = "stale"
    ENGINE_UNAVAILABLE = "engine_unavailable"


class ClaimCategory(StrEnum):
    """Epistemic categorization of an investigation claim."""

    OBSERVED_FACT = "observed_fact"
    EXTERNAL_INTELLIGENCE = "external_intelligence"
    INFERENCE = "inference"
    UNKNOWN = "unknown"


class GroundingStatus(StrEnum):
    """Deterministic validation status of a claim against provided context."""

    VALIDATED_REFERENCE = "validated_reference"
    ANALYST_REVIEW_REQUIRED = "analyst_review_required"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"


class ContextEventItem(BaseModel):
    """Normalized security telemetry event included in the investigation context."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_uuid: uuid.UUID = Field(description="Normalized event database primary key")
    raw_evidence_sha256: str = Field(
        description="SHA-256 cryptographic digest of raw telemetry (64 hex characters)"
    )
    event_id: str = Field(description="Source-native event ID (e.g. Sysmon '1', '3')")
    event_type: str = Field(description="Canonical category (e.g. process_creation, network_connection)")
    timestamp_utc: datetime = Field(description="Observation time in UTC")
    action: str = Field(description="Action verb (e.g. created, connected, queried)")
    outcome: str = Field(default="unknown", description="Outcome status (success, failure, unknown)")
    severity: str = Field(
        default="informational",
        description="Pre-assessed severity (informational, low, medium, high, critical)",
    )
    source_identifier: str = Field(description="Endpoint hostname or sensor ID")
    summary: str = Field(description="Human-readable event summary")
    attributes: dict[str, Any] = Field(
        default_factory=dict, description="Sanitized key event attributes"
    )

    @field_validator("timestamp_utc", mode="after")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        return _validate_and_normalize_utc(v, "timestamp_utc")

    @field_validator("raw_evidence_sha256", mode="after")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        return _validate_sha256_hex(v, "raw_evidence_sha256")

    @field_validator("summary", mode="after")
    @classmethod
    def validate_summary(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("summary must contain meaningful non-whitespace content")
        return v


class ContextEntityItem(BaseModel):
    """Deduplicated atomic entity extracted across the investigation scope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_type: str = Field(
        description="Entity category: ip, host, user, process, file_hash, domain"
    )
    entity_value: str = Field(min_length=1, description="Canonical entity value")
    roles: list[str] = Field(
        default_factory=list,
        description="Observed roles (e.g. source, destination, target, executed)",
    )
    occurrence_count: int = Field(
        ge=1, description="Number of events in scope containing this entity"
    )
    associated_event_uuids: list[uuid.UUID] = Field(
        default_factory=list, description="UUIDs of events containing this entity"
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict, description="Contextual attributes"
    )


class ContextTIFindingItem(BaseModel):
    """Threat intelligence enrichment finding for an observable in scope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observable: str = Field(min_length=1, description="Normalized observable string")
    observable_type: str = Field(
        description="Canonical observable type: ipv4, ipv6, domain, sha256, url"
    )
    verdict: ContextTIVerdict = Field(
        default=ContextTIVerdict.UNKNOWN,
        description="Security verdict (malicious, suspicious, benign, unknown)",
    )
    threat_state: ContextTIThreatState = Field(
        default=ContextTIThreatState.ENGINE_UNAVAILABLE,
        description="Operational lookup state (shielded_internal, active, stale, engine_unavailable)",
    )
    is_shielded: bool = Field(
        default=False, description="True if blocked by PrivateNetworkShield (RFC1918/Loopback)"
    )
    is_stale: bool = Field(
        default=False, description="True if feed entry exceeded freshness TTL"
    )
    tags: list[str] = Field(
        default_factory=list, description="Categorization tags from feeds"
    )
    source_feeds: list[str] = Field(
        default_factory=list, description="Names of feeds reporting this indicator"
    )
    confidence: float = Field(
        ge=0.0, le=1.0, default=0.5, description="Attributed confidence score (0.0 to 1.0)"
    )

    @model_validator(mode="after")
    def validate_ti_invariants(self) -> Self:
        if self.is_shielded and self.threat_state != ContextTIThreatState.SHIELDED_INTERNAL:
            raise ValueError(
                "threat_state must be 'shielded_internal' when is_shielded is True"
            )
        if self.observable_type.lower() == "sha256":
            _validate_sha256_hex(self.observable, "observable")
        return self


class ContextKnowledgeChunkItem(BaseModel):
    """Retrieved reference knowledge chunk from the pgvector knowledge base."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    chunk_id: uuid.UUID = Field(description="KnowledgeEmbedding record UUID")
    source_document: str = Field(
        min_length=1,
        description="Relative path of source document (e.g. 'mitre/T1059.md')",
    )
    section_title: str = Field(min_length=1, description="Heading or section name")
    chunk_index: int = Field(
        ge=0, description="Positional 0-based chunk index within source document"
    )
    similarity_score: float = Field(
        ge=0.0, le=1.0, description="Cosine similarity score (0.0 to 1.0)"
    )
    content: str = Field(
        min_length=1, description="Raw markdown/text excerpt from knowledge base"
    )


class BudgetMetrics(BaseModel):
    """Telemetry budgeting, conservative token metrics, and omission tracking."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_events_in_scope: int = Field(
        ge=0, description="Total normalized events identified within scope window"
    )
    events_included: int = Field(
        ge=0, description="Number of events included in assembled context"
    )
    events_omitted_count: int = Field(
        ge=0, description="Number of events omitted due to budget constraints"
    )
    omitted_event_ids_summary: list[uuid.UUID] = Field(
        default_factory=list, description="UUIDs of omitted events for auditability"
    )
    total_entities_in_scope: int = Field(
        ge=0, default=0, description="Total entities identified in scope"
    )
    entities_included: int = Field(
        ge=0, default=0, description="Number of entities included in context"
    )
    knowledge_chunks_included: int = Field(
        ge=0, default=0, description="Number of knowledge chunks included"
    )
    estimated_character_count: int = Field(
        ge=0, default=0, description="Total estimated characters of assembled payload"
    )
    estimated_tokens: int = Field(
        ge=0,
        default=0,
        description="Estimated token count using conservative heuristic (chars / 3.5)",
    )
    context_truncated: bool = Field(
        default=False, description="Flag indicating if any telemetry was omitted"
    )

    @model_validator(mode="after")
    def validate_budget_invariants(self) -> Self:
        if self.events_included > self.total_events_in_scope:
            raise ValueError(
                f"events_included ({self.events_included}) cannot exceed total_events_in_scope ({self.total_events_in_scope})"
            )
        if self.entities_included > self.total_entities_in_scope:
            raise ValueError(
                f"entities_included ({self.entities_included}) cannot exceed total_entities_in_scope ({self.total_entities_in_scope})"
            )
        expected_omitted = self.total_events_in_scope - self.events_included
        if self.events_omitted_count != expected_omitted:
            raise ValueError(
                f"events_omitted_count ({self.events_omitted_count}) must equal total_events_in_scope - events_included ({expected_omitted})"
            )
        entities_omitted_count = self.total_entities_in_scope - self.entities_included
        has_omissions = (self.events_omitted_count > 0) or (entities_omitted_count > 0)
        if has_omissions and not self.context_truncated:
            raise ValueError(
                "context_truncated must be True when events or entities are omitted from scope"
            )
        if self.context_truncated and not has_omissions:
            raise ValueError(
                "context_truncated is True but no events or entities were omitted from scope"
            )
        if len(self.omitted_event_ids_summary) > self.events_omitted_count:
            raise ValueError(
                f"omitted_event_ids_summary count ({len(self.omitted_event_ids_summary)}) cannot exceed events_omitted_count ({self.events_omitted_count})"
            )
        return self


class ReproducibilityRecord(BaseModel):
    """Cryptographically verifiable audit record for deterministic context generation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: uuid.UUID = Field(
        default_factory=uuid.uuid4, description="Unique investigation request UUID"
    )
    time_window_start: datetime = Field(description="Scope start time in UTC")
    time_window_end: datetime = Field(description="Scope end time in UTC")
    root_event_id: Optional[uuid.UUID] = Field(
        default=None, description="Optional root event UUID anchor"
    )
    query_filter: Optional[str] = Field(
        default=None, description="Optional telemetry query filter string"
    )
    selected_event_uuids: list[uuid.UUID] = Field(
        default_factory=list, description="Chronologically ordered included event UUIDs"
    )
    selected_chunk_ids: list[uuid.UUID] = Field(
        default_factory=list, description="Included knowledge chunk UUIDs"
    )
    context_schema_version: str = Field(
        default="1.0.0", description="Context schema version"
    )
    context_sha256: str = Field(
        description="SHA-256 digest of canonical JSON context (64 hex characters)"
    )
    prompt_template_version: str = Field(
        default="1.0.0", description="Prompt template version string"
    )
    llm_provider: str = Field(default="ollama", description="LLM provider name")
    model_name: str = Field(default="qwen3:4b", description="Model name or tag")
    temperature: float = Field(
        ge=0.0, le=2.0, default=0.0, description="Inference temperature"
    )
    seed: Optional[int] = Field(
        default=42, description="Inference random seed where supported"
    )
    created_at_utc: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Record creation time in UTC",
    )

    @field_validator("time_window_start", "time_window_end", "created_at_utc", mode="after")
    @classmethod
    def validate_timestamps(cls, v: datetime, info: Any) -> datetime:
        return _validate_and_normalize_utc(v, info.field_name or "timestamp")

    @field_validator("context_sha256", mode="after")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        return _validate_sha256_hex(v, "context_sha256")

    @model_validator(mode="after")
    def validate_window_order(self) -> Self:
        if self.time_window_start >= self.time_window_end:
            raise ValueError(
                f"time_window_start ({self.time_window_start}) must be strictly before time_window_end ({self.time_window_end})"
            )
        return self


class InvestigationContext(BaseModel):
    """Complete, typed, and auditable input payload for LLM investigation synthesis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="1.0.0", description="Context schema version"
    )
    investigation_id: uuid.UUID = Field(
        default_factory=uuid.uuid4, description="Unique investigation tracking ID"
    )
    scope_type: InvestigationScopeType = Field(
        description="Scope classification of this investigation"
    )
    time_window_start: datetime = Field(
        description="Earliest event timestamp in scope (UTC)"
    )
    time_window_end: datetime = Field(
        description="Latest event timestamp in scope (UTC)"
    )
    target_hosts: list[str] = Field(
        default_factory=list, description="List of distinct hostnames analyzed"
    )

    events: list[ContextEventItem] = Field(
        default_factory=list,
        description="Chronologically sorted normalized events in scope",
    )
    entities: list[ContextEntityItem] = Field(
        default_factory=list,
        description="Deduplicated atomic entities across scope",
    )
    threat_intel: list[ContextTIFindingItem] = Field(
        default_factory=list,
        description="Threat intelligence findings for observables",
    )
    knowledge_chunks: list[ContextKnowledgeChunkItem] = Field(
        default_factory=list,
        description="Retrieved reference knowledge chunks",
    )

    budget_metrics: BudgetMetrics = Field(
        description="Context size, token estimate, and truncation metrics"
    )
    reproducibility: ReproducibilityRecord = Field(
        description="Forensic reproducibility record"
    )
    uncertainty_flags: list[str] = Field(
        default_factory=list,
        description="Recorded data gaps, truncation disclosures, or system degradations",
    )
    assembled_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC context assembly time",
    )

    @field_validator("time_window_start", "time_window_end", "assembled_at", mode="after")
    @classmethod
    def validate_timestamps(cls, v: datetime, info: Any) -> datetime:
        return _validate_and_normalize_utc(v, info.field_name or "timestamp")

    @model_validator(mode="after")
    def validate_context_invariants(self) -> Self:
        if self.time_window_start >= self.time_window_end:
            raise ValueError(
                f"time_window_start ({self.time_window_start}) must be strictly before time_window_end ({self.time_window_end})"
            )

        # Cross-field consistency with BudgetMetrics
        if len(self.events) != self.budget_metrics.events_included:
            raise ValueError(
                f"events count ({len(self.events)}) does not match budget_metrics.events_included ({self.budget_metrics.events_included})"
            )
        if len(self.entities) != self.budget_metrics.entities_included:
            raise ValueError(
                f"entities count ({len(self.entities)}) does not match budget_metrics.entities_included ({self.budget_metrics.entities_included})"
            )
        if len(self.knowledge_chunks) != self.budget_metrics.knowledge_chunks_included:
            raise ValueError(
                f"knowledge_chunks count ({len(self.knowledge_chunks)}) does not match budget_metrics.knowledge_chunks_included ({self.budget_metrics.knowledge_chunks_included})"
            )

        # Incomplete context and omission disclosure consistency
        if self.budget_metrics.context_truncated and not self.uncertainty_flags:
            raise ValueError(
                "context_truncated is True in budget_metrics but uncertainty_flags contains no disclosure entries"
            )

        # Reproducibility alignment
        if self.reproducibility.time_window_start != self.time_window_start:
            raise ValueError(
                "reproducibility.time_window_start must match context.time_window_start"
            )
        if self.reproducibility.time_window_end != self.time_window_end:
            raise ValueError(
                "reproducibility.time_window_end must match context.time_window_end"
            )
        expected_event_uuids = [e.event_uuid for e in self.events]
        if self.reproducibility.selected_event_uuids != expected_event_uuids:
            raise ValueError(
                "reproducibility.selected_event_uuids must match the ordered event UUIDs in context.events"
            )
        expected_chunk_ids = [k.chunk_id for k in self.knowledge_chunks]
        if self.reproducibility.selected_chunk_ids != expected_chunk_ids:
            raise ValueError(
                "reproducibility.selected_chunk_ids must match the chunk IDs in context.knowledge_chunks"
            )
        return self


class FactualClaimItem(BaseModel):
    """Atomic factual statement generated by LLM and validated against evidence context."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    claim_id: uuid.UUID = Field(
        default_factory=uuid.uuid4, description="Unique claim identifier"
    )
    claim_text: str = Field(
        min_length=1, description="Specific, atomic factual statement"
    )
    category: ClaimCategory = Field(
        description="Epistemic nature of the claim (observed_fact, external_intelligence, inference, unknown)"
    )
    supporting_evidence_ids: list[uuid.UUID] = Field(
        default_factory=list, description="Cited ContextEventItem UUIDs"
    )
    references_exist: bool = Field(
        description="True if all supporting_evidence_ids exist in the supplied investigation context"
    )
    grounding_status: GroundingStatus = Field(
        description="Deterministic validation status"
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score (0.0 to 1.0)"
    )
    analyst_notes: Optional[str] = Field(
        default=None, description="Validation warnings or flags"
    )
    # Task 1 (claim-assertion-v1): OPTIONAL structured assertions the model may attach and the deterministic verification of them. Both are
    # additive and default to None, so claims without them (including every historical claim) parse and behave exactly as before. Assertions
    # are kept as plain JSON values so that ONE malformed assertion can never reject a whole model response; they are validated strictly,
    # assertion by assertion, in app.modules.ai.guardrails.claim_verifier.
    assertions: Optional[list[Any]] = Field(
        default=None,
        description="Optional claim-assertion-v1 structured assertions (validated by the deterministic verifier, never trusted as-is)",
    )
    verification: Optional[ClaimVerification] = Field(
        default=None,
        description="Deterministic claim-to-evidence verification of the structured assertions (server-computed; absent = not machine-verifiable)",
    )

    @field_validator("assertions", mode="before")
    @classmethod
    def _assertions_must_be_a_list(cls, v: Any) -> Any:
        if v is None or isinstance(v, list):
            return v
        return ["MALFORMED_ASSERTIONS_CONTAINER"]  # not a list: becomes one malformed item (not_verifiable), never silently re-interpreted

    @model_validator(mode="after")
    def validate_grounding_invariants(self) -> Self:
        # Tier 1 Reference Existence Invariant:
        # A claim cannot be validated_reference if its cited references do not exist
        if not self.references_exist and self.grounding_status == GroundingStatus.VALIDATED_REFERENCE:
            raise ValueError(
                "Claim cannot have grounding_status='validated_reference' when references_exist is False"
            )
        # An observed fact claiming validated reference must cite at least one piece of evidence
        if self.grounding_status == GroundingStatus.VALIDATED_REFERENCE and not self.supporting_evidence_ids:
            raise ValueError(
                "Claim cannot have grounding_status='validated_reference' with empty supporting_evidence_ids"
            )
        return self


class MitreAttackHypothesis(BaseModel):
    """Advisory MITRE ATT&CK technique hypothesis connecting telemetry to tactics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str = Field(
        min_length=1, description="MITRE ATT&CK Technique ID (e.g. 'T1059.001')"
    )
    technique_name: str = Field(
        min_length=1, description="Canonical technique name (e.g. 'PowerShell')"
    )
    tactics: list[str] = Field(
        default_factory=list, description="Associated tactics (e.g. ['Execution'])"
    )
    supporting_event_uuids: list[uuid.UUID] = Field(
        default_factory=list,
        description="UUIDs of events demonstrating technique",
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Hypothesis confidence (0.0 to 1.0)"
    )
    reasoning: str = Field(
        min_length=1, description="Explanation connecting telemetry to the technique"
    )
    taxonomy: Optional[TechniqueTaxonomyStatus] = Field(
        default=None,
        description=(
            "Deterministic ATT&CK taxonomy validation status. Set ONLY by the guardrail validator (any model-supplied value is "
            "discarded); independent of confidence and evidence support. Absent means not recorded, never 'valid'."
        ),
    )


class StructuredInvestigationOutput(BaseModel):
    """Structured, auditable output contract for LLM-synthesized security investigations."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: uuid.UUID = Field(
        description="Corresponding InvestigationContext ID"
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Generation timestamp in UTC",
    )
    model_identifier: str = Field(
        min_length=1, description="LLM provider and model name"
    )
    investigation_summary: str = Field(
        min_length=20, description="High-level incident narrative"
    )
    claims: list[FactualClaimItem] = Field(
        default_factory=list,
        description="Structured, validated factual assertions",
    )
    mitre_attack_hypotheses: list[MitreAttackHypothesis] = Field(
        default_factory=list, description="ATT&CK technique hypotheses"
    )
    alternative_explanations: list[str] = Field(
        default_factory=list, description="Plausible benign hypotheses"
    )
    recommended_analyst_actions: list[str] = Field(
        min_length=1, description="Advisory verification steps (at least one required)"
    )
    uncertainty_and_data_gaps: list[str] = Field(
        default_factory=list, description="Missing telemetry disclosures"
    )
    overall_grounding_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Ratio of validated to total claims (0.0 to 1.0)",
    )

    @field_validator("generated_at", mode="after")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        return _validate_and_normalize_utc(v, "generated_at")

    @field_validator("investigation_summary", mode="after")
    @classmethod
    def validate_investigation_summary(cls, v: str) -> str:
        trimmed = v.strip()
        if len(trimmed) < 20:
            raise ValueError(
                f"investigation_summary must contain at least 20 non-whitespace characters, got {len(trimmed)}"
            )
        return v

    @model_validator(mode="after")
    def validate_grounding_score_consistency(self) -> Self:
        if self.claims:
            validated = sum(
                1 for c in self.claims if c.grounding_status == GroundingStatus.VALIDATED_REFERENCE
            )
            expected = validated / len(self.claims)
            if abs(self.overall_grounding_score - expected) > 0.01:
                raise ValueError(
                    f"overall_grounding_score ({self.overall_grounding_score:.4f}) is inconsistent with claims ratio ({expected:.4f})"
                )
        return self


class InvestigationSynthesizeRequest(BaseModel):
    """Request schema for initiating an investigation synthesis query."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    time_window_start: datetime = Field(
        description="Scope start time in UTC (inclusive)"
    )
    time_window_end: datetime = Field(
        description="Scope end time in UTC (exclusive)"
    )
    root_event_id: Optional[uuid.UUID] = Field(
        default=None, description="Optional root event UUID anchor"
    )
    query_filter: Optional[str] = Field(
        default=None, description="Optional telemetry query filter string"
    )
    model_override: Optional[str] = Field(
        default=None, description="Optional approved local model name"
    )

    @field_validator("time_window_start", "time_window_end", mode="after")
    @classmethod
    def validate_timestamps(cls, v: datetime, info: Any) -> datetime:
        return _validate_and_normalize_utc(v, info.field_name or "timestamp")

    @model_validator(mode="after")
    def validate_time_window(self) -> Self:
        if self.time_window_start >= self.time_window_end:
            raise ValueError(
                f"time_window_start ({self.time_window_start}) must be strictly before time_window_end ({self.time_window_end})"
            )
        return self


__all__ = [
    "InvestigationScopeType",
    "ContextTIVerdict",
    "ContextTIThreatState",
    "ClaimCategory",
    "GroundingStatus",
    "ContextEventItem",
    "ContextEntityItem",
    "ContextTIFindingItem",
    "ContextKnowledgeChunkItem",
    "BudgetMetrics",
    "ReproducibilityRecord",
    "InvestigationContext",
    "FactualClaimItem",
    "MitreAttackHypothesis",
    "StructuredInvestigationOutput",
    "InvestigationSynthesizeRequest",
]
