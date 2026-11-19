"""
AISOP Case Management & Scoping Pydantic Schemas.

Defines strict Pydantic V2 contracts for case creation, metadata updates,
analyst assignments, lead transfers, lifecycle transitions, and responses.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.rbac import CaseRole


class CaseStatus(str, Enum):
    """Lifecycle statuses for security cases."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    ARCHIVED = "archived"


class CaseSeverity(str, Enum):
    """Assessed severity tiers for security cases."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaseCreateRequest(BaseModel):
    """Request contract for creating a new security case."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(
        ...,
        min_length=3,
        max_length=200,
        description="Concise case title",
    )
    description: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional initial incident summary or briefing",
    )
    severity: CaseSeverity = Field(
        default=CaseSeverity.MEDIUM,
        description="Initial assessed case severity",
    )
    initial_evidence_ids: list[uuid.UUID] = Field(
        default_factory=list,
        max_length=100,
        description="Optional initial normalized evidence UUIDs to link",
    )


class CaseMetadataUpdateRequest(BaseModel):
    """Request contract for modifying mutable case metadata."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(
        default=None,
        min_length=3,
        max_length=200,
        description="Updated case title",
    )
    description: str | None = Field(
        default=None,
        max_length=2000,
        description="Updated incident summary",
    )
    severity: CaseSeverity | None = Field(
        default=None,
        description="Updated case severity tier",
    )

    @model_validator(mode="after")
    def _validate_at_least_one_field(self) -> Self:
        if self.title is None and self.description is None and self.severity is None:
            raise ValueError(
                "At least one field (title, description, or severity) must be provided for update."
            )
        return self


class CaseAssignmentRequest(BaseModel):
    """Request contract for assigning an analyst to a case."""

    model_config = ConfigDict(extra="forbid")

    analyst_id: uuid.UUID = Field(
        ...,
        description="Analyst UUID to assign to this case",
    )
    case_role: CaseRole = Field(
        ...,
        description="Role within case (viewer or investigator)",
    )

    @model_validator(mode="after")
    def _validate_non_lead_assignment(self) -> Self:
        if self.case_role == CaseRole.LEAD:
            raise ValueError(
                "Cannot assign 'lead' role via assignment request. "
                "Case lead is designated at creation or transferred via lead-transfer."
            )
        return self


class CaseAssignmentResponse(BaseModel):
    """Response contract representing an active analyst case assignment."""

    model_config = ConfigDict(extra="forbid")

    case_id: uuid.UUID = Field(description="Case UUID")
    analyst_id: uuid.UUID = Field(description="Assigned analyst UUID")
    username: str = Field(description="Assigned analyst username")
    case_role: CaseRole = Field(description="Assigned case role")
    assigned_at: datetime = Field(description="Assignment timestamp (UTC)")


class LeadTransferRequest(BaseModel):
    """
    Request contract for transferring active case leadership.
    Eligible targets must hold global role analyst_tier_2 or security_admin.
    """

    model_config = ConfigDict(extra="forbid")

    target_analyst_id: uuid.UUID = Field(
        ...,
        description="UUID of the eligible target analyst to assume leadership",
    )
    reason: str = Field(
        ...,
        min_length=5,
        max_length=500,
        description="Mandatory rationale for audit log",
    )


class CaseLifecycleUpdateRequest(BaseModel):
    """Request contract for formally closing or archiving a case."""

    model_config = ConfigDict(extra="forbid")

    status: CaseStatus = Field(
        ...,
        description="Target lifecycle status (must be 'closed' or 'archived')",
    )
    closure_reason: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="Mandatory closure or archival rationale for audit log",
    )

    @model_validator(mode="after")
    def _validate_terminal_status(self) -> Self:
        if self.status not in (CaseStatus.CLOSED, CaseStatus.ARCHIVED):
            raise ValueError(
                f"Invalid lifecycle transition to status '{self.status.value}'. "
                "Permitted target statuses: 'closed', 'archived'."
            )
        return self


class CaseResponse(BaseModel):
    """Detailed response contract for a security case."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(description="Unique case UUID")
    case_number: str = Field(
        pattern=r"^CASE-\d{8}-[A-Z0-9]{4}$",
        description="Human-readable case identifier (e.g. CASE-20261025-A1B2)",
    )
    title: str = Field(description="Case title")
    description: str | None = Field(default=None, description="Case briefing")
    severity: CaseSeverity = Field(description="Case severity")
    status: CaseStatus = Field(description="Current lifecycle status")
    lead_analyst_id: uuid.UUID = Field(description="Current lead analyst UUID")
    created_at: datetime = Field(description="Case creation timestamp (UTC)")
    updated_at: datetime = Field(description="Last metadata update timestamp (UTC)")
    closed_at: datetime | None = Field(default=None, description="Closure timestamp if terminal")


class CaseEvidenceLinkRequest(BaseModel):
    """Request contract for associating a normalized evidence record with a case."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: uuid.UUID = Field(
        ...,
        description="Normalized evidence event UUID to associate with this case",
    )


class CaseEvidenceLinkResponse(BaseModel):
    """Response contract representing an evidence record association with a case."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(description="Association record UUID")
    case_id: uuid.UUID = Field(description="Case UUID")
    evidence_id: uuid.UUID = Field(description="Normalized event UUID")
    linked_by_analyst_id: uuid.UUID | None = Field(description="Linking analyst UUID")
    linked_at: datetime = Field(description="Association timestamp (UTC)")


class CaseScopedEvidenceItem(BaseModel):
    """
    Case-scoped evidence record projection for authorized investigators and leads.
    Excludes raw evidence payloads and internal database attributes.
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(description="Normalized event UUID")
    event_id: str = Field(description="Source-native event ID")
    event_type: str = Field(description="Standardized event category")
    event_timestamp: datetime = Field(description="Event observation time (UTC)")
    provider: str = Field(description="Telemetry provider")
    action: str = Field(description="Action verb")
    outcome: str = Field(description="Execution outcome")
    severity: str = Field(description="Assessed severity")
    source_type: str | None = Field(default=None, description="Telemetry source type")
    source_identifier: str | None = Field(default=None, description="Endpoint identifier")
    normalized_payload: dict[str, Any] = Field(description="Structured canonical payload")
    linked_at: datetime = Field(description="Case association timestamp (UTC)")
    linked_by_analyst_id: uuid.UUID | None = Field(
        default=None, description="Analyst who linked evidence to case"
    )


def _validate_and_normalize_utc(dt: datetime, field_name: str) -> datetime:
    """Enforce timezone-awareness and normalize datetime to UTC."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"{field_name} must be timezone-aware (e.g. UTC)")
    return dt.astimezone(timezone.utc)


class CaseInvestigationSynthesizeRequest(BaseModel):
    """Request contract for initiating case-scoped AI investigation synthesis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    time_window_start: datetime | None = Field(
        default=None, description="Optional scope start time in UTC (inclusive)"
    )
    time_window_end: datetime | None = Field(
        default=None, description="Optional scope end time in UTC (exclusive)"
    )
    root_event_id: uuid.UUID | None = Field(
        default=None, description="Optional root event UUID anchor"
    )
    query_filter: str | None = Field(
        default=None, description="Optional telemetry query filter string"
    )
    model_override: str | None = Field(
        default=None, description="Optional approved local model name"
    )

    @field_validator("time_window_start", "time_window_end", mode="after")
    @classmethod
    def validate_timestamps(cls, v: datetime | None, info: Any) -> datetime | None:
        if v is not None:
            return _validate_and_normalize_utc(v, info.field_name or "timestamp")
        return None

    @model_validator(mode="after")
    def validate_time_window(self) -> Self:
        if self.time_window_start is not None and self.time_window_end is not None:
            if self.time_window_start >= self.time_window_end:
                raise ValueError(
                    f"time_window_start ({self.time_window_start}) must be strictly before time_window_end ({self.time_window_end})"
                )
        return self


class CaseAuditEventItem(BaseModel):
    """Case-scoped audit event item for authorized participants."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(description="Unique audit event UUID")
    case_id: uuid.UUID = Field(description="Associated case UUID")
    actor_analyst_id: uuid.UUID | None = Field(
        default=None, description="Acting analyst UUID if applicable"
    )
    actor_username: str = Field(description="Username of the acting entity")
    action: str = Field(description="Audit event action name")
    context_sha256: str | None = Field(
        default=None, description="Investigation context hash if applicable"
    )
    details: dict[str, Any] = Field(
        default_factory=dict, description="Structured audit event metadata"
    )
    created_at: datetime = Field(description="Event timestamp in UTC")

