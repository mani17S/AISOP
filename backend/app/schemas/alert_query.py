"""
AISOP Alert Query & Triage Schemas.

Defines the response contracts for paginated alert queue exploration and detailed
alert triage inspection prior to case creation.
Governed by ADR-007 and Decision 1A.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.schemas.alert import (
    AlertCategory,
    AlertObservable,
    AlertSeverity,
    AlertStatus,
    MitreAttackReference,
)
from app.schemas.entities import (
    DnsEntity,
    FileEntity,
    HostEntity,
    NetworkEntity,
    ProcessEntity,
    RegistryEntity,
    UserEntity,
)
from pydantic import BaseModel, ConfigDict, Field


class AlertSummaryItem(BaseModel):
    """
    Sanitized projection of a security alert for the triage queue.
    Excludes raw payloads and unmapped vendor attributes.
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(description="Normalized event UUID (serves as evidence_id)")
    source_alert_id: str = Field(description="Upstream vendor alert ID")
    source_type: str = Field(description="Source adapter type")
    provider: str = Field(description="Vendor provider name")
    source_identifier: str | None = Field(
        default=None, description="Endpoint/host identifier"
    )
    title: str = Field(description="Alert headline/title")
    description: str | None = Field(default=None, description="Alert description")
    category: AlertCategory = Field(description="Canonical alert category")
    severity: AlertSeverity = Field(description="Canonical alert severity")
    vendor_severity: str | None = Field(
        default=None, description="Original vendor severity"
    )
    status: AlertStatus = Field(default="new", description="Triage status")
    timestamp: datetime = Field(description="Event occurrence timestamp (UTC)")
    ingested_at: datetime = Field(description="Ingestion timestamp (UTC)")
    mitre_attack: list[MitreAttackReference] = Field(
        default_factory=list,
        description="Associated MITRE ATT&CK tactics and techniques",
    )
    top_observables: list[AlertObservable] = Field(
        default_factory=list,
        description="Key observables/IOCs for queue preview",
    )
    has_case: bool = Field(
        default=False,
        description="Whether alert is associated with at least one case",
    )
    case_count: int = Field(
        default=0,
        description="Number of cases associated with this alert",
    )


class AlertDetailResponse(BaseModel):
    """
    Detailed canonical alert structure for triage modal inspection.
    Excludes raw evidence payloads to maintain least privilege.
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(description="Normalized event UUID (serves as evidence_id)")
    source_alert_id: str = Field(description="Upstream vendor alert ID")
    source_type: str = Field(description="Source adapter type")
    provider: str = Field(description="Vendor provider name")
    source_identifier: str | None = Field(
        default=None, description="Host/sensor identifier"
    )
    title: str = Field(description="Alert title")
    description: str | None = Field(default=None, description="Alert description")
    category: AlertCategory = Field(description="Canonical category")
    severity: AlertSeverity = Field(description="Canonical severity")
    vendor_severity: str | None = Field(
        default=None, description="Original vendor severity"
    )
    status: AlertStatus = Field(default="new", description="Triage status")
    timestamp: datetime = Field(description="Occurrence timestamp (UTC)")
    ingested_at: datetime = Field(description="Ingestion timestamp (UTC)")
    raw_ref: str = Field(
        description="Cryptographic SHA-256 digest of raw alert payload"
    )
    mitre_attack: list[MitreAttackReference] = Field(
        default_factory=list,
        description="Associated MITRE ATT&CK tactics and techniques",
    )
    entities: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Extracted graph entities",
    )
    observables: list[AlertObservable] = Field(
        default_factory=list,
        description="Extracted observables / IOCs",
    )
    host: HostEntity | None = None
    user: UserEntity | None = None
    process: ProcessEntity | None = None
    network: NetworkEntity | None = None
    file: FileEntity | None = None
    dns: DnsEntity | None = None
    registry: RegistryEntity | None = None
    custom_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Unmapped vendor-specific attributes",
    )
    associated_case_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="UUIDs of cases linked to this alert",
    )
    has_case: bool = Field(
        default=False,
        description="Whether alert is associated with at least one case",
    )

