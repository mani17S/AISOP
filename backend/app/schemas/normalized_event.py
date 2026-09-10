"""
AISOP Canonical Normalized Event Schema.

Governed by ADR-004:
The canonical event schema is the architectural contract for AISOP.
All telemetry parsers transform raw logs into this standardized representation.
Downstream components (Correlation, AI/Hypothesis, Reporting) depend strictly on this schema.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.schemas.entities import (
    DnsEntity,
    FileEntity,
    HostEntity,
    NetworkEntity,
    ProcessEntity,
    RegistryEntity,
    UserEntity,
)


class CanonicalEvent(BaseModel):
    """
    Standardized, normalized security event contract.
    """
    id: UUID = Field(default_factory=uuid4, description="Unique normalized event identifier")
    event_id: str = Field(description="Source event ID (e.g. '1', '3', '4688')")
    event_type: str = Field(
        description="Standardized event category: process_creation, network_connection, image_load, file_create, registry_event, dns_query, authentication"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event observation time (UTC)",
    )
    provider: str = Field(
        default="unknown",
        description="Telemetry source provider (e.g. Microsoft-Windows-Sysmon, Microsoft-Windows-Security-Auditing)",
    )
    action: str = Field(
        default="observed",
        description="Standardized action verb (e.g. started, connected, created, loaded, modified, queried)",
    )
    outcome: Literal["success", "failure", "unknown"] = Field(
        default="success",
        description="Execution outcome",
    )
    severity: Literal["informational", "low", "medium", "high", "critical"] = Field(
        default="informational",
        description="Assessed event severity",
    )

    # Strongly typed entity payloads
    host: HostEntity | None = Field(default=None, description="Endpoint/host details")
    user: UserEntity | None = Field(default=None, description="User identity details")
    process: ProcessEntity | None = Field(default=None, description="Process context")
    network: NetworkEntity | None = Field(default=None, description="Network context")
    file: FileEntity | None = Field(default=None, description="Filesystem context")
    registry: RegistryEntity | None = Field(default=None, description="Windows Registry context")
    dns: DnsEntity | None = Field(default=None, description="DNS query context")

    # Provenance tracking
    raw_ref: str = Field(
        description="SHA-256 integrity hash of the raw evidence record from which this was parsed"
    )
    raw_payload_summary: str | None = Field(
        default=None,
        description="Brief human-readable summary of the original log entry",
    )
    custom_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Unmapped vendor-specific attributes preserved for context",
    )
