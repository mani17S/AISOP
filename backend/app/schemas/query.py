"""
AISOP SOC Investigation Query Schemas.

Defines the Pydantic contracts for analyst queries, timeline retrieval,
IOC lookups, and deterministic paginated responses.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

DEFAULT_PAGE_SIZE: int = 50
MAX_PAGE_SIZE: int = 200

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """
    Standardized envelope for deterministic paginated query responses.
    """

    items: list[T] = Field(description="Page items")
    total: int = Field(description="Total count of matching records across all pages")
    page: int = Field(description="Current 1-indexed page number")
    limit: int = Field(description="Page size limit")
    total_pages: int = Field(description="Total number of available pages")
    has_next: bool = Field(description="True if a subsequent page exists")
    has_previous: bool = Field(description="True if a preceding page exists")


class ExtractedEntityItem(BaseModel):
    """
    Atomic entity record extracted from telemetry for IOC correlation.
    """

    id: uuid.UUID = Field(description="Entity record primary key")
    event_id: uuid.UUID = Field(description="Associated normalized event UUID")
    raw_evidence_id: uuid.UUID = Field(description="Associated raw evidence UUID")
    entity_type: str = Field(
        description="Entity type (e.g. ip, host, user, process, file_hash, domain)"
    )
    entity_value: str = Field(description="Normalized entity value / identifier")
    role: str = Field(description="Entity role (e.g. source, destination, actor)")
    attributes: dict[str, Any] = Field(
        default_factory=dict, description="Contextual attributes"
    )


class NormalizedEventSummary(BaseModel):
    """
    Compact normalized security event summary for timeline views.
    """

    id: uuid.UUID = Field(description="Normalized event UUID")
    raw_evidence_id: uuid.UUID = Field(description="Associated raw evidence UUID")
    event_id: str = Field(description="Source-native event ID")
    event_type: str = Field(description="Standardized event category")
    event_timestamp: datetime = Field(description="Event observation time (UTC)")
    provider: str = Field(description="Telemetry provider")
    action: str = Field(description="Action verb")
    outcome: str = Field(description="Execution outcome")
    severity: str = Field(description="Assessed severity")
    source_type: str | None = Field(
        default=None, description="Raw evidence source type (e.g. sysmon)"
    )
    source_identifier: str | None = Field(
        default=None, description="Host/endpoint identifier"
    )
    normalized_payload: dict[str, Any] = Field(
        description="Full canonical event payload"
    )


class NormalizedEventDetail(NormalizedEventSummary):
    """
    Detailed normalized security event view including extracted entities and provenance.
    """

    raw_sha256_hash: str | None = Field(
        default=None, description="SHA-256 hash of parent raw evidence"
    )
    raw_ingested_at: datetime | None = Field(
        default=None, description="Ingestion timestamp of parent raw evidence"
    )
    entities: list[ExtractedEntityItem] = Field(
        default_factory=list, description="Entities extracted from this event"
    )


class RawEvidenceEventSummary(BaseModel):
    """
    Summary of a normalized event associated with a raw evidence record.
    """

    id: uuid.UUID = Field(description="Normalized event UUID")
    event_id: str = Field(description="Source event ID")
    event_type: str = Field(description="Event type")
    event_timestamp: datetime = Field(description="Event observation timestamp")
    severity: str = Field(description="Event severity")
    action: str = Field(description="Action verb")
    outcome: str = Field(description="Outcome")


class RawEvidenceDetailResponse(BaseModel):
    """
    Complete raw evidence record with cryptographic hash and associated normalized events.
    """

    id: uuid.UUID = Field(description="Raw evidence UUID")
    source_type: str = Field(description="Source log type")
    source_identifier: str = Field(description="Source machine / sensor identifier")
    sha256_hash: str = Field(description="Cryptographic SHA-256 integrity hash")
    ingested_at: datetime = Field(description="Ingestion timestamp (UTC)")
    raw_payload: dict[str, Any] = Field(description="Immutable raw telemetry JSON")
    normalized_events: list[RawEvidenceEventSummary] = Field(
        default_factory=list,
        description="Associated canonical events generated from this evidence",
    )
