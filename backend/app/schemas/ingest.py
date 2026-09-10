"""
AISOP Ingestion Schemas.

Request and response contracts for the evidence ingestion pipeline.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class IngestRequest(BaseModel):
    """Payload sent to POST /api/v1/evidence/ingest."""

    source_type: str = Field(
        default="sysmon",
        description="Type of telemetry log (e.g. sysmon, windows_event, generic_json)",
    )
    source_identifier: str = Field(
        default="collector-agent",
        description="Originating host or sensor identifier",
    )
    events: list[dict[str, Any]] = Field(
        description="List of raw event objects in JSON representation",
    )


class IngestError(BaseModel):
    """Details of an error during event parsing."""

    event_index: int
    error: str
    raw_sample: str | None = None


class IngestResponse(BaseModel):
    """Response returned from POST /api/v1/evidence/ingest."""

    batch_id: UUID = Field(
        default_factory=uuid4, description="Unique batch tracking ID"
    )
    source_type: str
    total_received: int = Field(description="Count of raw events provided in request")
    total_normalized: int = Field(description="Count of events successfully normalized")
    total_entities_extracted: int = Field(
        description="Count of atomic entities extracted"
    )
    total_skipped_duplicates: int = Field(
        default=0,
        description="Count of raw events skipped because identical evidence was already ingested",
    )
    existing_evidence_ids: list[UUID] = Field(
        default_factory=list,
        description="UUIDs of existing RawEvidence records referenced during deduplication",
    )
    errors: list[IngestError] = Field(
        default_factory=list, description="Parsing errors encountered"
    )
