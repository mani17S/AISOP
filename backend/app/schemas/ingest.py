"""
AISOP Ingestion Schemas.

Request and response contracts for the evidence ingestion pipeline.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

MAX_BATCH_SIZE: int = 2000
MAX_EVENT_PAYLOAD_BYTES: int = 65536  # 64 KB per raw event


class IngestRequest(BaseModel):
    """Payload sent to POST /api/v1/evidence/ingest."""

    source_type: str = Field(
        default="sysmon",
        min_length=1,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_.-]+$",
        description="Type of telemetry log (e.g. sysmon, windows_event, generic_json)",
    )
    source_identifier: str = Field(
        default="collector-agent",
        min_length=1,
        max_length=255,
        description="Originating host or sensor identifier",
    )
    events: list[dict[str, Any]] = Field(
        default_factory=list,
        max_length=MAX_BATCH_SIZE,
        description=f"List of raw event objects in JSON representation (max {MAX_BATCH_SIZE})",
    )

    @field_validator("events")
    @classmethod
    def validate_event_payloads(
        cls, events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        for idx, ev in enumerate(events):
            try:
                raw_bytes = len(json.dumps(ev, ensure_ascii=False).encode("utf-8"))
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Event at index {idx} contains non-serializable content: {exc}"
                )
            if raw_bytes > MAX_EVENT_PAYLOAD_BYTES:
                raise ValueError(
                    f"Event at index {idx} exceeds maximum allowed payload size of "
                    f"{MAX_EVENT_PAYLOAD_BYTES} bytes ({raw_bytes} bytes)"
                )
        return events


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
