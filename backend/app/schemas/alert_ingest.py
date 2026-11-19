"""
AISOP Alert Ingestion Schemas.

Request and response contracts for the vendor-neutral alert ingestion pipeline.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

MAX_ALERT_BATCH_SIZE: int = 1000
MAX_ALERT_PAYLOAD_BYTES: int = 131072  # 128 KB per alert payload


class AlertIngestRequest(BaseModel):
    """Payload sent to POST /api/v1/alerts/ingest."""

    source_type: str = Field(
        default="generic_siem",
        min_length=1,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_.-]+$",
        description="Source alert adapter type (e.g. sysmon, windows_security, linux_auth, edr_malware, firewall_ids, cloud_audit, email_phishing, generic_siem)",
    )
    source_identifier: str = Field(
        default="siem-forwarder",
        min_length=1,
        max_length=255,
        description="Originating SIEM, forwarder, or collector identifier",
    )
    alerts: list[dict[str, Any]] = Field(
        default_factory=list,
        max_length=MAX_ALERT_BATCH_SIZE,
        description=f"List of raw alert objects in JSON representation (max {MAX_ALERT_BATCH_SIZE})",
    )

    @field_validator("alerts")
    @classmethod
    def validate_alert_payloads(
        cls, alerts: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        for idx, alert in enumerate(alerts):
            try:
                raw_bytes = len(json.dumps(alert, ensure_ascii=False).encode("utf-8"))
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Alert at index {idx} contains non-serializable content: {exc}"
                )
            if raw_bytes > MAX_ALERT_PAYLOAD_BYTES:
                raise ValueError(
                    f"Alert at index {idx} exceeds maximum allowed payload size of "
                    f"{MAX_ALERT_PAYLOAD_BYTES} bytes ({raw_bytes} bytes)"
                )
        return alerts


class AlertIngestError(BaseModel):
    """Details of an error during alert parsing or normalization."""

    alert_index: int
    error: str
    raw_sample: str | None = None


class AlertIngestResponse(BaseModel):
    """Response returned from POST /api/v1/alerts/ingest."""

    batch_id: UUID = Field(
        default_factory=uuid4, description="Unique alert batch tracking ID"
    )
    source_type: str
    total_received: int = Field(description="Count of raw alerts provided in request")
    total_normalized: int = Field(description="Count of alerts successfully normalized")
    total_entities_extracted: int = Field(
        description="Count of atomic graph entities extracted"
    )
    total_skipped_duplicates: int = Field(
        default=0,
        description="Count of raw alerts skipped because identical evidence was already ingested",
    )
    existing_evidence_ids: list[UUID] = Field(
        default_factory=list,
        description="UUIDs of existing RawEvidence records referenced during deduplication",
    )
    alert_ids: list[UUID] = Field(
        default_factory=list,
        description="UUIDs of newly normalized alert records",
    )
    errors: list[AlertIngestError] = Field(
        default_factory=list, description="Parsing or adaptation errors encountered"
    )

