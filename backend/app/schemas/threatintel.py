"""
AISOP Threat Intelligence Public Schemas.

Re-exports typed threat intelligence request, result, observable, and verdict models,
and defines investigation enrichment findings for use across API routes, event
normalizers, and SOC investigation workflows.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid

from pydantic import BaseModel, Field

from app.modules.threatintel.models import (
    Observable,
    ObservableType,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatVerdict,
)


class InvestigationFindingState(str, Enum):
    """
    Mutually exclusive operational state of a threat intelligence finding
    within a security investigation.
    """

    FRESH_MATCH = "fresh_match"
    STALE_MATCH = "stale_match"
    VALID_UNMATCHED = "valid_unmatched"
    ENGINE_UNAVAILABLE = "engine_unavailable"
    INVALID_OBSERVABLE = "invalid_observable"
    LOOKUP_ERROR = "lookup_error"
    SHIELDED_INTERNAL = "shielded_internal"
    RATE_LIMITED = "rate_limited"
    TIMED_OUT = "timed_out"


class ThreatIntelFindingItem(BaseModel):
    """
    Standardized, source-attributed threat intelligence finding associated
    with an extracted entity within an investigation.
    """

    entity_id: uuid.UUID | None = Field(
        default=None, description="Extracted entity primary key if present"
    )
    event_id: uuid.UUID | None = Field(
        default=None, description="Associated normalized event UUID"
    )
    raw_evidence_id: uuid.UUID | None = Field(
        default=None, description="Associated raw evidence UUID"
    )
    observable_type: ObservableType = Field(
        description="Canonical observable type (ipv4, domain, sha256, etc.)"
    )
    raw_observable: str = Field(
        description="Raw observable value as extracted from telemetry"
    )
    normalized_observable: str = Field(
        description="Validated and normalized observable value"
    )
    status: ThreatIntelLookupStatus = Field(
        description="Engine operational lookup status"
    )
    verdict: ThreatVerdict = Field(
        description="Security verdict (malicious, suspicious, benign, unknown)"
    )
    integration_state: InvestigationFindingState = Field(
        description="Mutually exclusive operational integration state"
    )
    is_stale: bool = Field(
        default=False,
        description="True if any matching threat intelligence feed has exceeded freshness TTL",
    )
    stale_feeds: list[str] = Field(
        default_factory=list,
        description="Identifiers of matching feeds deemed stale",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Descriptive classification and warning tags",
    )
    sources: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Source-attributed provenance records preserving distinct feed findings",
    )
    error_message: str | None = Field(
        default=None,
        description="Error message if lookup was unsuccessful",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Enrichment timestamp in UTC",
    )


__all__ = [
    "ObservableType",
    "ThreatIntelLookupStatus",
    "ThreatVerdict",
    "Observable",
    "ThreatIntelRequest",
    "ThreatIntelResult",
    "InvestigationFindingState",
    "ThreatIntelFindingItem",
]
