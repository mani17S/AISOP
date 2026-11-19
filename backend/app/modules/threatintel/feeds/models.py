"""
AISOP Local Threat Intelligence Feed Data Models.

Defines typed, immutable domain models for local threat indicators,
feed metadata tracking, freshness, and parsing outcomes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.modules.threatintel.models import ObservableType, ThreatVerdict


class LocalIndicatorRecord(BaseModel):
    """
    Standardized, source-attributed record of an offline threat indicator.
    """

    observable_type: ObservableType = Field(description="Normalized indicator category")
    normalized_value: str = Field(description="Canonical normalized indicator string")
    raw_value: str = Field(description="Raw indicator string as seen in the source feed")
    source_feed: str = Field(description="Identifier of the source feed (e.g. 'feodo_tracker')")
    verdict: ThreatVerdict = Field(description="Security verdict justified by source semantics")
    threat_category: str | None = Field(
        default=None,
        description="Category classification (e.g. 'botnet_c2', 'anonymization_proxy')",
    )
    malware_family: str | None = Field(
        default=None,
        description="Associated malware family if provided by the source",
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Source-reported confidence percentage [0.0 - 100.0], or None if unstated",
    )
    first_seen: datetime | None = Field(
        default=None,
        description="First seen timestamp reported by source in UTC",
    )
    last_seen: datetime | None = Field(
        default=None,
        description="Last seen timestamp reported by source in UTC",
    )
    feed_retrieved_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the feed was retrieved/parsed in UTC",
    )
    feed_version: str | None = Field(
        default=None,
        description="Feed release or version identifier if available",
    )
    feed_checksum: str | None = Field(
        default=None,
        description="SHA-256 digest of the feed payload",
    )
    source_reference: str | None = Field(
        default=None,
        description="Source URL or documentation reference",
    )
    licence: str | None = Field(
        default=None,
        description="Attribution and redistribution licence (e.g. 'CC0 1.0')",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Descriptive tags associated with the indicator",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Source-specific key-value metadata",
    )

    @field_validator("first_seen", "last_seen", "feed_retrieved_at")
    @classmethod
    def enforce_utc_timestamps(cls, v: datetime | None) -> datetime | None:
        """Enforce timezone-aware UTC timestamps."""
        if v is None:
            return None
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class FeedMetadata(BaseModel):
    """
    Metadata tracking feed operational state, record count, and freshness.
    """

    feed_name: str = Field(description="Canonical feed identifier")
    retrieved_at: datetime = Field(description="UTC timestamp when the feed was parsed")
    record_count: int = Field(ge=0, description="Number of valid indicators in the feed")
    checksum: str = Field(description="SHA-256 digest of the feed payload")
    source_url: str = Field(description="Official source URL for the feed")
    licence: str = Field(description="Licensing and terms of use")
    max_age_seconds: float = Field(
        default=86400.0,
        gt=0,
        description="Maximum age in seconds before feed is deemed stale (24h default)",
    )
    last_error: str | None = Field(
        default=None,
        description="Explanation of recent parsing or update errors",
    )
    is_active: bool = Field(
        default=True,
        description="Whether the feed is currently active and eligible for lookups",
    )

    @field_validator("retrieved_at")
    @classmethod
    def enforce_utc_retrieved_at(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    def is_stale(self, now: datetime | None = None) -> bool:
        """Determine whether the feed has exceeded its configured freshness lifetime."""
        current_time = now or datetime.now(timezone.utc)
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)
        age = (current_time - self.retrieved_at).total_seconds()
        return age > self.max_age_seconds


class FeedParseResult(BaseModel):
    """
    Result of parsing a feed payload, with error reporting and operational counts.
    """

    feed_name: str = Field(description="Canonical feed identifier")
    records: list[LocalIndicatorRecord] = Field(
        default_factory=list,
        description="Validated indicator records parsed from the feed",
    )
    malformed_count: int = Field(
        default=0,
        ge=0,
        description="Count of lines/records rejected due to syntax or validation errors",
    )
    duplicate_count: int = Field(
        default=0,
        ge=0,
        description="Count of duplicate records ignored during ingestion",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Sample of parsing errors encountered",
    )
    metadata: FeedMetadata = Field(description="Freshness and origin metadata for this parse")
