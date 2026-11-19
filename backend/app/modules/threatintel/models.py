"""
AISOP Threat Intelligence Typed Domain Models.

In accordance with ADR-001 (Direct Lightweight Abstraction) and project conventions:
Defines immutable/strongly typed enumerations, observable specifications,
request objects, and standardized lookup result models for threat intelligence providers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Self

from pydantic import BaseModel, Field, field_validator, model_validator


class ObservableType(str, Enum):
    """Supported observable types for threat intelligence lookups."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class ThreatIntelLookupStatus(str, Enum):
    """Explicit operational outcomes for threat intelligence provider lookups."""

    SUCCESS = "success"
    NOT_FOUND = "not_found"
    UNSUPPORTED_OBSERVABLE = "unsupported_observable"
    MISSING_CREDENTIALS = "missing_credentials"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    PROVIDER_FAILURE = "provider_failure"


class ThreatVerdict(str, Enum):
    """
    Standardized threat assessment verdict.

    Distinct from operational lookup status: an operational failure (timeout,
    missing API key, rate limit) or NOT_FOUND always retains UNKNOWN verdict.
    """

    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Observable(BaseModel):
    """
    Validated and normalized observable value with associated type.
    """

    type: ObservableType = Field(description="Explicit observable category")
    raw_value: str = Field(description="Original, unnormalized raw input string")
    normalized_value: str = Field(description="Canonical normalized value")

    def __str__(self) -> str:
        return self.normalized_value


class ThreatIntelRequest(BaseModel):
    """
    Standardized request sent to threat intelligence providers.
    """

    observable: str = Field(description="Raw or normalized observable string")
    observable_type: ObservableType | None = Field(
        default=None,
        description="Explicit observable type hint, or None for auto-detection",
    )
    timeout_seconds: float | None = Field(
        default=None,
        gt=0,
        description="Optional request-specific timeout override",
    )


class ThreatIntelResult(BaseModel):
    """
    Typed, provider-neutral result of a threat intelligence lookup.

    Guarantees:
    - Timestamp is strictly UTC timezone-aware.
    - Unsuccessful lookups (timeouts, failures, missing credentials, unsupported
      observables) can NEVER be marked BENIGN or MALICIOUS.
    """

    provider_name: str = Field(
        description="Identifier of the threat intelligence provider (e.g. 'virustotal', 'abuseipdb')"
    )
    observable_type: ObservableType = Field(
        description="Normalized category of the queried observable"
    )
    raw_observable: str = Field(
        description="Original unnormalized observable input string"
    )
    normalized_observable: str = Field(
        description="Normalized canonical observable identifier"
    )
    status: ThreatIntelLookupStatus = Field(
        description="Operational status of the lookup attempt"
    )
    verdict: ThreatVerdict = Field(
        default=ThreatVerdict.UNKNOWN,
        description="Assessed security verdict (UNKNOWN, BENIGN, SUSPICIOUS, MALICIOUS)",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the lookup was completed",
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured, provider-specific response payload",
    )
    error_message: str | None = Field(
        default=None,
        description="Descriptive error explanation if status is not SUCCESS",
    )
    reputation_score: float | int | None = Field(
        default=None,
        description="Provider-specific reputation score or confidence percentage",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Threat categories, malware families, or MITRE ATT&CK tags",
    )

    @field_validator("timestamp")
    @classmethod
    def enforce_utc_timestamp(cls, v: datetime) -> datetime:
        """Enforce that timestamp is strictly UTC timezone-aware."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @model_validator(mode="after")
    def guard_unsuccessful_lookup_verdict(self) -> Self:
        """
        Enforce safety constraint:
        Operational failures, missing credentials, timeouts, rate limits, unsupported
        observables, or NOT_FOUND must NEVER produce a BENIGN or MALICIOUS verdict.
        An unsuccessful lookup must strictly retain an UNKNOWN verdict to prevent
        false negatives or unwarranted SOC alert dismissals.
        """
        if self.status != ThreatIntelLookupStatus.SUCCESS:
            if self.verdict != ThreatVerdict.UNKNOWN:
                raise ValueError(
                    f"Operational outcome '{self.status.value}' cannot have verdict '{self.verdict.value}'. "
                    f"Unsuccessful lookups must retain verdict '{ThreatVerdict.UNKNOWN.value}'."
                )
        return self

    @property
    def is_success(self) -> bool:
        """True if the provider returned a successful response."""
        return self.status == ThreatIntelLookupStatus.SUCCESS

    @property
    def is_malicious(self) -> bool:
        """True only if the lookup was successful and verdict is explicitly MALICIOUS."""
        return self.is_success and self.verdict == ThreatVerdict.MALICIOUS

    @property
    def is_suspicious(self) -> bool:
        """True only if the lookup was successful and verdict is explicitly SUSPICIOUS."""
        return self.is_success and self.verdict == ThreatVerdict.SUSPICIOUS

    @property
    def is_benign(self) -> bool:
        """True only if the lookup was successful and verdict is explicitly BENIGN."""
        return self.is_success and self.verdict == ThreatVerdict.BENIGN

    @property
    def has_threat_signal(self) -> bool:
        """True if the observable is confirmed suspicious or malicious."""
        return self.is_malicious or self.is_suspicious
