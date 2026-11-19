"""
AISOP Threat Intelligence Domain Exceptions.

In accordance with ADR-001 (Direct Lightweight Abstraction) and the AISOP
exception hierarchy conventions:
Provides typed domain exceptions for threat intelligence validation, observable
normalization, provider communication, authentication, timeouts, and response parsing.
"""

from __future__ import annotations

from typing import Any


class ThreatIntelError(Exception):
    """
    Base class for all AISOP threat intelligence domain errors.

    Attributes:
        message: Human-readable error description.
        details: Optional structured diagnostic context.
    """

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(message={self.message!r}, details={self.details!r})"
        )


class InvalidObservableError(ThreatIntelError):
    """
    Raised when an observable fails syntax, length, character set, or checksum validation.
    """

    def __init__(
        self,
        message: str,
        observable: str | None = None,
        observable_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        extra_details = dict(details or {})
        if observable is not None:
            extra_details["observable"] = observable
        if observable_type is not None:
            extra_details["observable_type"] = observable_type
        super().__init__(message, details=extra_details)
        self.observable = observable
        self.observable_type = observable_type


class UnsupportedObservableError(ThreatIntelError):
    """
    Raised when a provider does not support an observable type (e.g. hash query to IP-only provider).
    """


class ThreatIntelConnectionError(ThreatIntelError):
    """
    Raised when a threat intelligence provider endpoint is unreachable.
    """


class ThreatIntelTimeoutError(ThreatIntelError):
    """
    Raised when a threat intelligence query exceeds the configured timeout.
    """


class ThreatIntelRateLimitError(ThreatIntelError):
    """
    Raised when a threat intelligence provider returns HTTP 429 (rate limit / quota exceeded).
    """


class ThreatIntelAuthenticationError(ThreatIntelError):
    """
    Raised when threat intelligence provider credentials are missing, invalid, or expired.
    """


class ThreatIntelResponseError(ThreatIntelError):
    """
    Raised when a provider returns an unexpected HTTP status or malformed/unparseable body.

    Attributes:
        status_code: HTTP status code if available.
        response_body: Truncated response body if available.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        extra_details = dict(details or {})
        if status_code is not None:
            extra_details["status_code"] = status_code
        if response_body:
            extra_details["response_body"] = response_body[:200]
        super().__init__(message, details=extra_details)
        self.status_code = status_code
        self.response_body = response_body
