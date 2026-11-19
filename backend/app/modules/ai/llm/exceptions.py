"""
AISOP AI/LLM Domain Exceptions.

Hierarchy of typed exceptions for errors encountered during LLM provider communication,
inference, model availability checks, and response parsing.
"""

from __future__ import annotations

from typing import Any


class LLMError(Exception):
    """Base exception for all AI/LLM domain errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


class LLMDisabledError(LLMError):
    """Raised by the inert provider when AI assistance is disabled by configuration. No network call precedes it."""


class LLMConfigurationError(LLMError):
    """Raised when the LLM configuration is invalid or unsafe (for example a non-local endpoint that was not explicitly allowed)."""


class LLMConnectionError(LLMError):
    """Raised when the LLM provider daemon is unreachable, connection is refused, or network fails."""


class LLMTimeoutError(LLMError):
    """Raised when an inference or health request exceeds the configured timeout threshold."""


class LLMModelNotFoundError(LLMError):
    """Raised when the requested model tag is not available or has not been pulled in the provider."""


class LLMResponseError(LLMError):
    """Raised when the provider returns an unexpected HTTP error (e.g. 5xx, 4xx) or malformed payload."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.status_code = status_code
        self.response_body = response_body

    def __str__(self) -> str:
        parts = [self.message]
        if self.status_code is not None:
            parts.append(f"Status: {self.status_code}")
        if self.response_body:
            parts.append(f"Body: {self.response_body[:200]}")
        return " | ".join(parts)
