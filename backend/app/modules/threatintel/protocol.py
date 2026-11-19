"""
AISOP Threat Intelligence Provider Protocol Interface.

In accordance with ADR-001 (Direct Lightweight Abstraction):
Defines the runtime checkable Protocol that all AISOP threat intelligence
provider adapters must satisfy. Decouples incident investigation, enrichment,
and SOC reporting from vendor-specific REST API schemas.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.modules.threatintel.models import (
    ObservableType,
    ThreatIntelRequest,
    ThreatIntelResult,
)


@runtime_checkable
class ThreatIntelProvider(Protocol):
    """Protocol for asynchronous threat intelligence providers."""

    @property
    def provider_name(self) -> str:
        """The canonical lowercase identifier of the provider (e.g. 'virustotal')."""
        ...

    @property
    def supported_observable_types(self) -> frozenset[ObservableType]:
        """Set of observable types supported by this provider."""
        ...

    async def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
        """
        Execute an asynchronous threat intelligence lookup.

        Args:
            request: Standardized request containing observable and optional type hint.

        Returns:
            ThreatIntelResult containing normalized observable, operational status,
            assessed verdict, UTC timestamp, and provider payload.
        """
        ...

    async def aclose(self) -> None:
        """Release underlying HTTP client and connection pool resources."""
        ...
