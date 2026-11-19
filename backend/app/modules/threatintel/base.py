"""
AISOP Threat Intelligence Base Provider Implementation.

In accordance with ADR-001 (Direct Lightweight Abstraction):
Provides an abstract base class managing:
- httpx.AsyncClient lifecycle (dependency injection, ownership, connection pooling).
- Pre-lookup normalization and validation.
- Guarding against unsupported observable types.
- Credential validation and missing credentials reporting.
- Standardized error translation for timeouts, rate limits (429), not-found (404),
  server errors (5xx), and malformed response bodies into typed ThreatIntelResult models.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Self

import httpx
from app.core.config import Settings, get_settings
from app.core.logging import redact_sensitive_data, redact_text
from app.modules.threatintel.exceptions import (
    InvalidObservableError,
    ThreatIntelAuthenticationError,
    ThreatIntelConnectionError,
    ThreatIntelError,
    ThreatIntelRateLimitError,
    ThreatIntelTimeoutError,
    UnsupportedObservableError,
)
from app.modules.threatintel.models import (
    Observable,
    ObservableType,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatVerdict,
)
from app.modules.threatintel.validation import normalize_observable
from loguru import logger


class BaseThreatIntelProvider(ABC):
    """
    Abstract base class for asynchronous threat intelligence providers.

    Subclasses implement:
    - `provider_name` (property)
    - `supported_observable_types` (property)
    - `_execute_lookup(self, observable: Observable, client: httpx.AsyncClient)`
    """

    def __init__(
        self,
        api_key: str = "",
        timeout_seconds: float = 10.0,
        client: httpx.AsyncClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._api_key = api_key.strip()
        self._timeout_seconds = timeout_seconds
        self._settings = settings or get_settings()
        self._client = client
        self._owns_client = client is None

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier of this provider."""
        ...

    @property
    @abstractmethod
    def supported_observable_types(self) -> frozenset[ObservableType]:
        """Observable types handled by this provider."""
        ...

    @property
    def has_credentials(self) -> bool:
        """True if an API key or credential is configured for this provider."""
        return bool(self._api_key)

    def _get_client(self, request_timeout: float | None = None) -> httpx.AsyncClient:
        """Return or instantiate the AsyncClient instance."""
        timeout = request_timeout or self._timeout_seconds
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(timeout, connect=5.0)
            )
            self._owns_client = True
        elif self._owns_client and request_timeout is not None:
            self._client.timeout = httpx.Timeout(request_timeout, connect=5.0)
        return self._client

    async def aclose(self) -> None:
        """Close the underlying client if owned by this provider."""
        if (
            self._owns_client
            and self._client is not None
            and not self._client.is_closed
        ):
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
        """
        Execute a standardized, normalized threat intelligence lookup.

        Handles observable normalization, credential checks, supported observable
        guards, and translates network exceptions into typed ThreatIntelResults.
        """
        # 1. Normalize and strictly validate observable
        try:
            observable = normalize_observable(
                request.observable, request.observable_type
            )
        except InvalidObservableError as exc:
            obs_type: ObservableType
            if isinstance(request.observable_type, ObservableType):
                obs_type = request.observable_type
            elif isinstance(request.observable_type, str):
                try:
                    obs_type = ObservableType(request.observable_type.strip().lower())
                except ValueError:
                    obs_type = ObservableType.DOMAIN
            elif exc.observable_type and exc.observable_type in ObservableType._value2member_map_:
                obs_type = ObservableType(exc.observable_type)
            else:
                obs_type = ObservableType.DOMAIN

            logger.warning(
                "Threat intelligence lookup rejected malformed observable",
                provider=self.provider_name,
                observable=redact_sensitive_data(request.observable),
                error=redact_text(str(exc)),
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=obs_type,
                raw_observable=request.observable,
                normalized_observable=request.observable,
                status=ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=redact_text(f"Observable validation failed: {exc.message}"),
            )

        # 2. Verify observable type is supported by this provider
        if observable.type not in self.supported_observable_types:
            logger.info(
                "Observable type not supported by provider",
                provider=self.provider_name,
                observable_type=observable.type.value,
                observable=redact_sensitive_data(observable.normalized_value),
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=(
                    f"Provider '{self.provider_name}' does not support "
                    f"observable type '{observable.type.value}'"
                ),
            )

        # 3. Verify credentials
        if not self.has_credentials:
            logger.warning(
                "Missing credentials for provider lookup",
                provider=self.provider_name,
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.MISSING_CREDENTIALS,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=(
                    f"Provider '{self.provider_name}' has no API key configured. "
                    "Set credentials in configuration or environment."
                ),
            )

        # 4. Dispatch lookup with standardized exception translation
        client = self._get_client(request.timeout_seconds)
        try:
            return await self._execute_lookup(observable, client)
        except httpx.TimeoutException as exc:
            logger.warning(
                "Threat intelligence provider lookup timed out",
                provider=self.provider_name,
                observable=redact_sensitive_data(observable.normalized_value),
                timeout=request.timeout_seconds or self._timeout_seconds,
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.TIMEOUT,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=redact_text(f"Request to provider '{self.provider_name}' timed out: {exc}"),
            )
        except ThreatIntelTimeoutError as exc:
            logger.warning(
                "Threat intelligence provider lookup timed out",
                provider=self.provider_name,
                observable=redact_sensitive_data(observable.normalized_value),
                timeout=request.timeout_seconds or self._timeout_seconds,
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.TIMEOUT,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=redact_text(f"Request to provider '{self.provider_name}' timed out: {exc.message}"),
            )
        except ThreatIntelAuthenticationError as exc:
            logger.warning(
                "Threat intelligence provider authentication failed",
                provider=self.provider_name,
                error=redact_text(str(exc)),
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.MISSING_CREDENTIALS,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=redact_text(f"Provider '{self.provider_name}' authentication failed: {exc.message}"),
                raw_data={"status_code": 401},
            )
        except ThreatIntelRateLimitError as exc:
            logger.warning(
                "Threat intelligence provider rate limit exceeded",
                provider=self.provider_name,
                error=redact_text(str(exc)),
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.RATE_LIMITED,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=redact_text(f"Provider '{self.provider_name}' rate limit or quota exceeded: {exc.message}"),
                raw_data={"status_code": 429},
            )
        except UnsupportedObservableError as exc:
            logger.info(
                "Observable type not supported by provider",
                provider=self.provider_name,
                observable_type=observable.type.value,
                observable=redact_sensitive_data(observable.normalized_value),
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=redact_text(f"Provider '{self.provider_name}' does not support observable: {exc.message}"),
            )
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            logger.warning(
                "Threat intelligence provider returned HTTP error",
                provider=self.provider_name,
                status_code=status_code,
            )
            if status_code == 429:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    observable_type=observable.type,
                    raw_observable=observable.raw_value,
                    normalized_observable=observable.normalized_value,
                    status=ThreatIntelLookupStatus.RATE_LIMITED,
                    verdict=ThreatVerdict.UNKNOWN,
                    error_message=f"Provider '{self.provider_name}' rate limit or quota exceeded (HTTP 429)",
                    raw_data={"status_code": 429},
                )
            elif status_code == 404:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    observable_type=observable.type,
                    raw_observable=observable.raw_value,
                    normalized_observable=observable.normalized_value,
                    status=ThreatIntelLookupStatus.NOT_FOUND,
                    verdict=ThreatVerdict.UNKNOWN,
                    raw_data={"status_code": 404},
                )
            elif status_code in (401, 403):
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    observable_type=observable.type,
                    raw_observable=observable.raw_value,
                    normalized_observable=observable.normalized_value,
                    status=ThreatIntelLookupStatus.MISSING_CREDENTIALS,
                    verdict=ThreatVerdict.UNKNOWN,
                    error_message=f"Provider '{self.provider_name}' authentication failed (HTTP {status_code})",
                    raw_data={"status_code": status_code},
                )
            else:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    observable_type=observable.type,
                    raw_observable=observable.raw_value,
                    normalized_observable=observable.normalized_value,
                    status=ThreatIntelLookupStatus.PROVIDER_FAILURE,
                    verdict=ThreatVerdict.UNKNOWN,
                    error_message=f"Provider '{self.provider_name}' returned HTTP {status_code}",
                    raw_data={"status_code": status_code},
                )
        except json.JSONDecodeError as exc:
            logger.error(
                "Malformed JSON response received from provider",
                provider=self.provider_name,
                error=redact_text(str(exc)),
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.PROVIDER_FAILURE,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=redact_text(f"Provider '{self.provider_name}' returned malformed JSON response: {exc}"),
            )
        except (httpx.RequestError, ThreatIntelConnectionError, ThreatIntelError) as exc:
            logger.error(
                "Threat intelligence lookup encountered request error",
                provider=self.provider_name,
                error=redact_text(str(exc)),
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.PROVIDER_FAILURE,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=redact_text(f"Provider '{self.provider_name}' communication failure: {exc}"),
            )
        except Exception as exc:
            logger.error(
                "Threat intelligence lookup encountered unexpected error",
                provider=self.provider_name,
                error=redact_text(str(exc)),
            )
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.PROVIDER_FAILURE,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=redact_text(f"Provider '{self.provider_name}' internal execution failure: {exc}"),
            )

    @abstractmethod
    async def _execute_lookup(
        self,
        observable: Observable,
        client: httpx.AsyncClient,
    ) -> ThreatIntelResult:
        """
        Execute provider-specific HTTP request and response parsing.

        Must be implemented by concrete provider adapters.
        """
        ...
