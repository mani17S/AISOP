"""
AbuseIPDB threat intelligence adapter (IPv4 and IPv6 only).

This adapter performs I/O only when it is called. It is never constructed by the registry and is queried only
when the operator has enabled external lookups (``TI_EXTERNAL_ENABLED``), listed ``abuseipdb`` in
``TI_ENABLED_SOURCES`` and supplied ``ABUSEIPDB_API_KEY``; the orchestrator also applies the private-network
shield before any address leaves the host.

Verdict policy (conservative, because the score is crowd-sourced report volume, not a determination):
* confidence >= 75   -> MALICIOUS
* confidence 25..74  -> SUSPICIOUS
* confidence < 25    -> UNKNOWN. The absence of reports is never reported as BENIGN.
Operational failures never produce a verdict other than UNKNOWN.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx

from app.modules.threatintel.models import (
    ObservableType,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatVerdict,
)

_DEFAULT_BASE_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBProvider:
    """Asynchronous AbuseIPDB ``/check`` client satisfying the ThreatIntelProvider protocol."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        max_age_days: int = 90,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._api_key = api_key.strip()
        self._base_url = base_url.rstrip("/")
        self._max_age_days = max_age_days
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)

    @property
    def provider_name(self) -> str:
        return "abuseipdb"

    @property
    def supported_observable_types(self) -> frozenset[ObservableType]:
        return frozenset({ObservableType.IPV4, ObservableType.IPV6})

    @staticmethod
    def _failure(request: ThreatIntelRequest, otype: ObservableType, normalized: str, status: ThreatIntelLookupStatus, message: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider_name="abuseipdb",
            observable_type=otype,
            raw_observable=request.observable,
            normalized_observable=normalized,
            status=status,
            verdict=ThreatVerdict.UNKNOWN,
            error_message=message,
        )

    async def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
        try:
            address = ipaddress.ip_address(request.observable.strip())
        except ValueError:
            return self._failure(
                request, request.observable_type or ObservableType.IPV4, request.observable,
                ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE, "AbuseIPDB supports IP addresses only.",
            )
        otype = ObservableType.IPV6 if address.version == 6 else ObservableType.IPV4
        normalized = str(address)

        if not self._api_key:
            return self._failure(request, otype, normalized, ThreatIntelLookupStatus.MISSING_CREDENTIALS, "No AbuseIPDB API key is configured.")

        try:
            response = await self._client.get(
                f"{self._base_url}/check",
                params={"ipAddress": normalized, "maxAgeInDays": str(self._max_age_days)},
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=request.timeout_seconds,
            )
        except httpx.TimeoutException:
            return self._failure(request, otype, normalized, ThreatIntelLookupStatus.TIMEOUT, "AbuseIPDB request timed out.")
        except httpx.HTTPError:
            return self._failure(request, otype, normalized, ThreatIntelLookupStatus.PROVIDER_FAILURE, "AbuseIPDB request failed.")

        if response.status_code == 429:
            return self._failure(request, otype, normalized, ThreatIntelLookupStatus.RATE_LIMITED, "AbuseIPDB rate limit reached.")
        if response.status_code in (401, 403):
            return self._failure(request, otype, normalized, ThreatIntelLookupStatus.MISSING_CREDENTIALS, "AbuseIPDB rejected the API key.")
        if response.status_code != 200:
            return self._failure(request, otype, normalized, ThreatIntelLookupStatus.PROVIDER_FAILURE, f"AbuseIPDB returned HTTP {response.status_code}.")

        try:
            data: dict[str, Any] = response.json()["data"]
            score = int(data["abuseConfidenceScore"])
        except (ValueError, KeyError, TypeError):
            return self._failure(request, otype, normalized, ThreatIntelLookupStatus.PROVIDER_FAILURE, "AbuseIPDB returned an unreadable response.")

        if score >= 75:
            verdict = ThreatVerdict.MALICIOUS
        elif score >= 25:
            verdict = ThreatVerdict.SUSPICIOUS
        else:
            verdict = ThreatVerdict.UNKNOWN

        # Keep only a small, fixed set of fields. Free-text report content is never stored.
        raw = {k: data.get(k) for k in ("abuseConfidenceScore", "totalReports", "numDistinctUsers", "lastReportedAt", "countryCode", "isp", "usageType", "isWhitelisted") if k in data}
        return ThreatIntelResult(
            provider_name="abuseipdb",
            observable_type=otype,
            raw_observable=request.observable,
            normalized_observable=normalized,
            status=ThreatIntelLookupStatus.SUCCESS,
            verdict=verdict,
            raw_data=raw,
            reputation_score=score,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
