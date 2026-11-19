"""
AISOP Threat Intelligence Multi-Source Orchestrator.

In accordance with TI-3B Architectural Specification & Phase 1.2 Security Gate:
Implements a provider-neutral, fault-tolerant, privacy-preserving threat intelligence
orchestrator that queries local feeds first, enforces strict external opt-in, shields
private enterprise networks, isolates provider failures, and executes deterministic
verdict conflict synthesis.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Sequence

from app.modules.threatintel.disclosure import ExternalDisclosurePolicy, evaluate_external_disclosure
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.modules.threatintel.models import (
    Observable,
    ObservableType,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatVerdict,
)
from app.modules.threatintel.protocol import ThreatIntelProvider
from app.modules.threatintel.registry import SourceRegistry
from app.modules.threatintel.resilience import CircuitBreaker, TokenBucketRateLimiter
from app.modules.threatintel.shield import PrivateNetworkShield
from app.schemas.threatintel import InvestigationFindingState

logger = logging.getLogger(__name__)

# All observable types supported across orchestrator
_ALL_SUPPORTED_TYPES = frozenset(
    {
        ObservableType.IPV4,
        ObservableType.IPV6,
        ObservableType.DOMAIN,
        ObservableType.SHA256,
        ObservableType.MD5,
        ObservableType.SHA1,
    }
)


class ThreatIntelOrchestrator:
    """
    Multi-source Threat Intelligence Orchestrator conforming to ThreatIntelProvider.

    Guarantees:
    - Tier 1 (Local-First): Always queries offline local feeds and cache first.
    - Fast-Path Optimization: Definitive high-confidence local matches short-circuit external egress.
    - Privacy & OPSEC Shielding: Private IPs, link-local, loopback, and internal domains are blocked
      before any external query dispatch. Shielded observables return verdict=UNKNOWN with SHIELDED_INTERNAL state.
    - Dual-Gate Opt-In: External network calls occur ONLY if enable_external=True AND allow_external=True.
    - Resilient Concurrency: Concurrently queries providers under semaphores, timeouts, rate limiters, and circuit breakers.
    - Deterministic Synthesis: MALICIOUS > SUSPICIOUS > BENIGN > UNKNOWN.
      Incomplete or failed provider responses NEVER produce BENIGN. Benign never overrides malicious.
    - Full Provenance: Retains per-provider verdicts, metadata, references, and freshness timestamps.
    """

    def __init__(
        self,
        local_engine: LocalThreatIntelEngine | None = None,
        providers: dict[str, ThreatIntelProvider] | None = None,
        shield: PrivateNetworkShield | None = None,
        rate_limiters: dict[str, TokenBucketRateLimiter] | None = None,
        circuit_breakers: dict[str, CircuitBreaker] | None = None,
        enable_external: bool = False,
        per_provider_timeout_seconds: float = 2.5,
        max_concurrent_lookups: int = 5,
        disclosure_policy: ExternalDisclosurePolicy | None = None,
        source_registry: SourceRegistry | None = None,
    ) -> None:
        self.local_engine = local_engine or LocalThreatIntelEngine()
        self.providers: dict[str, ThreatIntelProvider] = providers or {}
        # Closed by default: public-looking domains are not sent unless the operator's policy allows it (see disclosure.py).
        self.disclosure_policy = disclosure_policy or ExternalDisclosurePolicy()
        self.shield = shield or self.disclosure_policy.build_shield()
        # Optional. When given, a provider is queried only if the registry permits it (global switch, per-source enablement,
        # known ID, capability). When absent the caller's explicit ``providers`` dict is the selection, as before.
        self.source_registry = source_registry
        self.rate_limiters: dict[str, TokenBucketRateLimiter] = rate_limiters or {}
        self.circuit_breakers: dict[str, CircuitBreaker] = circuit_breakers or {}
        self.enable_external = enable_external
        self.per_provider_timeout_seconds = per_provider_timeout_seconds
        self._semaphore = asyncio.Semaphore(max_concurrent_lookups)

    @property
    def provider_name(self) -> str:
        """Canonical provider identifier."""
        return "orchestrator"

    @property
    def supported_observable_types(self) -> frozenset[ObservableType]:
        """Aggregate observable types supported by the orchestrator."""
        return _ALL_SUPPORTED_TYPES

    async def aclose(self) -> None:
        """Release local engine and all child provider client resources."""
        await self.local_engine.aclose()
        for p in self.providers.values():
            try:
                await p.aclose()
            except Exception as exc:
                logger.warning("Error closing provider '%s': %s", p.provider_name, exc)

    async def lookup(
        self,
        request: ThreatIntelRequest,
        allow_external: bool = False,
    ) -> ThreatIntelResult:
        """
        Execute multi-source lookup with local precedence, privacy shielding, and synthesis.

        Args:
            request: Standard ThreatIntelRequest.
            allow_external: Per-query opt-in flag to authorize external lookups if enabled.

        Returns:
            ThreatIntelResult containing synthesized verdict and full source provenance.
        """
        # 1. Tier 1: Local Engine Lookup
        local_res = await self.local_engine.lookup(request)

        # Fast-Path: High-confidence local malicious hit short-circuits external queries
        if local_res.verdict == ThreatVerdict.MALICIOUS:
            return local_res

        # 2. OPSEC & Private Network Shield Check
        # Evaluated BEFORE checking external gates or dispatching external providers.
        is_shielded, shield_reason = self.shield.shield_observable(
            request.observable, request.observable_type
        )
        if is_shielded:
            raw = dict(local_res.raw_data or {})
            raw["shielded"] = True
            raw["shielded_internal"] = True
            # A fixed reason code only: the shield's own text can contain the raw internal value, which must not be recorded.
            raw["shield_reason"] = self._shield_reason_code(request)
            raw["state"] = InvestigationFindingState.SHIELDED_INTERNAL.value
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=local_res.observable_type,
                raw_observable=local_res.raw_observable,
                normalized_observable=local_res.normalized_observable,
                status=ThreatIntelLookupStatus.SUCCESS,
                verdict=ThreatVerdict.UNKNOWN,  # NEVER BENIGN! Blocked lookup must be UNKNOWN
                tags=sorted(set(local_res.tags) | {"shielded_internal"}),
                raw_data=raw,
                error_message=None,
                timestamp=datetime.now(timezone.utc),
            )

        # 3. Check external permission gates (Both global AND per-query required)
        if not self.enable_external or not allow_external or not self.providers:
            return local_res
        if self.source_registry is not None and not self.source_registry.external_enabled:
            return local_res  # the operator's global external switch is off

        # 3b. Last point before any provider call: the external-disclosure gate (fail closed). Eligibility controls
        # disclosure only; the local result stands and is annotated so the analyst can see external sources were not consulted.
        decision = evaluate_external_disclosure(request.observable_type, request.observable, self.disclosure_policy, self.shield)
        if not decision.eligible:
            raw = dict(local_res.raw_data or {})
            raw["external_disclosure_denied"] = True
            raw["disclosure_reason"] = decision.reason.value
            return local_res.model_copy(update={"raw_data": raw})

        # 4. Filter eligible external providers by supported observable type (and by the registry, if one is configured)
        candidate_providers: list[tuple[str, ThreatIntelProvider]] = [
            (name, p)
            for name, p in self.providers.items()
            if request.observable_type in p.supported_observable_types
            and (self.source_registry is None or self.source_registry.external_lookup_permitted(name, request.observable_type, True)[0])
        ]

        if not candidate_providers:
            return local_res

        # 5. Dispatch concurrent queries under resilience boundaries
        tasks = [
            self._query_provider_safely(name, provider, request)
            for name, provider in candidate_providers
        ]
        provider_results = await asyncio.gather(*tasks, return_exceptions=False)

        # 6. Deterministic Verdict Conflict Synthesis
        return self._synthesize_results(request, local_res, provider_results)

    def _shield_reason_code(self, request: ThreatIntelRequest) -> str:
        decision = evaluate_external_disclosure(request.observable_type, request.observable, self.disclosure_policy, self.shield)
        return decision.reason.value if not decision.eligible else "internal_or_reserved"

    async def _query_provider_safely(
        self,
        name: str,
        provider: ThreatIntelProvider,
        request: ThreatIntelRequest,
    ) -> dict[str, Any]:
        """Query an individual external provider with timeout, rate limiter, and circuit breaker."""
        cb = self.circuit_breakers.get(name)
        rl = self.rate_limiters.get(name)

        # Check circuit breaker
        if cb and not cb.allow_request():
            logger.warning("Circuit breaker OPEN for provider '%s'; skipping external query.", name)
            return {
                "source_provider": name,
                "status": ThreatIntelLookupStatus.PROVIDER_FAILURE.value,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "error": "Circuit breaker is OPEN",
                "circuit_tripped": True,
            }

        # Check rate limiter
        if rl and not rl.acquire():
            logger.warning("Rate limit exceeded for provider '%s'; skipping external query.", name)
            return {
                "source_provider": name,
                "status": ThreatIntelLookupStatus.RATE_LIMITED.value,
                "verdict": ThreatVerdict.UNKNOWN.value,
                "error": "Provider rate limit exceeded",
                "rate_limited": True,
            }

        # Bounded concurrency & strict timeout execution
        async with self._semaphore:
            try:
                res = await asyncio.wait_for(
                    provider.lookup(request),
                    timeout=self.per_provider_timeout_seconds,
                )
                if cb:
                    cb.record_success()
                return {
                    "source_provider": name,
                    "status": res.status.value,
                    "verdict": res.verdict.value,
                    "tags": list(res.tags),
                    "raw_data": res.raw_data or {},
                    "error": res.error_message,
                    "timestamp": res.timestamp.isoformat() if res.timestamp else None,
                }
            except asyncio.TimeoutError:
                if cb:
                    cb.record_failure()
                logger.warning("Provider '%s' timed out after %.2fs", name, self.per_provider_timeout_seconds)
                return {
                    "source_provider": name,
                    "status": ThreatIntelLookupStatus.TIMEOUT.value,
                    "verdict": ThreatVerdict.UNKNOWN.value,
                    "error": f"Provider timed out after {self.per_provider_timeout_seconds}s",
                    "timed_out": True,
                }
            except Exception as exc:
                if cb:
                    cb.record_failure()
                logger.error("Provider '%s' lookup failed: %s", name, exc)
                return {
                    "source_provider": name,
                    "status": ThreatIntelLookupStatus.PROVIDER_FAILURE.value,
                    "verdict": ThreatVerdict.UNKNOWN.value,
                    "error": f"Provider error: {exc}",
                }

    def _synthesize_results(
        self,
        request: ThreatIntelRequest,
        local_res: ThreatIntelResult,
        external_results: list[dict[str, Any]],
    ) -> ThreatIntelResult:
        """
        Synthesize local engine findings and external provider responses.

        Deterministic Conflict Hierarchy:
        1. If ANY source reports MALICIOUS -> MALICIOUS
        2. Else if ANY source reports SUSPICIOUS -> SUSPICIOUS
        3. Else if ANY external provider failed (timed_out, rate_limited, circuit_tripped, provider_failure):
           Incomplete evidence MUST NEVER produce BENIGN -> UNKNOWN
        4. Else if ALL valid queried sources report BENIGN -> BENIGN
        5. Else -> UNKNOWN
        """
        all_sources: list[dict[str, Any]] = []
        combined_tags: set[str] = set(local_res.tags)

        # Include local sources if present
        local_raw = local_res.raw_data or {}
        local_sources = local_raw.get("sources", [])
        if local_sources:
            all_sources.extend(local_sources)
        elif local_res.status == ThreatIntelLookupStatus.SUCCESS:
            all_sources.append({
                "source_provider": "local_feeds",
                "verdict": local_res.verdict.value,
                "tags": list(local_res.tags),
                "raw_data": local_raw,
            })

        # Include external provider sources
        for ext in external_results:
            all_sources.append(ext)
            if ext.get("tags"):
                combined_tags.update(ext["tags"])

        # Collect verdicts from successful responses
        verdicts: list[ThreatVerdict] = []
        if local_res.status == ThreatIntelLookupStatus.SUCCESS:
            verdicts.append(local_res.verdict)

        for ext in external_results:
            if ext.get("status") == ThreatIntelLookupStatus.SUCCESS.value:
                try:
                    verdicts.append(ThreatVerdict(ext["verdict"]))
                except ValueError:
                    verdicts.append(ThreatVerdict.UNKNOWN)

        # Failure detection
        has_provider_failures = any(
            ext.get("timed_out") or ext.get("rate_limited") or ext.get("circuit_tripped") or ext.get("status") != ThreatIntelLookupStatus.SUCCESS.value
            for ext in external_results
            if ext.get("status") != ThreatIntelLookupStatus.NOT_FOUND.value
        )

        error_msg = local_res.error_message

        # Hierarchy Synthesis:
        # 1. Malicious always wins
        if any(v == ThreatVerdict.MALICIOUS for v in verdicts):
            synthesized_verdict = ThreatVerdict.MALICIOUS
            synthesized_status = ThreatIntelLookupStatus.SUCCESS
            synthesized_state = InvestigationFindingState.FRESH_MATCH.value
        # 2. Suspicious wins over benign and unknown
        elif any(v == ThreatVerdict.SUSPICIOUS for v in verdicts):
            synthesized_verdict = ThreatVerdict.SUSPICIOUS
            synthesized_status = ThreatIntelLookupStatus.SUCCESS
            synthesized_state = InvestigationFindingState.FRESH_MATCH.value
        # 3. Incomplete evidence cannot be BENIGN!
        elif has_provider_failures:
            synthesized_verdict = ThreatVerdict.UNKNOWN
            if all(ext.get("timed_out") for ext in external_results):
                synthesized_status = ThreatIntelLookupStatus.TIMEOUT
                synthesized_state = InvestigationFindingState.TIMED_OUT.value
                error_msg = "All external threat intelligence providers timed out"
            elif all(ext.get("rate_limited") for ext in external_results):
                synthesized_status = ThreatIntelLookupStatus.RATE_LIMITED
                synthesized_state = InvestigationFindingState.RATE_LIMITED.value
                error_msg = "All external threat intelligence providers exceeded rate limits"
            elif all(ext.get("circuit_tripped") for ext in external_results):
                synthesized_status = ThreatIntelLookupStatus.PROVIDER_FAILURE
                synthesized_state = InvestigationFindingState.ENGINE_UNAVAILABLE.value
                error_msg = "All external threat intelligence provider circuits are OPEN"
            elif any(ext.get("status") == ThreatIntelLookupStatus.SUCCESS.value for ext in external_results):
                synthesized_status = ThreatIntelLookupStatus.SUCCESS
                synthesized_state = InvestigationFindingState.FRESH_MATCH.value
            else:
                synthesized_status = ThreatIntelLookupStatus.PROVIDER_FAILURE
                synthesized_state = InvestigationFindingState.LOOKUP_ERROR.value
                error_msg = "One or more external threat intelligence providers failed"
        # 4. Unanimous BENIGN without any failures
        elif verdicts and all(v == ThreatVerdict.BENIGN for v in verdicts):
            synthesized_verdict = ThreatVerdict.BENIGN
            synthesized_status = ThreatIntelLookupStatus.SUCCESS
            synthesized_state = InvestigationFindingState.FRESH_MATCH.value
        # 5. Default UNKNOWN / NOT_FOUND
        else:
            synthesized_verdict = ThreatVerdict.UNKNOWN
            if any(ext.get("status") == ThreatIntelLookupStatus.SUCCESS.value for ext in external_results):
                synthesized_status = ThreatIntelLookupStatus.SUCCESS
                synthesized_state = InvestigationFindingState.FRESH_MATCH.value
            elif any(ext.get("status") == ThreatIntelLookupStatus.NOT_FOUND.value for ext in external_results):
                synthesized_status = ThreatIntelLookupStatus.NOT_FOUND
                synthesized_state = InvestigationFindingState.VALID_UNMATCHED.value
            elif local_res.status == ThreatIntelLookupStatus.NOT_FOUND:
                synthesized_status = ThreatIntelLookupStatus.NOT_FOUND
                synthesized_state = InvestigationFindingState.VALID_UNMATCHED.value
            else:
                synthesized_status = local_res.status
                synthesized_state = InvestigationFindingState.LOOKUP_ERROR.value

        raw_data: dict[str, Any] = {
            "sources": all_sources,
            "providers_queried": [ext["source_provider"] for ext in external_results],
            "local_verdict": local_res.verdict.value,
            "is_stale": local_raw.get("is_stale", False),
            "stale_feeds": local_raw.get("stale_feeds", []),
            "state": synthesized_state,
        }

        return ThreatIntelResult(
            provider_name=self.provider_name,
            observable_type=local_res.observable_type,
            raw_observable=local_res.raw_observable,
            normalized_observable=local_res.normalized_observable,
            status=synthesized_status,
            verdict=synthesized_verdict,
            tags=sorted(combined_tags),
            raw_data=raw_data,
            error_message=error_msg,
            timestamp=datetime.now(timezone.utc),
        )
