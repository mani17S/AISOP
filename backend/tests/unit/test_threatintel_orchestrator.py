"""
Unit tests for ThreatIntelOrchestrator.
Phase 1.2 Security Gate verification:
- ThreatIntelProvider protocol compliance
- Tier 1 local precedence and fast-path short-circuiting on local MALICIOUS
- Dual-gate external opt-in (enable_external & allow_external)
- Privacy & OPSEC shielding of RFC 1918 / internal domains before dispatch
- Verdict=UNKNOWN for shielded observables (never infer BENIGN)
- Deterministic conflict synthesis & Incomplete Evidence Handling:
  Incomplete / failed provider responses NEVER produce BENIGN
- Fault isolation (exceptions, timeouts, rate limiting, circuit breaker trip)
- Provider observable type filtering
- Resource cleanup via aclose()
"""

import asyncio
from datetime import datetime, timezone
from typing import Any
import pytest

from app.modules.threatintel.disclosure import ExternalDisclosurePolicy
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.modules.threatintel.models import (
    ObservableType,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatVerdict,
)
from app.modules.threatintel.orchestrator import ThreatIntelOrchestrator
from app.modules.threatintel.protocol import ThreatIntelProvider
from app.modules.threatintel.resilience import (
    CircuitBreaker,
    CircuitBreakerState,
    TokenBucketRateLimiter,
)
from app.modules.threatintel.shield import PrivateNetworkShield
from app.schemas.threatintel import InvestigationFindingState


# Phase 4A: public-looking domains are closed by default (a domain cannot be proven public offline). The tests below that
# dispatch a public domain to a mock provider state that choice explicitly.
OPEN_DOMAINS = ExternalDisclosurePolicy(allow_public_domains=True)


class MockProvider:
    """Mock external ThreatIntelProvider with configurable behavior."""

    def __init__(
        self,
        name: str = "mock_provider",
        supported_types: frozenset[ObservableType] | None = None,
        verdict: ThreatVerdict = ThreatVerdict.UNKNOWN,
        status: ThreatIntelLookupStatus = ThreatIntelLookupStatus.SUCCESS,
        tags: list[str] | None = None,
        delay_seconds: float = 0.0,
        exception: Exception | None = None,
    ) -> None:
        self._name = name
        self._supported_types = supported_types or frozenset(
            {ObservableType.IPV4, ObservableType.DOMAIN, ObservableType.SHA256}
        )
        self.verdict = verdict
        self.status = status
        self.tags = tags or []
        self.delay_seconds = delay_seconds
        self.exception = exception
        self.lookup_call_count = 0
        self.closed = False

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def supported_observable_types(self) -> frozenset[ObservableType]:
        return self._supported_types

    async def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
        self.lookup_call_count += 1
        if self.delay_seconds > 0:
            await asyncio.sleep(self.delay_seconds)
        if self.exception:
            raise self.exception

        return ThreatIntelResult(
            provider_name=self._name,
            observable_type=request.observable_type,
            raw_observable=request.observable,
            normalized_observable=request.observable.strip().lower(),
            status=self.status,
            verdict=self.verdict,
            tags=self.tags,
            raw_data={"mock_field": "val"},
        )

    async def aclose(self) -> None:
        self.closed = True


class MockLocalEngine:
    """Mock LocalThreatIntelEngine."""

    def __init__(
        self,
        verdict: ThreatVerdict = ThreatVerdict.UNKNOWN,
        status: ThreatIntelLookupStatus = ThreatIntelLookupStatus.NOT_FOUND,
        tags: list[str] | None = None,
        raw_data: dict[str, Any] | None = None,
    ) -> None:
        self.verdict = verdict
        self.status = status
        self.tags = tags or []
        self.raw_data = raw_data or {}
        self.lookup_call_count = 0
        self.closed = False

    @property
    def provider_name(self) -> str:
        return "local_threat_intel"

    async def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
        self.lookup_call_count += 1
        return ThreatIntelResult(
            provider_name=self.provider_name,
            observable_type=request.observable_type,
            raw_observable=request.observable,
            normalized_observable=request.observable.strip().lower(),
            status=self.status,
            verdict=self.verdict,
            tags=self.tags,
            raw_data=self.raw_data,
        )

    async def aclose(self) -> None:
        self.closed = True


class TestProtocolConformance:
    def test_implements_protocol(self):
        orchestrator = ThreatIntelOrchestrator()
        assert isinstance(orchestrator, ThreatIntelProvider)
        assert orchestrator.provider_name == "orchestrator"
        assert ObservableType.IPV4 in orchestrator.supported_observable_types
        assert ObservableType.DOMAIN in orchestrator.supported_observable_types


class TestFastPathAndTier1:
    @pytest.mark.anyio
    async def test_fast_path_local_malicious_skips_external(self):
        local_mock = MockLocalEngine(
            verdict=ThreatVerdict.MALICIOUS,
            status=ThreatIntelLookupStatus.SUCCESS,
            tags=["local_c2"],
        )
        ext_mock = MockProvider(verdict=ThreatVerdict.MALICIOUS)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"ext1": ext_mock},
            enable_external=True,
        )

        req = ThreatIntelRequest(
            observable="evil.com",
            observable_type=ObservableType.DOMAIN,
        )

        res = await orchestrator.lookup(req, allow_external=True)

        assert res.verdict == ThreatVerdict.MALICIOUS
        assert local_mock.lookup_call_count == 1
        assert ext_mock.lookup_call_count == 0  # External was NEVER called!


class TestDualGateOptIn:
    @pytest.mark.anyio
    async def test_external_disabled_globally_skips_external(self):
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        ext_mock = MockProvider(verdict=ThreatVerdict.MALICIOUS)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"ext1": ext_mock},
            enable_external=False,  # Globally disabled
        )

        req = ThreatIntelRequest(observable="evil.com", observable_type=ObservableType.DOMAIN)
        res = await orchestrator.lookup(req, allow_external=True)

        assert res.verdict == ThreatVerdict.UNKNOWN
        assert ext_mock.lookup_call_count == 0

    @pytest.mark.anyio
    async def test_external_disabled_per_query_skips_external(self):
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        ext_mock = MockProvider(verdict=ThreatVerdict.MALICIOUS)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"ext1": ext_mock},
            enable_external=True,  # Globally enabled
        )

        req = ThreatIntelRequest(observable="evil.com", observable_type=ObservableType.DOMAIN)
        res = await orchestrator.lookup(req, allow_external=False)  # Per-query disabled

        assert res.verdict == ThreatVerdict.UNKNOWN
        assert ext_mock.lookup_call_count == 0

    @pytest.mark.anyio
    async def test_external_enabled_both_gates_calls_external(self):
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        ext_mock = MockProvider(verdict=ThreatVerdict.MALICIOUS)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"ext1": ext_mock},
            enable_external=True,
            disclosure_policy=OPEN_DOMAINS,
        )

        req = ThreatIntelRequest(observable="evil.com", observable_type=ObservableType.DOMAIN)
        res = await orchestrator.lookup(req, allow_external=True)

        assert res.verdict == ThreatVerdict.MALICIOUS
        assert ext_mock.lookup_call_count == 1


class TestPrivacyShielding:
    @pytest.mark.anyio
    @pytest.mark.parametrize("private_observable,obs_type", [
        ("192.168.1.10", ObservableType.IPV4),
        ("10.0.5.23", ObservableType.IPV4),
        ("127.0.0.1", ObservableType.IPV4),
        ("169.254.10.20", ObservableType.IPV4),
        ("100.64.0.1", ObservableType.IPV4),
        ("fe80::1", ObservableType.IPV6),
        ("fc00::1", ObservableType.IPV6),
        ("server.local", ObservableType.DOMAIN),
        ("ad.corp", ObservableType.DOMAIN),
        ("internal-router", ObservableType.DOMAIN),
    ])
    async def test_private_observables_shielded_from_external(
        self, private_observable, obs_type
    ):
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        ext_mock = MockProvider(verdict=ThreatVerdict.MALICIOUS)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"ext1": ext_mock},
            enable_external=True,
        )

        req = ThreatIntelRequest(observable=private_observable, observable_type=obs_type)
        res = await orchestrator.lookup(req, allow_external=True)

        # Zero provider calls
        assert ext_mock.lookup_call_count == 0
        
        # Verdict MUST be UNKNOWN - never inferred as BENIGN
        assert res.verdict == ThreatVerdict.UNKNOWN
        assert res.verdict != ThreatVerdict.BENIGN
        
        # State MUST be SHIELDED_INTERNAL
        assert res.raw_data.get("shielded_internal") is True
        assert res.raw_data.get("state") == InvestigationFindingState.SHIELDED_INTERNAL.value
        assert res.raw_data.get("shield_reason") is not None

    @pytest.mark.anyio
    async def test_shielded_observable_never_benign_even_if_local_is_benign(self):
        """Rule: A shielded observable MUST NEVER return BENIGN, even if local had benign."""
        local_mock = MockLocalEngine(verdict=ThreatVerdict.BENIGN, status=ThreatIntelLookupStatus.SUCCESS)
        ext_mock = MockProvider(verdict=ThreatVerdict.BENIGN)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"ext1": ext_mock},
            enable_external=True,
        )

        req = ThreatIntelRequest(observable="192.168.1.1", observable_type=ObservableType.IPV4)
        res = await orchestrator.lookup(req, allow_external=True)

        assert ext_mock.lookup_call_count == 0
        assert res.verdict == ThreatVerdict.UNKNOWN
        assert res.verdict != ThreatVerdict.BENIGN
        assert res.raw_data.get("state") == InvestigationFindingState.SHIELDED_INTERNAL.value

    @pytest.mark.anyio
    async def test_shielded_url_and_email_observables_before_dispatch(self):
        """Rule: URLs and emails with private/internal hosts are shielded before external dispatch."""
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        ext_mock = MockProvider(verdict=ThreatVerdict.MALICIOUS)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"ext1": ext_mock},
            enable_external=True,
        )

        # URL with internal IP
        req_url = ThreatIntelRequest(observable="http://192.168.1.50/admin.php", observable_type=ObservableType.DOMAIN)
        res_url = await orchestrator.lookup(req_url, allow_external=True)
        assert ext_mock.lookup_call_count == 0
        assert res_url.verdict == ThreatVerdict.UNKNOWN
        assert res_url.raw_data.get("shielded_internal") is True

        # Email with internal domain
        req_email = ThreatIntelRequest(observable="admin@ad.corp", observable_type=ObservableType.DOMAIN)
        res_email = await orchestrator.lookup(req_email, allow_external=True)
        assert ext_mock.lookup_call_count == 0
        assert res_email.verdict == ThreatVerdict.UNKNOWN
        assert res_email.raw_data.get("shielded_internal") is True


class TestDeterministicSynthesisAndIncompleteEvidence:
    @pytest.mark.anyio
    async def test_incomplete_evidence_timeout_never_produces_benign(self):
        """Security Invariant: If one provider reports BENIGN but another times out, verdict MUST be UNKNOWN."""
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        good_benign = MockProvider(name="good", verdict=ThreatVerdict.BENIGN)
        slow_provider = MockProvider(name="slow", delay_seconds=1.0)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"good": good_benign, "slow": slow_provider},
            enable_external=True,
            per_provider_timeout_seconds=0.05,
        )

        req = ThreatIntelRequest(observable="8.8.8.8", observable_type=ObservableType.IPV4)
        res = await orchestrator.lookup(req, allow_external=True)

        # MUST NOT be BENIGN! Incomplete evidence cannot clear an indicator
        assert res.verdict == ThreatVerdict.UNKNOWN
        assert res.verdict != ThreatVerdict.BENIGN

    @pytest.mark.anyio
    async def test_incomplete_evidence_rate_limited_never_produces_benign(self):
        """Security Invariant: If one provider reports BENIGN but another is rate-limited, verdict MUST be UNKNOWN."""
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        good_benign = MockProvider(name="good", verdict=ThreatVerdict.BENIGN)
        rate_limited_provider = MockProvider(name="limited", verdict=ThreatVerdict.MALICIOUS)
        limiter = TokenBucketRateLimiter(capacity=1.0, refill_rate=0.0)
        limiter.acquire(1.0)  # Exhaust token bucket

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"good": good_benign, "limited": rate_limited_provider},
            rate_limiters={"limited": limiter},
            enable_external=True,
        )

        req = ThreatIntelRequest(observable="8.8.8.8", observable_type=ObservableType.IPV4)
        res = await orchestrator.lookup(req, allow_external=True)

        assert res.verdict == ThreatVerdict.UNKNOWN
        assert res.verdict != ThreatVerdict.BENIGN

    @pytest.mark.anyio
    async def test_malicious_preserved_despite_partial_failures(self):
        """Security Invariant: Malicious evidence is NEVER suppressed by provider failures or timeouts."""
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        slow_provider = MockProvider(name="slow", delay_seconds=1.0)
        malicious_provider = MockProvider(name="vt", verdict=ThreatVerdict.MALICIOUS, tags=["ransomware"])

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"slow": slow_provider, "vt": malicious_provider},
            enable_external=True,
            per_provider_timeout_seconds=0.05,
        )

        req = ThreatIntelRequest(observable="93.184.216.34", observable_type=ObservableType.IPV4)
        res = await orchestrator.lookup(req, allow_external=True)

        assert res.verdict == ThreatVerdict.MALICIOUS
        assert "ransomware" in res.tags

    @pytest.mark.anyio
    async def test_benign_never_overrides_malicious(self):
        """Rule: If any provider reports MALICIOUS, synthesized verdict MUST be MALICIOUS."""
        local_mock = MockLocalEngine(verdict=ThreatVerdict.BENIGN, status=ThreatIntelLookupStatus.SUCCESS)
        ext_vt = MockProvider(name="vt", verdict=ThreatVerdict.MALICIOUS, tags=["c2"])
        ext_abuse = MockProvider(name="abuseipdb", verdict=ThreatVerdict.BENIGN)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"vt": ext_vt, "abuseipdb": ext_abuse},
            enable_external=True,
        )

        req = ThreatIntelRequest(observable="93.184.216.34", observable_type=ObservableType.IPV4)
        res = await orchestrator.lookup(req, allow_external=True)

        assert res.verdict == ThreatVerdict.MALICIOUS
        assert "c2" in res.tags

    @pytest.mark.anyio
    async def test_suspicious_hierarchy(self):
        """Rule: SUSPICIOUS overrides BENIGN and UNKNOWN, but yields to MALICIOUS."""
        local_mock = MockLocalEngine(verdict=ThreatVerdict.BENIGN, status=ThreatIntelLookupStatus.SUCCESS)
        ext_mock = MockProvider(verdict=ThreatVerdict.SUSPICIOUS, tags=["scanner"])

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"ext1": ext_mock},
            enable_external=True,
        )

        req = ThreatIntelRequest(observable="93.184.216.34", observable_type=ObservableType.IPV4)
        res = await orchestrator.lookup(req, allow_external=True)

        assert res.verdict == ThreatVerdict.SUSPICIOUS
        assert "scanner" in res.tags

    @pytest.mark.anyio
    async def test_unanimous_benign_without_failures_yields_benign(self):
        """Rule: BENIGN requires all valid responding sources to agree with zero provider failures."""
        local_mock = MockLocalEngine(verdict=ThreatVerdict.BENIGN, status=ThreatIntelLookupStatus.SUCCESS)
        ext_p1 = MockProvider(name="p1", verdict=ThreatVerdict.BENIGN)
        ext_p2 = MockProvider(name="p2", verdict=ThreatVerdict.BENIGN)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"p1": ext_p1, "p2": ext_p2},
            enable_external=True,
        )

        req = ThreatIntelRequest(observable="8.8.8.8", observable_type=ObservableType.IPV4)
        res = await orchestrator.lookup(req, allow_external=True)

        assert res.verdict == ThreatVerdict.BENIGN


class TestFaultIsolationAndResilience:
    @pytest.mark.anyio
    async def test_provider_exception_isolated(self):
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        failing_provider = MockProvider(
            name="faulty", exception=RuntimeError("Remote socket connection reset")
        )
        working_provider = MockProvider(
            name="good", verdict=ThreatVerdict.MALICIOUS, tags=["trojan"]
        )

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"faulty": failing_provider, "good": working_provider},
            enable_external=True,
            disclosure_policy=OPEN_DOMAINS,
        )

        req = ThreatIntelRequest(observable="evil-site.com", observable_type=ObservableType.DOMAIN)
        res = await orchestrator.lookup(req, allow_external=True)

        # Fault did not crash orchestrator, working provider verdict synthesized
        assert res.verdict == ThreatVerdict.MALICIOUS
        assert "trojan" in res.tags

    @pytest.mark.anyio
    async def test_all_providers_timed_out_preserves_timeout_state(self):
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        slow_p1 = MockProvider(name="slow1", delay_seconds=1.0)
        slow_p2 = MockProvider(name="slow2", delay_seconds=1.0)

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"slow1": slow_p1, "slow2": slow_p2},
            enable_external=True,
            per_provider_timeout_seconds=0.05,
        )

        req = ThreatIntelRequest(observable="89.100.2.1", observable_type=ObservableType.IPV4)
        res = await orchestrator.lookup(req, allow_external=True)

        assert res.verdict == ThreatVerdict.UNKNOWN
        assert res.status == ThreatIntelLookupStatus.TIMEOUT
        assert res.raw_data.get("state") == InvestigationFindingState.TIMED_OUT.value
        assert "timed out" in res.error_message.lower()

    @pytest.mark.anyio
    async def test_rate_limiter_skips_provider(self):
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        ext_provider = MockProvider(name="vt", verdict=ThreatVerdict.MALICIOUS)
        rate_limiter = TokenBucketRateLimiter(capacity=1.0, refill_rate=0.0)
        assert rate_limiter.acquire(1.0) is True

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"vt": ext_provider},
            rate_limiters={"vt": rate_limiter},
            enable_external=True,
            disclosure_policy=OPEN_DOMAINS,
        )

        req = ThreatIntelRequest(observable="bad.com", observable_type=ObservableType.DOMAIN)
        res = await orchestrator.lookup(req, allow_external=True)

        assert ext_provider.lookup_call_count == 0
        assert res.status == ThreatIntelLookupStatus.RATE_LIMITED
        assert res.raw_data.get("state") == InvestigationFindingState.RATE_LIMITED.value
        sources = res.raw_data.get("sources", [])
        vt_source = next((s for s in sources if s.get("source_provider") == "vt"), None)
        assert vt_source is not None
        assert vt_source.get("rate_limited") is True

    @pytest.mark.anyio
    async def test_circuit_breaker_trips_and_skips(self):
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        ext_provider = MockProvider(name="otx", verdict=ThreatVerdict.MALICIOUS)
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout_seconds=60.0)
        cb.record_failure()
        assert cb.state == CircuitBreakerState.OPEN

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"otx": ext_provider},
            circuit_breakers={"otx": cb},
            enable_external=True,
            disclosure_policy=OPEN_DOMAINS,
        )

        req = ThreatIntelRequest(observable="bad.com", observable_type=ObservableType.DOMAIN)
        res = await orchestrator.lookup(req, allow_external=True)

        assert ext_provider.lookup_call_count == 0
        assert res.status == ThreatIntelLookupStatus.PROVIDER_FAILURE
        assert res.raw_data.get("state") == InvestigationFindingState.ENGINE_UNAVAILABLE.value
        sources = res.raw_data.get("sources", [])
        otx_source = next((s for s in sources if s.get("source_provider") == "otx"), None)
        assert otx_source is not None
        assert otx_source.get("circuit_tripped") is True


class TestProviderFilteringAndCleanup:
    @pytest.mark.anyio
    async def test_provider_observable_type_filtering(self):
        local_mock = MockLocalEngine(verdict=ThreatVerdict.UNKNOWN)
        domain_only_provider = MockProvider(
            name="domain_intel",
            supported_types=frozenset({ObservableType.DOMAIN}),
            verdict=ThreatVerdict.MALICIOUS,
        )

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"domain_intel": domain_only_provider},
            enable_external=True,
        )

        # Lookup IPv4 -> domain_only_provider must be skipped
        req = ThreatIntelRequest(observable="8.8.8.8", observable_type=ObservableType.IPV4)
        res = await orchestrator.lookup(req, allow_external=True)

        assert domain_only_provider.lookup_call_count == 0

    @pytest.mark.anyio
    async def test_aclose_cleans_up_all_providers(self):
        local_mock = MockLocalEngine()
        p1 = MockProvider(name="p1")
        p2 = MockProvider(name="p2")

        orchestrator = ThreatIntelOrchestrator(
            local_engine=local_mock,  # type: ignore
            providers={"p1": p1, "p2": p2},
        )

        await orchestrator.aclose()
        assert local_mock.closed is True
        assert p1.closed is True
        assert p2.closed is True
