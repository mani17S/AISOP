"""Phase 4A work item C: source registry and operator settings. Offline; DNS and sockets are blocked; no provider is constructed."""

from __future__ import annotations

import asyncio
import socket

import pytest

from app.core.config import Settings
from app.modules.threatintel.models import ObservableType, ThreatIntelLookupStatus, ThreatIntelRequest, ThreatIntelResult, ThreatVerdict
from app.modules.threatintel.orchestrator import ThreatIntelOrchestrator
from app.modules.threatintel.registry import SourceDescriptor, SourceKind, SourceRegistry, SourceState, TermsStatus, UnknownSourceError


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    real_connect = socket.socket.connect

    def _blocked(*a, **k):
        raise AssertionError("network or DNS access attempted in an offline test")

    def _loopback_only(self, address, *a, **k):
        # asyncio's Windows event loop connects an internal loopback socket pair; anything else is a real network attempt.
        host = address[0] if isinstance(address, tuple) else address
        if host in ("127.0.0.1", "::1"):
            return real_connect(self, address, *a, **k)
        raise AssertionError("network access attempted in an offline test")

    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _loopback_only)


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # never reads a .env file


def _synthetic(source_id="synthetic_ext", implemented=True, requires_credential=False, setting=None) -> SourceDescriptor:
    return SourceDescriptor(source_id, "Synthetic", SourceKind.EXTERNAL_API, frozenset({ObservableType.IPV4}), implemented=implemented,
                            terms_status=TermsStatus.UNVERIFIED, requires_credential=requires_credential, credential_setting=setting)


# ── defaults ──────────────────────────────────────────────────────────────────
def test_default_settings_disable_everything_external():
    s = _settings()
    assert s.TI_EXTERNAL_ENABLED is False and s.TI_ENABLED_SOURCES == [] and s.TI_ALLOW_PUBLIC_DOMAIN_LOOKUPS is False
    assert s.TI_INTERNAL_DOMAIN_SUFFIXES == [] and s.TI_INTERNAL_NETWORKS == []
    reg = SourceRegistry.from_settings(s)
    for sid in reg.ids():
        if reg.get(sid).kind is SourceKind.EXTERNAL_API:
            assert reg.state(sid) is SourceState.DISABLED


def test_an_api_key_alone_does_not_enable_a_source():
    reg = SourceRegistry.from_settings(_settings(ABUSEIPDB_API_KEY="synthetic-key", ALIENVAULT_OTX_API_KEY="synthetic-key", VIRUSTOTAL_API_KEY="synthetic-key"))
    for sid in ("abuseipdb", "alienvault_otx", "virustotal"):
        assert reg.state(sid) is SourceState.DISABLED
        assert reg.external_lookup_permitted(sid, ObservableType.IPV4, True) == (False, "disabled")


def test_listing_a_source_without_the_global_switch_does_not_enable_it():
    reg = SourceRegistry.from_settings(_settings(TI_ENABLED_SOURCES="abuseipdb"))
    assert reg.state("abuseipdb") is SourceState.DISABLED


def test_global_switch_without_listing_does_not_enable_a_source():
    reg = SourceRegistry.from_settings(_settings(TI_EXTERNAL_ENABLED=True))
    assert all(reg.state(i) is SourceState.DISABLED for i in ("abuseipdb", "alienvault_otx", "virustotal"))


def test_enabled_but_not_implemented_candidates_are_unavailable_not_enabled():
    reg = SourceRegistry.from_settings(_settings(TI_EXTERNAL_ENABLED=True, TI_ENABLED_SOURCES="abuseipdb,virustotal", ABUSEIPDB_API_KEY="synthetic-key"))
    # AbuseIPDB has an adapter now and becomes ENABLED only with the global switch, the allowlist and a key.
    assert reg.state("abuseipdb") is SourceState.ENABLED
    # VirusTotal has no adapter and is deferred by the owner: enabling it never makes it usable.
    assert reg.state("virustotal") is SourceState.UNAVAILABLE
    assert reg.external_lookup_permitted("virustotal", ObservableType.IPV4, True) == (False, "unavailable")
    # Without a key the adapter is not configured, even when enabled.
    no_key = SourceRegistry.from_settings(_settings(TI_EXTERNAL_ENABLED=True, TI_ENABLED_SOURCES="abuseipdb"))
    assert no_key.state("abuseipdb") is SourceState.NOT_CONFIGURED


# ── distinguishable states (using a synthetic implemented descriptor) ─────────
def test_disabled_not_configured_enabled_and_unsupported_are_distinct():
    d = _synthetic(requires_credential=True, setting="ABUSEIPDB_API_KEY")
    off = SourceRegistry([d])
    no_key = SourceRegistry([d], external_enabled=True, enabled_source_ids=["synthetic_ext"], credentials_present={"synthetic_ext": False})
    ready = SourceRegistry([d], external_enabled=True, enabled_source_ids=["synthetic_ext"], credentials_present={"synthetic_ext": True})
    assert off.state("synthetic_ext") is SourceState.DISABLED
    assert no_key.state("synthetic_ext") is SourceState.NOT_CONFIGURED
    assert ready.state("synthetic_ext") is SourceState.ENABLED
    assert ready.external_lookup_permitted("synthetic_ext", ObservableType.IPV4, True) == (True, "permitted")
    assert ready.external_lookup_permitted("synthetic_ext", ObservableType.DOMAIN, True) == (False, "unsupported")
    assert len({SourceState.DISABLED, SourceState.NOT_CONFIGURED, SourceState.ENABLED, SourceState.UNSUPPORTED, SourceState.UNAVAILABLE}) == 5


def test_per_query_opt_in_is_required_even_when_everything_else_is_enabled():
    reg = SourceRegistry([_synthetic()], external_enabled=True, enabled_source_ids=["synthetic_ext"])
    assert reg.external_lookup_permitted("synthetic_ext", ObservableType.IPV4, False) == (False, "per_query_opt_in_missing")


# ── unknown IDs and capabilities ──────────────────────────────────────────────
def test_unknown_source_id_fails_closed_and_is_reported():
    reg = SourceRegistry.from_settings(_settings(TI_EXTERNAL_ENABLED=True, TI_ENABLED_SOURCES="no_such_source, abuseipdb"))
    assert "no_such_source" in reg.unknown_enabled_source_ids and "no_such_source" not in reg.enabled_source_ids
    assert reg.external_lookup_permitted("no_such_source", ObservableType.IPV4, True) == (False, "unknown_source")
    with pytest.raises(UnknownSourceError):
        reg.state("no_such_source")


def test_unsupported_capability_is_rejected_safely_including_bad_types():
    reg = SourceRegistry([_synthetic()], external_enabled=True, enabled_source_ids=["synthetic_ext"])
    assert reg.external_lookup_permitted("synthetic_ext", "not-a-type", True) == (False, "unsupported")
    assert reg.external_lookup_permitted("synthetic_ext", None, True) == (False, "unsupported")


def test_duplicate_descriptor_ids_are_rejected():
    with pytest.raises(ValueError):
        SourceRegistry([_synthetic(), _synthetic()])


# ── metadata honesty and no I/O ───────────────────────────────────────────────
def test_registry_describes_only_what_exists_and_makes_no_unverified_claims():
    reg = SourceRegistry()
    assert set(reg.ids()) == {"feodo_tracker", "tor_exit_nodes", "abuseipdb", "alienvault_otx", "virustotal"}  # no Shodan, RDAP, NVD or other deferred names
    for sid in reg.ids():
        d = reg.get(sid)
        if d.kind is SourceKind.EXTERNAL_API:
            assert d.implemented is (sid == "abuseipdb") and d.terms_status is TermsStatus.UNVERIFIED
        assert d.terms_status is not TermsStatus.VERIFIED
    assert "Deferred by the owner" in reg.get("virustotal").note


def test_local_feeds_are_described_as_they_behave_today():
    reg = SourceRegistry()
    for sid in ("feodo_tracker", "tor_exit_nodes"):
        d = reg.get(sid)
        assert d.kind is SourceKind.LOCAL_FEED and d.implemented and reg.state(sid) is SourceState.ENABLED
        assert reg.external_lookup_permitted(sid, ObservableType.IPV4, True) == (False, "not_external")


def test_registry_and_settings_construction_make_no_network_calls_and_store_no_key_values():
    reg = SourceRegistry.from_settings(_settings(TI_EXTERNAL_ENABLED=True, TI_ENABLED_SOURCES="abuseipdb", ABUSEIPDB_API_KEY="synthetic-secret-value"))  # sockets are blocked by the fixture
    assert "synthetic-secret-value" not in repr(vars(reg))


def test_list_settings_accept_comma_separated_and_json_forms():
    s = _settings(TI_ENABLED_SOURCES='["a", "b"]', TI_INTERNAL_DOMAIN_SUFFIXES=".corp.example-company.com, .lab.example-company.com", TI_INTERNAL_NETWORKS="10.8.0.0/16")
    assert s.TI_ENABLED_SOURCES == ["a", "b"] and len(s.TI_INTERNAL_DOMAIN_SUFFIXES) == 2 and s.TI_INTERNAL_NETWORKS == ["10.8.0.0/16"]


# ── orchestrator integration: registry gates the provider; no fallback ────────
class _Provider:
    def __init__(self, name):
        self._name, self.calls = name, 0

    @property
    def provider_name(self):
        return self._name

    @property
    def supported_observable_types(self):
        return frozenset({ObservableType.IPV4})

    async def lookup(self, request):
        self.calls += 1
        return ThreatIntelResult(provider_name=self._name, observable_type=request.observable_type, raw_observable=request.observable,
                                 normalized_observable=request.observable, status=ThreatIntelLookupStatus.SUCCESS, verdict=ThreatVerdict.SUSPICIOUS)

    async def aclose(self):
        pass


class _Local:
    provider_name = "local_threat_intel"

    async def lookup(self, request):
        return ThreatIntelResult(provider_name="local_threat_intel", observable_type=request.observable_type, raw_observable=request.observable,
                                 normalized_observable=request.observable, status=ThreatIntelLookupStatus.NOT_FOUND, verdict=ThreatVerdict.UNKNOWN)

    async def aclose(self):
        pass


def _run(orch, allow=True):
    return asyncio.run(orch.lookup(ThreatIntelRequest(observable="8.8.8.8", observable_type=ObservableType.IPV4), allow_external=allow))


def test_orchestrator_with_registry_never_queries_a_disabled_or_unknown_provider():
    p_off, p_unknown = _Provider("synthetic_ext"), _Provider("mystery")
    reg = SourceRegistry([_synthetic()], external_enabled=True, enabled_source_ids=[])  # listed in the registry but not enabled
    res = _run(ThreatIntelOrchestrator(local_engine=_Local(), providers={"synthetic_ext": p_off, "mystery": p_unknown}, enable_external=True, source_registry=reg))
    assert p_off.calls == 0 and p_unknown.calls == 0 and res.verdict is ThreatVerdict.UNKNOWN


def test_orchestrator_with_registry_queries_only_the_enabled_provider_and_does_not_fall_back_to_another():
    enabled, other = _Provider("synthetic_ext"), _Provider("other_ext")
    reg = SourceRegistry([_synthetic(), _synthetic("other_ext")], external_enabled=True, enabled_source_ids=["synthetic_ext"])
    res = _run(ThreatIntelOrchestrator(local_engine=_Local(), providers={"synthetic_ext": enabled, "other_ext": other}, enable_external=True, source_registry=reg))
    assert enabled.calls == 1 and other.calls == 0 and res.verdict is ThreatVerdict.SUSPICIOUS


def test_orchestrator_global_registry_switch_off_prevents_any_provider_call():
    provider = _Provider("synthetic_ext")
    reg = SourceRegistry([_synthetic()], external_enabled=False, enabled_source_ids=["synthetic_ext"])
    _run(ThreatIntelOrchestrator(local_engine=_Local(), providers={"synthetic_ext": provider}, enable_external=True, source_registry=reg))
    assert provider.calls == 0


def test_orchestrator_dual_opt_in_still_required_with_a_registry():
    provider = _Provider("synthetic_ext")
    reg = SourceRegistry([_synthetic()], external_enabled=True, enabled_source_ids=["synthetic_ext"])
    _run(ThreatIntelOrchestrator(local_engine=_Local(), providers={"synthetic_ext": provider}, enable_external=True, source_registry=reg), allow=False)
    _run(ThreatIntelOrchestrator(local_engine=_Local(), providers={"synthetic_ext": provider}, enable_external=False, source_registry=reg), allow=True)
    assert provider.calls == 0
