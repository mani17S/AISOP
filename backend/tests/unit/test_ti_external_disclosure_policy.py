"""Phase 4A work item A: external-disclosure eligibility gate. Offline, synthetic values only; DNS and sockets are blocked."""

from __future__ import annotations

import asyncio
import socket
from types import SimpleNamespace

import pytest

from app.modules.evidence_domains.ti import IndicatorMatch, StaticIndicatorSet, enrich
from app.modules.threatintel.disclosure import DisclosureReason, ExternalDisclosurePolicy, evaluate_external_disclosure
from app.modules.threatintel.models import ObservableType, ThreatIntelLookupStatus, ThreatIntelRequest, ThreatIntelResult, ThreatVerdict
from app.modules.threatintel.orchestrator import ThreatIntelOrchestrator


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


OPEN = ExternalDisclosurePolicy(allow_public_domains=True)
CLOSED = ExternalDisclosurePolicy()


def _decide(kind, value, policy=CLOSED):
    return evaluate_external_disclosure(kind, value, policy)


# ── IP addresses ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("value", ["8.8.8.8", "91.240.118.172", "2606:4700:4700::1111"])
def test_public_global_ip_is_eligible(value):
    assert _decide("ip", value).eligible is True


@pytest.mark.parametrize("value", [
    "10.1.2.3", "172.16.5.5", "192.168.1.10", "fc00::1", "fd12:3456::1",          # private
    "127.0.0.1", "::1",                                                            # loopback
    "169.254.10.20", "fe80::1",                                                    # link-local
    "224.0.0.1", "ff02::1",                                                        # multicast
    "0.0.0.0", "::",                                                               # unspecified
    "240.0.0.1", "255.255.255.255",                                                # reserved / broadcast
    "100.64.0.1",                                                                  # shared address space
    "192.0.2.7", "198.51.100.7", "203.0.113.7", "2001:db8::1", "198.18.0.1",       # documentation / benchmarking
    "::ffff:192.168.1.1",                                                          # IPv4-mapped private
])
def test_non_public_ip_is_denied(value):
    d = _decide("ip", value)
    assert d.eligible is False and d.reason is DisclosureReason.NON_PUBLIC_IP


@pytest.mark.parametrize("value", ["2130706433", "0x7f000001", "0177.0.0.1", "8.8.8.8:80", "999.1.1.1", "not-an-ip", ""])
def test_non_canonical_or_malformed_ip_fails_closed(value):
    assert _decide("ipv4", value).eligible is False


def test_operator_internal_network_is_denied_even_though_it_is_globally_routable():
    policy = ExternalDisclosurePolicy(internal_networks=("8.8.8.0/24",))
    assert _decide("ip", "8.8.8.8", policy).reason is DisclosureReason.NON_PUBLIC_IP


# ── domains and hostnames ─────────────────────────────────────────────────────
@pytest.mark.parametrize("value", ["WORKSTATION-01", "dc-01", "localhost", "printer"])
def test_single_label_and_localhost_are_denied_as_internal(value):
    assert _decide("domain", value, OPEN).reason is DisclosureReason.INTERNAL_OR_RESERVED_DOMAIN


@pytest.mark.parametrize("value", ["db01.corp", "x.local", "x.internal", "x.lan", "x.home", "x.arpa", "x.test", "x.example", "x.invalid", "a.b.localhost"])
def test_reserved_and_internal_suffixes_are_denied(value):
    assert _decide("domain", value, OPEN).reason is DisclosureReason.INTERNAL_OR_RESERVED_DOMAIN


def test_ordinary_looking_domain_marked_internal_by_operator_policy_is_denied():
    policy = ExternalDisclosurePolicy(internal_domain_suffixes=(".department.example-company.com",), allow_public_domains=True)
    assert _decide("domain", "host.department.example-company.com", policy).reason is DisclosureReason.INTERNAL_OR_RESERVED_DOMAIN
    assert _decide("domain", "department.example-company.com", policy).eligible is False  # the apex is internal too
    assert _decide("domain", "www.example-company.com", policy).eligible is True          # a sibling name is not listed


def test_operator_suffix_without_leading_dot_is_normalised():
    policy = ExternalDisclosurePolicy(internal_domain_suffixes=("corp.example-company.com",), allow_public_domains=True)
    assert _decide("domain", "a.corp.example-company.com", policy).eligible is False


def test_public_looking_domain_fails_closed_by_default_and_opens_only_by_policy():
    assert _decide("domain", "unlisted.example-site.net").reason is DisclosureReason.DOMAIN_POLICY_CLOSED
    assert _decide("domain", "unlisted.example-site.net", OPEN).eligible is True


@pytest.mark.parametrize("value", ["bad host.com", "evil.com/path", "evil.com:8080", "8.8.8.8", "-.com", "a..com", "x" * 300 + ".com"])
def test_malformed_or_ambiguous_domain_fails_closed_even_when_domains_are_open(value):
    assert _decide("domain", value, OPEN).eligible is False


def test_internal_ip_literal_given_as_domain_is_denied():
    assert _decide("domain", "192.168.1.5", OPEN).eligible is False


# ── URLs and e-mail ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("value", [
    "http://192.168.1.50/admin.php",                 # private IP literal
    "https://db01.corp/login",                       # internal hostname
    "https://public-looking.example-site.net/x",     # public host: still never sent
    "https://user:secret@public-looking.example-site.net/",  # userinfo
    "ftp://public-looking.example-site.net/file",    # unsupported scheme
    "http://",                                       # malformed
    "http://[::1]/",                                 # IPv6 literal
    "https://a.example-site.net/?token=abc#frag",    # query and fragment
])
def test_urls_are_never_disclosed(value):
    assert _decide("url", value, OPEN).reason is DisclosureReason.URL_NOT_AUTHORISED
    assert _decide("domain", value, OPEN).reason is DisclosureReason.URL_NOT_AUTHORISED  # a URL passed under another type is caught by shape


@pytest.mark.parametrize("value", ["admin@ad.corp", "alice@example-site.net"])
def test_email_addresses_are_never_disclosed(value):
    assert _decide("domain", value, OPEN).reason is DisclosureReason.EMAIL_NOT_AUTHORISED
    assert _decide("email", value, OPEN).reason is DisclosureReason.EMAIL_NOT_AUTHORISED


# ── hashes, unknown types, bad input ──────────────────────────────────────────
def test_hashes_must_be_well_formed_hex():
    assert _decide("file_hash", "a" * 64).eligible is True
    assert _decide("md5", "b" * 32).eligible is True
    assert _decide("file_hash", "g" * 64).eligible is False
    assert _decide("file_hash", "a" * 10).eligible is False


@pytest.mark.parametrize("kind,value", [("username", "alice"), ("cve", "CVE-2024-0001"), ("", "8.8.8.8"), (None, "8.8.8.8")])
def test_unknown_or_unclassifiable_type_fails_closed(kind, value):
    assert _decide(kind, value).reason is DisclosureReason.UNSUPPORTED_TYPE


@pytest.mark.parametrize("value", [None, 5, b"8.8.8.8", "", "   ", "8.8.8.8\x00", "x" * 5000])
def test_non_string_empty_control_or_oversized_input_fails_closed(value):
    assert _decide("ip", value).eligible is False


def test_reason_codes_never_contain_the_value():
    for kind, value in [("ip", "192.168.1.77"), ("domain", "secret-host.corp"), ("url", "https://user:pw@secret-host.corp/p"), ("email", "bob@secret-host.corp")]:
        d = _decide(kind, value, OPEN)
        assert d.eligible is False and value not in d.reason.value and "secret" not in d.reason.value and "192" not in d.reason.value


def test_policy_rejects_invalid_operator_entries_without_echoing_them():
    with pytest.raises(ValueError) as e1:
        ExternalDisclosurePolicy(internal_networks=("10.0.0.0/33",))
    assert "10.0.0.0" not in str(e1.value)  # a bad entry must fail loudly, never leave a range unshielded
    with pytest.raises(ValueError):
        ExternalDisclosurePolicy(internal_domain_suffixes=("bad suffix",))
    with pytest.raises(ValueError):
        ExternalDisclosurePolicy(internal_domain_suffixes=("",))


# ── the gate in the enrichment path (provider invocation is not reached) ──────
def _obs(*entities, key="k1"):
    return SimpleNamespace(counts_for_corroboration=True, entities=list(entities), key=key)


class _Spy:
    """No ``is_local_only`` declaration, so it is treated as an external provider."""

    def __init__(self):
        self.looked_up: list[tuple[str, str]] = []

    def lookup(self, entity_type, value):
        self.looked_up.append((entity_type, value))
        return []


def test_enrich_never_passes_internal_or_unauthorised_values_to_an_external_provider():
    spy = _Spy()
    enrich([_obs(("ip", "10.0.0.5"), ("ip", "100.64.1.1"), ("domain", "db01.corp.internal"), ("domain", "host.department.example-company.com"),
                 ("url", "https://public-looking.example-site.net/a"), ("url", "http://192.168.1.2/"), ("file_hash", "zz"))], spy,
           ExternalDisclosurePolicy(internal_domain_suffixes=(".department.example-company.com",), allow_public_domains=True))
    assert spy.looked_up == []


def test_enrich_default_policy_is_closed_for_domains_but_allows_public_ips_and_hashes():
    spy = _Spy()
    enrich([_obs(("ip", "91.240.118.172"), ("domain", "unlisted.example-site.net"), ("file_hash", "c" * 64))], spy)
    assert sorted(spy.looked_up) == [("file_hash", "c" * 64), ("ip", "91.240.118.172")]


def test_enrich_public_domain_reaches_provider_only_when_operator_opens_domains():
    spy = _Spy()
    enrich([_obs(("domain", "unlisted.example-site.net"))], spy, OPEN)
    assert spy.looked_up == [("domain", "unlisted.example-site.net")]


def test_enrich_local_only_provider_keeps_existing_offline_behaviour():
    s = StaticIndicatorSet()
    s.add("domain", "db01.corp.internal", IndicatorMatch(source="synthetic", description="offline static entry"))
    out = enrich([_obs(("domain", "db01.corp.internal"))], s)
    assert len(out) == 1  # the gate controls external disclosure only; an offline provider is unaffected


def test_enrich_provider_failure_still_yields_no_enrichment_and_no_exception():
    class Boom(_Spy):
        def lookup(self, t, v):
            raise RuntimeError("feed down")

    assert enrich([_obs(("ip", "91.240.118.172"))], Boom()) == []


# ── the gate in the orchestrator ──────────────────────────────────────────────
class _Provider:
    def __init__(self):
        self.calls = 0

    @property
    def provider_name(self):
        return "synthetic_ext"

    @property
    def supported_observable_types(self):
        return frozenset({ObservableType.IPV4, ObservableType.DOMAIN, ObservableType.SHA256})

    async def lookup(self, request):
        self.calls += 1
        return ThreatIntelResult(provider_name="synthetic_ext", observable_type=request.observable_type, raw_observable=request.observable,
                                 normalized_observable=request.observable, status=ThreatIntelLookupStatus.SUCCESS, verdict=ThreatVerdict.MALICIOUS)

    async def aclose(self):
        pass


class _Local:
    provider_name = "local_threat_intel"

    async def lookup(self, request):
        return ThreatIntelResult(provider_name="local_threat_intel", observable_type=request.observable_type, raw_observable=request.observable,
                                 normalized_observable=request.observable, status=ThreatIntelLookupStatus.NOT_FOUND, verdict=ThreatVerdict.UNKNOWN)

    async def aclose(self):
        pass


def _lookup(observable, kind, policy=None):
    provider = _Provider()
    orch = ThreatIntelOrchestrator(local_engine=_Local(), providers={"ext": provider}, enable_external=True, disclosure_policy=policy)
    res = asyncio.run(orch.lookup(ThreatIntelRequest(observable=observable, observable_type=kind), allow_external=True))
    return res, provider


def test_orchestrator_default_policy_does_not_send_a_public_looking_domain():
    res, provider = _lookup("unlisted.example-site.net", ObservableType.DOMAIN)
    assert provider.calls == 0
    assert res.raw_data["external_disclosure_denied"] is True and res.raw_data["disclosure_reason"] == "domain_policy_closed"
    assert res.verdict is ThreatVerdict.UNKNOWN  # not a benign finding: external sources were simply not consulted


def test_orchestrator_open_policy_sends_a_public_domain_but_not_one_marked_internal():
    res, provider = _lookup("unlisted.example-site.net", ObservableType.DOMAIN, OPEN)
    assert provider.calls == 1 and res.verdict is ThreatVerdict.MALICIOUS
    marked = ExternalDisclosurePolicy(internal_domain_suffixes=(".example-site.net",), allow_public_domains=True)
    res2, provider2 = _lookup("unlisted.example-site.net", ObservableType.DOMAIN, marked)
    assert provider2.calls == 0 and res2.raw_data["shielded_internal"] is True


def test_orchestrator_public_url_under_domain_type_is_never_dispatched():
    res, provider = _lookup("https://unlisted.example-site.net/x?t=1", ObservableType.DOMAIN, OPEN)
    assert provider.calls == 0 and res.raw_data["disclosure_reason"] == "url_not_authorised"


def test_orchestrator_shield_reason_is_a_code_not_the_internal_value():
    res, provider = _lookup("192.168.77.88", ObservableType.IPV4)
    assert provider.calls == 0 and res.raw_data["shielded_internal"] is True
    assert res.raw_data["shield_reason"] == "non_public_ip" and "192.168" not in str(res.raw_data["shield_reason"])


def test_orchestrator_public_ip_still_reaches_provider_under_default_policy():
    res, provider = _lookup("8.8.8.8", ObservableType.IPV4)
    assert provider.calls == 1
