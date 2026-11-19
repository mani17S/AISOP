"""
Unit tests for PrivateNetworkShield.
Comprehensive Phase 1.2 security gate suite verifying:
- RFC 1918, link-local, loopback, CGNAT, benchmark, documentation, multicast, IPv6
- IPv4-mapped IPv6 representations
- Integer, hex, octal, and port IP notations
- Fail-closed behavior on ambiguous or malformed inputs
- Internal domain suffixes, single-label hostnames, trailing dots, IDNA
- URL candidate host parsing (userinfo, backslashes, percent-encoding, brackets)
- Email host/literal parsing
- Verdict=UNKNOWN and state=SHIELDED_INTERNAL semantics (never inferred as BENIGN)
"""
import pytest
from app.schemas.threatintel import ObservableType, ThreatIntelResult, ThreatVerdict, InvestigationFindingState
from app.modules.threatintel.shield import PrivateNetworkShield


@pytest.fixture
def shield():
    return PrivateNetworkShield()


class TestPrivateNetworkShieldIP:
    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "192.168.254.254",
    ])
    def test_rfc1918_ipv4_shielded(self, shield, ip):
        assert shield.is_shielded(ip, ObservableType.IPV4) is True
        reason = shield.get_shield_reason(ip, ObservableType.IPV4)
        assert reason is not None
        assert "RFC 1918" in reason

    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "127.0.1.1",
        "127.255.255.255",
    ])
    def test_loopback_ipv4_shielded(self, shield, ip):
        assert shield.is_shielded(ip, ObservableType.IPV4) is True
        reason = shield.get_shield_reason(ip, ObservableType.IPV4)
        assert reason is not None
        assert "Loopback" in reason

    @pytest.mark.parametrize("ip", [
        "169.254.1.1",
        "169.254.169.254",
    ])
    def test_link_local_ipv4_shielded(self, shield, ip):
        assert shield.is_shielded(ip, ObservableType.IPV4) is True
        reason = shield.get_shield_reason(ip, ObservableType.IPV4)
        assert reason is not None
        assert "Link-local" in reason or "RFC 3927" in reason

    @pytest.mark.parametrize("ip", [
        "100.64.0.1",
        "100.127.255.254",
    ])
    def test_cgnat_ipv4_shielded(self, shield, ip):
        """Verify CGNAT (RFC 6598) is shielded even though ip.is_private is False in Python."""
        assert shield.is_shielded(ip, ObservableType.IPV4) is True
        reason = shield.get_shield_reason(ip, ObservableType.IPV4)
        assert reason is not None
        assert "Carrier-Grade NAT" in reason or "RFC 6598" in reason

    @pytest.mark.parametrize("ip", [
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
    ])
    def test_documentation_ipv4_shielded(self, shield, ip):
        assert shield.is_shielded(ip, ObservableType.IPV4) is True
        reason = shield.get_shield_reason(ip, ObservableType.IPV4)
        assert reason is not None
        assert "Documentation" in reason or "RFC 5737" in reason

    def test_documentation_ipv6_shielded(self, shield):
        assert shield.is_shielded("2001:db8::1", ObservableType.IPV6) is True
        reason = shield.get_shield_reason("2001:db8::1", ObservableType.IPV6)
        assert reason is not None
        assert "RFC 3849" in reason

    @pytest.mark.parametrize("ip", [
        "224.0.0.1",
        "224.0.0.251",
        "239.255.255.250",
    ])
    def test_multicast_ipv4_shielded(self, shield, ip):
        """Verify Multicast is shielded even though ip.is_private is False and is_global is True in Python."""
        assert shield.is_shielded(ip, ObservableType.IPV4) is True
        reason = shield.get_shield_reason(ip, ObservableType.IPV4)
        assert reason is not None
        assert "Multicast" in reason

    def test_multicast_ipv6_shielded(self, shield):
        assert shield.is_shielded("ff02::1", ObservableType.IPV6) is True
        reason = shield.get_shield_reason("ff02::1", ObservableType.IPV6)
        assert reason is not None
        assert "Multicast" in reason

    @pytest.mark.parametrize("ip", [
        "0.0.0.0",
        "0.0.0.1",
    ])
    def test_unspecified_this_network_shielded(self, shield, ip):
        assert shield.is_shielded(ip, ObservableType.IPV4) is True
        reason = shield.get_shield_reason(ip, ObservableType.IPV4)
        assert reason is not None
        assert "Unspecified" in reason or "RFC 1122" in reason

    @pytest.mark.parametrize("ip", [
        "198.18.0.1",
        "198.19.255.254",
    ])
    def test_benchmarking_network_shielded(self, shield, ip):
        assert shield.is_shielded(ip, ObservableType.IPV4) is True
        reason = shield.get_shield_reason(ip, ObservableType.IPV4)
        assert reason is not None
        assert "Benchmarking" in reason or "RFC 2544" in reason

    @pytest.mark.parametrize("ip", [
        "240.0.0.1",
        "255.255.255.255",
    ])
    def test_reserved_future_use_shielded(self, shield, ip):
        assert shield.is_shielded(ip, ObservableType.IPV4) is True
        reason = shield.get_shield_reason(ip, ObservableType.IPV4)
        assert reason is not None
        assert "Reserved" in reason or "RFC 1112" in reason

    @pytest.mark.parametrize("ip", [
        "::1",
        "fe80::1",
        "fe80::1ff:fe23:4567:890a",
        "fc00::1",
        "fd12:3456:789a:1::1",
    ])
    def test_ipv6_private_and_local_shielded(self, shield, ip):
        assert shield.is_shielded(ip, ObservableType.IPV6) is True
        assert shield.get_shield_reason(ip, ObservableType.IPV6) is not None

    @pytest.mark.parametrize("mapped_ip", [
        "::ffff:192.168.1.1",
        "::ffff:10.0.0.1",
        "::ffff:100.64.0.1",
        "::ffff:127.0.0.1",
    ])
    def test_ipv4_mapped_ipv6_private_shielded(self, shield, mapped_ip):
        """Security invariant: IPv4-mapped IPv6 private addresses MUST be shielded."""
        assert shield.is_shielded(mapped_ip, ObservableType.IPV6) is True
        reason = shield.get_shield_reason(mapped_ip, ObservableType.IPV6)
        assert reason is not None

    def test_ipv4_mapped_ipv6_public_allowed(self, shield):
        assert shield.is_shielded("::ffff:8.8.8.8", ObservableType.IPV6) is False

    @pytest.mark.parametrize("noncanonical_ip", [
        "2130706433",      # 127.0.0.1 as integer
        "0x7f000001",      # 127.0.0.1 as hex
        "0177.0.0.1",      # 127.0.0.1 as octal
        "192.168.1.1:80",  # IP with port
        "10.0.0.1:443",    # IP with port
    ])
    def test_noncanonical_and_port_private_ips_shielded(self, shield, noncanonical_ip):
        assert shield.is_shielded(noncanonical_ip, ObservableType.IPV4) is True

    @pytest.mark.parametrize("malformed_ip", [
        "999.1.1.1",
        "1.2.3.4.5",
        "192.168.1.1/24",
        "invalid-ip-format",
        "127.0.0.1\x00",
        "10.0.0.1 admin",
    ])
    def test_malformed_ips_fail_closed_shielded(self, shield, malformed_ip):
        """Security invariant: Unparseable/malformed IP observables must fail closed."""
        assert shield.is_shielded(malformed_ip, ObservableType.IPV4) is True
        reason = shield.get_shield_reason(malformed_ip, ObservableType.IPV4)
        assert "shielded conservatively" in reason or "RFC" in reason

    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
    ])
    def test_globally_routable_public_ips_not_shielded(self, shield, ip):
        obs_type = ObservableType.IPV4 if ":" not in ip else ObservableType.IPV6
        assert shield.is_shielded(ip, obs_type) is False
        assert shield.get_shield_reason(ip, obs_type) is None


class TestPrivateNetworkShieldDomain:
    @pytest.mark.parametrize("domain", [
        "server.local",
        "server.local.",
        "myhost.internal",
        "ad.corp",
        "ad.corp.",
        "router.lan",
        "nas.home",
        "staging.test",
        "demo.example",
        "bad.invalid",
        "app.localhost",
        "1.168.192.in-addr.arpa",
    ])
    def test_internal_domain_suffixes_shielded(self, shield, domain):
        assert shield.is_shielded(domain, ObservableType.DOMAIN) is True
        reason = shield.get_shield_reason(domain, ObservableType.DOMAIN)
        assert reason is not None
        assert "Internal enterprise" in reason or "RFC" in reason or "domain" in reason.lower()

    @pytest.mark.parametrize("hostname", [
        "dc01",
        "fileserver",
        "intranet",
        "localhost",
        "win-server-2022",
    ])
    def test_single_label_hostnames_shielded(self, shield, hostname):
        assert shield.is_shielded(hostname, ObservableType.DOMAIN) is True
        reason = shield.get_shield_reason(hostname, ObservableType.DOMAIN)
        assert reason is not None
        assert "Unqualified" in reason or "hostname" in reason.lower()

    def test_domain_containing_private_ip_literal_shielded(self, shield):
        assert shield.is_shielded("192.168.1.1", ObservableType.DOMAIN) is True
        assert shield.is_shielded("10.0.0.1", ObservableType.DOMAIN) is True
        assert shield.is_shielded("::1", ObservableType.DOMAIN) is True

    @pytest.mark.parametrize("malformed_domain", [
        "server\x00.internal.com",
        "corp \t.com",
        "bad\r\ndomain.org",
    ])
    def test_malformed_control_char_domains_fail_closed(self, shield, malformed_domain):
        assert shield.is_shielded(malformed_domain, ObservableType.DOMAIN) is True

    @pytest.mark.parametrize("domain", [
        "google.com",
        "evil-threat-actor.ru",
        "subdomain.legit-site.org",
        "github.com",
        "münchen.de",
    ])
    def test_public_domains_not_shielded(self, shield, domain):
        assert shield.is_shielded(domain, ObservableType.DOMAIN) is False
        assert shield.get_shield_reason(domain, ObservableType.DOMAIN) is None


class TestPrivateNetworkShieldOtherTypes:
    @pytest.mark.parametrize("url", [
        "http://192.168.1.50/admin",
        "https://intranet/dashboard",
        "http://[fe80::1]/test",
        "http://[::1]:8080/",
        "http://10.0.0.1:8080/api",
        "http://admin:secret@10.0.0.1/api",
        "http://10.0.0.1@evil.com/",          # Ambiguous userinfo hiding private host
        "http://localhost\\admin",            # Backslash normalization
        "http://192%2e168%2e1%2e1/",          # Percent-encoded host
        "http://server.local./path",          # Trailing dot in URL
        "http://:8080/",                      # Malformed empty host
    ])
    def test_url_with_private_or_ambiguous_host_shielded(self, shield, url):
        assert shield.is_shielded(url, "url") is True

    @pytest.mark.parametrize("url", [
        "https://evil.com/payload.exe",
        "https://8.8.8.8/dns-query",
        "http://[2606:4700:4700::1111]/",
        "http://user:pass@evil.com/",
    ])
    def test_url_with_public_host_not_shielded(self, shield, url):
        assert shield.is_shielded(url, "url") is False
        assert shield.get_shield_reason(url, "url") is None

    @pytest.mark.parametrize("email", [
        "admin@corp.internal",
        "root@[192.168.1.1]",
        "root@[::1]",
        "operator@localhost",
        "user@ad.corp",
        "malformed-email-no-at",
        "admin@corp\x00.com",
        "@evil.com",
        " @evil.com",
        "user@",
    ])
    def test_email_with_internal_or_malformed_host_shielded(self, shield, email):
        assert shield.is_shielded(email, "email") is True

    @pytest.mark.parametrize("email", [
        "phisher@external-domain.com",
        "attacker@[8.8.8.8]",
        "user@evil.com",
    ])
    def test_email_with_public_domain_not_shielded(self, shield, email):
        assert shield.is_shielded(email, "email") is False
        assert shield.get_shield_reason(email, "email") is None

    def test_email_empty_local_part_regression_fails_closed_never_benign(self, shield):
        """Regression test for TI-3B Phase 1.3 finding: empty local part fails closed."""
        for invalid_email in ["@evil.com", " @evil.com", "user@"]:
            assert shield.is_shielded(invalid_email, "email") is True
            reason = shield.get_shield_reason(invalid_email, "email")
            assert reason is not None
            res = shield.create_shielded_result(invalid_email, "email")
            assert res.verdict == ThreatVerdict.UNKNOWN  # NEVER BENIGN
            assert res.raw_data.get("state") == InvestigationFindingState.SHIELDED_INTERNAL.value

    @pytest.mark.parametrize("obs_type,val", [
        (ObservableType.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (ObservableType.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        (ObservableType.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    ])
    def test_hashes_never_shielded(self, shield, obs_type, val):
        assert shield.is_shielded(val, obs_type) is False
        assert shield.get_shield_reason(val, obs_type) is None


class TestShieldThreatIntelResult:
    def test_shield_result_structure_returns_unknown_never_benign(self, shield):
        """
        Crucial Semantics:
        A shielded observable MUST return verdict=UNKNOWN with state=SHIELDED_INTERNAL.
        Never infer BENIGN from a blocked or shielded lookup.
        """
        reason = shield.get_shield_reason("192.168.1.1", ObservableType.IPV4)
        res = shield.create_shielded_result(
            observable_value="192.168.1.1",
            observable_type=ObservableType.IPV4,
            reason=reason
        )
        assert isinstance(res, ThreatIntelResult)
        assert res.raw_observable == "192.168.1.1"
        assert res.normalized_observable == "192.168.1.1"
        assert res.observable_type == ObservableType.IPV4
        
        # NEVER BENIGN! Must be UNKNOWN
        assert res.verdict == ThreatVerdict.UNKNOWN
        assert res.verdict != ThreatVerdict.BENIGN
        
        assert res.raw_data.get("shielded") is True
        assert res.raw_data.get("shielded_internal") is True
        assert res.raw_data.get("state") == InvestigationFindingState.SHIELDED_INTERNAL.value
        assert "RFC 1918" in res.raw_data.get("reason", "")
        assert "shielded_internal" in res.tags
