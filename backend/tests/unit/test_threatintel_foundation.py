"""
Unit tests for AISOP Threat Intelligence Foundation.

Validates:
- Strict observable validation and normalization (IPv4, IPv6, Domain, MD5, SHA-1, SHA-256).
- Invalid observables (bad IPs, malformed domains, invalid hash lengths, non-hex chars).
- Case and trailing-dot normalization.
- Extraction from CanonicalEvent ExtractedEntityRecord.
- Safety constraint: unsuccessful lookups (failures, rate limits, timeouts, missing credentials,
  unsupported observables) can NEVER be marked BENIGN or MALICIOUS.
- UTC timestamp enforcement on ThreatIntelResult.
- BaseThreatIntelProvider with httpx.MockTransport:
  - Successful lookup
  - 404 Not Found
  - Unsupported observable types
  - Missing credentials
  - HTTP 429 Rate Limiting
  - Network timeouts
  - HTTP 5xx provider failures
  - Malformed JSON responses
  - Client dependency injection and lifecycle management
  - Runtime checkable ThreatIntelProvider protocol compliance
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from app.modules.evidence.entity_extractor import ExtractedEntityRecord
from app.modules.threatintel import (
    BaseThreatIntelProvider,
    InvalidObservableError,
    Observable,
    ObservableType,
    ThreatIntelAuthenticationError,
    ThreatIntelConnectionError,
    ThreatIntelError,
    ThreatIntelLookupStatus,
    ThreatIntelProvider,
    ThreatIntelRateLimitError,
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatIntelTimeoutError,
    ThreatVerdict,
    UnsupportedObservableError,
    detect_observable_type,
    from_extracted_entity,
    normalize_observable,
    validate_domain,
    validate_hash,
    validate_ipv4,
    validate_ipv6,
    validate_md5,
    validate_sha1,
    validate_sha256,
)

# ==============================================================================
# 1. Observable Validation & Normalization Tests
# ==============================================================================


@pytest.mark.parametrize(
    "raw_input,expected_canonical",
    [
        ("192.168.1.1", "192.168.1.1"),
        ("  10.0.0.1  ", "10.0.0.1"),
        ("8.8.8.8", "8.8.8.8"),
        ("172.16.254.1", "172.16.254.1"),
        ("1.1.1.1", "1.1.1.1"),
    ],
)
def test_valid_ipv4_normalization(raw_input: str, expected_canonical: str):
    res = validate_ipv4(raw_input)
    assert res == expected_canonical

    obs = normalize_observable(raw_input, ObservableType.IPV4)
    assert obs.type == ObservableType.IPV4
    assert obs.normalized_value == expected_canonical


@pytest.mark.parametrize(
    "raw_input,expected_canonical",
    [
        ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"),
        ("  ::1  ", "::1"),
        ("[fe80::1]", "fe80::1"),
        ("2001:db8::1", "2001:db8::1"),
    ],
)
def test_valid_ipv6_normalization(raw_input: str, expected_canonical: str):
    res = validate_ipv6(raw_input)
    assert res == expected_canonical

    obs = normalize_observable(raw_input, ObservableType.IPV6)
    assert obs.type == ObservableType.IPV6
    assert obs.normalized_value == expected_canonical


@pytest.mark.parametrize(
    "raw_input,expected_canonical",
    [
        ("example.com", "example.com"),
        ("  EXAMPLE.COM.  ", "example.com"),
        ("MALICIOUS-C2.THREAT-ACTOR.RU.", "malicious-c2.threat-actor.ru"),
        ("sub-domain.internal-api.co.uk", "sub-domain.internal-api.co.uk"),
        ("test.io", "test.io"),
    ],
)
def test_valid_domain_normalization(raw_input: str, expected_canonical: str):
    res = validate_domain(raw_input)
    assert res == expected_canonical

    obs = normalize_observable(raw_input, ObservableType.DOMAIN)
    assert obs.type == ObservableType.DOMAIN
    assert obs.normalized_value == expected_canonical


@pytest.mark.parametrize(
    "raw_input,expected_canonical",
    [
        ("d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e"),
        ("  D41D8CD98F00B204E9800998ECF8427E  ", "d41d8cd98f00b204e9800998ecf8427e"),
    ],
)
def test_valid_md5_normalization(raw_input: str, expected_canonical: str):
    res = validate_md5(raw_input)
    assert res == expected_canonical

    obs = normalize_observable(raw_input, ObservableType.MD5)
    assert obs.type == ObservableType.MD5
    assert obs.normalized_value == expected_canonical


@pytest.mark.parametrize(
    "raw_input,expected_canonical",
    [
        (
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
        (
            "  DA39A3EE5E6B4B0D3255BFEF95601890AFD80709  ",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
    ],
)
def test_valid_sha1_normalization(raw_input: str, expected_canonical: str):
    res = validate_sha1(raw_input)
    assert res == expected_canonical

    obs = normalize_observable(raw_input, ObservableType.SHA1)
    assert obs.type == ObservableType.SHA1
    assert obs.normalized_value == expected_canonical


@pytest.mark.parametrize(
    "raw_input,expected_canonical",
    [
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "  E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855  ",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    ],
)
def test_valid_sha256_normalization(raw_input: str, expected_canonical: str):
    res = validate_sha256(raw_input)
    assert res == expected_canonical

    obs = normalize_observable(raw_input, ObservableType.SHA256)
    assert obs.type == ObservableType.SHA256
    assert obs.normalized_value == expected_canonical


# ==============================================================================
# 2. Invalid Observables Rejection Tests
# ==============================================================================


@pytest.mark.parametrize(
    "bad_ip",
    [
        "999.1.1.1",
        "256.0.0.1",
        "1.2.3",
        "192.168.1",
        "192.168.1.abc",
        "192.168.1.1.1",
        "",
        "not_an_ip",
        "2001:xyz::1",
        "1200::AB00:1234::2552:7777:1313",  # double '::'
    ],
)
def test_invalid_ip_rejection(bad_ip: str):
    with pytest.raises(InvalidObservableError):
        validate_ipv4(bad_ip)

    with pytest.raises(InvalidObservableError):
        normalize_observable(bad_ip, "ip")


@pytest.mark.parametrize(
    "bad_domain",
    [
        "http://evil.com",  # URL scheme
        "https://evil.com/path",  # Path included
        "evil.com:8080",  # Port included
        "evil.com/index.html",  # Path
        "evil.com?id=1",  # Query params
        "-bad.com",  # Leading hyphen
        "bad-.com",  # Trailing hyphen
        "sub.-bad.com",  # Label leading hyphen
        "bad..com",  # Empty label / double dot
        ".example.com",  # Leading dot
        "example.123",  # All-numeric TLD
        "example.c",  # Single-character TLD
        "localhost",  # Single word (no TLD)
        "singleword",  # Single word
        "192.168.1.1",  # IP address is not domain
        "2001:db8::1",  # IPv6 is not domain
        " " * 5,  # Whitespace only
        "a" * 64 + ".com",  # Label exceeds 63 chars
        ("a" * 60 + ".") * 5 + "com",  # Total length exceeds 253 chars
    ],
)
def test_invalid_domain_rejection(bad_domain: str):
    with pytest.raises(InvalidObservableError):
        validate_domain(bad_domain)

    with pytest.raises(InvalidObservableError):
        normalize_observable(bad_domain, ObservableType.DOMAIN)


@pytest.mark.parametrize(
    "bad_hash,algo",
    [
        ("d41d8cd98f00b204e9800998ecf8427", ObservableType.MD5),  # 31 chars
        ("d41d8cd98f00b204e9800998ecf8427ee", ObservableType.MD5),  # 33 chars
        ("d41d8cd98f00b204e9800998ecf8427g", ObservableType.MD5),  # 'g' is non-hex
        ("da39a3ee5e6b4b0d3255bfef95601890afd8070", ObservableType.SHA1),  # 39 chars
        ("da39a3ee5e6b4b0d3255bfef95601890afd807099", ObservableType.SHA1),  # 41 chars
        (
            "da39a3ee5e6b4b0d3255bfef95601890afd8070z",
            ObservableType.SHA1,
        ),  # 'z' is non-hex
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
            ObservableType.SHA256,
        ),  # 63 chars
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555",
            ObservableType.SHA256,
        ),  # 65 chars
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85z",
            ObservableType.SHA256,
        ),  # 'z' is non-hex
        ("imphash123456", ObservableType.MD5),  # Arbitrary imphash
        ("", ObservableType.SHA256),
    ],
)
def test_invalid_hash_rejection(bad_hash: str, algo: ObservableType):
    with pytest.raises(InvalidObservableError):
        validate_hash(
            bad_hash,
            (
                32
                if algo == ObservableType.MD5
                else (40 if algo == ObservableType.SHA1 else 64)
            ),
            algo,
        )

    with pytest.raises(InvalidObservableError):
        normalize_observable(bad_hash, algo)


# ==============================================================================
# 3. Auto-Detection & Entity Extractor Bridge Tests
# ==============================================================================


def test_auto_detect_observable_type():
    assert detect_observable_type("192.168.1.1") == ObservableType.IPV4
    assert detect_observable_type("2001:db8::1") == ObservableType.IPV6
    assert detect_observable_type("evil-c2.com") == ObservableType.DOMAIN
    assert (
        detect_observable_type("d41d8cd98f00b204e9800998ecf8427e") == ObservableType.MD5
    )
    assert (
        detect_observable_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        == ObservableType.SHA1
    )
    assert (
        detect_observable_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        == ObservableType.SHA256
    )

    with pytest.raises(InvalidObservableError):
        detect_observable_type("completely_invalid_garbage_$$$")


def test_from_extracted_entity_bridge():
    # 1. Valid IP entity
    ip_rec = ExtractedEntityRecord(
        entity_type="ip",
        entity_value="10.10.10.10",
        role="destination",
        attributes={"port": 443},
    )
    obs_ip = from_extracted_entity(ip_rec)
    assert obs_ip.type == ObservableType.IPV4
    assert obs_ip.normalized_value == "10.10.10.10"

    # 2. Valid Domain entity
    dom_rec = ExtractedEntityRecord(
        entity_type="domain",
        entity_value="BAD-ACTOR.XYZ.",
        role="queried_domain",
        attributes={},
    )
    obs_dom = from_extracted_entity(dom_rec)
    assert obs_dom.type == ObservableType.DOMAIN
    assert obs_dom.normalized_value == "bad-actor.xyz"

    # 3. Valid File Hash entity with SHA256 algorithm
    sha_rec = ExtractedEntityRecord(
        entity_type="file_hash",
        entity_value="E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        role="file_hash",
        attributes={"algorithm": "SHA256"},
    )
    obs_sha = from_extracted_entity(sha_rec)
    assert obs_sha.type == ObservableType.SHA256
    assert (
        obs_sha.normalized_value
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    # 4. File hash entity with invalid characters is NOT treated as valid IOC
    corrupt_rec = ExtractedEntityRecord(
        entity_type="file_hash",
        entity_value="not_a_hex_hash_at_all!",
        role="file_hash",
        attributes={"algorithm": "MD5"},
    )
    with pytest.raises(InvalidObservableError) as exc_info:
        from_extracted_entity(corrupt_rec)
    assert "Invalid MD5 hash" in str(exc_info.value)

    # 5. Unsupported entity type (e.g. process name or user) rejected
    user_rec = ExtractedEntityRecord(
        entity_type="user",
        entity_value="admin",
        role="actor",
    )
    with pytest.raises(InvalidObservableError) as exc_info:
        from_extracted_entity(user_rec)
    assert "cannot be converted" in str(exc_info.value)


# ==============================================================================
# 4. Result Model & Security Invariant Tests
# ==============================================================================


def test_result_model_utc_timestamp_enforcement():
    # 1. Aware UTC timestamp
    utc_now = datetime.now(timezone.utc)
    res1 = ThreatIntelResult(
        provider_name="test_provider",
        observable_type=ObservableType.IPV4,
        raw_observable="1.1.1.1",
        normalized_observable="1.1.1.1",
        status=ThreatIntelLookupStatus.SUCCESS,
        verdict=ThreatVerdict.BENIGN,
        timestamp=utc_now,
    )
    assert res1.timestamp.tzinfo == timezone.utc

    # 2. Naive datetime automatically converted to UTC
    naive_dt = datetime(2026, 10, 21, 12, 0, 0)
    res2 = ThreatIntelResult(
        provider_name="test_provider",
        observable_type=ObservableType.IPV4,
        raw_observable="1.1.1.1",
        normalized_observable="1.1.1.1",
        status=ThreatIntelLookupStatus.SUCCESS,
        verdict=ThreatVerdict.BENIGN,
        timestamp=naive_dt,
    )
    assert res2.timestamp.tzinfo == timezone.utc
    assert res2.timestamp.hour == 12

    # 3. Non-UTC aware datetime converted to UTC
    plus_five = timezone(timedelta(hours=5))
    offset_dt = datetime(2026, 10, 21, 17, 0, 0, tzinfo=plus_five)
    res3 = ThreatIntelResult(
        provider_name="test_provider",
        observable_type=ObservableType.IPV4,
        raw_observable="1.1.1.1",
        normalized_observable="1.1.1.1",
        status=ThreatIntelLookupStatus.SUCCESS,
        verdict=ThreatVerdict.BENIGN,
        timestamp=offset_dt,
    )
    assert res3.timestamp.tzinfo == timezone.utc
    assert res3.timestamp.hour == 12  # 17:00 +05:00 == 12:00 UTC


@pytest.mark.parametrize(
    "failure_status",
    [
        ThreatIntelLookupStatus.NOT_FOUND,
        ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE,
        ThreatIntelLookupStatus.MISSING_CREDENTIALS,
        ThreatIntelLookupStatus.RATE_LIMITED,
        ThreatIntelLookupStatus.TIMEOUT,
        ThreatIntelLookupStatus.PROVIDER_FAILURE,
    ],
)
@pytest.mark.parametrize(
    "illegal_verdict",
    [
        ThreatVerdict.BENIGN,
        ThreatVerdict.MALICIOUS,
        ThreatVerdict.SUSPICIOUS,
    ],
)
def test_unsuccessful_lookup_cannot_have_benign_or_malicious_verdict(
    failure_status: ThreatIntelLookupStatus,
    illegal_verdict: ThreatVerdict,
):
    """
    CRITICAL SECURITY INVARIANT:
    An unsuccessful lookup or NOT_FOUND status MUST NEVER be assigned BENIGN,
    SUSPICIOUS, or MALICIOUS verdict. Unsuccessful lookups must strictly retain
    verdict UNKNOWN.
    """
    with pytest.raises(ValueError) as exc_info:
        ThreatIntelResult(
            provider_name="test_provider",
            observable_type=ObservableType.IPV4,
            raw_observable="8.8.8.8",
            normalized_observable="8.8.8.8",
            status=failure_status,
            verdict=illegal_verdict,
        )

    assert "cannot have verdict" in str(exc_info.value)
    assert "Unsuccessful lookups must retain verdict 'unknown'" in str(exc_info.value)


def test_result_model_helper_properties():
    # Successful malicious
    res_mal = ThreatIntelResult(
        provider_name="test_provider",
        observable_type=ObservableType.IPV4,
        raw_observable="1.2.3.4",
        normalized_observable="1.2.3.4",
        status=ThreatIntelLookupStatus.SUCCESS,
        verdict=ThreatVerdict.MALICIOUS,
    )
    assert res_mal.is_success is True
    assert res_mal.is_malicious is True
    assert res_mal.is_benign is False
    assert res_mal.is_suspicious is False
    assert res_mal.has_threat_signal is True

    # Failed lookup (e.g. timeout)
    res_timeout = ThreatIntelResult(
        provider_name="test_provider",
        observable_type=ObservableType.IPV4,
        raw_observable="1.2.3.4",
        normalized_observable="1.2.3.4",
        status=ThreatIntelLookupStatus.TIMEOUT,
        verdict=ThreatVerdict.UNKNOWN,
        error_message="Connection timed out",
    )
    assert res_timeout.is_success is False
    assert res_timeout.is_malicious is False
    assert res_timeout.is_benign is False
    assert res_timeout.is_suspicious is False
    assert res_timeout.has_threat_signal is False


# ==============================================================================
# 5. BaseThreatIntelProvider & Async Protocol Tests (Mock Transport)
# ==============================================================================


class SyntheticThreatIntelProvider(BaseThreatIntelProvider):
    """Synthetic concrete provider implementation for contract testing."""

    @property
    def provider_name(self) -> str:
        return "synthetic_intel"

    @property
    def supported_observable_types(self) -> frozenset[ObservableType]:
        return frozenset(
            {ObservableType.IPV4, ObservableType.DOMAIN, ObservableType.SHA256}
        )

    async def _execute_lookup(
        self,
        observable: Observable,
        client: httpx.AsyncClient,
    ) -> ThreatIntelResult:
        response = await client.get(
            f"https://api.synthetic.test/v1/indicators/{observable.normalized_value}"
        )
        response.raise_for_status()
        data = response.json()

        verdict_str = data.get("verdict", "unknown").lower()
        verdict = (
            ThreatVerdict.MALICIOUS
            if verdict_str == "malicious"
            else (
                ThreatVerdict.BENIGN
                if verdict_str == "benign"
                else ThreatVerdict.UNKNOWN
            )
        )

        return ThreatIntelResult(
            provider_name=self.provider_name,
            observable_type=observable.type,
            raw_observable=observable.raw_value,
            normalized_observable=observable.normalized_value,
            status=ThreatIntelLookupStatus.SUCCESS,
            verdict=verdict,
            raw_data=data,
            reputation_score=data.get("score"),
            tags=data.get("tags", []),
        )


def test_provider_protocol_conformance():
    """Verify runtime checkable Protocol implementation."""
    provider = SyntheticThreatIntelProvider(api_key="synthetic-test-key")
    assert isinstance(provider, ThreatIntelProvider)
    assert provider.provider_name == "synthetic_intel"
    assert ObservableType.IPV4 in provider.supported_observable_types


@pytest.mark.anyio
async def test_provider_successful_lookup():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/indicators/198.51.100.1"
        return httpx.Response(
            200,
            json={
                "indicator": "198.51.100.1",
                "verdict": "malicious",
                "score": 95.5,
                "tags": ["c2", "cobalt-strike"],
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = SyntheticThreatIntelProvider(
            api_key="synthetic-test-key",
            client=client,
        )
        req = ThreatIntelRequest(observable=" 198.51.100.1 ")
        result = await provider.lookup(req)

        assert result.status == ThreatIntelLookupStatus.SUCCESS
        assert result.verdict == ThreatVerdict.MALICIOUS
        assert result.observable_type == ObservableType.IPV4
        assert result.normalized_observable == "198.51.100.1"
        assert result.reputation_score == 95.5
        assert "c2" in result.tags
        assert result.is_malicious is True


@pytest.mark.anyio
async def test_provider_not_found_404():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Indicator not found"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = SyntheticThreatIntelProvider(
            api_key="synthetic-test-key",
            client=client,
        )
        req = ThreatIntelRequest(observable="benign-clean.org")
        result = await provider.lookup(req)

        assert result.status == ThreatIntelLookupStatus.NOT_FOUND
        assert result.verdict == ThreatVerdict.UNKNOWN
        assert result.is_success is False
        assert result.is_benign is False
        assert result.is_malicious is False


@pytest.mark.anyio
async def test_provider_unsupported_observable_type():
    # SyntheticThreatIntelProvider does NOT support MD5
    provider = SyntheticThreatIntelProvider(api_key="synthetic-test-key")
    req = ThreatIntelRequest(
        observable="d41d8cd98f00b204e9800998ecf8427e",
        observable_type=ObservableType.MD5,
    )
    result = await provider.lookup(req)

    assert result.status == ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE
    assert result.verdict == ThreatVerdict.UNKNOWN
    assert "does not support observable type 'md5'" in (result.error_message or "")


@pytest.mark.anyio
async def test_provider_missing_credentials():
    # Empty API key
    provider = SyntheticThreatIntelProvider(api_key="")
    assert provider.has_credentials is False

    req = ThreatIntelRequest(observable="198.51.100.1")
    result = await provider.lookup(req)

    assert result.status == ThreatIntelLookupStatus.MISSING_CREDENTIALS
    assert result.verdict == ThreatVerdict.UNKNOWN
    assert "has no API key configured" in (result.error_message or "")


@pytest.mark.anyio
async def test_provider_rate_limited_429():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "Quota exceeded"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = SyntheticThreatIntelProvider(
            api_key="synthetic-test-key",
            client=client,
        )
        req = ThreatIntelRequest(observable="198.51.100.1")
        result = await provider.lookup(req)

        assert result.status == ThreatIntelLookupStatus.RATE_LIMITED
        assert result.verdict == ThreatVerdict.UNKNOWN
        assert "rate limit" in (result.error_message or "").lower()


@pytest.mark.anyio
async def test_provider_timeout_handling():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Read timed out during test")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = SyntheticThreatIntelProvider(
            api_key="synthetic-test-key",
            client=client,
        )
        req = ThreatIntelRequest(observable="198.51.100.1")
        result = await provider.lookup(req)

        assert result.status == ThreatIntelLookupStatus.TIMEOUT
        assert result.verdict == ThreatVerdict.UNKNOWN
        assert "timed out" in (result.error_message or "").lower()


@pytest.mark.anyio
async def test_provider_http_500_server_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = SyntheticThreatIntelProvider(
            api_key="synthetic-test-key",
            client=client,
        )
        req = ThreatIntelRequest(observable="198.51.100.1")
        result = await provider.lookup(req)

        assert result.status == ThreatIntelLookupStatus.PROVIDER_FAILURE
        assert result.verdict == ThreatVerdict.UNKNOWN
        assert "HTTP 500" in (result.error_message or "")


@pytest.mark.anyio
async def test_provider_malformed_json_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<xml>This is not JSON</xml>")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = SyntheticThreatIntelProvider(
            api_key="synthetic-test-key",
            client=client,
        )
        req = ThreatIntelRequest(observable="198.51.100.1")
        result = await provider.lookup(req)

        assert result.status == ThreatIntelLookupStatus.PROVIDER_FAILURE
        assert result.verdict == ThreatVerdict.UNKNOWN
        assert "malformed JSON" in (result.error_message or "")


@pytest.mark.anyio
async def test_provider_dependency_injected_client_lifecycle():
    # 1. Injected client is NOT closed by provider.aclose()
    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, json={"verdict": "unknown"})
    )
    injected_client = httpx.AsyncClient(transport=transport)

    provider = SyntheticThreatIntelProvider(
        api_key="test-key",
        client=injected_client,
    )
    assert provider._owns_client is False
    await provider.aclose()
    assert injected_client.is_closed is False
    await injected_client.aclose()

    # 2. Owned client IS closed by provider.aclose()
    async with SyntheticThreatIntelProvider(api_key="test-key") as owned_provider:
        owned_client = owned_provider._get_client()
        assert owned_provider._owns_client is True
        assert owned_client.is_closed is False

    assert owned_client.is_closed is True


# ==============================================================================
# 6. Security Gate Regression Tests
# ==============================================================================


@pytest.mark.anyio
@pytest.mark.parametrize("status_code", [401, 403])
async def test_provider_http_401_403_authentication_failure(status_code: int):
    """Verify HTTP 401 and 403 errors map to MISSING_CREDENTIALS with UNKNOWN verdict."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"error": "Unauthorized or forbidden"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = SyntheticThreatIntelProvider(
            api_key="synthetic-test-key",
            client=client,
        )
        req = ThreatIntelRequest(observable="198.51.100.1")
        result = await provider.lookup(req)

        assert result.status == ThreatIntelLookupStatus.MISSING_CREDENTIALS
        assert result.verdict == ThreatVerdict.UNKNOWN
        assert result.is_success is False
        assert result.is_malicious is False
        assert f"HTTP {status_code}" in (result.error_message or "")


@pytest.mark.anyio
async def test_provider_connection_error_handling():
    """Verify transport connection failures map to PROVIDER_FAILURE with UNKNOWN verdict."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Failed to establish a new connection: [Errno 11001] getaddrinfo failed")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = SyntheticThreatIntelProvider(
            api_key="synthetic-test-key",
            client=client,
        )
        req = ThreatIntelRequest(observable="198.51.100.1")
        result = await provider.lookup(req)

        assert result.status == ThreatIntelLookupStatus.PROVIDER_FAILURE
        assert result.verdict == ThreatVerdict.UNKNOWN
        assert result.is_success is False
        assert "communication failure" in (result.error_message or "").lower()


class ExceptionRaisingProvider(BaseThreatIntelProvider):
    """Test provider adapter for testing exception translation."""

    def __init__(self, exc_to_raise: Exception) -> None:
        super().__init__(api_key="test-key")
        self.exc_to_raise = exc_to_raise

    @property
    def provider_name(self) -> str:
        return "raising_provider"

    @property
    def supported_observable_types(self) -> frozenset[ObservableType]:
        return frozenset({ObservableType.IPV4})

    async def _execute_lookup(
        self,
        observable: Observable,
        client: httpx.AsyncClient,
    ) -> ThreatIntelResult:
        raise self.exc_to_raise


@pytest.mark.anyio
@pytest.mark.parametrize(
    "domain_exc,expected_status",
    [
        (
            ThreatIntelAuthenticationError("API key expired"),
            ThreatIntelLookupStatus.MISSING_CREDENTIALS,
        ),
        (
            ThreatIntelRateLimitError("Quota reached for today"),
            ThreatIntelLookupStatus.RATE_LIMITED,
        ),
        (
            ThreatIntelTimeoutError("Gateway timed out"),
            ThreatIntelLookupStatus.TIMEOUT,
        ),
        (
            UnsupportedObservableError("Provider does not support IPv6"),
            ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE,
        ),
        (
            ThreatIntelConnectionError("Endpoint unreachable"),
            ThreatIntelLookupStatus.PROVIDER_FAILURE,
        ),
    ],
)
async def test_provider_domain_exceptions_translation(
    domain_exc: ThreatIntelError,
    expected_status: ThreatIntelLookupStatus,
):
    """Verify domain exceptions are classified into correct ThreatIntelLookupStatus."""
    provider = ExceptionRaisingProvider(domain_exc)
    req = ThreatIntelRequest(observable="198.51.100.1")
    result = await provider.lookup(req)

    assert result.status == expected_status
    assert result.verdict == ThreatVerdict.UNKNOWN
    assert result.is_success is False


@pytest.mark.anyio
@pytest.mark.parametrize(
    "unexpected_exc",
    [
        KeyError("attributes"),
        IndexError("list index out of range"),
        TypeError("'NoneType' object is not subscriptable"),
        ValueError("invalid literal for int()"),
    ],
)
async def test_provider_unexpected_exceptions_contained(unexpected_exc: Exception):
    """Verify unexpected Python exceptions cannot escape lookup() unhandled."""
    provider = ExceptionRaisingProvider(unexpected_exc)
    req = ThreatIntelRequest(observable="198.51.100.1")
    result = await provider.lookup(req)

    assert result.status == ThreatIntelLookupStatus.PROVIDER_FAILURE
    assert result.verdict == ThreatVerdict.UNKNOWN
    assert result.is_success is False
    assert "internal execution failure" in (result.error_message or "")


@pytest.mark.anyio
async def test_provider_malformed_observable_lookup_handling():
    """Verify lookup with malformed observable is safely rejected and preserves type hint."""
    provider = SyntheticThreatIntelProvider(api_key="test-key")

    # 1. No type hint
    req_no_hint = ThreatIntelRequest(observable="malformed!observable!!!")
    res1 = await provider.lookup(req_no_hint)
    assert res1.status == ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE
    assert res1.verdict == ThreatVerdict.UNKNOWN
    assert "Observable validation failed" in (res1.error_message or "")

    # 2. Explicit IPv4 hint with bad IP
    req_ip_hint = ThreatIntelRequest(
        observable="999.1.1.1",
        observable_type=ObservableType.IPV4,
    )
    res2 = await provider.lookup(req_ip_hint)
    assert res2.status == ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE
    assert res2.observable_type == ObservableType.IPV4
    assert res2.verdict == ThreatVerdict.UNKNOWN


@pytest.mark.anyio
async def test_provider_error_message_credential_redaction():
    """Verify sensitive API keys or credentials in error messages are redacted."""
    provider = ExceptionRaisingProvider(
        httpx.RequestError("Failure communicating with api_key=SECRET_TOKEN_XYZ12345")
    )
    req = ThreatIntelRequest(observable="198.51.100.1")
    result = await provider.lookup(req)

    assert result.status == ThreatIntelLookupStatus.PROVIDER_FAILURE
    assert "SECRET_TOKEN_XYZ12345" not in (result.error_message or "")
    assert "[REDACTED]" in (result.error_message or "")


def test_from_extracted_entity_rejects_non_standard_algorithms():
    """Verify extracted entities with explicit non-standard algorithms like imphash are rejected."""
    # imphash is 32 hex chars, but NOT a standard cryptographic file hash
    imphash_rec = ExtractedEntityRecord(
        entity_type="file_hash",
        entity_value="d41d8cd98f00b204e9800998ecf8427e",
        role="file_hash",
        attributes={"algorithm": "imphash"},
    )
    with pytest.raises(InvalidObservableError) as exc_info:
        from_extracted_entity(imphash_rec)
    assert "Unsupported or non-standard file hash algorithm 'imphash'" in str(exc_info.value)

    # sha512 is not in supported IOC algorithms (MD5, SHA1, SHA256)
    sha512_rec = ExtractedEntityRecord(
        entity_type="file_hash",
        entity_value="a" * 128,
        role="file_hash",
        attributes={"algorithm": "SHA512"},
    )
    with pytest.raises(InvalidObservableError) as exc_info:
        from_extracted_entity(sha512_rec)
    assert "Unsupported or non-standard file hash algorithm" in str(exc_info.value)


@pytest.mark.anyio
async def test_provider_request_timeout_override_applied_to_owned_client():
    """Verify request-specific timeout override updates the owned AsyncClient timeout."""
    provider = SyntheticThreatIntelProvider(api_key="test-key", timeout_seconds=15.0)
    # Default client timeout is 15.0
    client = provider._get_client()
    assert client.timeout.read == 15.0

    # Lookup with timeout override updates owned client timeout
    req = ThreatIntelRequest(observable="198.51.100.1", timeout_seconds=3.5)
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"verdict": "unknown"}))
    provider._client = httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(15.0))
    provider._owns_client = True

    await provider.lookup(req)
    assert provider._client.timeout.read == 3.5
    await provider.aclose()
