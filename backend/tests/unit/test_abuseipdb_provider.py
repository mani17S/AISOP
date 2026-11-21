"""AbuseIPDB adapter tests. No network and no real key: every request goes through httpx.MockTransport."""

import asyncio

import httpx
import pytest

from app.modules.threatintel.abuseipdb.provider import AbuseIPDBProvider
from app.modules.threatintel.models import ThreatIntelLookupStatus, ThreatIntelRequest, ThreatVerdict


def _provider(handler, key="test-key"):
    return AbuseIPDBProvider(key, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def _run(coro):
    return asyncio.run(coro)


def _ok(score):
    return lambda req: httpx.Response(200, json={"data": {"abuseConfidenceScore": score, "totalReports": 12, "countryCode": "NL"}})


@pytest.mark.parametrize("score,verdict", [(90, ThreatVerdict.MALICIOUS), (75, ThreatVerdict.MALICIOUS), (40, ThreatVerdict.SUSPICIOUS), (0, ThreatVerdict.UNKNOWN)])
def test_score_maps_to_verdict_and_zero_is_never_benign(score, verdict):
    res = _run(_provider(_ok(score)).lookup(ThreatIntelRequest(observable="203.0.113.9")))
    assert res.status == ThreatIntelLookupStatus.SUCCESS
    assert res.verdict == verdict
    assert res.verdict != ThreatVerdict.BENIGN


def test_key_is_sent_as_header_not_in_url():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["key"] = req.headers.get("Key")
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 1}})

    _run(_provider(handler, key="secret-123").lookup(ThreatIntelRequest(observable="203.0.113.9")))
    assert seen["key"] == "secret-123"
    assert "secret-123" not in seen["url"]


def test_missing_key_makes_no_request():
    called = []
    res = _run(_provider(lambda r: called.append(r) or httpx.Response(200), key="").lookup(ThreatIntelRequest(observable="203.0.113.9")))
    assert res.status == ThreatIntelLookupStatus.MISSING_CREDENTIALS
    assert called == []


@pytest.mark.parametrize(
    "code,status",
    [(429, ThreatIntelLookupStatus.RATE_LIMITED), (401, ThreatIntelLookupStatus.MISSING_CREDENTIALS), (500, ThreatIntelLookupStatus.PROVIDER_FAILURE)],
)
def test_http_failures_never_yield_a_verdict(code, status):
    res = _run(_provider(lambda r: httpx.Response(code)).lookup(ThreatIntelRequest(observable="203.0.113.9")))
    assert res.status == status
    assert res.verdict == ThreatVerdict.UNKNOWN


def test_non_ip_is_unsupported_and_unreadable_body_is_a_failure():
    res = _run(_provider(_ok(10)).lookup(ThreatIntelRequest(observable="example.com")))
    assert res.status == ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE
    bad = _run(_provider(lambda r: httpx.Response(200, json={"unexpected": 1})).lookup(ThreatIntelRequest(observable="203.0.113.9")))
    assert bad.status == ThreatIntelLookupStatus.PROVIDER_FAILURE
