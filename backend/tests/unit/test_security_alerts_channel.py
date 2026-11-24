"""Notification channel for platform security alerts (backend/app/core/security_alerts.py)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.core.config import Settings
from app.core.security_alerts import MAX_ALERTS_PER_MESSAGE, AlertDeduper, AlertDispatcher, dispatcher_from_settings, sign, validate_webhook_url, verify
from app.core.security_events import SecurityEventBuffer
from app.services.security_event_service import current_alerts, flush_security_events

SECRET = "s" * 24
URL = "https://hooks.example.test/aisop"
T0 = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)


def _alert(i: int = 1, severity: str = "high", last_seen: datetime = T0, **extra):
    base = {"id": f"id{i:04d}", "rule": "key_guessing", "severity": severity, "title": f"Repeated failed API key attempts from 203.0.113.{i}", "subject": f"203.0.113.{i}",
            "count": 12, "first_seen": (last_seen - timedelta(minutes=2)).isoformat(), "last_seen": last_seen.isoformat(), "recommended_action": "Check the address.",
            "what_happened": "INTERNAL-NARRATIVE", "why_it_matters": "INTERNAL-NARRATIVE"}
    base.update(extra)
    return base


class _Recorder:
    def __init__(self, status: int = 200, raises: Exception | None = None):
        self.requests: list[httpx.Request] = []
        self.status, self.raises = status, raises

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            if self.raises:
                raise self.raises
            return httpx.Response(self.status)
        return httpx.MockTransport(handler)


@pytest.mark.anyio
async def test_without_a_webhook_nothing_leaves_the_process():
    rec = _Recorder()
    d = AlertDispatcher("", "", transport=rec.transport())
    assert not d.webhook_enabled
    assert await d.handle([_alert()], T0) == 1
    assert rec.requests == []


@pytest.mark.anyio
async def test_a_configured_webhook_gets_one_signed_message_with_only_the_whitelisted_fields():
    rec = _Recorder()
    d = AlertDispatcher(URL, SECRET, transport=rec.transport(), instance="aisop pilot/1")
    assert await d.handle([_alert(1), _alert(2, "critical")], T0) == 2
    assert len(rec.requests) == 1
    req = rec.requests[0]
    body = req.content
    assert verify(SECRET, req.headers["X-AISOP-Timestamp"], body, req.headers["X-AISOP-Signature"])
    assert not verify("x" * 24, req.headers["X-AISOP-Timestamp"], body, req.headers["X-AISOP-Signature"])
    assert not verify(SECRET, req.headers["X-AISOP-Timestamp"], body + b" ", req.headers["X-AISOP-Signature"])      # tampering is detected
    payload = json.loads(body)
    assert payload["schema"] == "aisop.security_alerts.v1" and payload["instance"] == "aisoppilot1"      # unsafe characters are dropped from the instance name
    assert len(payload["alerts"]) == 2 and set(payload["alerts"][0]) == {"id", "rule", "severity", "title", "subject", "count", "first_seen", "last_seen", "recommended_action"}
    assert b"INTERNAL-NARRATIVE" not in body


@pytest.mark.anyio
async def test_minimum_severity_filters():
    rec = _Recorder()
    d = AlertDispatcher(URL, SECRET, "high", transport=rec.transport())
    assert await d.handle([_alert(1, "medium"), _alert(2, "high"), _alert(3, "critical"), _alert(4, "informational")], T0) == 2
    assert [a["severity"] for a in json.loads(rec.requests[0].content)["alerts"]] == ["high", "critical"]


@pytest.mark.anyio
async def test_an_alert_is_sent_once_and_again_only_on_new_activity_after_the_cooldown():
    rec = _Recorder()
    d = AlertDispatcher(URL, SECRET, cooldown_seconds=1800, transport=rec.transport())
    assert await d.handle([_alert(1, last_seen=T0)], T0) == 1
    assert await d.handle([_alert(1, last_seen=T0)], T0 + timedelta(hours=1)) == 0                        # same activity, cooldown over: not repeated
    assert await d.handle([_alert(1, last_seen=T0 + timedelta(minutes=5))], T0 + timedelta(minutes=10)) == 0   # new activity but inside the cooldown
    assert await d.handle([_alert(1, last_seen=T0 + timedelta(minutes=40))], T0 + timedelta(minutes=45)) == 1  # new activity after the cooldown
    assert len(rec.requests) == 2


def test_deduper_is_bounded():
    dd = AlertDeduper(cooldown_seconds=3600, max_keys=5)
    kept = dd.filter([_alert(i) for i in range(1, 30)], T0)
    assert len(kept) >= 5 and len(dd._sent) <= 5


@pytest.mark.anyio
async def test_one_message_carries_at_most_the_cap():
    rec = _Recorder()
    d = AlertDispatcher(URL, SECRET, transport=rec.transport())
    await d.handle([_alert(i) for i in range(1, 40)], T0)
    assert len(json.loads(rec.requests[0].content)["alerts"]) == MAX_ALERTS_PER_MESSAGE


@pytest.mark.anyio
@pytest.mark.parametrize("recorder", [_Recorder(status=500), _Recorder(status=302), _Recorder(raises=httpx.ConnectError("boom"))])
async def test_delivery_failures_are_swallowed_and_not_retried(recorder):
    d = AlertDispatcher(URL, SECRET, transport=recorder.transport())
    assert await d.handle([_alert()], T0) == 1          # the alert was still notified to the log; nothing raised
    assert len(recorder.requests) == 1                  # no retry, no redirect followed


@pytest.mark.parametrize("url,ok", [
    ("https://hooks.example.test/x", True), ("http://localhost:9000/x", True), ("http://127.0.0.1:9000/x", True), ("http://[::1]:9000/x", True),
    ("http://hooks.example.test/x", False), ("https://user:pw@hooks.example.test/x", False), ("ftp://hooks.example.test/x", False), ("https:///x", False), ("not a url", False)])
def test_webhook_url_validation(url, ok):
    if ok:
        assert validate_webhook_url(url) == url
    else:
        with pytest.raises(ValueError):
            validate_webhook_url(url)


def test_a_missing_or_short_secret_or_bad_url_disables_the_webhook_instead_of_sending_unsigned():
    assert not AlertDispatcher(URL, "").webhook_enabled
    assert not AlertDispatcher(URL, "short").webhook_enabled
    assert not AlertDispatcher("http://example.com/x", SECRET).webhook_enabled
    assert AlertDispatcher(URL, SECRET).webhook_enabled


def test_defaults_send_nothing():
    d = dispatcher_from_settings(Settings())
    assert not d.webhook_enabled and d.min_rank == 0


def test_signature_depends_on_timestamp_and_body():
    assert sign(SECRET, "1", b"a") != sign(SECRET, "2", b"a") and sign(SECRET, "1", b"a") != sign(SECRET, "1", b"b")


@pytest.mark.anyio
async def test_current_alerts_uses_the_same_derivation_as_the_security_page(db_session):
    buf = SecurityEventBuffer()
    now = datetime.now(timezone.utc)
    for _ in range(12):
        buf.record("auth_failed", "203.0.113.50", "GET", "/api/v1/cases", 401, "curl", now)
    buf.record("unknown_path", "203.0.113.60", "GET", "/.env", 404, "scanner", now)
    await flush_security_events(buf, db_session)
    alerts = await current_alerts(db_session, hours=1, now=now + timedelta(minutes=1))
    assert [a["rule"] for a in alerts] == ["key_guessing"] and alerts[0]["subject"] == "203.0.113.50" and alerts[0]["severity"] == "high"
    rec = _Recorder()
    d = AlertDispatcher(URL, SECRET, transport=rec.transport())
    assert await d.handle(alerts, now) == 1
    sent = json.loads(rec.requests[0].content)["alerts"][0]
    assert sent["rule"] == "key_guessing" and "203.0.113.50" in sent["title"]


@pytest.fixture
def app_instance():
    """The notifier reads only ``app.state``, so a stand-in is enough and keeps these tests independent of the full application."""
    from types import SimpleNamespace

    return SimpleNamespace(state=SimpleNamespace(security_alerts=None))


class _Ctx:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *exc):
        return False


@pytest.mark.anyio
async def test_the_background_notifier_derives_alerts_and_hands_them_to_the_dispatcher(db_session, app_instance, monkeypatch):
    import app.db.session as db_session_module
    import app.main as main_module

    monkeypatch.setattr(db_session_module, "get_session_factory", lambda: (lambda: _Ctx(db_session)))
    buf = SecurityEventBuffer()
    for _ in range(12):
        buf.record("auth_failed", "203.0.113.77", "GET", "/api/v1/cases", 401, "curl")
    await flush_security_events(buf, db_session)
    rec = _Recorder()
    app_instance.state.security_alerts = AlertDispatcher(URL, SECRET, transport=rec.transport())
    await main_module._notify_security_alerts_once(app_instance)
    await main_module._notify_security_alerts_once(app_instance)                      # the same activity is not notified twice
    assert len(rec.requests) == 1
    assert json.loads(rec.requests[0].content)["alerts"][0]["subject"] == "203.0.113.77"


@pytest.mark.anyio
async def test_the_background_notifier_never_raises_into_the_server(app_instance, monkeypatch):
    import app.db.session as db_session_module
    import app.main as main_module

    def broken():
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(db_session_module, "get_session_factory", broken)
    app_instance.state.security_alerts = AlertDispatcher("", "")
    await main_module._notify_security_alerts_once(app_instance)                      # must return normally
    app_instance.state.security_alerts = None
    await main_module._notify_security_alerts_once(app_instance)
