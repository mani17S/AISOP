"""
Notification channel for the platform security alerts (pilot prerequisite: "no notification channel").

What it does: takes the alerts that ``services.security_alert_service.derive_alerts`` already produces for the Security page (one definition of an alert, so the
page and the channel cannot disagree) and sends the ones at or above a minimum severity to (1) the application log, always, and (2) one operator-configured
webhook, only if the operator configured one with a signing secret. It adds no detection of its own.

Design limits, stated:
* OFF for the network by default. With no webhook URL nothing leaves the process. A URL without a signing secret of at least 16 characters is refused (fail
  closed: never send unsigned alerts). The URL must be https, or http only to a loopback host; a URL with embedded credentials is refused; redirects are not
  followed.
* The message carries only what the server composed from cleaned values (rule, severity, title, subject address or username, counts, times, the recommended
  action). It never carries an API key, a request body, a header value or a path.
* Each alert is notified once, and again only if new activity arrives (its last_seen advances) after the cooldown, so a persistent attacker cannot turn the
  channel into a flood. One message carries at most MAX_ALERTS_PER_MESSAGE alerts.
* A failure to deliver (timeout, error status) is logged by type and never raised, and there is no retry: a persistent problem is visible in the log and alerting
  cannot break the server.
* It reports what THIS process observed. It does not block anything and a quiet channel does not prove nothing happened. State is in memory: after a restart
  alerts still inside the one-hour window are notified again, which errs toward telling the operator.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from loguru import logger

COOLDOWN_SECONDS = 1800
MAX_ALERTS_PER_MESSAGE = 20
MIN_SECRET_LENGTH = 16
TIMEOUT_SECONDS = 5.0
SEVERITIES = ("medium", "high", "critical")
SCHEMA = "aisop.security_alerts.v1"
_FIELDS = ("id", "rule", "severity", "title", "subject", "count", "first_seen", "last_seen", "recommended_action")


def _parse(iso: str) -> datetime:
    return datetime.fromisoformat(str(iso).replace("Z", "+00:00"))


class AlertDeduper:
    """Notify an alert once; again only when its last_seen has advanced AND the cooldown has passed since the last notification."""

    def __init__(self, cooldown_seconds: int = COOLDOWN_SECONDS, max_keys: int = 2000) -> None:
        self.cooldown = cooldown_seconds
        self.max_keys = max_keys
        self._sent: dict[str, tuple[datetime, datetime]] = {}  # alert id -> (notified at, last_seen then)

    def filter(self, alerts: list[dict[str, Any]], now: Optional[datetime] = None) -> list[dict[str, Any]]:
        moment = now or datetime.now(timezone.utc)
        kept: list[dict[str, Any]] = []
        for a in alerts:
            alert_id, last_seen = str(a.get("id", "")), _parse(a["last_seen"])
            previous = self._sent.get(alert_id)
            if previous is not None:
                notified_at, seen_then = previous
                if last_seen <= seen_then or (moment - notified_at).total_seconds() < self.cooldown:
                    continue
            if previous is None and len(self._sent) >= self.max_keys:
                self._sent = {k: v for k, v in self._sent.items() if (moment - v[0]).total_seconds() < self.cooldown}
            if previous is not None or len(self._sent) < self.max_keys:
                self._sent[alert_id] = (moment, last_seen)
            kept.append(a)
        return kept


def sign(secret: str, timestamp: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


def verify(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, timestamp, body), signature.removeprefix("sha256="))


def validate_webhook_url(url: str) -> str:
    """The URL if acceptable, else ValueError. https required; http only to a loopback host; no embedded credentials."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise ValueError("webhook URL must be an http(s) URL with a host")
    if parsed.username or parsed.password:
        raise ValueError("webhook URL must not carry credentials")
    if parsed.scheme == "http":
        host = parsed.hostname
        loopback = host == "localhost"
        try:
            loopback = loopback or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if not loopback:
            raise ValueError("http is allowed only to a loopback host; use https")
    return url.strip()


class AlertDispatcher:
    """Log every new alert; POST a signed message to the webhook if (and only if) one is configured and valid."""

    def __init__(self, webhook_url: str = "", secret: str = "", min_severity: str = "medium", *, cooldown_seconds: int = COOLDOWN_SECONDS,
                 transport: Optional[httpx.AsyncBaseTransport] = None, instance: str = "aisop") -> None:
        self.min_rank = SEVERITIES.index(min_severity) if min_severity in SEVERITIES else 0
        self.deduper = AlertDeduper(cooldown_seconds)
        self.instance = "".join(ch for ch in str(instance) if ch.isalnum() or ch in "-_.")[:64] or "aisop"
        self._transport = transport
        self._secret = secret
        self.webhook_url = ""
        if webhook_url.strip():
            if len(secret) < MIN_SECRET_LENGTH:
                logger.warning("Security alert webhook ignored: a signing secret of at least {} characters is required", MIN_SECRET_LENGTH)
            else:
                try:
                    self.webhook_url = validate_webhook_url(webhook_url)
                except ValueError as exc:
                    logger.warning("Security alert webhook ignored: {}", exc)

    @property
    def webhook_enabled(self) -> bool:
        return bool(self.webhook_url)

    async def handle(self, alerts: list[dict[str, Any]], now: Optional[datetime] = None) -> int:
        """Filter, log and deliver. Returns how many alerts were notified. Never raises."""
        try:
            wanted = [a for a in alerts if a.get("severity") in SEVERITIES and SEVERITIES.index(a["severity"]) >= self.min_rank]
            fresh = self.deduper.filter(wanted, now)[:MAX_ALERTS_PER_MESSAGE]
            for a in fresh:
                logger.warning("SECURITY ALERT {} [{}] subject={} count={}: {}", a.get("rule"), a.get("severity"), a.get("subject"), a.get("count"), a.get("title"))
            if fresh and self.webhook_enabled:
                await self._post(fresh, now or datetime.now(timezone.utc))
            return len(fresh)
        except Exception as exc:  # alerting must never break the caller
            logger.warning("Security alert handling failed", error_type=type(exc).__name__)
            return 0

    async def _post(self, alerts: list[dict[str, Any]], sent_at: datetime) -> None:
        payload = {"schema": SCHEMA, "instance": self.instance, "sent_at": sent_at.astimezone(timezone.utc).isoformat(),
                   "alerts": [{k: a.get(k) for k in _FIELDS} for a in alerts]}
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        timestamp = str(int(sent_at.timestamp()))
        headers = {"Content-Type": "application/json", "X-AISOP-Timestamp": timestamp, "X-AISOP-Signature": "sha256=" + sign(self._secret, timestamp, body)}
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=TIMEOUT_SECONDS) as client:  # httpx does not follow redirects by default (guard test)
                response = await client.post(self.webhook_url, content=body, headers=headers)
            if response.status_code >= 300:
                logger.warning("Security alert webhook returned status {}", response.status_code)
        except Exception as exc:
            logger.warning("Security alert webhook delivery failed", error_type=type(exc).__name__)


def dispatcher_from_settings(settings: Any, instance: str = "aisop") -> AlertDispatcher:
    secret = settings.SECURITY_ALERT_WEBHOOK_SECRET.get_secret_value() if settings.SECURITY_ALERT_WEBHOOK_SECRET is not None else ""
    return AlertDispatcher(settings.SECURITY_ALERT_WEBHOOK_URL, secret, settings.SECURITY_ALERT_MIN_SEVERITY, instance=instance)


__all__ = ["AlertDeduper", "AlertDispatcher", "dispatcher_from_settings", "sign", "validate_webhook_url", "verify"]
