"""
Attack visibility: the rules and the bounded counter behind the Security page.

This module only decides what counts as suspicious and keeps a small in-memory count. It never sees a credential, a request
body or a header value except a cleaned, truncated user agent. Under a flood it stops adding new keys (and counts what it
dropped) instead of growing, so recording cannot become the denial of service it is meant to reveal.

What it can and cannot show: it records what THIS process observed. It is not a WAF, it does not block anything, and a quiet
page does not prove nothing happened (traffic dropped before it reached the application is never seen).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

KIND_AUTH_FAILED = "auth_failed"
KIND_AUTH_LOCKED_OUT = "auth_locked_out"
KIND_RATE_LIMITED = "rate_limited"
KIND_FORBIDDEN = "forbidden"
KIND_UNKNOWN_PATH = "unknown_path"
KIND_METHOD_NOT_ALLOWED = "method_not_allowed"
KIND_PAYLOAD_TOO_LARGE = "payload_too_large"
KIND_UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
KIND_MALFORMED_REQUEST = "malformed_request"

KINDS: tuple[str, ...] = (
    KIND_AUTH_FAILED,
    KIND_AUTH_LOCKED_OUT,
    KIND_RATE_LIMITED,
    KIND_FORBIDDEN,
    KIND_UNKNOWN_PATH,
    KIND_METHOD_NOT_ALLOWED,
    KIND_PAYLOAD_TOO_LARGE,
    KIND_UNSUPPORTED_MEDIA_TYPE,
    KIND_MALFORMED_REQUEST,
)

#: Set on ``request.state.security_reason`` by code that knows a 429 is an authentication lockout and not ordinary throttling.
REASON_AUTH_LOCKED_OUT = "auth_locked_out"

MAX_KEYS = 5000
MAX_IP = 64
MAX_METHOD = 8
MAX_PATH = 160
MAX_USER_AGENT = 160

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]+")
_UUID_SEGMENT = re.compile(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)")
_NUMBER_SEGMENT = re.compile(r"/\d+(?=/|$)")


def classify(status_code: int, route_matched: bool, reason: str | None = None) -> str | None:
    """Name the kind of suspicious response, or None for ordinary traffic. A missing record on a real route is not a probe."""
    if status_code == 401:
        return KIND_AUTH_FAILED
    if status_code == 403:
        return KIND_FORBIDDEN
    if status_code == 404:
        return None if route_matched else KIND_UNKNOWN_PATH
    if status_code == 405:
        return KIND_METHOD_NOT_ALLOWED
    if status_code == 413:
        return KIND_PAYLOAD_TOO_LARGE
    if status_code == 415:
        return KIND_UNSUPPORTED_MEDIA_TYPE
    if status_code in (400, 422):
        return KIND_MALFORMED_REQUEST
    if status_code == 429:
        return KIND_AUTH_LOCKED_OUT if reason == REASON_AUTH_LOCKED_OUT else KIND_RATE_LIMITED
    return None


def route_path(raw_path: object) -> str:
    """The path of a real route with identifiers replaced, so an id never becomes part of what is stored or grouped."""
    text = clean_text(raw_path, MAX_PATH)
    text = _UUID_SEGMENT.sub("/{id}", text)
    return _NUMBER_SEGMENT.sub("/{n}", text)


def clean_text(value: object, limit: int) -> str:
    """Make attacker-controlled text safe to store and show: no control characters, no line breaks, bounded length."""
    if value is None:
        return ""
    text = _CONTROL.sub(" ", str(value))
    text = re.sub(r" {2,}", " ", text).strip()
    return text[:limit]


@dataclass
class Bucket:
    bucket_minute: datetime
    kind: str
    source_ip: str
    method: str
    path: str
    user_agent: str
    status_code: int
    count: int = 1


class SecurityEventBuffer:
    """Counts suspicious responses per (minute, kind, source, status). Single event loop use; no locking needed."""

    def __init__(self, max_keys: int = MAX_KEYS) -> None:
        self.max_keys = max(1, int(max_keys))
        self._buckets: dict[tuple[datetime, str, str, int, str], Bucket] = {}
        self._dropped = 0
        self.dropped_total = 0

    def record(
        self,
        kind: str,
        source_ip: object,
        method: object,
        path: object,
        status_code: int,
        user_agent: object,
        when: datetime | None = None,
    ) -> None:
        moment = (when or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(second=0, microsecond=0)
        ip = clean_text(source_ip, MAX_IP) or "unknown"
        path_text = clean_text(path, MAX_PATH)
        key = (moment, kind, ip, int(status_code), path_text)
        existing = self._buckets.get(key)
        if existing is not None:
            existing.count += 1
            return
        if len(self._buckets) >= self.max_keys:
            self._dropped += 1
            self.dropped_total += 1
            return
        self._buckets[key] = Bucket(
            bucket_minute=moment,
            kind=kind,
            source_ip=ip,
            method=clean_text(method, MAX_METHOD),
            path=path_text,
            user_agent=clean_text(user_agent, MAX_USER_AGENT),
            status_code=int(status_code),
        )

    def restore(self, buckets: list[Bucket]) -> None:
        """Put drained buckets back after a failed write, merging with what arrived meanwhile and respecting the cap."""
        for b in buckets:
            key = (b.bucket_minute, b.kind, b.source_ip, b.status_code, b.path)
            existing = self._buckets.get(key)
            if existing is not None:
                existing.count += b.count
            elif len(self._buckets) < self.max_keys:
                self._buckets[key] = b
            else:
                self._dropped += b.count
                self.dropped_total += b.count

    def drain(self) -> tuple[list[Bucket], int]:
        """Take everything recorded so far, and how many events were not recorded because the buffer was full."""
        buckets = list(self._buckets.values())
        dropped = self._dropped
        self._buckets = {}
        self._dropped = 0
        return buckets, dropped
