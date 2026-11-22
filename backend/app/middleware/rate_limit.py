"""
AISOP Ingress Rate Limiting & Abuse Prevention Middleware (P3-H4).

Provides thread-safe, local-first in-memory Token Bucket rate limiting across
all API endpoints to protect against DoS, brute-force, and resource exhaustion.

Invariants:
- OWASP API Security API4:2023 (Unrestricted Resource Consumption) and
  API6:2023 (Unrestricted Access to Sensitive Flows) mitigation.
- Pure in-memory execution: zero external Redis or cloud dependencies ($0 budget).
- Exempts operational health checks and documentation endpoints.
- Emits RFC 6585 compliant HTTP 429 Too Many Requests with standard Retry-After headers.
- Automatic stale bucket eviction to prevent memory exhaustion attacks.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import threading
import time
from typing import Callable, Sequence

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.errors import RATE_LIMITED, build_body


#: Endpoints that start LLM-capable or correlation-heavy work. They get a tighter per-credential bucket on top of the
#: general one so a single key cannot queue unbounded local-model inference (API4:2023 / API6:2023).
EXPENSIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("POST", re.compile(r"^/api/v1/cases/[^/]+/(investigations/synthesize|synthesize|reports/synthesize|investigations/multisource)/?$")),
    ("GET", re.compile(r"^/api/v1/cases/[^/]+/reports/export/?$")),
)

#: A credentialed client is also charged to an aggregate per-address bucket this many times larger than its own, so
#: rotating invalid or random keys from one address cannot mint unlimited fresh buckets.
IP_AGGREGATE_MULTIPLIER = 4.0


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_client_ip(request: Request, trusted_proxies: Sequence[str] | set[str]) -> str:
    """
    Address of the real client. X-Forwarded-For is only honoured when the socket peer is a configured trusted proxy, and
    is read from the right: each trusted proxy appends the address it saw, so the first entry that is not a trusted proxy
    is the nearest untrusted hop. Entries further left are client-controlled and are ignored (API4/API8 spoofing).
    A malformed entry stops the walk and the socket peer is used.
    """
    peer = request.client.host if request.client and request.client.host else "unknown"
    if peer not in trusted_proxies:
        return peer
    forwarded = request.headers.get("X-Forwarded-For")
    if not forwarded:
        return peer
    for entry in reversed([e.strip() for e in forwarded.split(",")]):
        if not entry:
            continue
        if not _is_ip(entry):
            return peer
        if entry in trusted_proxies:
            continue
        return entry
    return peer


class ClientTokenBucket:
    """Thread-safe single-client token bucket."""

    __slots__ = ("capacity", "refill_rate", "tokens", "last_refill", "last_activity")

    def __init__(self, capacity: float, refill_rate: float, now: float) -> None:
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.last_refill = now
        self.last_activity = now

    def refill(self, now: float) -> None:
        elapsed = now - self.last_refill
        if elapsed > 0:
            added = elapsed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + added)
            self.last_refill = now
        self.last_activity = now

    def try_acquire(self, tokens: float, now: float) -> tuple[bool, float]:
        """
        Attempt to consume tokens.
        Returns: (success, retry_after_seconds)
        """
        self.refill(now)
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True, 0.0
        needed = tokens - self.tokens
        retry_after = needed / self.refill_rate if self.refill_rate > 0 else 60.0
        return False, retry_after


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware enforcing token-bucket ingress rate limiting per client.
    """

    EXEMPT_PATHS: set[str] = {
        "/",
        "/health",
        "/api/v1/health",
        "/api/v1/health/readiness",
        "/api/v1/health/liveness",
        "/docs",
        "/redoc",
        "/api/v1/openapi.json",
    }

    def __init__(
        self,
        app,
        enabled: bool = True,
        requests_per_minute: int = 120,
        burst_capacity: int = 60,
        time_func: Callable[[], float] | None = None,
        max_buckets: int = 10000,
        cleanup_interval_seconds: float = 300.0,
        trusted_proxies: Sequence[str] | set[str] | None = None,
        expensive_requests_per_minute: int = 20,
        expensive_burst_capacity: int = 10,
    ) -> None:
        super().__init__(app)
        self.expensive_capacity = float(max(1, expensive_burst_capacity))
        self.expensive_refill_rate = float(max(1, expensive_requests_per_minute)) / 60.0
        self.enabled = enabled
        self.capacity = float(max(1, burst_capacity))
        self.refill_rate = float(max(1, requests_per_minute)) / 60.0
        self.time_func = time_func or time.time
        self.max_buckets = max_buckets
        self.cleanup_interval = cleanup_interval_seconds
        self._last_cleanup = self.time_func()
        if trusted_proxies is None:
            self.trusted_proxies: set[str] = {"127.0.0.1", "::1"}
        else:
            self.trusted_proxies = set(trusted_proxies)

        self._buckets: dict[str, ClientTokenBucket] = {}
        self._lock = threading.Lock()

    def _resolve_client_identifier(self, request: Request) -> str:
        """
        Derive unique client identifier prioritizing API credentials over IP.
        Tokens and API keys are stored as keyed SHA-256 digests to prevent in-memory
        plaintext secret exposure (AUD-RL-02).
        Forwarded headers (X-Forwarded-For) are only accepted when connecting from
        explicitly verified trusted proxies (AUD-RL-01).
        """
        # 1. Authorization header (Bearer or API key)
        auth_header = request.headers.get("Authorization")
        if auth_header:
            digest = hashlib.sha256(auth_header.strip().encode("utf-8")).hexdigest()[:16]
            return f"auth:{digest}"

        # 2. X-API-Key header
        api_key = request.headers.get("X-API-Key")
        if api_key:
            digest = hashlib.sha256(api_key.strip().encode("utf-8")).hexdigest()[:16]
            return f"key:{digest}"

        # 3. Client IP address (X-Forwarded-For only from verified trusted proxies, read from the right)
        return f"ip:{self._resolve_client_ip(request)}"

    def _resolve_client_ip(self, request: Request) -> str:
        return resolve_client_ip(request, self.trusted_proxies)

    def _is_expensive(self, request: Request) -> bool:
        return any(request.method == m and pat.match(request.url.path) for m, pat in EXPENSIVE_PATTERNS)

    def _acquire(self, bucket_id: str, capacity: float, refill_rate: float, now: float) -> tuple[bool, float, float]:
        """Charge one token to ``bucket_id`` (created on first use). Caller holds the lock. Returns (ok, retry_after, tokens_left)."""
        bucket = self._buckets.get(bucket_id)
        if bucket is None:
            if len(self._buckets) >= self.max_buckets:
                oldest_key = min(self._buckets.keys(), key=lambda k: self._buckets[k].last_activity)
                del self._buckets[oldest_key]
            bucket = ClientTokenBucket(capacity=capacity, refill_rate=refill_rate, now=now)
            self._buckets[bucket_id] = bucket
        ok, retry_after = bucket.try_acquire(1.0, now)
        return ok, retry_after, bucket.tokens

    def _cleanup_stale_buckets(self, now: float) -> None:
        """
        Purge inactive client buckets older than 1 hour, and enforce strict capacity bound
        via LRU eviction if max_buckets is exceeded (AUD-RL-03).
        """
        if now - self._last_cleanup < self.cleanup_interval and len(self._buckets) < self.max_buckets:
            return

        stale_threshold = now - 3600.0
        stale_keys = [
            k for k, bucket in self._buckets.items()
            if bucket.last_activity < stale_threshold
        ]
        for k in stale_keys:
            del self._buckets[k]

        # Enforce hard capacity ceiling with LRU eviction
        if len(self._buckets) >= self.max_buckets:
            sorted_keys = sorted(
                self._buckets.keys(),
                key=lambda k: self._buckets[k].last_activity,
            )
            # Evict at least 10% or excess to ensure headroom
            num_to_evict = max(1, len(self._buckets) - self.max_buckets + int(self.max_buckets * 0.1))
            for k in sorted_keys[:num_to_evict]:
                del self._buckets[k]

        self._last_cleanup = now

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled:
            return await call_next(request)

        path = request.url.path
        if path in self.EXEMPT_PATHS or any(path.startswith(p) for p in ("/docs", "/redoc")):
            return await call_next(request)

        client_id = self._resolve_client_identifier(request)
        now = self.time_func()
        has_credential = not client_id.startswith("ip:")

        with self._lock:
            self._cleanup_stale_buckets(now)

            acquired, retry_after, current_tokens = True, 0.0, 0
            if has_credential:
                # Aggregate per-address bucket first: it is what stops a client rotating random keys to dodge its own bucket.
                ip_id = f"ipk:{self._resolve_client_ip(request)}"
                acquired, retry_after, _ = self._acquire(
                    ip_id, self.capacity * IP_AGGREGATE_MULTIPLIER, self.refill_rate * IP_AGGREGATE_MULTIPLIER, now
                )
            if acquired:
                acquired, retry_after, tokens = self._acquire(client_id, self.capacity, self.refill_rate, now)
                current_tokens = max(0, int(tokens))
            if acquired and self._is_expensive(request):
                acquired, retry_after, _ = self._acquire(f"exp:{client_id}", self.expensive_capacity, self.expensive_refill_rate, now)

        if not acquired:
            retry_sec = math.ceil(retry_after)
            headers = {
                "Retry-After": str(retry_sec),
                "X-RateLimit-Limit": str(int(self.capacity)),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(now + retry_after)),
            }
            # Legacy fields (detail, retry_after_seconds) are preserved; the stable envelope is added (Phase 2.2).
            message = "Rate limit exceeded. Too many requests. Please slow down."
            rid = getattr(request.state, "request_id", None)
            if rid:
                headers["X-Request-ID"] = rid
            return JSONResponse(
                status_code=429,
                content=build_body(
                    RATE_LIMITED,
                    message,
                    rid,
                    error_extra={"retry_after_seconds": retry_sec},
                    top_level_extra={"retry_after_seconds": retry_sec},
                ),
                headers=headers,
            )

        response: Response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(int(self.capacity))
        response.headers["X-RateLimit-Remaining"] = str(current_tokens)
        return response

