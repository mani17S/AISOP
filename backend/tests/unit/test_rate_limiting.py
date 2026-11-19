"""
Unit and Integration Tests for AISOP Ingress Rate Limiting Middleware (P3-H4).

Validates:
- Token bucket consumption and mathematical refill invariants.
- Enforcing HTTP 429 Too Many Requests upon token exhaustion.
- Presence of RFC 6585 Retry-After and X-RateLimit headers.
- Client discrimination by Authorization header, X-API-Key, and IP address.
- Path exemptions for health probes and API documentation.
- Automatic recovery after cooldown.
- Stale client bucket cleanup and memory bound safety.
"""

from __future__ import annotations

import time
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import pytest
from starlette.testclient import TestClient

from app.middleware.rate_limit import ClientTokenBucket, RateLimitMiddleware


class MockTime:
    """Controllable clock for deterministic rate limit testing."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestClientTokenBucket:
    """Direct unit tests for ClientTokenBucket mathematical invariants."""

    def test_bucket_initialization(self) -> None:
        bucket = ClientTokenBucket(capacity=10.0, refill_rate=1.0, now=100.0)
        assert bucket.capacity == 10.0
        assert bucket.refill_rate == 1.0
        assert bucket.tokens == 10.0
        assert bucket.last_refill == 100.0

    def test_bucket_consumption_and_exhaustion(self) -> None:
        bucket = ClientTokenBucket(capacity=5.0, refill_rate=1.0, now=100.0)

        # Consume 3 tokens
        ok, retry_after = bucket.try_acquire(3.0, now=100.0)
        assert ok is True
        assert retry_after == 0.0
        assert bucket.tokens == 2.0

        # Consume 2 tokens (reaches 0)
        ok, retry_after = bucket.try_acquire(2.0, now=100.0)
        assert ok is True
        assert bucket.tokens == 0.0

        # Attempt to consume 1 token (exhausted)
        ok, retry_after = bucket.try_acquire(1.0, now=100.0)
        assert ok is False
        assert retry_after == 1.0  # Needs 1 token at 1.0 token/sec

    def test_bucket_refill_over_time(self) -> None:
        bucket = ClientTokenBucket(capacity=10.0, refill_rate=2.0, now=100.0)
        bucket.tokens = 0.0

        # Advance 2.5 seconds -> 2.5 * 2.0 = 5.0 tokens
        bucket.refill(now=102.5)
        assert bucket.tokens == 5.0

        # Advance another 10 seconds -> capped at capacity (10.0)
        bucket.refill(now=112.5)
        assert bucket.tokens == 10.0


class TestRateLimitMiddleware:
    """Integration tests for FastAPI application with RateLimitMiddleware."""

    @pytest.fixture
    def mock_time(self) -> MockTime:
        return MockTime(1000.0)

    @pytest.fixture
    def test_app(self, mock_time: MockTime) -> FastAPI:
        app = FastAPI()
        app.add_middleware(
            RateLimitMiddleware,
            enabled=True,
            requests_per_minute=60,  # 1 token per second
            burst_capacity=5,        # 5 tokens burst
            time_func=mock_time,
            cleanup_interval_seconds=60.0,
            trusted_proxies={"127.0.0.1", "::1", "testclient"},
        )

        @app.get("/api/v1/resource")
        def protected_resource():
            return {"status": "ok"}

        @app.get("/api/v1/health")
        def health_probe():
            return {"status": "healthy"}

        @app.get("/docs")
        def docs_page():
            return {"docs": "swagger"}

        return app

    def test_allows_requests_within_capacity(self, test_app: FastAPI, mock_time: MockTime) -> None:
        client = TestClient(test_app)

        for _ in range(5):
            resp = client.get("/api/v1/resource", headers={"X-Forwarded-For": "192.168.1.50"})
            assert resp.status_code == 200
            assert "X-RateLimit-Limit" in resp.headers
            assert "X-RateLimit-Remaining" in resp.headers

    def test_throttles_excessive_burst_with_429(self, test_app: FastAPI, mock_time: MockTime) -> None:
        client = TestClient(test_app)
        headers = {"X-Forwarded-For": "10.0.0.99"}

        # Exhaust 5 burst tokens
        for _ in range(5):
            resp = client.get("/api/v1/resource", headers=headers)
            assert resp.status_code == 200

        # 6th request must be rejected with HTTP 429
        resp = client.get("/api/v1/resource", headers=headers)
        assert resp.status_code == 429
        data = resp.json()
        assert "Rate limit exceeded" in data["detail"]
        assert data["retry_after_seconds"] >= 1

        # Assert standard rate limit headers
        assert "Retry-After" in resp.headers
        assert resp.headers["X-RateLimit-Remaining"] == "0"
        assert resp.headers["X-RateLimit-Limit"] == "5"
        assert "X-RateLimit-Reset" in resp.headers

    def test_recovers_after_cooldown(self, test_app: FastAPI, mock_time: MockTime) -> None:
        client = TestClient(test_app)
        headers = {"X-Forwarded-For": "10.0.0.100"}

        # Exhaust tokens
        for _ in range(5):
            client.get("/api/v1/resource", headers=headers)
        assert client.get("/api/v1/resource", headers=headers).status_code == 429

        # Advance time by 3 seconds (refills 3 tokens at 1 token/sec)
        mock_time.advance(3.0)

        # Now 3 requests succeed
        for _ in range(3):
            assert client.get("/api/v1/resource", headers=headers).status_code == 200

        # 4th request throttles again
        assert client.get("/api/v1/resource", headers=headers).status_code == 429

    def test_discriminates_clients_by_authorization(self, test_app: FastAPI, mock_time: MockTime) -> None:
        client = TestClient(test_app)

        # Client A exhausts tokens
        for _ in range(5):
            client.get("/api/v1/resource", headers={"Authorization": "Bearer client-a-token"})
        assert client.get("/api/v1/resource", headers={"Authorization": "Bearer client-a-token"}).status_code == 429

        # Client B has separate independent bucket
        resp_b = client.get("/api/v1/resource", headers={"Authorization": "Bearer client-b-token"})
        assert resp_b.status_code == 200

    def test_discriminates_clients_by_api_key(self, test_app: FastAPI, mock_time: MockTime) -> None:
        client = TestClient(test_app)

        # Client Key 1 exhausts tokens
        for _ in range(5):
            client.get("/api/v1/resource", headers={"X-API-Key": "key-alpha"})
        assert client.get("/api/v1/resource", headers={"X-API-Key": "key-alpha"}).status_code == 429

        # Client Key 2 remains unthrottled
        resp_key2 = client.get("/api/v1/resource", headers={"X-API-Key": "key-beta"})
        assert resp_key2.status_code == 200

    def test_exempt_paths_are_never_throttled(self, test_app: FastAPI, mock_time: MockTime) -> None:
        client = TestClient(test_app)
        headers = {"X-Forwarded-For": "172.16.0.5"}

        # Request health probe 50 times in burst
        for _ in range(50):
            resp = client.get("/api/v1/health", headers=headers)
            assert resp.status_code == 200

        # Request docs 20 times in burst
        for _ in range(20):
            resp = client.get("/docs", headers=headers)
            assert resp.status_code == 200

    def test_disabled_middleware_allows_unrestricted_flow(self, mock_time: MockTime) -> None:
        app = FastAPI()
        app.add_middleware(
            RateLimitMiddleware,
            enabled=False,
            burst_capacity=2,
            time_func=mock_time,
        )

        @app.get("/test")
        def route():
            return {"ok": True}

        client = TestClient(app)
        for _ in range(10):
            resp = client.get("/test")
            assert resp.status_code == 200
            assert "X-RateLimit-Limit" not in resp.headers

    def test_stale_bucket_cleanup(self, mock_time: MockTime) -> None:
        middleware = RateLimitMiddleware(
            app=None,
            enabled=True,
            requests_per_minute=60,
            burst_capacity=10,
            time_func=mock_time,
            cleanup_interval_seconds=10.0,
        )

        # Create active and stale buckets
        now = mock_time()
        middleware._buckets["client-recent"] = ClientTokenBucket(10, 1, now)
        middleware._buckets["client-stale"] = ClientTokenBucket(10, 1, now - 4000.0)

        # Trigger cleanup after time advance
        mock_time.advance(15.0)
        middleware._cleanup_stale_buckets(mock_time())

        assert "client-recent" in middleware._buckets
        assert "client-stale" not in middleware._buckets

    def test_untrusted_client_cannot_spoof_x_forwarded_for(self, mock_time: MockTime) -> None:
        """
        Verify AUD-RL-01: An untrusted client attempting to bypass rate limits
        via spoofed X-Forwarded-For headers is keyed by their actual ASGI client IP,
        preventing spoofing attacks.
        """
        app = FastAPI()
        app.add_middleware(
            RateLimitMiddleware,
            enabled=True,
            requests_per_minute=60,
            burst_capacity=3,
            time_func=mock_time,
            trusted_proxies={"10.10.10.10"},  # 'testclient' is NOT in trusted_proxies
        )

        @app.get("/api/v1/protected")
        def protected():
            return {"ok": True}

        client = TestClient(app)
        # Attempt to bypass by rotating X-Forwarded-For IPs
        for i in range(3):
            resp = client.get("/api/v1/protected", headers={"X-Forwarded-For": f"198.51.100.{i}"})
            assert resp.status_code == 200

        # 4th request must be throttled because all requests mapped to actual peer (testclient),
        # not the spoofed X-Forwarded-For header
        resp = client.get("/api/v1/protected", headers={"X-Forwarded-For": "198.51.100.99"})
        assert resp.status_code == 429

    def test_credentials_are_hashed_in_memory(self, mock_time: MockTime) -> None:
        """
        Verify AUD-RL-02: Authorization tokens and API keys are stored as keyed SHA-256
        digests, never in plaintext in memory.
        """
        import hashlib
        from starlette.requests import Request

        middleware = RateLimitMiddleware(
            app=None,
            enabled=True,
            requests_per_minute=60,
            burst_capacity=5,
            time_func=mock_time,
        )

        raw_auth = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.super-secret-token"
        raw_key = "aisop-api-key-ultra-confidential-998877"

        req_auth = Request({
            "type": "http",
            "method": "GET",
            "path": "/api/v1/test",
            "headers": [(b"authorization", raw_auth.encode())],
        })
        req_key = Request({
            "type": "http",
            "method": "GET",
            "path": "/api/v1/test",
            "headers": [(b"x-api-key", raw_key.encode())],
        })

        id_auth = middleware._resolve_client_identifier(req_auth)
        id_key = middleware._resolve_client_identifier(req_key)

        expected_auth_digest = hashlib.sha256(raw_auth.encode("utf-8")).hexdigest()[:16]
        expected_key_digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]

        assert id_auth == f"auth:{expected_auth_digest}"
        assert id_key == f"key:{expected_key_digest}"
        assert raw_auth not in id_auth
        assert raw_key not in id_key

    def test_max_buckets_lru_eviction(self, mock_time: MockTime) -> None:
        """
        Verify AUD-RL-03: When max_buckets is exceeded, older inactive buckets
        are evicted via LRU pruning to prevent memory exhaustion.
        """
        middleware = RateLimitMiddleware(
            app=None,
            enabled=True,
            requests_per_minute=60,
            burst_capacity=5,
            time_func=mock_time,
            max_buckets=3,
            cleanup_interval_seconds=10.0,
        )

        now = mock_time()
        # Add 3 buckets at different timestamps
        middleware._buckets["client-1"] = ClientTokenBucket(5, 1, now=now)
        middleware._buckets["client-2"] = ClientTokenBucket(5, 1, now=now + 1.0)
        middleware._buckets["client-3"] = ClientTokenBucket(5, 1, now=now + 2.0)
        assert len(middleware._buckets) == 3

        # Advance time and add 4th bucket via cleanup
        mock_time.advance(15.0)
        middleware._buckets["client-4"] = ClientTokenBucket(5, 1, now=mock_time())
        middleware._cleanup_stale_buckets(mock_time())

        # Assert max_buckets capacity bound was enforced
        assert len(middleware._buckets) <= 3
        # Oldest bucket (client-1) must have been evicted first
        assert "client-1" not in middleware._buckets

