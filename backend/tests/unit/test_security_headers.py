"""
Unit and Integration Tests for AISOP Security Headers Middleware.

Validates:
- Injection of defensive HTTP security headers into all application responses.
- Clickjacking protection via X-Frame-Options: DENY.
- MIME-sniffing prevention via X-Content-Type-Options: nosniff.
- Content-Security-Policy (CSP) headers with frame-ancestors 'none'.
- HTTP Strict Transport Security (HSTS) on HTTPS connections.
- Permissions-Policy and Referrer-Policy defense headers.
- Disabling middleware via configuration flag.
"""

from __future__ import annotations

from fastapi import FastAPI
from starlette.testclient import TestClient

from app.middleware.security_headers import SecurityHeadersMiddleware


class TestSecurityHeadersMiddleware:
    """Tests for SecurityHeadersMiddleware behavior and header injection."""

    def test_standard_security_headers_injected(self) -> None:
        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware, enabled=True)

        @app.get("/test")
        def endpoint():
            return {"message": "hello"}

        client = TestClient(app)
        resp = client.get("/test")

        assert resp.status_code == 200
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert resp.headers["X-XSS-Protection"] == "0"
        assert "geolocation=()" in resp.headers["Permissions-Policy"]
        assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]

    def test_hsts_header_injected_on_https(self) -> None:
        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware, enabled=True)

        @app.get("/secure")
        def endpoint():
            return {"secure": True}

        client = TestClient(app, base_url="https://testserver")
        resp = client.get("/secure", headers={"X-Forwarded-Proto": "https"})

        assert resp.status_code == 200
        assert "Strict-Transport-Security" in resp.headers
        assert "max-age=31536000" in resp.headers["Strict-Transport-Security"]

    def test_hsts_omitted_on_plain_http(self) -> None:
        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware, enabled=True)

        @app.get("/plain")
        def endpoint():
            return {"plain": True}

        client = TestClient(app, base_url="http://testserver")
        resp = client.get("/plain")

        assert resp.status_code == 200
        assert "Strict-Transport-Security" not in resp.headers

    def test_disabled_middleware_omits_headers(self) -> None:
        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware, enabled=False)

        @app.get("/unprotected")
        def endpoint():
            return {"unprotected": True}

        client = TestClient(app)
        resp = client.get("/unprotected")

        assert resp.status_code == 200
        assert "X-Frame-Options" not in resp.headers
        assert "X-Content-Type-Options" not in resp.headers

