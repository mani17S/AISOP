"""
AISOP Security Headers Middleware.

Injects defense-in-depth HTTP security headers into all outgoing responses
to mitigate Clickjacking, MIME-confusion attacks, XSS, and unauthorized framing.

Invariants:
- OWASP Top 10:2025 A02 (Security Misconfiguration) & API8:2023 mitigation.
- Enforces strict Content-Security-Policy (CSP) with frame-ancestors 'none'.
- Enforces X-Content-Type-Options: nosniff.
- Enforces X-Frame-Options: DENY.
- Enforces Strict-Transport-Security (HSTS) on HTTPS connections.
"""

from __future__ import annotations

from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that injects standard hardened HTTP security headers into all responses."""

    def __init__(self, app, enabled: bool = True) -> None:
        super().__init__(app)
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response: Response = await call_next(request)

        if not self.enabled:
            return response

        headers = response.headers
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        headers["X-XSS-Protection"] = "0"
        headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"

        # Defensive CSP for API responses
        if "Content-Security-Policy" not in headers:
            headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "frame-ancestors 'none'; "
                "object-src 'none'; "
                "base-uri 'self';"
            )

        # HSTS on HTTPS / TLS or forwarded HTTPS
        proto = request.headers.get("X-Forwarded-Proto", request.url.scheme)
        if proto == "https":
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

