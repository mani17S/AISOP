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

from typing import Callable, Sequence
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that injects standard hardened HTTP security headers into all responses."""

    def __init__(self, app, enabled: bool = True, trusted_proxies: Sequence[str] | set[str] | None = None) -> None:
        super().__init__(app)
        self.enabled = enabled
        self.trusted_proxies: set[str] = {"127.0.0.1", "::1"} if trusted_proxies is None else set(trusted_proxies)

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

        # API responses carry case and evidence data: never let a browser or shared proxy cache them.
        if "Cache-Control" not in headers:
            headers["Cache-Control"] = "no-store"

        # HSTS only over real TLS. X-Forwarded-Proto is client-controlled unless it comes from a configured trusted proxy.
        peer = request.client.host if request.client else None
        proto = request.url.scheme
        if peer in self.trusted_proxies:
            proto = request.headers.get("X-Forwarded-Proto", proto)
        if proto == "https":
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

