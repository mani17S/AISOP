"""
Security events middleware: counts suspicious responses (see app/core/security_events.py).

Pure ASGI, placed outside the rate limiter and the body size limits so their 429 and 413 answers are seen. It observes the
response status after the fact and can never change a response or raise into one: any failure in recording is swallowed.
"""

from __future__ import annotations

from typing import Sequence

from app.core.security_events import classify, route_path
from app.middleware.rate_limit import resolve_client_ip
from starlette.requests import Request


class SecurityEventsMiddleware:
    def __init__(self, app, trusted_proxies: Sequence[str] | set[str] | None = None) -> None:
        self.app = app
        self.trusted_proxies: set[str] = {"127.0.0.1", "::1"} if trusted_proxies is None else set(trusted_proxies)

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        seen: dict[str, int] = {}

        async def send_wrapper(message) -> None:
            if message.get("type") == "http.response.start":
                seen["status"] = int(message.get("status", 0))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            try:
                self._observe(scope, seen.get("status"))
            except Exception:  # recording must never affect the response
                pass

    def _observe(self, scope, status_code: int | None) -> None:
        if not status_code:
            return
        route = scope.get("route")
        reason = (scope.get("state") or {}).get("security_reason")
        kind = classify(status_code, route is not None, reason)
        if kind is None:
            return
        buffer = getattr(getattr(scope.get("app"), "state", None), "security_events", None)
        if buffer is None:
            return
        request = Request(scope)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        # A real route keeps its own path with identifiers replaced; an unknown path is kept as sent (that is the evidence).
        path = route_path(scope.get("path", "")) if route is not None else scope.get("path", "")
        buffer.record(
            kind,
            resolve_client_ip(request, self.trusted_proxies),
            scope.get("method", ""),
            path,
            status_code,
            headers.get("user-agent"),
        )
