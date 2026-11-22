"""
AISOP request-body size limit (Stage 6 closure, ADR-011).

Pure ASGI middleware: rejects a request to a size-limited path with 413 BEFORE the application parses the body, using
the declared Content-Length and, for chunked or lying clients, a running byte count. It exists because the
source-agnostic import accepts up to 500 records of up to 1 MiB each; without a request-level cap one request could ask
the application to parse about 500 MiB. Only the paths listed in ``LIMITS`` are affected; everything else is untouched.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.core.errors import PAYLOAD_TOO_LARGE, REQUEST_INVALID, build_body

#: (compiled path pattern, maximum body bytes)
LIMITS: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"^/api/v1/cases/[^/]+/evidence/domain/?$"), 8 * 1024 * 1024),
    # Stage 6A: up to MAX_ALERT_BATCH_SIZE (1000) alerts per request; 16 MiB is ~16 KiB per alert, far above real SIEM/EDR alerts.
    (re.compile(r"^/api/v1/alerts/ingest/?$"), 16 * 1024 * 1024),
    # Sysmon/telemetry ingest: schema allows 2000 events x 64 KiB (checked only AFTER the body is parsed). 64 MiB is half that theoretical
    # maximum and orders of magnitude above real batches. Tunable here; a client with a larger batch must split it.
    (re.compile(r"^/api/v1/evidence/ingest/?$"), 64 * 1024 * 1024),
)

#: Second, separate table (API4:2023) for write endpoints whose bodies are small structured JSON but whose schemas have no byte cap of
#: their own (for example a free-text ``query_filter``). Applied by a second BodySizeLimitMiddleware instance in ``create_app``.
SMALL_BODY_LIMITS: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"^/api/v1/cases/?$"), 1024 * 1024),
    (re.compile(r"^/api/v1/cases/[^/]+/?$"), 1024 * 1024),
    (re.compile(r"^/api/v1/cases/[^/]+/(assignments|lead|close|synthesize|investigations/synthesize|reports/synthesize|investigations/multisource(/review)?)/?$"), 1024 * 1024),
    (re.compile(r"^/api/v1/(investigations|reports)/synthesize/?$"), 1024 * 1024),
    # The report formatter carries a full validation result plus its investigation context, the largest JSON body of this group.
    (re.compile(r"^/api/v1/reports/format/?$"), 8 * 1024 * 1024),
)


class _TooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    def __init__(self, app: Any, limits: tuple[tuple[re.Pattern[str], int], ...] = LIMITS) -> None:
        self.app = app
        self.limits = limits

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = next((n for pat, n in self.limits if pat.match(scope.get("path", ""))), None)
        if limit is None:
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > limit:
                    await self._reject(send, 413, scope)
                    return
            except ValueError:
                await self._reject(send, 400, scope)
                return

        seen = 0
        exceeded = False
        started = False
        replaced = False

        async def counting_receive() -> dict:
            nonlocal seen, exceeded
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    exceeded = True  # remembered even if the application swallows or converts the exception
                    raise _TooLarge
            return message

        async def tracking_send(message: dict) -> None:
            # FastAPI turns ANY exception raised while it reads the body into a generic 400. If the limit was exceeded,
            # that response is replaced by the documented 413 so the client is told the truth.
            nonlocal started, replaced
            if exceeded and message["type"] == "http.response.start" and not started:
                started = replaced = True
                await self._reject(send, 413, scope)
                return
            if replaced:
                return  # drop the application's own (400) body
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._reject(send, 413, scope)

    @staticmethod
    async def _reject(send: Any, status: int = 413, scope: Any = None) -> None:
        # Legacy ``detail`` text is preserved; the stable envelope is added (Phase 2.2).
        message = "Request body too large." if status == 413 else "Invalid Content-Length."
        code = PAYLOAD_TOO_LARGE if status == 413 else REQUEST_INVALID
        rid = ((scope or {}).get("state") or {}).get("request_id")
        detail = json.dumps(build_body(code, message, rid if isinstance(rid, str) else None)).encode()
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(detail)).encode())]
        if isinstance(rid, str):
            headers.append((b"x-request-id", rid.encode()))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": detail})


__all__ = ["BodySizeLimitMiddleware", "LIMITS", "SMALL_BODY_LIMITS"]
