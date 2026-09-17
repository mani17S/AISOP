"""
AISOP Request Correlation & Observability Middleware.

Extracts or generates an X-Request-ID correlation identifier for every HTTP request,
binds it to the request lifecycle, and logs request completion without sensitive payloads.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware

SAFE_REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    """
    Middleware that attaches correlation IDs to requests and logs request execution metrics.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 1. Resolve or generate correlation request_id
        client_req_id = request.headers.get("X-Request-ID")
        if client_req_id and SAFE_REQUEST_ID_REGEX.match(client_req_id):
            request_id = client_req_id
        else:
            request_id = uuid.uuid4().hex

        request.state.request_id = request_id

        # 2. Measure request duration
        start_time = time.perf_counter()
        method = request.method
        path = request.url.path

        # Contextual logger bound with request_id
        req_logger = logger.bind(
            component="http",
            request_id=request_id,
            method=method,
            path=path,
        )

        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            response.headers["X-Request-ID"] = request_id

            # Skip noisy health probe logging at INFO level
            if path in ("/api/v1/health", "/health"):
                req_logger.debug(
                    "Health check processed",
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                )
            else:
                req_logger.info(
                    "HTTP request completed",
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                    client_ip=request.client.host if request.client else "unknown",
                )

            return response
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            req_logger.error(
                "Unhandled error during HTTP request processing",
                error=str(exc),
                duration_ms=duration_ms,
            )
            raise
