"""
Unit tests for the stable API error contract (Phase 2.2).

No database or network: small FastAPI apps use the real correlation middleware and the real error handlers.
Covers every mapped category, typed errors, unknown exceptions, request-ID rules, legacy ``detail`` compatibility,
validation details without input reflection, and non-disclosure of sensitive diagnostics.
"""

from __future__ import annotations

import re
import uuid

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.core.errors import (
    CODE_PATTERN,
    CONTEXT_BUDGET_EXCEEDED,
    ApiError,
    StructuredHttpError,
    build_body,
    code_for_status,
    install_error_handlers,
    looks_unsafe,
    safe_exception_text,
    safe_validation_details,
)
from app.middleware.body_limit import BodySizeLimitMiddleware
from app.middleware.correlation import RequestCorrelationMiddleware
from app.middleware.rate_limit import RateLimitMiddleware

pytestmark = pytest.mark.anyio

SENSITIVE = [
    "psycopg", "SELECT", "hunter2", "/app/backend", "Traceback", "10.0.0.5", "ollama", "OperationalError", "secret_value_123",
    "C:\\Users",
]
DIAGNOSTIC = (
    "psycopg.errors.OperationalError: SELECT * FROM cases WHERE password=hunter2 at /app/backend/db.py "
    "host 10.0.0.5 ollama Traceback secret_value_123 C:\\Users\\x"
)


class Payload(BaseModel):
    title: str = Field(min_length=3)
    owner: uuid.UUID
    digest: str

    @field_validator("digest")
    @classmethod
    def _digest(cls, v: str) -> str:
        raise ValueError(f"digest must be 64 hex characters, got {v!r}")


def make_app(with_correlation: bool = True) -> FastAPI:
    app = FastAPI()
    if with_correlation:
        app.add_middleware(RequestCorrelationMiddleware)
    install_error_handlers(app)

    @app.get("/ok")
    async def ok():
        return {"ok": True}

    @app.get("/e400")
    async def e400():
        raise HTTPException(400, "Title is required")

    @app.get("/e401")
    async def e401():
        raise HTTPException(401, "Invalid or expired token.", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})

    @app.get("/e403")
    async def e403():
        raise HTTPException(403, "Insufficient role.")

    @app.get("/e404")
    async def e404():
        raise HTTPException(404, "Case not found.")

    @app.get("/e409")
    async def e409():
        raise HTTPException(409, "Case is already in terminal state 'closed'.")

    @app.get("/e413")
    async def e413():
        raise HTTPException(413, "Too big.")

    @app.get("/e429")
    async def e429():
        raise HTTPException(429, "Slow down.")

    @app.get("/e503")
    async def e503():
        raise HTTPException(503, DIAGNOSTIC)

    @app.get("/e500http")
    async def e500http():
        raise HTTPException(500, DIAGNOSTIC)

    @app.get("/unsafe400")
    async def unsafe400():
        raise HTTPException(400, DIAGNOSTIC)

    @app.get("/dict400")
    async def dict400():
        raise HTTPException(400, {"internal": DIAGNOSTIC})

    @app.get("/typed422")
    async def typed422():
        raise ApiError(422, CONTEXT_BUDGET_EXCEEDED, "Mandatory investigation context exceeds maximum evidence budget.")

    @app.get("/typed500")
    async def typed500():
        raise ApiError(500, "EVIDENCE_PERSISTENCE_FAILED", "The evidence could not be stored; nothing was imported.")

    @app.get("/structured")
    async def structured():
        raise StructuredHttpError(503, "SERVICE_UNAVAILABLE", "The service is not ready.", {"status": "degraded", "checks": {"database": {"status": "unavailable"}}})

    @app.get("/boom")
    async def boom():
        raise RuntimeError(DIAGNOSTIC)

    @app.post("/validate")
    async def validate(body: Payload):  # pragma: no cover - body always fails validation in these tests
        return {"ok": True}

    @app.get("/query")
    async def query(limit: int):
        return {"limit": limit}

    return app


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test")


def assert_contract(response: httpx.Response, status: int, code: str) -> dict:
    assert response.status_code == status
    body = response.json()
    assert set(body) >= {"detail", "error"}
    err = body["error"]
    assert err["code"] == code
    assert CODE_PATTERN.match(err["code"])
    assert isinstance(err["message"], str) and err["message"]
    return body


def assert_no_sensitive(text: str) -> None:
    for needle in SENSITIVE:
        assert needle not in text, f"leaked {needle!r}"


# ── Category mapping ──────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "path,status,code",
    [
        ("/e400", 400, "REQUEST_INVALID"),
        ("/e401", 401, "AUTHENTICATION_REQUIRED"),
        ("/e403", 403, "PERMISSION_DENIED"),
        ("/e404", 404, "RESOURCE_NOT_FOUND"),
        ("/e409", 409, "CONFLICT"),
        ("/e413", 413, "PAYLOAD_TOO_LARGE"),
        ("/e429", 429, "RATE_LIMITED"),
        ("/e503", 503, "SERVICE_UNAVAILABLE"),
        ("/e500http", 500, "INTERNAL_ERROR"),
    ],
)
async def test_status_categories_map_to_stable_codes(path, status, code):
    async with client_for(make_app()) as client:
        res = await client.get(path)
    body = assert_contract(res, status, code)
    assert body["error"]["request_id"] == res.headers["X-Request-ID"]


async def test_safe_developer_message_is_kept_and_legacy_detail_matches():
    async with client_for(make_app()) as client:
        res = await client.get("/e400")
    body = assert_contract(res, 400, "REQUEST_INVALID")
    assert body["error"]["message"] == "Title is required"
    assert body["detail"] == "Title is required"  # legacy consumers keep working


async def test_auth_headers_are_preserved():
    async with client_for(make_app()) as client:
        res = await client.get("/e401")
    assert res.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'
    assert res.json()["detail"] == "Invalid or expired token."


async def test_typed_api_errors_carry_their_code_and_authored_message():
    async with client_for(make_app()) as client:
        a = await client.get("/typed422")
        b = await client.get("/typed500")
    body = assert_contract(a, 422, CONTEXT_BUDGET_EXCEEDED)
    assert body["detail"] == body["error"]["message"]
    body = assert_contract(b, 500, "EVIDENCE_PERSISTENCE_FAILED")
    assert body["error"]["message"] == "The evidence could not be stored; nothing was imported."


# ── Non-disclosure ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("path,status", [("/e503", 503), ("/e500http", 500), ("/unsafe400", 400), ("/dict400", 400), ("/boom", 500)])
async def test_sensitive_diagnostics_never_reach_the_response(path, status):
    async with client_for(make_app()) as client:
        res = await client.get(path)
    assert res.status_code == status
    assert_no_sensitive(res.text)
    assert_no_sensitive(str(dict(res.headers)))
    assert CODE_PATTERN.match(res.json()["error"]["code"])


async def test_unknown_exception_returns_fixed_500_with_request_id():
    async with client_for(make_app()) as client:
        res = await client.get("/boom")
    body = assert_contract(res, 500, "INTERNAL_ERROR")
    assert body["error"]["message"] == "The server could not complete the request."
    assert body["detail"] == body["error"]["message"]
    assert re.fullmatch(r"[0-9a-f]{32}", body["error"]["request_id"])
    assert res.headers["X-Request-ID"] == body["error"]["request_id"]


async def test_unhandled_exception_log_has_type_only():
    from loguru import logger

    captured: list[str] = []
    sink_id = logger.add(lambda m: captured.append(str(m)), level="DEBUG", format="{message} {extra}")
    try:
        async with client_for(make_app()) as client:
            await client.get("/boom")
    finally:
        logger.remove(sink_id)
    logged = " ".join(captured)
    assert "RuntimeError" in logged
    assert_no_sensitive(logged)


# ── Request IDs ───────────────────────────────────────────────────────────────
async def test_client_supplied_request_id_is_not_authoritative():
    async with client_for(make_app()) as client:
        res = await client.get("/e404", headers={"X-Request-ID": "attacker-chosen-id-123"})
    rid = res.json()["error"]["request_id"]
    assert rid != "attacker-chosen-id-123"
    assert res.headers["X-Request-ID"] == rid
    assert "attacker-chosen-id-123" not in res.text


async def test_missing_request_id_omits_the_field_without_failing():
    async with client_for(make_app(with_correlation=False)) as client:
        res = await client.get("/e404")
    body = assert_contract(res, 404, "RESOURCE_NOT_FOUND")
    assert "request_id" not in body["error"]
    assert "X-Request-ID" not in res.headers


# ── Validation (422): details without input reflection ───────────────────────
async def test_validation_errors_use_static_messages_and_never_echo_input():
    submitted = {"title": "ab", "owner": "not-a-uuid-secret_value_123", "digest": "deadbeef-hunter2"}
    async with client_for(make_app()) as client:
        res = await client.post("/validate", json=submitted)
    body = assert_contract(res, 422, "VALIDATION_FAILED")
    details = body["error"]["details"]
    fields = {d["field"] for d in details}
    assert {"title", "owner"} <= fields
    for d in details:
        assert set(d) == {"field", "code", "message"}
    text = res.text
    for value in ("not-a-uuid-secret_value_123", "deadbeef-hunter2", '"input"', '"ctx"'):
        assert value not in text, value
    # legacy list shape preserved for old consumers: loc / msg / type, no input
    assert all(set(item) == {"loc", "msg", "type"} for item in body["detail"])


async def test_value_error_message_reflecting_the_input_is_replaced():
    async with client_for(make_app()) as client:
        res = await client.post("/validate", json={"title": "abc", "owner": str(uuid.uuid4()), "digest": "reflected-value-xyz"})
    digest = [d for d in res.json()["error"]["details"] if d["field"] == "digest"][0]
    assert "reflected-value-xyz" not in res.text
    assert digest["message"] == "Value failed validation."


async def test_query_parameter_validation_is_safe():
    async with client_for(make_app()) as client:
        res = await client.get("/query", params={"limit": "abc-hunter2"})
    body = assert_contract(res, 422, "VALIDATION_FAILED")
    assert "hunter2" not in res.text
    assert body["error"]["details"][0]["field"] == "limit"
    assert body["error"]["details"][0]["message"] == "Value must be an integer."


def test_safe_validation_details_handles_malformed_errors():
    out = safe_validation_details([{"loc": ("body", "a b<script>"), "type": "weird type!", "msg": "x", "input": "secret"}, {}])
    assert out[0] == {"field": "?", "code": "invalid", "message": "Value is invalid."}
    assert out[1]["field"] == ""
    assert "secret" not in str(out)


# ── Helpers ───────────────────────────────────────────────────────────────────
def test_code_mapping_and_unknown_status_defaults():
    assert code_for_status(418) == "REQUEST_INVALID"
    assert code_for_status(502) == "INTERNAL_ERROR"
    assert CODE_PATTERN.match("RATE_LIMITED") and not CODE_PATTERN.match("rate_limited")


def test_looks_unsafe_and_safe_exception_text():
    assert looks_unsafe(DIAGNOSTIC) and looks_unsafe("x" * 300) and looks_unsafe("")
    assert not looks_unsafe("limit must be between 1 and 100")
    assert safe_exception_text(ValueError("limit must be between 1 and 100"), "fallback") == "limit must be between 1 and 100"
    assert safe_exception_text(ValueError(DIAGNOSTIC), "fallback") == "fallback"


def test_build_body_shape():
    body = build_body("X_ERROR", "m", None)
    assert body == {"detail": "m", "error": {"code": "X_ERROR", "message": "m"}}


# ── Middleware paths (rate limit, body size) ─────────────────────────────────
async def test_rate_limit_response_keeps_legacy_fields_and_adds_envelope():
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, enabled=True, requests_per_minute=1, burst_capacity=1, trusted_proxies=[])
    app.add_middleware(RequestCorrelationMiddleware)

    @app.get("/x")
    async def x():
        return {"ok": True}

    async with client_for(app) as client:
        await client.get("/x")
        res = await client.get("/x")
    assert res.status_code == 429
    body = res.json()
    assert body["detail"] == "Rate limit exceeded. Too many requests. Please slow down."
    assert isinstance(body["retry_after_seconds"], int)
    assert body["error"]["code"] == "RATE_LIMITED"
    assert body["error"]["retry_after_seconds"] == body["retry_after_seconds"]
    assert body["error"]["request_id"] == res.headers["X-Request-ID"]
    assert "Retry-After" in res.headers


async def test_body_limit_response_keeps_legacy_detail_and_adds_envelope():
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware, limits=((re.compile(r"^/up$"), 10),))
    app.add_middleware(RequestCorrelationMiddleware)
    install_error_handlers(app)

    @app.post("/up")
    async def up(payload: dict):
        return payload

    async with client_for(app) as client:
        res = await client.post("/up", content=b'{"a": "0123456789012345"}', headers={"Content-Type": "application/json"})
    assert res.status_code == 413
    body = res.json()
    assert body["detail"] == "Request body too large."
    assert body["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert body["error"]["request_id"] == res.headers["x-request-id"]


def test_create_app_installs_the_error_handlers():
    from app.main import create_app

    handlers = create_app().exception_handlers
    assert Exception in handlers
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    assert RequestValidationError in handlers and StarletteHTTPException in handlers


async def test_structured_detail_is_preserved_for_routes_with_a_special_contract():
    async with client_for(make_app()) as client:
        res = await client.get("/structured")
    body = assert_contract(res, 503, "SERVICE_UNAVAILABLE")
    assert body["detail"] == {"status": "degraded", "checks": {"database": {"status": "unavailable"}}}
    assert body["error"]["message"] == "The service is not ready."
    assert body["error"]["request_id"] == res.headers["X-Request-ID"]
