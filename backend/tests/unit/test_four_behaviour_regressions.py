"""
Regression protection for the four owner-approved behaviour changes (Phase 2.4). Each test is named for its change.
If one of these fails, a behaviour the owner approved has changed: do not "fix" the test without owner approval.

 1. 422 validation: new wording, submitted values never echoed, `loc` flattened to the field name.
 2. Unhandled exceptions: JSON envelope with the trusted request id (not plain text).
 3. Client X-Request-ID: not echoed or trusted; retained only as `client_request_id` in the request log.
 4. Internal logs: exception type only by default; the diagnostic record is separate and never carries the message.
"""

from __future__ import annotations

import json
import re
import uuid

import httpx
import pytest
from fastapi import FastAPI
from loguru import logger
from pydantic import BaseModel, Field, field_validator

from app.core.errors import install_error_handlers
from app.core.logging import _json_line
from app.middleware.correlation import RequestCorrelationMiddleware

pytestmark = pytest.mark.anyio

LEAK = "Sup3r-S3cret-Value-XYZ"


class Inner(BaseModel):
    name: str = Field(min_length=3)


class Body(BaseModel):
    title: str = Field(min_length=3)
    owner: uuid.UUID
    inner: Inner
    digest: str

    @field_validator("digest")
    @classmethod
    def _d(cls, v: str) -> str:
        raise ValueError(f"digest must be hex, got {v!r}")


def app_under_test() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestCorrelationMiddleware)
    install_error_handlers(app)

    @app.post("/items")
    async def items(body: Body):  # pragma: no cover
        return {"ok": True}

    @app.get("/boom")
    async def boom():
        raise RuntimeError(f"db password={LEAK} host 10.1.2.3")

    @app.get("/ok")
    async def ok():
        return {"ok": True}

    return app


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app_under_test(), raise_app_exceptions=False), base_url="http://t")


class Logs:
    def __enter__(self):
        self.records = []
        self.sid = logger.add(lambda m: self.records.append(m.record), level="DEBUG", format="{message}")
        return self

    def __exit__(self, *a):
        logger.remove(self.sid)

    def text(self) -> str:
        return "\n".join(_json_line(r) for r in self.records)


# ── Change 1: 422 ─────────────────────────────────────────────────────────────
async def test_change1_422_never_echoes_submitted_values_and_flattens_loc():
    payload = {"title": "ab", "owner": f"not-a-uuid-{LEAK}", "inner": {"name": f"x{LEAK}"[:2]}, "digest": f"reflect-{LEAK}"}
    async with client() as c:
        res = await c.post("/items", json=payload)
    assert res.status_code == 422
    assert LEAK not in res.text and '"input"' not in res.text and '"ctx"' not in res.text and '"url"' not in res.text
    body = res.json()
    assert body["error"]["code"] == "VALIDATION_FAILED"
    fields = {d["field"] for d in body["error"]["details"]}
    assert {"title", "owner", "inner.name", "digest"} <= fields, "safe field location is retained"
    for item in body["detail"]:
        assert set(item) == {"loc", "msg", "type"}
        assert len(item["loc"]) <= 1 and "body" not in item["loc"], "loc is flattened to the field name"
        assert re.fullmatch(r"[A-Za-z0-9_.?-]*", item["loc"][0] if item["loc"] else "")
    msgs = {d["field"]: d["message"] for d in body["error"]["details"]}
    assert msgs["title"] == "Value is too short." and msgs["owner"] == "Value must be a valid UUID."


async def test_change1_wording_is_the_approved_static_table_not_pydantics_text():
    async with client() as c:
        res = await c.post("/items", json={})
    assert {d["message"] for d in res.json()["error"]["details"]} == {"Field is required."}
    assert "Field required" not in res.text


# ── Change 2: unhandled 500 ───────────────────────────────────────────────────
async def test_change2_unhandled_500_is_a_json_envelope_with_the_trusted_request_id():
    async with client() as c:
        res = await c.get("/boom")
    assert res.status_code == 500
    assert res.headers["content-type"].startswith("application/json"), "not plain text"
    body = res.json()
    assert body["detail"] == body["error"]["message"] == "The server could not complete the request."
    assert body["error"]["code"] == "INTERNAL_ERROR"
    assert re.fullmatch(r"[0-9a-f]{32}", body["error"]["request_id"])
    assert res.headers["X-Request-ID"] == body["error"]["request_id"]
    assert LEAK not in res.text and "10.1.2.3" not in res.text


# ── Change 3: client X-Request-ID ─────────────────────────────────────────────
async def test_change3_client_request_id_is_not_echoed_or_trusted():
    async with client() as c:
        ok = await c.get("/ok", headers={"X-Request-ID": "caller-id-0001"})
        err = await c.get("/boom", headers={"X-Request-ID": "caller-id-0002"})
    for res, mine in ((ok, "caller-id-0001"), (err, "caller-id-0002")):
        assert res.headers["X-Request-ID"] != mine and mine not in res.text
        assert re.fullmatch(r"[0-9a-f]{32}", res.headers["X-Request-ID"])
    assert err.json()["error"]["request_id"] == err.headers["X-Request-ID"]


async def test_change3_a_wellformed_client_id_is_logged_only_as_client_request_id():
    with Logs() as logs:
        async with client() as c:
            res = await c.get("/ok", headers={"X-Request-ID": "caller-id-0003"})
    completed = [r for r in logs.records if r["message"] == "HTTP request completed"]
    assert completed and completed[0]["extra"]["client_request_id"] == "caller-id-0003"
    assert completed[0]["extra"]["request_id"] == res.headers["X-Request-ID"] != "caller-id-0003"


async def test_change3_malformed_client_ids_are_dropped_entirely():
    with Logs() as logs:
        async with client() as c:
            await c.get("/ok", headers={"X-Request-ID": "bad id with spaces!"})
            await c.get("/ok", headers={"X-Request-ID": "x" * 80})
    for r in logs.records:
        assert r["extra"].get("client_request_id") in (None,), "hostile values must never be logged"
    assert "bad id with spaces" not in logs.text() and "x" * 80 not in logs.text()


# ── Change 4: internal logs ───────────────────────────────────────────────────
async def test_change4_logs_carry_exception_type_but_never_the_message():
    with Logs() as logs:
        async with client() as c:
            res = await c.get("/boom")
    text = logs.text()
    assert LEAK not in text and "10.1.2.3" not in text and "password=" not in text
    assert "RuntimeError" in text, "exception type remains the baseline"
    assert res.headers["X-Request-ID"] in text, "request id remains available"
    middleware = [r for r in logs.records if r["message"].startswith("Unhandled error during HTTP request processing")]
    assert middleware and middleware[0]["extra"]["error_type"] == "RuntimeError" and "error" not in middleware[0]["extra"]


async def test_change4_diagnostic_record_is_separate_and_message_free_by_default():
    with Logs() as logs:
        async with client() as c:
            await c.get("/boom")
    diag = [r for r in logs.records if r["extra"].get("component") == "diagnostic"]
    assert len(diag) == 1
    assert "message_shape" not in diag[0]["extra"] and diag[0]["exception"] is None
    assert json.loads(_json_line(diag[0]))["context"]["message_length"] > 0
