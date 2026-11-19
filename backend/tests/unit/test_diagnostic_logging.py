"""
Tests for the restricted diagnostic record (Phase 2.4): redaction, non-disclosure, bounds, de-duplication and
failure isolation. No database, no network, no settings file is read.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request
from loguru import logger

import app.core.diagnostics as diagnostics
from app.core.diagnostics import COMPONENT, RECORD_MESSAGE, shape_message
from app.core.errors import CodedHTTPException, StructuredHttpError, install_error_handlers
from app.core.logging import _add_diagnostic_file_sink, _is_diagnostic, _json_line
from app.middleware.correlation import RequestCorrelationMiddleware

pytestmark = pytest.mark.anyio

SECRET_BITS = ["hunter2", "secret_value_123", "SELECT * FROM", "/app/backend/db.py", "10.0.0.5", "ollama", "alice@example.com", "C:\\Users\\x"]
SENSITIVE_MESSAGE = (
    "psycopg OperationalError: SELECT * FROM cases WHERE password=hunter2 token=secret_value_123 "
    "at /app/backend/db.py host 10.0.0.5 ollama user alice@example.com C:\\Users\\x"
)


def make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestCorrelationMiddleware)
    install_error_handlers(app)

    @app.get("/boom")
    async def boom():
        raise RuntimeError(SENSITIVE_MESSAGE)

    @app.get("/from-app-code")
    async def from_app_code():
        shape_message(None)  # type: ignore[arg-type]  # raises inside app code on purpose

    @app.get("/e500")
    async def e500():
        raise HTTPException(500, SENSITIVE_MESSAGE)

    @app.get("/coded500")
    async def coded500():
        raise CodedHTTPException(500, "Authorization service unavailable.", code="AUTHORIZATION_SERVICE_UNAVAILABLE")

    @app.get("/e404")
    async def e404():
        raise HTTPException(404, "Case not found or access denied.")

    @app.get("/ready")
    async def ready():
        raise StructuredHttpError(503, "SERVICE_UNAVAILABLE", "The service is not ready.", {"status": "degraded"})

    @app.get("/badstr")
    async def badstr():
        class Odd(Exception):
            def __str__(self):  # an exception whose text cannot be produced
                raise ValueError("no text")

        raise Odd()

    return app


class Capture:
    """Collects loguru records (message, extra and the rendered JSON line) for the duration of a block."""

    def __init__(self) -> None:
        self.records: list = []
        self.sink_id = None

    def __enter__(self):
        self.sink_id = logger.add(lambda m: self.records.append(m.record), level="DEBUG", format="{message}")
        return self

    def __exit__(self, *exc):
        logger.remove(self.sink_id)

    @property
    def diag(self):
        return [r for r in self.records if r["extra"].get("component") == COMPONENT]

    def rendered(self) -> str:
        return "\n".join(_json_line(r) for r in self.records)


def client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://t")


async def call(path: str, headers: dict | None = None):
    with Capture() as cap:
        async with client(make_app()) as c:
            res = await c.get(path, headers=headers)
    return res, cap


def assert_clean(text: str) -> None:
    for bit in SECRET_BITS:
        assert bit not in text, f"leaked {bit!r}"


# ── Public response boundary ──────────────────────────────────────────────────
@pytest.mark.parametrize("path", ["/boom", "/e500", "/badstr"])
async def test_responses_never_contain_exception_text(path):
    res, _ = await call(path)
    assert res.status_code == 500
    assert_clean(res.text)
    body = res.json()
    assert body["error"]["code"] == "INTERNAL_ERROR"
    assert body["error"]["request_id"] == res.headers["X-Request-ID"]


# ── Diagnostic record content ─────────────────────────────────────────────────
async def test_unhandled_exception_produces_exactly_one_allowlisted_record():
    res, cap = await call("/boom")
    assert len(cap.diag) == 1, "exactly one diagnostic record per failing request"
    rec = cap.diag[0]
    extra = rec["extra"]
    assert rec["message"] == RECORD_MESSAGE
    assert set(extra) == {
        "component", "request_id", "method", "route", "status", "error_code", "exception_class", "origin",
        "message_sha256_12", "message_length",
    }
    assert extra["request_id"] == res.headers["X-Request-ID"]
    assert extra["exception_class"] == "builtins.RuntimeError"
    assert (extra["status"], extra["error_code"], extra["method"], extra["route"]) == (500, "INTERNAL_ERROR", "GET", "/boom")
    assert len(extra["message_sha256_12"]) == 12 and extra["message_length"] == len(SENSITIVE_MESSAGE)
    assert "message_shape" not in extra, "message shape is opt-in and off by default"
    assert rec["exception"] is None, "no traceback is attached to the record"


async def test_origin_is_the_innermost_aisop_frame_without_paths_or_source():
    _, cap = await call("/from-app-code")
    origin = cap.diag[0]["extra"]["origin"]
    assert origin["module"] == "app.core.logging" and origin["function"] == "redact_text" and isinstance(origin["line"], int)
    assert set(origin) == {"module", "function", "line"}
    assert "\\" not in json.dumps(origin) and ".py" not in json.dumps(origin)


async def test_origin_is_an_aisop_frame_or_null_never_a_path():
    # The route here lives in the test module, so the innermost AISOP frame is the correlation middleware that the
    # exception unwinds through; in production it is the raising AISOP function. Either way: module/function/line only.
    _, cap = await call("/boom")
    origin = cap.diag[0]["extra"]["origin"]
    assert origin is None or (origin["module"].startswith("app.") and set(origin) == {"module", "function", "line"})


async def test_http_5xx_and_typed_5xx_are_diagnosed_with_their_codes():
    r1, c1 = await call("/e500")
    r2, c2 = await call("/coded500")
    assert c1.diag[0]["extra"]["exception_class"].endswith("HTTPException") and c1.diag[0]["extra"]["error_code"] == "INTERNAL_ERROR"
    assert c2.diag[0]["extra"]["exception_class"].endswith("CodedHTTPException")
    assert c2.diag[0]["extra"]["error_code"] == "AUTHORIZATION_SERVICE_UNAVAILABLE"
    assert r2.json()["error"]["code"] == "AUTHORIZATION_SERVICE_UNAVAILABLE"


async def test_4xx_and_the_readiness_503_produce_no_diagnostic_record():
    for path in ("/e404", "/ready"):
        _, cap = await call(path)
        assert cap.diag == [], path


# ── Redaction: sensitive text never reaches diagnostic output ─────────────────
@pytest.mark.parametrize("path", ["/boom", "/e500", "/badstr", "/from-app-code"])
async def test_no_sensitive_text_in_any_rendered_log_line(path):
    _, cap = await call(path)
    assert_clean(cap.rendered())


async def test_exception_type_and_request_id_remain_available_and_message_is_fingerprinted():
    res, cap = await call("/boom")
    line = json.loads(_json_line(cap.diag[0]))
    ctx = line["context"]
    assert ctx["exception_class"] == "builtins.RuntimeError" and ctx["request_id"] == res.headers["X-Request-ID"]
    other, cap2 = await call("/boom")
    assert cap2.diag[0]["extra"]["message_sha256_12"] == cap.diag[0]["extra"]["message_sha256_12"], "same error, same fingerprint"


async def test_unprintable_exception_message_does_not_break_logging_or_the_response():
    res, cap = await call("/badstr")
    assert res.status_code == 500 and cap.diag[0]["extra"]["message_sha256_12"] == "unavailable"


# ── Bounded, not duplicated ───────────────────────────────────────────────────
async def test_one_record_even_if_emitted_twice_for_the_same_request():
    app = make_app()

    @app.get("/twice2")
    async def twice2(request: Request):
        try:
            raise RuntimeError("x")
        except RuntimeError as exc:
            diagnostics.emit_diagnostic(request, exc, status=500, code="INTERNAL_ERROR")
            diagnostics.emit_diagnostic(request, exc, status=500, code="INTERNAL_ERROR")
        return {"ok": True}

    with Capture() as cap:
        async with client(app) as c:
            await c.get("/twice2")
    assert len(cap.diag) == 1


async def test_fields_are_bounded_even_for_hostile_class_names_and_huge_messages():
    big = type("X" * 500 + "<script>", (Exception,), {})
    app = FastAPI()
    app.add_middleware(RequestCorrelationMiddleware)
    install_error_handlers(app)

    @app.get("/huge/{item}")
    async def huge(item: str):
        raise big("m" * 2_000_000)

    with Capture() as cap:
        async with client(app) as c:
            await c.get("/huge/abc")
    extra = cap.diag[0]["extra"]
    assert len(extra["exception_class"]) <= diagnostics.MAX_CLASS and "<script>" not in extra["exception_class"].replace("<", "?") or "?" in extra["exception_class"]
    assert extra["route"] == "/huge/{item}", "route TEMPLATE, never the concrete value"
    assert extra["message_length"] <= 1_000_000
    assert len(json.dumps({k: v for k, v in extra.items()})) < 1500


# ── Logging failure isolation ─────────────────────────────────────────────────
async def test_logging_failure_does_not_change_the_api_response(monkeypatch):
    baseline, _ = await call("/boom")

    def explode(*a, **k):
        raise RuntimeError("logger down: " + SENSITIVE_MESSAGE)

    monkeypatch.setattr(diagnostics.logger, "bind", explode)
    res, _ = await call("/boom")
    assert res.status_code == baseline.status_code == 500
    assert res.json()["error"]["code"] == "INTERNAL_ERROR" and res.json()["detail"] == baseline.json()["detail"]
    assert_clean(res.text)


async def test_building_the_record_failing_is_also_isolated(monkeypatch):
    monkeypatch.setattr(diagnostics, "build_record", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad")))
    res, _ = await call("/e500")
    assert res.status_code == 500 and res.json()["error"]["code"] == "INTERNAL_ERROR"


# ── Opt-in message shape ──────────────────────────────────────────────────────
async def test_message_shape_is_added_only_when_enabled_and_masks_variable_content(monkeypatch):
    monkeypatch.setattr(diagnostics, "_shape_enabled", lambda: True)
    res, cap = await call("/boom")
    shape = cap.diag[0]["extra"]["message_shape"]
    for bit in ("hunter2", "secret_value_123", "10.0.0.5", "alice@example.com", "/app/backend/db.py", "C:\\Users\\x"):
        assert bit not in shape, bit
    assert len(shape) <= diagnostics.MAX_SHAPE
    assert_clean(res.text)
    assert "hunter2" not in cap.rendered()


@pytest.mark.parametrize(
    "raw,must_not_contain",
    [
        ("user 'alice' not found for token abcdefghijklmnopqrstuvwx0123456789", ["alice", "abcdefghijkl"]),
        ("cannot reach 192.168.1.20:5432 as bob@corp.example", ["192.168", "bob@corp"]),
        ("file C:\\data\\case_1\\evidence.json and /var/lib/x/y.log", ["case_1", "/var/lib", "evidence.json"]),
        ("id 123e4567-e89b-12d3-a456-426614174000 hash " + "a" * 64, ["123e4567", "a" * 20]),
        ("password=hunter2 Bearer abcdef123456789", ["hunter2", "abcdef123456789"]),
        ("see https://internal.example/x?y=1", ["internal.example"]),
        ("x" * 600, ["xxxxxxxx"]),
    ],
)
def test_shape_message_masks_variable_content(raw, must_not_contain):
    shaped = shape_message(raw)
    assert len(shaped) <= diagnostics.MAX_SHAPE
    for bit in must_not_contain:
        assert bit not in shaped


def test_shape_message_documented_limit_plain_words_survive():
    # Free-text words cannot be proven clean; this is the documented limitation, asserted so it stays visible.
    assert "relation" in shape_message("relation customers does not exist")


# ── Client request id (change 3) stays out of diagnostics ────────────────────
async def test_client_request_id_is_only_a_labelled_log_field_and_never_in_the_diagnostic_record():
    res, cap = await call("/boom", headers={"X-Request-ID": "caller-chosen-id-1"})
    assert "caller-chosen-id-1" not in res.text and res.headers["X-Request-ID"] != "caller-chosen-id-1"
    assert "caller-chosen-id-1" not in json.dumps({k: str(v) for k, v in cap.diag[0]["extra"].items()})


# ── Dedicated restricted file sink ───────────────────────────────────────────
async def test_dedicated_diagnostic_file_receives_only_diagnostic_records_and_general_sink_excludes_them(tmp_path):
    path = tmp_path / "restricted" / "diag.log"
    settings = SimpleNamespace(LOG_ROTATION="10 MB", LOG_RETENTION="30 days")
    general: list = []
    sid = logger.add(lambda m: general.append(m.record), filter=lambda r: not _is_diagnostic(r), level="DEBUG")
    try:
        assert _add_diagnostic_file_sink(str(path), settings, "DEBUG") is True
        async with client(make_app()) as c:
            await c.get("/boom")
            await c.get("/e404")
    finally:
        logger.remove()
    lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(lines) == 1 and lines[0]["context"]["component"] == COMPONENT
    assert_clean(path.read_text(encoding="utf-8"))
    assert all(r["extra"].get("component") != COMPONENT for r in general), "general sink must not receive diagnostics"
    del sid


def test_an_unusable_diagnostic_path_degrades_safely(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    settings = SimpleNamespace(LOG_ROTATION="10 MB", LOG_RETENTION="30 days")
    assert _add_diagnostic_file_sink(str(blocker / "sub" / "diag.log"), settings, "DEBUG") is False
