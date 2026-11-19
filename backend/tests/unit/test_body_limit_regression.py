"""
Post-implementation verification of the request-body limit (Master Prompt 25). Offline; loopback/ASGI only.

Findings that motivated these tests (observed 2026-11-12, see the verification addendum):
 * FastAPI converts ANY exception raised while it reads the body into a generic 400, so a STREAMED over-limit body was rejected with
   "400 There was an error parsing the body" instead of 413 (memory stayed bounded; the status was wrong). Fixed in the middleware.
 * ``POST /api/v1/evidence/ingest`` (Sysmon ingestion) had no limit at all. Added.
Wire-level proof against uvicorn on loopback (chunked, Content-Length, understated Content-Length) is recorded in the addendum; these tests
cover the same behaviour through the ASGI stack.
"""

from __future__ import annotations

import re

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from app.main import app as real_app
from app.middleware.body_limit import LIMITS, BodySizeLimitMiddleware
from tests.unit.test_multisource_api import MACHINE

MiB = 1024 * 1024


@pytest.fixture
def anyio_backend():
    return "asyncio"


def stream(total_bytes: int, sent: dict, chunk: int = MiB):
    async def gen():
        yield b'{"records":[{"a":"'
        n = 0
        while n < total_bytes:
            yield b"x" * chunk
            n += chunk
            sent["bytes"] = n
        yield b'"}]}'

    return gen()


class Body(BaseModel):
    records: list[dict]


def probe_app() -> FastAPI:
    app = FastAPI()

    @app.post("/api/v1/cases/abc/evidence/domain")
    async def handler(b: Body):
        return {"n": len(b.records)}

    app.add_middleware(BodySizeLimitMiddleware)
    return app


@pytest.mark.anyio
async def test_streamed_oversize_body_is_413_not_fastapis_generic_400_and_reading_stops_near_the_limit():
    sent = {"bytes": 0}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=probe_app()), base_url="http://t") as c:
        ok = await c.post("/api/v1/cases/abc/evidence/domain", content=stream(1 * MiB, {"bytes": 0}), headers={"content-type": "application/json"})
        big = await c.post("/api/v1/cases/abc/evidence/domain", content=stream(40 * MiB, sent), headers={"content-type": "application/json"})
    assert ok.status_code == 200 and ok.json() == {"n": 1}
    assert big.status_code == 413 and big.json()["detail"] == "Request body too large." and big.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert "error parsing the body" not in big.text
    assert sent["bytes"] <= 8 * MiB + 2 * MiB          # the client was cut off near the 8 MiB limit, not after 40 MiB


@pytest.mark.anyio
@pytest.mark.parametrize("path, limit_mib", [
    ("/api/v1/alerts/ingest", 16),
    ("/api/v1/cases/00000000-0000-0000-0000-000000000000/evidence/domain", 8),
    ("/api/v1/evidence/ingest", 64),
])
async def test_every_protected_path_rejects_declared_and_streamed_oversize_with_413_before_authentication(path, limit_mib):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=real_app), base_url="http://t") as c:
        declared = await c.post(path, content=b"x" * ((limit_mib + 1) * MiB), headers={**MACHINE, "content-type": "application/json"})
        streamed = await c.post(path, content=stream((limit_mib + 2) * MiB, {"bytes": 0}), headers={**MACHINE, "content-type": "application/json"})
    for r in (declared, streamed):
        assert r.status_code == 413 and r.json()["detail"] == "Request body too large." and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
        assert r.headers.get("x-content-type-options") == "nosniff"        # the 413 passes through the OUTER security-header middleware


@pytest.mark.anyio
async def test_a_body_just_under_the_limit_is_not_rejected_by_the_middleware():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=real_app), base_url="http://t") as c:
        r = await c.post("/api/v1/alerts/ingest", content=b"x" * (15 * MiB), headers={"content-type": "application/json"})
    assert r.status_code != 413                                            # whatever the app answers (401/422), the limiter let it through


@pytest.mark.anyio
async def test_unlisted_paths_are_not_limited_by_this_middleware():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=real_app), base_url="http://t") as c:
        r = await c.post("/api/v1/cases/00000000-0000-0000-0000-000000000000/evidence", content=b"x" * (9 * MiB), headers={"content-type": "application/json"})
    assert r.status_code != 413


def test_limit_table_and_middleware_position():
    assert [n for _p, n in LIMITS] == [8 * MiB, 16 * MiB, 64 * MiB]
    assert all(isinstance(p, re.Pattern) for p, _n in LIMITS)
    # Starlette keeps user middleware outermost-first: the limiter was added first, so it is the INNERMOST user layer (closest to the
    # router), under correlation, rate-limit, CORS and security headers. Responses it generates therefore pass through all of them.
    assert real_app.user_middleware[-1].cls is BodySizeLimitMiddleware
    assert [m.cls.__name__ for m in real_app.user_middleware][:1] == ["CORSMiddleware"]


@pytest.mark.anyio
async def test_malformed_and_conflicting_content_length_values_fail_closed():
    mw_hits: list[int] = []

    async def inner(scope, receive, send):
        mw_hits.append(1)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = BodySizeLimitMiddleware(inner, ((re.compile(r"^/x$"), 1000),))
    out: list[dict] = []

    async def send(m):
        out.append(m)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    for value in (b"abc", b"1e9", b"", b"1 000"):
        out.clear()
        await mw({"type": "http", "path": "/x", "headers": [(b"content-length", value)]}, receive, send)
        assert out[0]["status"] == 400 and mw_hits == []                   # never reaches the application
    out.clear()
    await mw({"type": "http", "path": "/x", "headers": [(b"content-length", b"-5")]}, receive, send)
    assert mw_hits == [1] and out[0]["status"] == 200                      # negative length is harmless: the byte counter still enforces
