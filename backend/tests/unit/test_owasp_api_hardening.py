"""
OWASP API Security Top 10 (2023) review: API1 IDOR matrix, API4 resource consumption, API5/API9 inventory,
API8 security misconfiguration. Offline: real FastAPI app, SQLite harness, no network. Synthetic data only.
Each test is a regression guard for a finding recorded in docs/07_Security/OWASP_API_Top10_Review.md.
"""
from __future__ import annotations

import re
import uuid

import httpx
import pytest
from fastapi import FastAPI, Request
from pydantic import ValidationError
from starlette.testclient import TestClient

from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.main import create_app
from app.middleware.body_limit import BodySizeLimitMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from tests.unit.test_multisource_api import (  # noqa: F401  (fixtures and helpers)
    anyio_backend,
    app_instance,
    auth_settings,
    bearer,
    seed_analyst_with_token,
    seed_case_with_lead,
)

LEAK_MARKERS = ("Traceback", "sqlalchemy", "psycopg", "sqlite3", "File \"", "site-packages", "D:\\", "/usr/")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class MockTime:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _tolerant_db(app, db_session) -> None:
    """The synthesis routes open their own session on the shared SQLite connection, which ends the harness transaction; the
    shared session must then tolerate the closing commit (a harness artefact, not application behaviour)."""

    async def override():
        yield db_session
        try:
            await db_session.commit()
        except Exception:
            await db_session.rollback()

    app.dependency_overrides[get_db_session] = override


def _env_app(monkeypatch, **env: str) -> FastAPI:
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    try:
        return create_app()
    finally:
        get_settings.cache_clear()


# ── API1: IDOR matrix (every case-scoped route, three non-assigned roles) ───────────────────────────
EV_ID = str(uuid.uuid4())
CASE_ROUTE_BODIES: dict[tuple[str, str], object] = {
    ("GET", "/api/v1/cases/{case_id}"): None,
    ("PATCH", "/api/v1/cases/{case_id}"): {"title": "idor probe title"},
    ("GET", "/api/v1/cases/{case_id}/activity"): None,
    ("POST", "/api/v1/cases/{case_id}/assignments"): {"analyst_id": str(uuid.uuid4()), "case_role": "viewer"},
    ("POST", "/api/v1/cases/{case_id}/close"): {"status": "closed", "closure_reason": "idor probe closure"},
    ("POST", "/api/v1/cases/{case_id}/evidence"): {"evidence_id": EV_ID},
    ("GET", "/api/v1/cases/{case_id}/evidence"): None,
    ("POST", "/api/v1/cases/{case_id}/evidence/domain"): {"records": []},
    ("POST", "/api/v1/cases/{case_id}/investigations/multisource"): {},
    ("GET", "/api/v1/cases/{case_id}/investigations/multisource/export"): None,
    ("POST", "/api/v1/cases/{case_id}/investigations/multisource/review"): {"decision": "approve", "evidence_fingerprint": "a" * 64},
    ("GET", "/api/v1/cases/{case_id}/investigations/multisource/{section}"): None,
    ("POST", "/api/v1/cases/{case_id}/investigations/synthesize"): {},
    ("POST", "/api/v1/cases/{case_id}/lead"): {"target_analyst_id": str(uuid.uuid4()), "reason": "idor probe"},
    ("GET", "/api/v1/cases/{case_id}/reports/export"): None,
    ("POST", "/api/v1/cases/{case_id}/reports/synthesize"): {},
    ("POST", "/api/v1/cases/{case_id}/synthesize"): {},
}


def _all_routes(app: FastAPI) -> set[tuple[str, str]]:
    """(METHOD, path template) for every operation, taken from the generated schema (the router tree is nested)."""
    return {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops if m.upper() not in ("HEAD", "OPTIONS")}


def _case_scoped_routes(app: FastAPI) -> set[tuple[str, str]]:
    return {(m, p) for m, p in _all_routes(app) if "{case_id}" in p}


def _norm(r: httpx.Response):
    try:
        body = r.json()
    except Exception:
        return (r.status_code, r.text)

    def strip(x):
        if isinstance(x, dict):
            return {k: strip(v) for k, v in x.items() if k != "request_id"}
        if isinstance(x, list):
            return [strip(v) for v in x]
        if isinstance(x, str):
            return UUID_RE.sub("<uuid>", x)
        return x

    return (r.status_code, strip(body))


def test_idor_matrix_covers_every_case_scoped_route():
    """A new /cases/{case_id}/... route must be added to the IDOR matrix (API9 inventory guard)."""
    assert _case_scoped_routes(create_app()) == set(CASE_ROUTE_BODIES)


@pytest.mark.anyio
@pytest.mark.parametrize("role,global_role", [("tier1", "analyst_tier_1"), ("admin", "security_admin"), ("ingest", "ingest")])
async def test_api1_unassigned_and_nonexistent_cases_are_indistinguishable_on_every_route(db_session, app_instance, role, global_role):
    lead_tok, lead = await seed_analyst_with_token(db_session, prefix="idorlead", username="idorlead", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)
    tok, _ = await seed_analyst_with_token(db_session, prefix=f"idor{role}", username=f"idor{role}", global_role=global_role)
    _tolerant_db(app_instance, db_session)
    async with client_for(app_instance) as c:
        for (method, template), body in CASE_ROUTE_BODIES.items():
            path = template.replace("{section}", "status")
            real = await c.request(method, path.format(case_id=case.id), json=body, headers=bearer(tok))
            ghost = await c.request(method, path.format(case_id=uuid.uuid4()), json=body, headers=bearer(tok))
            assert real.status_code == 404, f"{role} {method} {template} -> {real.status_code}"
            assert _norm(real) == _norm(ghost), f"{role} {method} {template}: unassigned differs from nonexistent"
            assert not any(m in real.text for m in LEAK_MARKERS)
        # the lead's own access is unaffected (positive control)
        assert (await c.get(f"/api/v1/cases/{case.id}", headers=bearer(lead_tok))).status_code == 200


@pytest.mark.anyio
async def test_api1_malformed_body_does_not_reveal_whether_the_case_exists(db_session, app_instance):
    lead_tok, lead = await seed_analyst_with_token(db_session, prefix="idorbad", username="idorbad", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)
    out, _ = await seed_analyst_with_token(db_session, prefix="idorbad2", username="idorbad2", global_role="analyst_tier_1")
    _tolerant_db(app_instance, db_session)
    async with client_for(app_instance) as c:
        for method, path in (("POST", "/evidence"), ("PATCH", ""), ("POST", "/close"), ("POST", "/assignments"), ("POST", "/lead")):
            a = await c.request(method, f"/api/v1/cases/{case.id}{path}", json={"zzz": 1}, headers=bearer(out))
            b = await c.request(method, f"/api/v1/cases/{uuid.uuid4()}{path}", json={"zzz": 1}, headers=bearer(out))
            assert _norm(a) == _norm(b), (method, path)


@pytest.mark.anyio
async def test_api1_unscoped_evidence_and_synthesis_routes_are_uniformly_disabled(db_session, app_instance):
    tok, _ = await seed_analyst_with_token(db_session, prefix="unscoped", username="unscoped", global_role="analyst_tier_2")
    async with client_for(app_instance) as c:
        shapes = set()
        for _ in range(3):
            for p in (f"/api/v1/evidence/events/{uuid.uuid4()}", f"/api/v1/evidence/{uuid.uuid4()}", "/api/v1/evidence/by-hash/" + "a" * 64):
                r = await c.get(p, headers=bearer(tok))
                assert r.status_code == 403
                shapes.add(r.json()["error"]["code"])
        assert shapes == {"UNSCOPED_ENDPOINT_DISABLED"}
        for p in ("/api/v1/investigations/synthesize", "/api/v1/reports/synthesize"):
            assert (await c.post(p, json={}, headers=bearer(tok))).status_code in (403, 422)


@pytest.mark.anyio
async def test_api1_alert_lookup_is_uniform_for_nonexistent_ids(db_session, app_instance):
    tok, _ = await seed_analyst_with_token(db_session, prefix="alertid", username="alertid", global_role="analyst_tier_1")
    async with client_for(app_instance) as c:
        a = await c.get(f"/api/v1/alerts/{uuid.uuid4()}", headers=bearer(tok))
        b = await c.get(f"/api/v1/alerts/{uuid.uuid4()}", headers=bearer(tok))
        assert a.status_code == 404 and _norm(a) == _norm(b)


# ── API3: mass assignment on every write body ───────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_api3_extra_fields_are_rejected_on_every_case_write_body(db_session, app_instance):
    tok, lead = await seed_analyst_with_token(db_session, prefix="mass3", username="mass3", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)
    _tolerant_db(app_instance, db_session)
    extras = {"lead_analyst_id": str(uuid.uuid4()), "status": "closed", "role": "security_admin", "id": str(uuid.uuid4()), "is_admin": True}
    async with client_for(app_instance) as c:
        for (method, template), body in CASE_ROUTE_BODIES.items():
            if body is None or "evidence/domain" in template or "multisource" in template:
                continue
            payload = {**body, **extras} if isinstance(body, dict) else body
            r = await c.request(method, template.format(case_id=case.id), json=payload, headers=bearer(tok))
            assert r.status_code == 422, f"{method} {template} accepted unknown fields: {r.status_code}"


# ── API4: resource consumption ──────────────────────────────────────────────────────────────────────
def _rl_app(mock: MockTime, **kw) -> FastAPI:
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, enabled=True, requests_per_minute=60, burst_capacity=5, time_func=mock,
                       trusted_proxies=kw.pop("trusted_proxies", {"testclient", "127.0.0.1"}), **kw)

    @app.get("/api/v1/cases")
    def cases():
        return {"ok": True}

    @app.post("/api/v1/cases/{cid}/synthesize")
    def synth(cid: str):
        return {"ok": True}

    @app.post("/api/v1/cases/{cid}/investigations/multisource")
    def multisource(cid: str):
        return {"ok": True}

    return app


def test_api4_rotating_credentials_cannot_bypass_the_per_client_rate_limit():
    c = TestClient(_rl_app(MockTime()))
    codes = [c.get("/api/v1/cases", headers={"X-API-Key": f"random-{i}"}).status_code for i in range(60)]
    assert 429 in codes, "every invalid key got a fresh bucket: unlimited guessing from one address"
    assert codes.index(429) <= 25


def test_api4_a_valid_client_keeps_its_own_bucket_when_another_key_is_throttled():
    c = TestClient(_rl_app(MockTime()))
    for _ in range(5):
        c.get("/api/v1/cases", headers={"X-API-Key": "key-alpha"})
    assert c.get("/api/v1/cases", headers={"X-API-Key": "key-alpha"}).status_code == 429
    assert c.get("/api/v1/cases", headers={"X-API-Key": "key-beta"}).status_code == 200


def test_api4_forged_leftmost_forwarded_for_entries_do_not_create_new_buckets():
    c = TestClient(_rl_app(MockTime(), trusted_proxies={"testclient", "10.0.0.1"}))
    codes = [c.get("/api/v1/cases", headers={"X-Forwarded-For": f"198.51.100.{i}, 203.0.113.9"}).status_code for i in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429, codes


def test_api4_garbage_forwarded_for_falls_back_to_the_socket_peer():
    c = TestClient(_rl_app(MockTime()))
    codes = [c.get("/api/v1/cases", headers={"X-Forwarded-For": f"not-an-ip-{i}"}).status_code for i in range(6)]
    assert codes[5] == 429, codes


def test_api4_expensive_llm_capable_endpoints_have_a_tighter_per_credential_limit():
    c = TestClient(_rl_app(MockTime(), expensive_requests_per_minute=60, expensive_burst_capacity=3))
    h = {"X-API-Key": "analyst-key"}
    cid = uuid.uuid4()
    assert [c.post(f"/api/v1/cases/{cid}/synthesize", headers=h).status_code for _ in range(3)] == [200, 200, 200]
    # one shared expensive bucket per credential across the LLM-capable routes
    assert c.post(f"/api/v1/cases/{cid}/investigations/multisource", headers=h).status_code == 429
    # ordinary reads on the same key are not affected, and another analyst has an independent bucket
    assert c.get("/api/v1/cases", headers=h).status_code == 200
    assert c.post(f"/api/v1/cases/{cid}/synthesize", headers={"X-API-Key": "other-key"}).status_code == 200


def test_api4_small_json_write_endpoints_have_a_request_body_cap():
    app = create_app()
    client = TestClient(app)
    big = b'{"query_filter":"' + b"A" * (2 * 1024 * 1024) + b'"}'
    r = client.post(f"/api/v1/cases/{uuid.uuid4()}/synthesize", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413, r.status_code
    assert r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
    r = client.post("/api/v1/cases", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413
    # the report formatter legitimately carries a full validation result: it keeps a larger explicit cap
    r = client.post("/api/v1/reports/format", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 401
    # ordinary small request still reaches authentication
    assert client.post("/api/v1/cases", json={"title": "ok"}).status_code == 401


def test_api4_body_cap_counts_streamed_bytes_for_a_lying_or_missing_content_length():
    seen = {}
    inner = FastAPI()

    @inner.post("/api/v1/anything")
    async def anything(request: Request):
        await request.body()
        seen["reached"] = True
        return {}

    app = BodySizeLimitMiddleware(inner, limits=((re.compile(r"^/api/v1/anything$"), 1024),))
    client = TestClient(app)

    def gen():
        for _ in range(8):
            yield b"x" * 512

    r = client.post("/api/v1/anything", content=gen())
    assert r.status_code == 413
    assert "reached" not in seen


@pytest.mark.anyio
async def test_api4_pagination_and_offset_abuse_is_bounded(db_session, app_instance):
    tok, _ = await seed_analyst_with_token(db_session, prefix="pgn", username="pgn", global_role="analyst_tier_2")
    async with client_for(app_instance) as c:
        for path in ("/api/v1/cases", "/api/v1/alerts", "/api/v1/evidence/events", "/api/v1/evidence/entities"):
            for q in ("limit=100000", "limit=0", "limit=-1", "page=0", "page=-5", "limit=abc"):
                assert (await c.get(f"{path}?{q}", headers=bearer(tok))).status_code == 422, (path, q)
            r = await c.get(f"{path}?page=99999999999999999999", headers=bearer(tok))
            assert r.status_code in (200, 422), (path, r.status_code)
            assert not any(m in r.text for m in LEAK_MARKERS)


# ── API5/API9: inventory and function-level guard ───────────────────────────────────────────────────
PUBLIC = {("GET", "/"), ("GET", "/api/v1/health"), ("GET", "/api/v1/health/ready")}


def test_api9_every_registered_route_requires_authentication_except_the_public_probes():
    app = create_app()
    client = TestClient(app)
    seen = 0
    for m, template in sorted(_all_routes(app)):
        if (m, template) in PUBLIC:
            continue
        path = template
        for name in ("case_id", "alert_id", "event_id", "evidence_id"):
            path = path.replace("{" + name + "}", str(uuid.uuid4()))
        path = path.replace("{sha256_hash}", "a" * 64).replace("{section}", "status")
        resp = client.request(m, path, json={} if m in ("POST", "PATCH", "PUT") else None)
        assert resp.status_code == 401, f"{m} {template} reachable without credentials: {resp.status_code}"
        seen += 1
    assert seen >= 30


def test_api9_no_unversioned_or_legacy_route_prefixes_exist():
    paths = {p for _, p in _all_routes(create_app())}
    assert all(p == "/" or p.startswith("/api/v1/") for p in paths), sorted(p for p in paths if not p.startswith("/api/v1/"))


def test_api8_root_does_not_advertise_docs_outside_development(monkeypatch):
    prod = TestClient(_env_app(monkeypatch, ENVIRONMENT="production", API_AUTH_ENABLED="true"))
    assert "docs" not in prod.get("/").json()
    dev = TestClient(_env_app(monkeypatch, ENVIRONMENT="development", API_AUTH_ENABLED="true"))
    assert dev.get("/").json().get("docs") == "/docs"


def test_api8_staging_also_hides_docs_and_schema(monkeypatch):
    client = TestClient(_env_app(monkeypatch, ENVIRONMENT="staging", API_AUTH_ENABLED="true"))
    for p in ("/docs", "/redoc", "/openapi.json", "/api/v1/openapi.json"):
        assert client.get(p).status_code == 404, p


# ── API8: headers, CORS, health detail ──────────────────────────────────────────────────────────────
def test_api8_throttled_429_responses_still_carry_the_security_headers(monkeypatch):
    app = _env_app(monkeypatch, RATE_LIMIT_BURST_CAPACITY="1", RATE_LIMIT_REQUESTS_PER_MINUTE="1", ENVIRONMENT="development")
    client = TestClient(app)
    client.get("/api/v1/cases")
    r = client.get("/api/v1/cases")
    assert r.status_code == 429
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert "frame-ancestors 'none'" in r.headers.get("content-security-policy", "")


def test_api8_api_responses_are_not_cacheable():
    client = TestClient(create_app())
    r = client.get("/api/v1/cases")
    assert r.status_code == 401
    assert "no-store" in r.headers.get("cache-control", "")


def test_api8_hsts_is_only_sent_for_real_tls_not_a_spoofed_forwarded_proto_header():
    def app(**kw):
        a = FastAPI()
        a.add_middleware(SecurityHeadersMiddleware, enabled=True, **kw)

        @a.get("/x")
        def x():
            return {}

        return a

    # direct plain-HTTP client forging X-Forwarded-Proto: not a trusted proxy, so no HSTS
    plain = TestClient(app(trusted_proxies={"10.10.10.10"}), base_url="http://testserver")
    assert "strict-transport-security" not in plain.get("/x", headers={"X-Forwarded-Proto": "https"}).headers
    # the same header from a configured trusted reverse proxy is honoured
    proxied = TestClient(app(trusted_proxies={"testclient"}), base_url="http://testserver")
    assert "max-age=" in proxied.get("/x", headers={"X-Forwarded-Proto": "https"}).headers.get("strict-transport-security", "")
    # genuine TLS to the application itself
    tls = TestClient(app(trusted_proxies={"10.10.10.10"}), base_url="https://testserver")
    assert "max-age=" in tls.get("/x").headers.get("strict-transport-security", "")


def test_api8_cors_methods_are_limited_to_those_the_api_implements(monkeypatch):
    client = TestClient(_env_app(monkeypatch, ENVIRONMENT="development", API_AUTH_ENABLED="true"))
    ok = client.options("/api/v1/cases", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "PATCH"})
    assert ok.status_code == 200
    for method in ("DELETE", "PUT"):
        r = client.options("/api/v1/cases", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": method})
        assert r.status_code == 400, method


def test_api8_wildcard_cors_origin_is_refused_outside_development():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, ENVIRONMENT="production", CORS_ORIGINS=["*"])
    with pytest.raises(ValidationError):
        Settings(_env_file=None, ENVIRONMENT="staging", CORS_ORIGINS=["http://localhost:3000", "*"])
    assert Settings(_env_file=None, ENVIRONMENT="production", CORS_ORIGINS=["https://soc.example.org"]).CORS_ORIGINS == ["https://soc.example.org"]
    assert Settings(_env_file=None, ENVIRONMENT="development", CORS_ORIGINS=["*"]).CORS_ORIGINS == ["*"]


@pytest.mark.anyio
@pytest.mark.parametrize("environment,expect_detail", [("development", True), ("staging", False), ("production", False)])
async def test_api8_unauthenticated_readiness_hides_infrastructure_detail_outside_development(db_session, monkeypatch, environment, expect_detail):
    monkeypatch.setattr("app.api.v1.endpoints.health.get_settings", lambda: Settings(_env_file=None, ENVIRONMENT=environment, LLM_ENABLED=False))
    app = create_app()

    async def override_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_db
    async with client_for(app) as c:
        r = await c.get("/api/v1/health/ready")
    body = r.json()
    assert r.status_code == 200 and body["status"] == "ok"
    text = r.text.lower()
    if expect_detail:
        assert "checks" in body
    else:
        assert "checks" not in body
        for marker in ("pgvector", "sqlite", "postgresql", "dimension", "knowledge_embeddings", "ollama"):
            assert marker not in text, marker


# ── API8: production start-up refusal (default database credentials, wildcard CORS) ─────────────────
def test_api8_production_settings_check_refuses_default_database_credentials():
    from app.core.config import ProductionConfigError, validate_production_settings

    default = Settings(_env_file=None, ENVIRONMENT="production")  # default DATABASE_URL is aisop:aisop
    with pytest.raises(ProductionConfigError):
        validate_production_settings(default)
    for url in ("postgresql+psycopg://postgres:postgres@127.0.0.1:5432/aisop", "postgresql+psycopg://aisop:@127.0.0.1/aisop"):
        with pytest.raises(ProductionConfigError):
            validate_production_settings(Settings(_env_file=None, ENVIRONMENT="production", DATABASE_URL=url))
    strong = Settings(_env_file=None, ENVIRONMENT="production", DATABASE_URL="postgresql+psycopg://aisop_app:" + "x7Qp2mZk9vLr4TnB8wYc" + "@127.0.0.1:5432/aisop")
    validate_production_settings(strong)  # no exception
    validate_production_settings(Settings(_env_file=None, ENVIRONMENT="development"))  # development keeps the demo credentials


def test_api8_production_settings_check_error_never_contains_the_password():
    from app.core.config import ProductionConfigError, validate_production_settings

    s = Settings(_env_file=None, ENVIRONMENT="production", DATABASE_URL="postgresql+psycopg://aisop:aisop@127.0.0.1/aisop")
    with pytest.raises(ProductionConfigError) as exc:
        validate_production_settings(s)
    assert "aisop:aisop" not in str(exc.value)


@pytest.mark.anyio
async def test_api8_application_refuses_to_start_in_production_with_default_database_credentials(monkeypatch):
    from app.core.config import ProductionConfigError

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://aisop:aisop@127.0.0.1:5432/aisop_dev")
    get_settings.cache_clear()
    try:
        app = create_app()
        with pytest.raises(ProductionConfigError):
            async with app.router.lifespan_context(app):
                pass
    finally:
        get_settings.cache_clear()
