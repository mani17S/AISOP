"""
OWASP-mapped security probe suite (five-day plan, brief 20 section 4). Offline: real FastAPI app, SQLite harness, no network.

Each test is a probe: a failure is a FINDING, recorded with severity in docs/07_Security/Security_Test_Findings.md.
Mapping: API Security Top 10:2023 (API1 BOLA, API2 broken auth, API3 property exposure, API4 resource consumption, API5 BFLA,
API8 misconfiguration), OWASP Top 10 injection / access control / security misconfiguration, OWASP LLM Top 10 (LLM02/LLM05/LLM06).
All data is synthetic. SQLite passing does NOT validate PostgreSQL behaviour (the same probes are rerun against the disposable PostgreSQL).
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import func, select

from app.models.evidence import RawEvidence
from app.modules.ai.llm.exceptions import LLMConfigurationError
from app.modules.ai.llm.locality import assert_endpoint_allowed
from app.modules.threatintel.shield import PrivateNetworkShield
from tests.unit.test_multisource_api import (  # noqa: F401  (fixtures and helpers)
    MACHINE,
    START,
    Keep,
    anyio_backend,
    app_instance,
    auth_settings,
    bearer,
    seed_analyst_with_token,
    seed_case_with_lead,
    setup,
)
from app.modules.correlation.demo_data import intrusion_chain

INGEST = "/api/v1/alerts/ingest"
LEAK_MARKERS = ("Traceback", "sqlalchemy", "psycopg", "sqlite3", "File \"", "site-packages", "D:\\", "/usr/")


def client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def siem(i: int = 1, **over):
    a = {"source_type": "generic_siem", "rule_id": f"R-{i}", "rule_name": f"probe rule {i}", "severity": "high",
         "timestamp": "2026-11-07T09:00:00Z", "host": "probe-host", "user": "probe-user"}
    a.update(over)
    return a


# ── API1 BOLA / IDOR ────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_api1_bola_another_analyst_cannot_reach_a_case_or_its_investigation(db_session, app_instance):
    client, _tok_a, lead, case = await setup(db_session, app_instance, [siem(1)], prefix="bolaA")
    tok_b, _b = await seed_analyst_with_token(db_session, prefix="bolaB", username="bolaB", global_role="analyst_tier_2")
    async with Keep(client):
        cid = case.id
        probes = [
            ("GET", f"/api/v1/cases/{cid}", None), ("GET", f"/api/v1/cases/{cid}/evidence", None),
            ("GET", f"/api/v1/cases/{cid}/activity", None),
            ("POST", f"/api/v1/cases/{cid}/investigations/multisource", {}),
            ("GET", f"/api/v1/cases/{cid}/investigations/multisource/timeline", None),
            ("POST", f"/api/v1/cases/{cid}/evidence", {"evidence_id": str(uuid.uuid4())}),
            ("POST", f"/api/v1/cases/{cid}/evidence/domain", {"records": []}),
            ("GET", f"/api/v1/cases/{cid}/reports/export", None),
        ]
        for method, path, body in probes:
            r = await client.request(method, path, json=body, headers=bearer(tok_b))
            assert r.status_code in (403, 404), f"BOLA: {method} {path} -> {r.status_code}"
            assert not any(m in r.text for m in LEAK_MARKERS)


# ── API5 BFLA / function-level authorization ────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_api5_bfla_roles_cannot_call_functions_outside_their_role(db_session, app_instance):
    tok_t1, _ = await seed_analyst_with_token(db_session, prefix="bfla1", username="bfla1", global_role="analyst_tier_1")
    tok_in, _ = await seed_analyst_with_token(db_session, prefix="bflai", username="bflai", global_role="ingest")
    async with client_for(app_instance) as c:
        # an analyst token is not allowed raw ingestion (ingest identities only)
        assert (await c.post(INGEST, json={"source_type": "auto", "source_identifier": "x", "alerts": [siem()]}, headers=bearer(tok_t1))).status_code in (401, 403)
        # an ingest identity cannot triage, open cases, or create cases
        for method, path, body in [("GET", "/api/v1/alerts", None), ("GET", "/api/v1/cases", None), ("POST", "/api/v1/cases", {"title": "bfla probe case"}),
                                   ("GET", "/api/v1/evidence/events", None)]:
            r = await c.request(method, path, json=body, headers=bearer(tok_in))
            if method == "GET" and path == "/api/v1/cases" and r.status_code == 200:
                # "cases assigned to the caller": an identity with no assignments must see nothing (no function-level leak)
                body_ = r.json()
                assert (body_.get("items", body_) if isinstance(body_, dict) else body_) == [], "ingest identity can list cases"
                continue
            assert r.status_code in (401, 403), f"BFLA: ingest identity {method} {path} -> {r.status_code}"


@pytest.mark.anyio
async def test_api5_case_viewer_cannot_link_evidence_or_start_an_investigation(db_session, app_instance):
    from app.models.case import CaseAssignmentModel

    client, _tok, lead, case = await setup(db_session, app_instance, [], prefix="viewL")
    tok_v, viewer = await seed_analyst_with_token(db_session, prefix="viewV", username="viewV", global_role="analyst_tier_1")
    db_session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case.id, analyst_id=viewer.id, case_role="viewer", assigned_at=datetime.now(timezone.utc)))
    await db_session.commit()
    async with Keep(client):
        r = await client.post(f"/api/v1/cases/{case.id}/evidence", json={"evidence_id": str(uuid.uuid4())}, headers=bearer(tok_v))
        assert r.status_code in (403, 404)
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(tok_v))
        assert r.status_code in (403, 404)


# ── API2 broken authentication ──────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
@pytest.mark.parametrize("header", [
    {}, {"Authorization": ""}, {"Authorization": "Bearer "}, {"Authorization": "Bearer not-a-token"},
    {"Authorization": "Basic YWRtaW46YWRtaW4="}, {"Authorization": "bearer aisop_live_" + "0" * 16 + "_" + "0" * 64},
    {"X-API-Key": "' OR '1'='1"},
])
async def test_api2_invalid_credentials_are_rejected_without_detail_leak(app_instance, header):
    async with client_for(app_instance) as c:
        for path in ("/api/v1/cases", "/api/v1/alerts", "/api/v1/evidence/events"):
            r = await c.get(path, headers=header)
            assert r.status_code in (401, 403), f"{path} accepted {header}"
            assert not any(m in r.text for m in LEAK_MARKERS)


@pytest.mark.anyio
async def test_api2_deactivated_analyst_token_is_rejected(db_session, app_instance):
    tok, _ = await seed_analyst_with_token(db_session, prefix="deact", username="deact", global_role="analyst_tier_2", is_active=False)
    async with client_for(app_instance) as c:
        assert (await c.get("/api/v1/cases", headers=bearer(tok))).status_code in (401, 403)


# ── Injection: SQL metacharacters in filters/sort/ids ───────────────────────────────────────────────
@pytest.mark.anyio
async def test_injection_sql_metacharacters_in_query_parameters_do_not_error_or_leak(db_session, app_instance):
    client, tok, _lead, _case = await setup(db_session, app_instance, [siem(7)], prefix="sqli")
    payloads = ["' OR '1'='1", "x'; DROP TABLE raw_evidence;--", "1 UNION SELECT sha256_hash FROM raw_evidence", "%", "\\", "\u0000", "a" * 5000]
    async with Keep(client):
        before = (await db_session.execute(select(func.count(RawEvidence.id)))).scalar_one()
        for p in payloads:
            for path, key in [("/api/v1/alerts", "severity"), ("/api/v1/alerts", "source_type"), ("/api/v1/alerts", "category"),
                              ("/api/v1/alerts", "provider"), ("/api/v1/evidence/events", "event_type"), ("/api/v1/evidence/events", "source_identifier")]:
                r = await client.get(path, params={key: p}, headers=bearer(tok))
                assert r.status_code < 500, f"{path}?{key}=<payload> -> {r.status_code}"
                assert not any(m in r.text for m in LEAK_MARKERS)
                if r.status_code == 200 and p.startswith(("' OR", "x';", "1 UNION")):
                    body = r.json()
                    items = body.get("items", body) if isinstance(body, dict) else body
                    assert len(items) == 0, f"filter payload returned rows (possible injection) at {path}?{key}"
        assert (await db_session.execute(select(func.count(RawEvidence.id)))).scalar_one() == before            # nothing dropped or altered


@pytest.mark.anyio
async def test_injection_path_ids_that_are_not_uuids_are_rejected_cleanly(db_session, app_instance):
    tok, _ = await seed_analyst_with_token(db_session, prefix="pid", username="pid", global_role="analyst_tier_2")
    async with client_for(app_instance) as c:
        for bad in ["1' OR '1'='1", "../../etc/passwd", "%00", "00000000-0000-0000-0000-00000000000Z"]:
            for pre in ("/api/v1/cases/", "/api/v1/alerts/"):
                r = await c.get(pre + bad, headers=bearer(tok))
                assert r.status_code in (400, 404, 422), f"{pre}{bad} -> {r.status_code}"
                assert not any(m in r.text for m in LEAK_MARKERS)


# ── API4 unrestricted resource consumption ──────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_api4_pagination_and_batch_limits_are_enforced(db_session, app_instance):
    tok, _ = await seed_analyst_with_token(db_session, prefix="lim", username="lim", global_role="analyst_tier_2")
    async with client_for(app_instance) as c:
        for params in ({"limit": 100000}, {"limit": 0}, {"page": 0}, {"page": -3}, {"limit": "abc"}):
            assert (await c.get("/api/v1/alerts", params=params, headers=bearer(tok))).status_code == 422, params
        too_many = {"source_type": "auto", "source_identifier": "x", "alerts": [siem(i) for i in range(1001)]}
        assert (await c.post(INGEST, json=too_many, headers=MACHINE)).status_code == 422


# ── API3 / mass assignment ──────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_api3_mass_assignment_unknown_fields_are_rejected(db_session, app_instance):
    tok, analyst = await seed_analyst_with_token(db_session, prefix="mass", username="mass", global_role="analyst_tier_2")
    async with client_for(app_instance) as c:
        r = await c.post("/api/v1/cases", json={"title": "mass assignment probe", "status": "closed", "id": str(uuid.uuid4()),
                                                "lead_analyst_id": str(uuid.uuid4()), "created_by": "someone-else"}, headers=bearer(tok))
        assert r.status_code == 422


# ── API8 security misconfiguration: headers, CORS, errors ───────────────────────────────────────────
@pytest.mark.anyio
async def test_api8_security_headers_are_present(app_instance):
    async with client_for(app_instance) as c:
        h = (await c.get("/api/v1/health")).headers
    assert h.get("x-content-type-options", "").lower() == "nosniff"
    assert h.get("x-frame-options", "").upper() == "DENY"
    assert "frame-ancestors 'none'" in h.get("content-security-policy", "")


@pytest.mark.anyio
async def test_api8_cors_does_not_allow_a_foreign_origin(app_instance):
    async with client_for(app_instance) as c:
        r = await c.options("/api/v1/cases", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
        allow = r.headers.get("access-control-allow-origin")
        assert allow not in ("*", "https://evil.example")
        r2 = await c.get("/api/v1/health", headers={"Origin": "https://evil.example"})
        assert r2.headers.get("access-control-allow-origin") not in ("*", "https://evil.example")


@pytest.mark.anyio
async def test_api8_errors_do_not_leak_internals(db_session, app_instance):
    tok, _ = await seed_analyst_with_token(db_session, prefix="err", username="err", global_role="analyst_tier_2")
    async with client_for(app_instance) as c:
        for method, path, body in [("GET", f"/api/v1/cases/{uuid.uuid4()}", None), ("GET", "/api/v1/nope", None), ("POST", "/api/v1/cases", {"title": 5}),
                                   ("POST", INGEST, "not json")]:
            r = await c.request(method, path, json=body, headers=bearer(tok)) if not isinstance(body, str) else await c.post(path, content=body, headers={**bearer(tok), "content-type": "application/json"})
            assert r.status_code >= 400
            assert not any(m in r.text for m in LEAK_MARKERS), f"{method} {path}: {r.text[:200]}"


# ── Stored XSS / markdown injection through evidence text (output treated as untrusted) ─────────────
@pytest.mark.anyio
async def test_xss_script_and_markup_in_evidence_text_is_not_rendered_active_in_the_report(db_session, app_instance):
    evil = '<script>alert(1)</script><img src=x onerror=alert(1)>[click](javascript:alert(1))'
    recs = [siem(i, rule_name=evil, description=evil) for i in range(1, 3)] + intrusion_chain()[:4]
    client, tok, _lead, case = await setup(db_session, app_instance, recs, prefix="xss")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(tok))
        assert r.status_code in (200, 201)
        body = r.json()
        markdowns = [body.get("batch_report_markdown") or ""] + [inc.get("report_markdown") or "" for inc in body.get("incidents", [])]
        assert any(markdowns), "no markdown report was produced"
        # JSON string fields carry the raw evidence text as data (the React UI escapes it; it never uses innerHTML). The rendered
        # Markdown reports are what a downstream renderer may interpret: they must not contain active markup or script links.
        for md in markdowns:
            low = md.lower()
            assert "<script" not in low and "<img" not in low, "active HTML survived into a Markdown report"
            assert "&lt;script" in low or "script" not in low  # escaped text stays visible but inert
            assert "](javascript:" not in low, "javascript: link survived into a Markdown report"


# ── Input hygiene ───────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_input_nul_bytes_in_alert_text_do_not_cause_a_server_error(db_session, app_instance):
    client, _tok, _l, _c = await setup(db_session, app_instance, [], prefix="nul")
    async with Keep(client):
        r = await client.post(INGEST, json={"source_type": "auto", "source_identifier": "x", "alerts": [siem(3, rule_name="a\u0000b", host="h\u0000")]}, headers=MACHINE)
        assert r.status_code < 500, r.text[:200]


# ── Secrets / data minimisation in responses and audit ──────────────────────────────────────────────
@pytest.mark.anyio
async def test_secrets_tokens_and_raw_payloads_do_not_appear_in_investigation_or_audit_responses(db_session, app_instance):
    secret_cmd = "powershell.exe -enc SECRET-COMMANDLINE-MARKER-12345"
    recs = intrusion_chain() + [siem(9, command_line=secret_cmd)]
    client, tok, _lead, case = await setup(db_session, app_instance, recs, prefix="sec")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(tok))
        act = await client.get(f"/api/v1/cases/{case.id}/activity", headers=bearer(tok))
        blob = r.text + act.text
        assert tok not in blob and "Bearer " not in blob
        assert not re.search(r"aisop_(live|test)_[0-9a-f]{16}_[0-9a-f]{64}", blob)
        assert "SECRET-COMMANDLINE-MARKER-12345" not in act.text                         # the audit trail stores no raw command lines


# ── LLM layer (OWASP LLM Top 10): locality, no silent fallback, AI-off ──────────────────────────────
def test_llm_endpoint_must_be_loopback_unless_explicitly_allowed():
    for ok in ("http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434"):
        assert_endpoint_allowed(ok, False)
    for bad in ("http://example.com:11434", "http://169.254.169.254/latest", "http://10.0.0.5:11434", "http://user:pw@127.0.0.1:11434", "ftp://127.0.0.1", "file:///etc/passwd", ""):
        with pytest.raises(LLMConfigurationError):
            assert_endpoint_allowed(bad, False)


def test_llm_disabled_returns_the_inert_provider_and_unknown_providers_fail_closed():
    from app.core.config import Settings
    from app.modules.ai.llm.inert import InertLLMProvider
    from app.modules.ai.llm.manager import get_llm_provider

    assert isinstance(get_llm_provider(Settings(_env_file=None, LLM_ENABLED=False)), InertLLMProvider)
    with pytest.raises(Exception):
        get_llm_provider(Settings(_env_file=None, LLM_ENABLED=True, LLM_PROVIDER="openai"))                  # no silent switch to a cloud provider
    with pytest.raises(Exception):
        get_llm_provider(Settings(_env_file=None, LLM_ENABLED=True, LLM_PROVIDER="ollama", OLLAMA_BASE_URL="http://203.0.113.9:11434"))


# ── SSRF / privacy: private indicators never go to external TI ──────────────────────────────────────
@pytest.mark.parametrize("value,kind", [("10.1.2.3", "ipv4"), ("127.0.0.1", "ipv4"), ("169.254.169.254", "ipv4"), ("192.168.0.9", "ipv4"),
                                        ("172.16.0.1", "ipv4"), ("::1", "ipv6"), ("fe80::1", "ipv6"), ("localhost", "domain"), ("printer.corp.local", "domain")])
def test_ssrf_private_and_internal_indicators_are_shielded_from_external_lookup(value, kind):
    assert PrivateNetworkShield().is_shielded(value, kind) is True


def test_ssrf_public_indicator_is_not_shielded():
    assert PrivateNetworkShield().is_shielded("185.220.101.4", "ipv4") is False
