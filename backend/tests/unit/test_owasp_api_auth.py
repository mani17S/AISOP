"""
OWASP API Security Top 10 (2023) review: API2 broken authentication / API key hardening, offline.

Real FastAPI app, SQLite harness, no network. Each test is a regression guard for a finding recorded in
docs/07_Security/OWASP_API_Top10_Review.md. Synthetic data only.
"""
from __future__ import annotations

import secrets
import uuid

import httpx
import pytest
from sqlalchemy import select

from app.models.analyst import AnalystApiClient
from tests.unit.test_multisource_api import (  # noqa: F401  (fixtures and helpers)
    anyio_backend,
    app_instance,
    auth_settings,
    bearer,
    seed_analyst_with_token,
)

CASES = "/api/v1/cases"


def client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def random_canonical_key() -> str:
    return f"aisop_live_{secrets.token_hex(8)}_{secrets.token_hex(32)}"


def from_ip(ip: str, token: str | None = None) -> dict[str, str]:
    """Client IP as seen through the trusted loopback proxy (the ASGI test peer is 127.0.0.1)."""
    h = {"X-Forwarded-For": ip}
    if token:
        h["X-API-Key"] = token
    return h


# ── API2: non-ASCII credentials must never produce a 500 ────────────────────────────────────────────
@pytest.mark.anyio
async def test_non_ascii_credentials_in_both_headers_are_a_401_not_a_500(app_instance):
    async with client_for(app_instance) as c:
        r = await c.get(CASES, headers={"Authorization": b"Bearer caf\xe9tok", "X-API-Key": b"caf\xe9tok"})
        assert r.status_code == 401, r.text
        r = await c.get(CASES, headers={"Authorization": b"Bearer caf\xe9tok", "X-API-Key": b"caf\xe9abc"})
        assert r.status_code == 401, r.text


@pytest.mark.anyio
async def test_non_ascii_legacy_key_is_a_401_not_a_500(app_instance, auth_settings):
    # Legacy static keys are enabled in this fixture: compare_digest on non-ASCII str would raise TypeError.
    async with client_for(app_instance) as c:
        r = await c.get(CASES, headers={"X-API-Key": b"caf\xc3\xa9-legacy"})
        assert r.status_code == 401, r.text


# ── API2/API4: brute-force protection for invalid keys ──────────────────────────────────────────────
@pytest.mark.anyio
async def test_many_invalid_keys_from_one_client_are_locked_out_with_429(app_instance):
    async with client_for(app_instance) as c:
        codes = []
        for _ in range(40):
            r = await c.get(CASES, headers=from_ip("198.51.100.7", random_canonical_key()))
            codes.append(r.status_code)
            if r.status_code == 429:
                assert r.headers.get("retry-after")
                assert r.json()["error"]["code"] == "RATE_LIMITED"
                break
        assert 429 in codes, f"no lockout after {len(codes)} invalid keys: {set(codes)}"
        assert codes[0] == 401 and codes.index(429) <= 25


@pytest.mark.anyio
async def test_wrong_secret_for_a_known_prefix_locks_that_client_but_not_others(db_session, app_instance):
    token, _ = await seed_analyst_with_token(db_session, prefix="brute1", username="brute1", global_role="analyst_tier_2")
    wrong = token[:-1] + ("c" if token[-1] != "c" else "d")
    async with client_for(app_instance) as c:
        for i in range(5):
            r = await c.get(CASES, headers=from_ip("198.51.100.20", wrong))
            assert r.status_code == 401, (i, r.status_code)
        # the attacking address is now locked out, even with the right key
        r = await c.get(CASES, headers=from_ip("198.51.100.20", token))
        assert r.status_code == 429
        assert r.headers.get("retry-after")
        # the legitimate owner on a different address is not affected (no account-wide lockout DoS)
        r = await c.get(CASES, headers=from_ip("198.51.100.21", token))
        assert r.status_code == 200, r.text


@pytest.mark.anyio
async def test_a_successful_login_resets_the_failure_counter(db_session, app_instance):
    token, _ = await seed_analyst_with_token(db_session, prefix="brute2", username="brute2", global_role="analyst_tier_2")
    wrong = token[:-1] + ("c" if token[-1] != "c" else "d")
    async with client_for(app_instance) as c:
        for _ in range(3):
            assert (await c.get(CASES, headers=from_ip("198.51.100.30", wrong))).status_code == 401
        assert (await c.get(CASES, headers=from_ip("198.51.100.30", token))).status_code == 200
        for _ in range(3):
            assert (await c.get(CASES, headers=from_ip("198.51.100.30", wrong))).status_code == 401


@pytest.mark.anyio
async def test_requests_without_any_credential_do_not_feed_the_lockout(app_instance):
    async with client_for(app_instance) as c:
        for _ in range(30):
            assert (await c.get(CASES, headers=from_ip("198.51.100.40"))).status_code == 401


# ── API2: last_used tracking ────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_last_used_at_is_recorded_after_a_successful_authentication(db_session, app_instance):
    token, analyst = await seed_analyst_with_token(db_session, prefix="lastuse", username="lastuse", global_role="analyst_tier_2")
    before = (await db_session.execute(select(AnalystApiClient.last_used_at).where(AnalystApiClient.analyst_id == analyst.id))).scalar_one()
    assert before is None
    async with client_for(app_instance) as c:
        assert (await c.get(CASES, headers=bearer(token))).status_code == 200
    after = (await db_session.execute(select(AnalystApiClient.last_used_at).where(AnalystApiClient.analyst_id == analyst.id))).scalar_one()
    assert after is not None


@pytest.mark.anyio
async def test_failed_authentication_does_not_touch_last_used_at(db_session, app_instance):
    token, analyst = await seed_analyst_with_token(db_session, prefix="lastfail", username="lastfail", global_role="analyst_tier_2")
    wrong = token[:-1] + ("c" if token[-1] != "c" else "d")
    async with client_for(app_instance) as c:
        assert (await c.get(CASES, headers=bearer(wrong))).status_code == 401
    after = (await db_session.execute(select(AnalystApiClient.last_used_at).where(AnalystApiClient.analyst_id == analyst.id))).scalar_one()
    assert after is None


# ── API2: revoked / expired / inactive keys and key-in-log redaction ────────────────────────────────
@pytest.mark.anyio
async def test_revoked_inactive_and_deactivated_keys_are_a_uniform_401(db_session, app_instance):
    t_rev, _ = await seed_analyst_with_token(db_session, prefix="rev", username="rev", global_role="analyst_tier_2", client_active=False)
    t_off, _ = await seed_analyst_with_token(db_session, prefix="off", username="off", global_role="analyst_tier_2", is_active=False)
    async with client_for(app_instance) as c:
        bodies = []
        for i, t in enumerate((t_rev, t_off, random_canonical_key())):
            r = await c.get(CASES, headers=from_ip(f"198.51.100.{60 + i}", t))
            assert r.status_code == 401
            bodies.append(r.json()["detail"])
        assert len(set(bodies)) == 1, "revoked, deactivated and unknown keys must be indistinguishable"


def test_canonical_api_keys_are_redacted_wherever_they_appear_in_log_text():
    from app.core.logging import redact_sensitive_data, redact_text

    key = f"aisop_live_{secrets.token_hex(8)}_{secrets.token_hex(32)}"
    assert key not in redact_text(f"GET /api/v1/cases/{key} 404")
    assert key not in redact_text(f"query ?k={key}&x=1")
    assert key not in str(redact_sensitive_data({"path": f"/api/v1/cases/{key}", "nested": [f"value {key}"]}))
    assert "aisop_" in redact_text(f"/api/v1/cases/{key}")  # the shape stays recognisable for operators
    assert "/api/v1/cases/" in redact_text(f"/api/v1/cases/{key}")


@pytest.mark.anyio
async def test_a_key_sent_in_the_url_is_not_accepted_and_not_echoed(db_session, app_instance):
    token, _ = await seed_analyst_with_token(db_session, prefix="inurl", username="inurl", global_role="analyst_tier_2")
    async with client_for(app_instance) as c:
        for url in (f"{CASES}?api_key={token}", f"{CASES}?X-API-Key={token}", f"{CASES}?token={token}"):
            r = await c.get(url)
            assert r.status_code == 401
            assert token not in r.text and token not in str(r.headers)
        r = await c.get(f"{CASES}/{token}", headers=bearer(token))
        assert r.status_code == 422
        assert token not in r.text


@pytest.mark.anyio
async def test_invalid_key_lookup_does_not_leak_whether_the_prefix_exists(db_session, app_instance):
    token, _ = await seed_analyst_with_token(db_session, prefix="oracle", username="oracle", global_role="analyst_tier_2")
    wrong_known = token[:-1] + ("c" if token[-1] != "c" else "d")
    async with client_for(app_instance) as c:
        a = await c.get(CASES, headers=from_ip("198.51.100.80", wrong_known))
        b = await c.get(CASES, headers=from_ip("198.51.100.81", random_canonical_key()))
        assert (a.status_code, a.json()["detail"], a.headers.get("www-authenticate")) == (b.status_code, b.json()["detail"], b.headers.get("www-authenticate"))


def test_token_generation_has_enough_entropy_and_hashes_are_stored_not_secrets():
    from app.core.rbac import hash_canonical_token, is_canonical_token
    from backend.scripts.provision_demo_identities import generate_canonical_credential  # noqa: F401  (import guard)

    token, prefix, digest = generate_canonical_credential(env="live")
    assert is_canonical_token(token) and token.startswith("aisop_live_") and prefix in token
    assert digest == hash_canonical_token(token) and len(digest) == 64 and token not in digest
    # 8 random bytes of prefix + 32 random bytes (256 bit) of secret, never repeated across calls
    assert len({generate_canonical_credential(env="live")[0] for _ in range(50)}) == 50
    assert uuid  # keep import used
