"""
GET /api/v1/auth/me: who the server says you are.

The interface uses it to show the real account and role instead of a selector. It returns only what the server already knows
about the caller: the account name, the global role and the client name. Never the key, its hash or any other account.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.main import create_app
from tests.unit.test_case_api import seed_analyst_with_token


@pytest.fixture
def auth_settings() -> Settings:
    return Settings(
        _env_file=None, API_AUTH_ENABLED=True, API_AUTH_ALLOW_LEGACY_KEYS=True, API_AUTH_KEYS=["legacy-machine:legacy-machine-key-999"], RATE_LIMIT_ENABLED=False
    )


@pytest.fixture
def app_instance(db_session, auth_settings: Settings) -> FastAPI:
    app = create_app()

    async def override_get_db():
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    app.dependency_overrides[get_db_session] = override_get_db
    app.dependency_overrides[get_settings] = lambda: auth_settings
    return app


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.mark.anyio
@pytest.mark.parametrize("role", ["security_admin", "analyst_tier_2", "analyst_tier_1", "ingest"])
async def test_me_returns_the_callers_own_account_and_role(app_instance, db_session, role):
    token, analyst = await seed_analyst_with_token(db_session, prefix=f"me-{role}", username=f"user_{role}", global_role=role)
    async with _client(app_instance) as c:
        r = await c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body == {
        "authenticated": True,
        "username": f"user_{role}",
        "global_role": role,
        "client_name": f"user_{role}-client",
    }


@pytest.mark.anyio
async def test_me_never_reveals_a_key_a_hash_or_another_account(app_instance, db_session):
    token, _ = await seed_analyst_with_token(db_session, prefix="me-a", username="alice_me", global_role="analyst_tier_1")
    await seed_analyst_with_token(db_session, prefix="me-b", username="bob_me", global_role="security_admin")
    async with _client(app_instance) as c:
        text = (await c.get("/api/v1/auth/me", headers={"X-API-Key": token})).text
    assert token not in text and token.split("_")[-1] not in text and "bob_me" not in text
    assert "hashed_secret" not in text and "token_prefix" not in text


@pytest.mark.anyio
async def test_me_requires_a_valid_credential(app_instance, db_session):
    async with _client(app_instance) as c:
        assert (await c.get("/api/v1/auth/me")).status_code == 401
        assert (await c.get("/api/v1/auth/me", headers={"X-API-Key": "aisop_live_" + "0" * 16 + "_" + "f" * 64})).status_code == 401


@pytest.mark.anyio
async def test_a_machine_key_with_no_account_says_so_and_claims_no_role(app_instance, db_session):
    async with _client(app_instance) as c:
        r = await c.get("/api/v1/auth/me", headers={"X-API-Key": "legacy-machine-key-999"})
    assert r.status_code == 200
    body = r.json()
    assert body["authenticated"] is True and body["username"] is None and body["global_role"] is None
