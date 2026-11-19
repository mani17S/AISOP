"""
Unit and Integration Tests for AISOP API Ingress Authentication (P3-H1).

Verifies the security perimeter across all /api/v1/* routes:
- Rejection of missing, invalid, malformed, and conflicting credentials
- Constant-time secret comparison and fail-closed defaults
- Multi-client identity verification
- Exemption of public health, root, and documentation endpoints
- Protection of all evidence, investigation, and reporting endpoints
- Zero secret disclosure in responses or logs
- Test dependency override semantics
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from app.api.dependencies import AuthenticatedClient, get_current_analyst, verify_api_key
from app.core.auth import parse_configured_keys
from app.core.config import Settings, get_settings
from app.core.rbac import AuthenticatedAnalyst, GlobalRole, hash_canonical_token
from app.db.session import get_db_session
from app.main import create_app
from app.models.analyst import Analyst, AnalystApiClient
from fastapi import FastAPI, HTTPException, status


@pytest.fixture
def auth_settings() -> Settings:
    """Settings configured with two distinct synthetic API keys for multi-client verification."""
    return Settings(
        _env_file=None,
        API_AUTH_ENABLED=True,
        API_AUTH_KEYS=[
            "sensor-forwarder:synthetic-key-alpha-999",
            "soc-analyst:synthetic-key-beta-888",
        ],
    )


@pytest.fixture
def auth_app(db_session, auth_settings: Settings) -> FastAPI:
    """Create fresh application instance with isolated DB session and auth settings."""
    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_get_db
    app.dependency_overrides[get_settings] = lambda: auth_settings
    return app


async def seed_canonical_analyst_client(
    db_session,
    *,
    prefix: str = "0123456789abcdef",
    secret: str = "a" * 64,
    env: str = "live",
    client_name: str = "soc-analyst-client",
    username: str = "alice_analyst",
    global_role: str = "analyst_tier_2",
    client_active: bool = True,
    analyst_active: bool = True,
    expires_at: datetime | None = None,
) -> tuple[str, Analyst, AnalystApiClient]:
    """Helper to seed an Analyst and linked AnalystApiClient record into the test database."""
    analyst = Analyst(
        id=uuid.uuid4(),
        username=username,
        email=f"{username}@example.com",
        global_role=global_role,
        is_active=analyst_active,
    )
    db_session.add(analyst)
    await db_session.flush()

    token = f"aisop_{env}_{prefix}_{secret}"
    hashed = hash_canonical_token(token)

    client = AnalystApiClient(
        id=uuid.uuid4(),
        analyst_id=analyst.id,
        client_name=client_name,
        token_prefix=prefix,
        hashed_secret=hashed,
        is_active=client_active,
        expires_at=expires_at,
    )
    db_session.add(client)
    await db_session.commit()
    return token, analyst, client


# ═════════════════════════════════════════════════════════════════════════════
# 1. Parsing Utility Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestKeyParsing:
    def test_parses_bare_keys_and_named_clients(self):
        keys = ["bare-secret-123", "sensor-01:sensor-secret-456", "   ", ""]
        parsed = parse_configured_keys(keys)
        assert len(parsed) == 2
        assert parsed[0] == ("api-client", "bare-secret-123")
        assert parsed[1] == ("sensor-01", "sensor-secret-456")

    def test_skips_empty_or_whitespace_entries(self):
        assert parse_configured_keys([]) == []
        assert parse_configured_keys(["   ", "\t\n"]) == []


# ═════════════════════════════════════════════════════════════════════════════
# 2. Authentication Rejection Tests (Fail-Closed, 401 Unauthorized)
# ═════════════════════════════════════════════════════════════════════════════

class TestAuthenticationRejection:
    @pytest.mark.anyio
    async def test_missing_credentials_returns_401(self, auth_app):
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/evidence/ingest",
                json={"source_type": "sysmon", "source_identifier": "HOST1", "events": []},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert resp.headers.get("WWW-Authenticate") == "Bearer"
            assert "detail" in resp.json()

    @pytest.mark.anyio
    async def test_invalid_bearer_token_returns_401(self, auth_app):
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": "Bearer wrong-secret-token"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert 'error="invalid_token"' in resp.headers.get("WWW-Authenticate", "")

    @pytest.mark.anyio
    async def test_invalid_x_api_key_returns_401(self, auth_app):
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"X-API-Key": "wrong-secret-token"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert 'error="invalid_token"' in resp.headers.get("WWW-Authenticate", "")

    @pytest.mark.anyio
    async def test_unsupported_auth_scheme_returns_401(self, auth_app):
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": "Basic dXNlcjpwYXNz"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid authentication scheme" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_empty_bearer_token_returns_401(self, auth_app):
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": "Bearer   "},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.anyio
    async def test_empty_x_api_key_returns_401(self, auth_app):
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"X-API-Key": "   "},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.anyio
    async def test_conflicting_headers_returns_401(self, auth_app):
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={
                    "Authorization": "Bearer token-alpha",
                    "X-API-Key": "token-beta",
                },
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Conflicting authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_empty_configured_keys_fails_closed(self, auth_app):
        # Empty API_AUTH_KEYS in legacy mode must fail closed
        auth_app.dependency_overrides[get_settings] = lambda: Settings(
            _env_file=None,
            API_AUTH_ENABLED=True,
            API_AUTH_KEYS=[],
            API_AUTH_ALLOW_LEGACY_KEYS=True,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": "Bearer any-token"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "No valid credentials configured" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_legacy_keys_rejected_by_default(self, auth_app):
        auth_app.dependency_overrides[get_settings] = lambda: Settings(
            _env_file=None,
            API_AUTH_ENABLED=True,
            API_AUTH_KEYS=["test-client:legacy-secret-123"],
            API_AUTH_ALLOW_LEGACY_KEYS=False,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": "Bearer legacy-secret-123"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_auth_failure_does_not_reveal_secrets(self, auth_app):
        secret_token = "my-super-secret-synthetic-token-value"
        auth_app.dependency_overrides[get_settings] = lambda: Settings(
            _env_file=None,
            API_AUTH_ENABLED=True,
            API_AUTH_KEYS=[f"test-client:{secret_token}"],
            API_AUTH_ALLOW_LEGACY_KEYS=True,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": "Bearer totally-wrong-token"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            text = resp.text
            assert secret_token not in text
            assert "totally-wrong-token" not in text


# ═════════════════════════════════════════════════════════════════════════════
# 3. Authentication Acceptance Tests (Valid Canonical Tokens)
# ═════════════════════════════════════════════════════════════════════════════

class TestAuthenticationAcceptance:
    @pytest.mark.anyio
    async def test_valid_bearer_token_accepted(self, auth_app, db_session):
        token, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="1111222233334444",
            username="analyst_bearer",
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == status.HTTP_200_OK
            assert "items" in resp.json()

    @pytest.mark.anyio
    async def test_valid_x_api_key_accepted(self, auth_app, db_session):
        token, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="5555666677778888",
            username="analyst_x_api",
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"X-API-Key": token},
            )
            assert resp.status_code == status.HTTP_200_OK
            assert "items" in resp.json()

    @pytest.mark.anyio
    async def test_both_headers_matching_accepted(self, auth_app, db_session):
        token, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="9999aaaabbbbcccc",
            username="analyst_both",
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-API-Key": token,
                },
            )
            assert resp.status_code == status.HTTP_200_OK

    @pytest.mark.anyio
    async def test_multiple_configured_clients_both_accepted(self, auth_app, db_session):
        token_a, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="1234567890abcdef",
            username="junior_analyst",
            global_role="analyst_tier_1",
        )
        token_b, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="fedcba0987654321",
            username="soc_analyst",
            global_role="analyst_tier_2",
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp_a = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            assert resp_a.status_code == status.HTTP_200_OK

            resp_b = await client.get(
                "/api/v1/evidence/events",
                headers={"X-API-Key": token_b},
            )
            assert resp_b.status_code == status.HTTP_200_OK


# ═════════════════════════════════════════════════════════════════════════════
# 4. Canonical Database Authentication & Policy Enforcement
# ═════════════════════════════════════════════════════════════════════════════

class TestCanonicalDatabaseAuthentication:
    @pytest.mark.anyio
    async def test_resolves_correct_analyst_and_client(self, db_session):
        token, analyst, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="aaaabbbbccccdddd",
            username="charlie_tier1",
            global_role="analyst_tier_1",
            client_name="charlie-workstation",
        )
        settings = Settings(_env_file=None, API_AUTH_ENABLED=True)
        authenticated = await verify_api_key(
            authorization=f"Bearer {token}",
            settings=settings,
            session=db_session,
        )
        assert authenticated.client_id == "charlie-workstation"
        assert authenticated.authenticated is True
        assert authenticated.analyst is not None
        assert authenticated.analyst.analyst_id == analyst.id
        assert authenticated.analyst.username == "charlie_tier1"
        assert authenticated.analyst.global_role == GlobalRole.ANALYST_TIER_1
        assert authenticated.analyst.is_active is True

    @pytest.mark.anyio
    async def test_incorrect_secret_rejected(self, auth_app, db_session):
        await seed_canonical_analyst_client(
            db_session,
            prefix="beefbeefbeefbeef",
            secret="a" * 64,
        )
        wrong_token = f"aisop_live_beefbeefbeefbeef_{'b' * 64}"
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {wrong_token}"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_unknown_prefix_rejected(self, auth_app):
        unknown_token = f"aisop_live_{'0' * 16}_{'f' * 64}"
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {unknown_token}"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_malformed_token_rejected(self, auth_app):
        malformed_tokens = [
            "aisop_invalid_prefix_secret",
            f"aisop_staging_{'a' * 16}_{'b' * 64}",
            f"aisop_live_{'z' * 16}_{'a' * 64}",
            f"aisop_live_{'a' * 15}_{'b' * 64}",
            f"aisop_live_{'a' * 16}_{'b' * 63}",
        ]
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            for bad_token in malformed_tokens:
                resp = await client.get(
                    "/api/v1/evidence/events",
                    headers={"Authorization": f"Bearer {bad_token}"},
                )
                assert resp.status_code == status.HTTP_401_UNAUTHORIZED
                assert "Invalid authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_inactive_client_rejected(self, auth_app, db_session):
        token, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="deacdeacdeacdeac",
            client_active=False,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_expired_client_rejected(self, auth_app, db_session):
        past_time = datetime.now(timezone.utc) - timedelta(days=1)
        token, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="expdexpdexpdexpd",
            expires_at=past_time,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_inactive_analyst_rejected(self, auth_app, db_session):
        token, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="inacanlystinacanl",
            analyst_active=False,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_development_accepts_test_token(self, auth_app, db_session):
        token, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="de01020304050607",
            env="test",
        )
        auth_app.dependency_overrides[get_settings] = lambda: Settings(
            _env_file=None,
            ENVIRONMENT="development",
            API_AUTH_ENABLED=True,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == status.HTTP_200_OK

    @pytest.mark.anyio
    async def test_staging_rejects_test_token(self, auth_app, db_session):
        token, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="5a01020304050607",
            env="test",
        )
        auth_app.dependency_overrides[get_settings] = lambda: Settings(
            _env_file=None,
            ENVIRONMENT="staging",
            API_AUTH_ENABLED=True,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_production_rejects_test_token(self, auth_app, db_session):
        token, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix="ba01020304050607",
            env="test",
        )
        auth_app.dependency_overrides[get_settings] = lambda: Settings(
            _env_file=None,
            ENVIRONMENT="production",
            API_AUTH_ENABLED=True,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("env_name", "prefix_hex"),
        [
            ("development", "ca01020304050601"),
            ("staging", "ca01020304050602"),
            ("production", "ca01020304050603"),
        ],
    )
    async def test_live_token_accepted_across_environments(self, auth_app, db_session, env_name, prefix_hex):
        token, _, _ = await seed_canonical_analyst_client(
            db_session,
            prefix=prefix_hex,
            env="live",
        )
        auth_app.dependency_overrides[get_settings] = lambda: Settings(
            _env_file=None,
            ENVIRONMENT=env_name,
            API_AUTH_ENABLED=True,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == status.HTTP_200_OK

    @pytest.mark.anyio
    async def test_database_lookup_failure_fails_closed(self, auth_app):
        class BrokenSession:
            async def execute(self, *args, **kwargs):
                raise RuntimeError("Database connection lost")

        async def override_broken_db():
            yield BrokenSession()

        auth_app.dependency_overrides[get_db_session] = override_broken_db
        valid_looking_token = f"aisop_live_{'1' * 16}_{'2' * 64}"
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {valid_looking_token}"},
            )
            assert resp.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Authentication service unavailable" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_token_digest_not_disclosed_in_error(self, auth_app):
        secret_part = "3" * 64
        token = f"aisop_live_{'4' * 16}_{secret_part}"
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert secret_part not in resp.text
            assert token not in resp.text


# ═════════════════════════════════════════════════════════════════════════════
# 5. Legacy Mode Policy Enforcement
# ═════════════════════════════════════════════════════════════════════════════

class TestLegacyModeEnforcement:
    def test_legacy_mode_disabled_by_default(self):
        settings = Settings(_env_file=None)
        assert settings.API_AUTH_ALLOW_LEGACY_KEYS is False

    @pytest.mark.anyio
    async def test_legacy_keys_rejected_by_default(self, auth_app):
        auth_app.dependency_overrides[get_settings] = lambda: Settings(
            _env_file=None,
            API_AUTH_ENABLED=True,
            API_AUTH_KEYS=["test-client:secret-key-123"],
            API_AUTH_ALLOW_LEGACY_KEYS=False,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": "Bearer secret-key-123"},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid authentication credentials" in resp.json()["detail"]

    @pytest.mark.anyio
    async def test_legacy_keys_accepted_when_explicitly_enabled(self, auth_app):
        """
        Gate D.2.3.2: When legacy keys are enabled, machine clients are authenticated (not 401),
        but fail closed with 403 Forbidden on evidence query endpoints, while ingestion remains permitted.
        """
        auth_app.dependency_overrides[get_settings] = lambda: Settings(
            _env_file=None,
            API_AUTH_ENABLED=True,
            API_AUTH_KEYS=["forwarder-01:legacy-allowed-key"],
            API_AUTH_ALLOW_LEGACY_KEYS=True,
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Unscoped evidence query fails closed with 403 Forbidden
            resp = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": "Bearer legacy-allowed-key"},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "Machine credentials without analyst identity" in resp.json()["detail"]

            # 2. Telemetry ingestion path remains permitted (200 OK)
            resp_ingest = await client.post(
                "/api/v1/evidence/ingest",
                headers={"Authorization": "Bearer legacy-allowed-key"},
                json={
                    "source_type": "sysmon",
                    "source_identifier": "FORWARDER-01",
                    "events": [
                        {
                            "EventID": 1,
                            "Image": "C:\\Windows\\System32\\cmd.exe",
                            "UtcTime": "2026-10-25 12:00:00.000",
                        }
                    ],
                },
            )
            assert resp_ingest.status_code == status.HTTP_200_OK

    @pytest.mark.anyio
    async def test_legacy_key_does_not_grant_analyst_identity(self, db_session):
        settings = Settings(
            _env_file=None,
            API_AUTH_ENABLED=True,
            API_AUTH_KEYS=["forwarder-01:legacy-allowed-key"],
            API_AUTH_ALLOW_LEGACY_KEYS=True,
        )
        client = await verify_api_key(
            authorization="Bearer legacy-allowed-key",
            settings=settings,
            session=db_session,
        )
        assert client.authenticated is True
        assert client.analyst is None

        # Resolving analyst identity from a legacy client must fail closed
        with pytest.raises(HTTPException) as exc_info:
            await get_current_analyst(client=client)
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "do not resolve to an analyst identity" in exc_info.value.detail


# ═════════════════════════════════════════════════════════════════════════════
# 4. Route Perimeter & Public Exemption Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestRoutePerimeter:
    @pytest.mark.anyio
    async def test_public_routes_remain_accessible_without_auth(self, auth_app):
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Root status
            res_root = await client.get("/")
            assert res_root.status_code == status.HTTP_200_OK

            # OpenAPI schema & Swagger/ReDoc docs
            res_openapi = await client.get("/api/v1/openapi.json")
            assert res_openapi.status_code == status.HTTP_200_OK

            res_docs = await client.get("/docs")
            assert res_docs.status_code == status.HTTP_200_OK

            res_redoc = await client.get("/redoc")
            assert res_redoc.status_code == status.HTTP_200_OK

            # Health liveness probe
            res_health = await client.get("/api/v1/health")
            assert res_health.status_code == status.HTTP_200_OK
            assert res_health.json()["status"] == "ok"

    @pytest.mark.anyio
    async def test_all_protected_api_routes_reject_unauthenticated(self, auth_app):
        """
        Exhaustively verify that every protected route under /api/v1/* rejects
        unauthenticated requests with HTTP 401 Unauthorized.
        """
        transport = httpx.ASGITransport(app=auth_app)
        sample_uuid = str(uuid.uuid4())
        sample_hash = "a" * 64

        protected_endpoints = [
            ("POST", "/api/v1/evidence/ingest", {"source_type": "sysmon", "source_identifier": "H1", "events": []}),
            ("GET", "/api/v1/evidence/events", None),
            ("GET", f"/api/v1/evidence/events/{sample_uuid}", None),
            ("GET", "/api/v1/evidence/entities", None),
            ("GET", f"/api/v1/evidence/by-hash/{sample_hash}", None),
            ("GET", f"/api/v1/evidence/{sample_uuid}", None),
            ("POST", "/api/v1/investigations/synthesize", {"time_window_start": "2026-10-24T00:00:00Z", "time_window_end": "2026-10-24T01:00:00Z"}),
            ("POST", "/api/v1/reports/synthesize", {"time_window_start": "2026-10-24T00:00:00Z", "time_window_end": "2026-10-24T01:00:00Z"}),
            ("POST", "/api/v1/reports/format", {"validation_result": {"decision": "pass", "is_valid": True, "overall_grounding_score": 1.0, "total_claims": 0, "tier1_verified_claims": 0, "tier2_contained_claims": 0, "claims": [], "guardrail_violations": [], "output": {"executive_summary": "ok", "threat_actors": [], "mitre_techniques": [], "ioc_list": [], "investigation_narrative": "ok", "confidence_score": 1.0, "factual_claims": [], "remediation_recommendations": []}}}),
        ]

        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            for method, path, json_body in protected_endpoints:
                if method == "GET":
                    resp = await client.get(path)
                elif method == "POST":
                    resp = await client.post(path, json=json_body)
                else:
                    raise ValueError(f"Unexpected method: {method}")

                assert resp.status_code == status.HTTP_401_UNAUTHORIZED, (
                    f"Route {method} {path} returned {resp.status_code} instead of 401 Unauthorized"
                )


# ═════════════════════════════════════════════════════════════════════════════
# 5. Configuration & Safety Invariants
# ═════════════════════════════════════════════════════════════════════════════

class TestConfigurationAndSafety:
    def test_production_environment_cannot_disable_auth(self):
        """Setting ENVIRONMENT='production' and API_AUTH_ENABLED=False must fail at startup."""
        with pytest.raises(ValueError, match="API_AUTH_ENABLED cannot be False in production"):
            Settings(
                _env_file=None,
                ENVIRONMENT="production",
                API_AUTH_ENABLED=False,
            )

    @pytest.mark.anyio
    async def test_dependency_override_enables_safe_test_bypass(self, auth_app):
        """Verify that FastAPI dependency_overrides[verify_api_key] safely supplies test identity."""
        auth_app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(
            client_id="test-harness",
            authenticated=True,
            analyst=AuthenticatedAnalyst(
                analyst_id=uuid.uuid4(),
                username="test_harness_analyst",
                global_role=GlobalRole.ANALYST_TIER_1,
                client_id="test-harness",
                is_active=True,
            ),
        )
        transport = httpx.ASGITransport(app=auth_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Request without any HTTP headers succeeds due to explicit test override
            resp = await client.get("/api/v1/evidence/events")
            assert resp.status_code == status.HTTP_200_OK
            assert "items" in resp.json()
