"""
Unit and Integration Tests for AISOP Demo Identity Provisioning & Ingestion Boundary (P6.6).

Verifies:
1. Cryptographically secure canonical token generation (entropy, regex, 92 chars).
2. Token hashing and database-backed verification with constant-time comparison.
3. Provisioning execution: inserts viva_analyst (analyst_tier_1) and viva_sensor (ingest).
4. Collision and duplicate invocation protection (fails closed without writing).
5. Expiration timestamp calculation and verification.
6. Safe revocation (deactivation) of identities without record deletion.
7. Transaction rollback on provisioning failure.
8. Ingestion boundary enforcement:
   - viva_sensor (ingest) CAN submit raw alerts and telemetry (HTTP 200).
   - viva_analyst (analyst_tier_1) CANNOT submit raw telemetry (HTTP 403).
   - viva_sensor (ingest) CANNOT access analyst triage or create cases (HTTP 403).
   - viva_analyst (analyst_tier_1) CAN access alert triage and create cases (HTTP 200/201).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, status
from sqlalchemy import delete, select

from app.api.dependencies import get_current_analyst, verify_api_key
from app.core.auth import verify_api_key as verify_api_key_fn
from app.core.config import Settings, get_settings
from app.core.rbac import (
    CANONICAL_TOKEN_REGEX,
    GlobalRole,
    can_access_global_event_triage,
    can_create_case,
    can_ingest_telemetry,
    hash_canonical_token,
    is_canonical_token,
)
from app.db.session import get_db_session
from app.main import create_app
from app.models.analyst import Analyst, AnalystApiClient
from app.models.case import CaseAssignmentModel, CaseModel
from backend.scripts.provision_demo_identities import (
    DEMO_CONFIGS,
    check_existing_demo_identities,
    generate_canonical_credential,
    main_async,
    provision_identities,
    revoke_identities,
    rotate_identities,
)


# ═════════════════════════════════════════════════════════════════════════════
# 1. Cryptographic Token Generation & Hashing Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestTokenGeneration:
    def test_canonical_token_format_and_length(self):
        full_token, prefix, hashed_secret = generate_canonical_credential(env="live")

        # Must match 92 characters
        assert len(full_token) == 92
        assert len(prefix) == 16
        assert len(hashed_secret) == 64

        # Must match canonical regular expression
        assert CANONICAL_TOKEN_REGEX.fullmatch(full_token) is not None
        assert is_canonical_token(full_token) is True
        assert full_token.startswith("aisop_live_")

        # Prefix must be in the token string
        assert full_token[11:27] == prefix

        # Digest must be SHA-256 of complete token
        assert hash_canonical_token(full_token) == hashed_secret

    def test_token_uniqueness_and_entropy(self):
        # Generate 100 tokens and verify all are unique
        tokens = {generate_canonical_credential()[0] for _ in range(100)}
        assert len(tokens) == 100

    def test_canonical_test_env_token(self):
        full_token, prefix, _ = generate_canonical_credential(env="test")
        assert full_token.startswith("aisop_test_")
        assert len(full_token) == 92
        assert is_canonical_token(full_token) is True


# ═════════════════════════════════════════════════════════════════════════════
# 2. Provisioning Logic & Database Invariants (Isolated SQLite)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
class TestProvisioningWorkflow:
    async def test_successful_provisioning_and_credential_verification(self, db_session):
        # 1. Execute provisioning with 48h expiration
        results = await provision_identities(db_session, env="live", expires_in_hours=48)
        assert len(results) == 2

        analyst_item = next(r for r in results if r["username"] == "viva_analyst")
        sensor_item = next(r for r in results if r["username"] == "viva_sensor")

        assert analyst_item["global_role"] == "analyst_tier_1"
        assert sensor_item["global_role"] == "ingest"
        assert analyst_item["client_name"] == "viva-tier1-workstation"
        assert sensor_item["client_name"] == "viva-sysmon-forwarder"

        # 2. Verify analyst token against auth dependency
        settings = Settings(_env_file=None, API_AUTH_ENABLED=True)
        analyst_auth = await verify_api_key_fn(
            x_api_key=analyst_item["raw_token"],
            settings=settings,
            session=db_session,
        )
        assert analyst_auth.authenticated is True
        assert analyst_auth.analyst is not None
        assert analyst_auth.analyst.username == "viva_analyst"
        assert analyst_auth.analyst.global_role == GlobalRole.ANALYST_TIER_1
        assert analyst_auth.analyst.is_active is True

        # 3. Verify sensor token against auth dependency
        sensor_auth = await verify_api_key_fn(
            authorization=f"Bearer {sensor_item['raw_token']}",
            settings=settings,
            session=db_session,
        )
        assert sensor_auth.authenticated is True
        assert sensor_auth.analyst is not None
        assert sensor_auth.analyst.username == "viva_sensor"
        assert sensor_auth.analyst.global_role == GlobalRole.INGEST
        assert sensor_auth.analyst.is_active is True

    async def test_duplicate_invocation_protection(self, db_session):
        # First provisioning must succeed
        await provision_identities(db_session, env="live")

        # Second provisioning must fail closed with collision error
        with pytest.raises(RuntimeError) as exc_info:
            await provision_identities(db_session, env="live")

        err = str(exc_info.value)
        assert "Collision detected" in err
        assert "viva_analyst" in err
        assert "viva-tier1-workstation" in err

    async def test_revocation_deactivates_credentials(self, db_session):
        results = await provision_identities(db_session, env="live")
        analyst_token = next(r["raw_token"] for r in results if r["username"] == "viva_analyst")

        # Revoke identities
        revoked = await revoke_identities(db_session)
        assert revoked["analysts_deactivated"] == 2
        assert revoked["clients_deactivated"] == 2

        # Subsequent token verification must fail closed with 401
        settings = Settings(_env_file=None, API_AUTH_ENABLED=True)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await verify_api_key_fn(
                x_api_key=analyst_token,
                settings=settings,
                session=db_session,
            )
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_expired_token_rejected(self, db_session):
        # Provision with negative expiration to simulate expired token
        results = await provision_identities(db_session, env="live", expires_in_hours=0)
        sensor_token = next(r["raw_token"] for r in results if r["username"] == "viva_sensor")

        # Update client record expires_at to 1 hour in the past
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        client_stmt = select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-sysmon-forwarder")
        client_res = await db_session.execute(client_stmt)
        client_rec = client_res.scalars().first()
        client_rec.expires_at = past_time
        await db_session.commit()

        # Token must be rejected as expired (401)
        settings = Settings(_env_file=None, API_AUTH_ENABLED=True)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await verify_api_key_fn(
                authorization=f"Bearer {sensor_token}",
                settings=settings,
                session=db_session,
            )
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


# ═════════════════════════════════════════════════════════════════════════════
# 3. Ingestion & Analyst Endpoint Boundary Tests
# ═════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def boundary_app(db_session) -> FastAPI:
    app = create_app()

    async def override_get_db():
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    settings = Settings(_env_file=None, API_AUTH_ENABLED=True)
    app.dependency_overrides[get_db_session] = override_get_db
    app.dependency_overrides[get_settings] = lambda: settings
    return app


@pytest.mark.anyio
class TestBoundaryEnforcement:
    async def test_sensor_can_ingest_alerts_and_analyst_is_blocked(self, boundary_app: FastAPI, db_session):
        # Provision demo identities in DB
        results = await provision_identities(db_session, env="live")
        analyst_token = next(r["raw_token"] for r in results if r["username"] == "viva_analyst")
        sensor_token = next(r["raw_token"] for r in results if r["username"] == "viva_sensor")

        transport = httpx.ASGITransport(app=boundary_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. viva_sensor submits alert -> HTTP 200 OK
            payload = {
                "source_type": "sysmon",
                "source_identifier": "VIVA-HOST-01",
                "alerts": [
                    {
                        "event_id": 1,
                        "observed_time": "2026-11-01T12:00:00Z",
                        "title": "Suspicious Process Creation",
                        "description": "powershell.exe -enc SQBFAFgA",
                        "severity": "high",
                    }
                ],
            }
            resp_sensor = await client.post(
                "/api/v1/alerts/ingest",
                headers={"X-API-Key": sensor_token},
                json=payload,
            )
            assert resp_sensor.status_code == status.HTTP_200_OK
            assert resp_sensor.json()["total_received"] == 1

            # 2. viva_analyst attempts to submit raw alert -> HTTP 403 Forbidden
            resp_analyst = await client.post(
                "/api/v1/alerts/ingest",
                headers={"X-API-Key": analyst_token},
                json=payload,
            )
            assert resp_analyst.status_code == status.HTTP_403_FORBIDDEN
            assert "Insufficient global role" in resp_analyst.json()["detail"]

    async def test_sensor_can_ingest_telemetry_and_analyst_is_blocked(self, boundary_app: FastAPI, db_session):
        results = await provision_identities(db_session, env="live")
        analyst_token = next(r["raw_token"] for r in results if r["username"] == "viva_analyst")
        sensor_token = next(r["raw_token"] for r in results if r["username"] == "viva_sensor")

        transport = httpx.ASGITransport(app=boundary_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            telemetry_payload = {
                "source_type": "sysmon",
                "source_identifier": "VIVA-HOST-01",
                "events": [{"CommandLine": "powershell.exe -enc TEST", "UtcTime": "2026-11-01 12:00:00.000"}],
            }

            # viva_sensor -> 200 OK
            r_sensor = await client.post(
                "/api/v1/evidence/ingest",
                headers={"X-API-Key": sensor_token},
                json=telemetry_payload,
            )
            assert r_sensor.status_code == status.HTTP_200_OK

            # viva_analyst -> 403 Forbidden
            r_analyst = await client.post(
                "/api/v1/evidence/ingest",
                headers={"X-API-Key": analyst_token},
                json=telemetry_payload,
            )
            assert r_analyst.status_code == status.HTTP_403_FORBIDDEN
            assert "Insufficient global role" in r_analyst.json()["detail"]

    async def test_sensor_cannot_access_analyst_views(self, boundary_app: FastAPI, db_session):
        results = await provision_identities(db_session, env="live")
        sensor_token = next(r["raw_token"] for r in results if r["username"] == "viva_sensor")

        transport = httpx.ASGITransport(app=boundary_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. viva_sensor attempts alert triage -> 403 Forbidden
            r_alerts = await client.get(
                "/api/v1/alerts",
                headers={"X-API-Key": sensor_token},
            )
            assert r_alerts.status_code == status.HTTP_403_FORBIDDEN
            assert "Insufficient global role" in r_alerts.json()["detail"]

            # 2. viva_sensor attempts evidence query -> 403 Forbidden
            r_ev = await client.get(
                "/api/v1/evidence/events",
                headers={"X-API-Key": sensor_token},
            )
            assert r_ev.status_code == status.HTTP_403_FORBIDDEN

            # 3. viva_sensor attempts case creation -> 403 Forbidden
            r_case = await client.post(
                "/api/v1/cases",
                headers={"X-API-Key": sensor_token},
                json={"title": "Unauthorized Case", "severity": "low"},
            )
            assert r_case.status_code == status.HTTP_403_FORBIDDEN

    async def test_analyst_can_access_triage_and_create_cases(self, boundary_app: FastAPI, db_session):
        results = await provision_identities(db_session, env="live")
        analyst_token = next(r["raw_token"] for r in results if r["username"] == "viva_analyst")

        transport = httpx.ASGITransport(app=boundary_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. viva_analyst accesses alert triage -> 200 OK
            r_alerts = await client.get(
                "/api/v1/alerts",
                headers={"X-API-Key": analyst_token},
            )
            assert r_alerts.status_code == status.HTTP_200_OK

            # 2. viva_analyst creates a security case -> 201 Created
            r_create = await client.post(
                "/api/v1/cases",
                headers={"X-API-Key": analyst_token},
                json={
                    "title": "Viva Demonstration Case: Suspicious Execution",
                    "description": "Initial triage of detected suspicious PowerShell activity.",
                    "severity": "high",
                },
            )
            assert r_create.status_code == status.HTTP_201_CREATED
            case_data = r_create.json()
            assert case_data["title"] == "Viva Demonstration Case: Suspicious Execution"
            assert case_data["severity"] == "high"
            assert case_data["status"] == "open"


# ═════════════════════════════════════════════════════════════════════════════
# 4. Safe Credential Rotation Tests (P6.6 Extension)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
class TestCredentialRotation:
    """
    Verifies that --rotate safely rotates credentials in-place without deleting
    identities, disrupting case assignments, or corrupting audit trails.
    """

    async def test_successful_rotation_of_both_identities(self, db_session):
        # 1. Provision initial identities
        initial = await provision_identities(db_session, env="live", expires_in_hours=48)
        assert len(initial) == 2

        init_analyst = next(r for r in initial if r["username"] == "viva_analyst")
        init_sensor = next(r for r in initial if r["username"] == "viva_sensor")

        # 2. Execute credential rotation
        rotated = await rotate_identities(db_session, env="live", expires_in_hours=72)
        assert len(rotated) == 2

        rot_analyst = next(r for r in rotated if r["username"] == "viva_analyst")
        rot_sensor = next(r for r in rotated if r["username"] == "viva_sensor")

        # New tokens generated with canonical format
        assert rot_analyst["raw_token"] != init_analyst["raw_token"]
        assert rot_sensor["raw_token"] != init_sensor["raw_token"]
        assert is_canonical_token(rot_analyst["raw_token"]) is True
        assert is_canonical_token(rot_sensor["raw_token"]) is True

        # Prefixes must have rotated
        assert rot_analyst["token_prefix"] != init_analyst["token_prefix"]
        assert rot_sensor["token_prefix"] != init_sensor["token_prefix"]

    async def test_preservation_of_analyst_and_client_uuids_and_created_at(self, db_session):
        # 1. Initial provisioning
        initial = await provision_identities(db_session, env="live", expires_in_hours=48)
        init_analyst = next(r for r in initial if r["username"] == "viva_analyst")
        init_sensor = next(r for r in initial if r["username"] == "viva_sensor")

        # Retrieve DB records to capture created_at
        analyst_rec = (await db_session.execute(select(Analyst).where(Analyst.username == "viva_analyst"))).scalar_one()
        client_rec = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-tier1-workstation"))).scalar_one()
        orig_analyst_created_at = analyst_rec.created_at
        orig_client_created_at = client_rec.created_at

        # 2. Rotate credentials
        rotated = await rotate_identities(db_session, env="live", expires_in_hours=72)
        rot_analyst = next(r for r in rotated if r["username"] == "viva_analyst")
        rot_sensor = next(r for r in rotated if r["username"] == "viva_sensor")

        # UUIDs must be preserved exactly
        assert rot_analyst["analyst_id"] == init_analyst["analyst_id"]
        assert rot_analyst["client_id"] == init_analyst["client_id"]
        assert rot_sensor["analyst_id"] == init_sensor["analyst_id"]
        assert rot_sensor["client_id"] == init_sensor["client_id"]

        # Created_at must be preserved; updated_at must be updated
        analyst_rec_after = (await db_session.execute(select(Analyst).where(Analyst.username == "viva_analyst"))).scalar_one()
        client_rec_after = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-tier1-workstation"))).scalar_one()

        assert analyst_rec_after.created_at == orig_analyst_created_at
        assert client_rec_after.created_at == orig_client_created_at
        assert analyst_rec_after.updated_at >= orig_analyst_created_at

    async def test_preservation_of_case_assignment_relationships(self, db_session):
        # 1. Provision identities
        initial = await provision_identities(db_session, env="live")
        analyst_item = next(r for r in initial if r["username"] == "viva_analyst")
        analyst_uuid = uuid.UUID(analyst_item["analyst_id"])

        # 2. Create a case and link viva_analyst via CaseAssignmentModel
        case = CaseModel(
            id=uuid.uuid4(),
            case_number="CASE-VIVA-2026-001",
            title="Pre-existing Active Investigation",
            description="Case assigned to demo analyst prior to credential rotation.",
            severity="medium",
            status="open",
        )
        db_session.add(case)
        await db_session.flush()

        assignment = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case.id,
            analyst_id=analyst_uuid,
            case_role="lead",
        )
        db_session.add(assignment)
        await db_session.commit()

        # 3. Rotate credentials
        await rotate_identities(db_session, env="live")

        # 4. Verify case assignment is still intact and attached to viva_analyst
        assign_stmt = select(CaseAssignmentModel).where(CaseAssignmentModel.case_id == case.id)
        assign_res = await db_session.execute(assign_stmt)
        persisted_assign = assign_res.scalars().one()

        assert persisted_assign.analyst_id == analyst_uuid
        assert persisted_assign.case_role == "lead"

    async def test_old_credentials_rejected_after_rotation(self, db_session):
        initial = await provision_identities(db_session, env="live")
        old_analyst_token = next(r["raw_token"] for r in initial if r["username"] == "viva_analyst")
        old_sensor_token = next(r["raw_token"] for r in initial if r["username"] == "viva_sensor")

        # Rotate credentials
        await rotate_identities(db_session, env="live")

        settings = Settings(_env_file=None, API_AUTH_ENABLED=True)
        from fastapi import HTTPException

        # Old analyst token must be rejected with 401
        with pytest.raises(HTTPException) as exc_analyst:
            await verify_api_key_fn(x_api_key=old_analyst_token, settings=settings, session=db_session)
        assert exc_analyst.value.status_code == status.HTTP_401_UNAUTHORIZED

        # Old sensor token must be rejected with 401
        with pytest.raises(HTTPException) as exc_sensor:
            await verify_api_key_fn(authorization=f"Bearer {old_sensor_token}", settings=settings, session=db_session)
        assert exc_sensor.value.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_new_credentials_accepted_by_canonical_authentication_verifier(self, db_session):
        await provision_identities(db_session, env="live")
        rotated = await rotate_identities(db_session, env="live", expires_in_hours=48)

        new_analyst_token = next(r["raw_token"] for r in rotated if r["username"] == "viva_analyst")
        new_sensor_token = next(r["raw_token"] for r in rotated if r["username"] == "viva_sensor")

        settings = Settings(_env_file=None, API_AUTH_ENABLED=True)

        # 1. Verify rotated analyst token
        auth_analyst = await verify_api_key_fn(x_api_key=new_analyst_token, settings=settings, session=db_session)
        assert auth_analyst.authenticated is True
        assert auth_analyst.analyst is not None
        assert auth_analyst.analyst.username == "viva_analyst"
        assert auth_analyst.analyst.global_role == GlobalRole.ANALYST_TIER_1
        assert auth_analyst.analyst.is_active is True

        # 2. Verify rotated sensor token
        auth_sensor = await verify_api_key_fn(authorization=f"Bearer {new_sensor_token}", settings=settings, session=db_session)
        assert auth_sensor.authenticated is True
        assert auth_sensor.analyst is not None
        assert auth_sensor.analyst.username == "viva_sensor"
        assert auth_sensor.analyst.global_role == GlobalRole.INGEST
        assert auth_sensor.analyst.is_active is True

    async def test_reactivates_previously_revoked_identities(self, db_session):
        # 1. Provision and revoke
        await provision_identities(db_session, env="live")
        await revoke_identities(db_session)

        # Confirm inactive
        analyst_rec = (await db_session.execute(select(Analyst).where(Analyst.username == "viva_analyst"))).scalar_one()
        client_rec = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-tier1-workstation"))).scalar_one()
        assert analyst_rec.is_active is False
        assert client_rec.is_active is False

        # 2. Rotate credentials
        await rotate_identities(db_session, env="live")

        # 3. Confirm reactivated
        analyst_after = (await db_session.execute(select(Analyst).where(Analyst.username == "viva_analyst"))).scalar_one()
        client_after = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-tier1-workstation"))).scalar_one()
        assert analyst_after.is_active is True
        assert client_after.is_active is True

    async def test_correct_expiration_timestamp_calculation(self, db_session):
        await provision_identities(db_session, env="live")

        # Rotate with 72 hours
        before = datetime.now(timezone.utc)
        await rotate_identities(db_session, env="live", expires_in_hours=72)
        after = datetime.now(timezone.utc)

        client_rec = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-tier1-workstation"))).scalar_one()
        assert client_rec.expires_at is not None
        exp = client_rec.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        assert exp >= before + timedelta(hours=71, minutes=59)
        assert exp <= after + timedelta(hours=72, minutes=1)

        # Rotate with 0 hours (Never expires)
        await rotate_identities(db_session, env="live", expires_in_hours=None)
        client_rec_no_exp = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-tier1-workstation"))).scalar_one()
        assert client_rec_no_exp.expires_at is None

    async def test_missing_analyst_causes_complete_rollback(self, db_session):
        await provision_identities(db_session, env="live")

        # Delete associated client first to avoid ON DELETE RESTRICT, then analyst
        await db_session.execute(delete(AnalystApiClient).where(AnalystApiClient.client_name == "viva-sysmon-forwarder"))
        await db_session.execute(delete(Analyst).where(Analyst.username == "viva_sensor"))
        await db_session.commit()

        # Capture analyst prefix before failed rotate
        analyst_client_before = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-tier1-workstation"))).scalar_one()
        orig_prefix = analyst_client_before.token_prefix

        with pytest.raises(RuntimeError) as exc_info:
            await rotate_identities(db_session, env="live")

        assert "Rotation pre-flight check failed" in str(exc_info.value)
        assert "Expected 2 demo analysts, found 1" in str(exc_info.value)

        # Verify rollback: remaining analyst was NOT rotated
        analyst_client_after = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-tier1-workstation"))).scalar_one()
        assert analyst_client_after.token_prefix == orig_prefix

    async def test_missing_client_causes_complete_rollback(self, db_session):
        await provision_identities(db_session, env="live")

        # Delete one client
        await db_session.execute(delete(AnalystApiClient).where(AnalystApiClient.client_name == "viva-sysmon-forwarder"))
        await db_session.commit()

        with pytest.raises(RuntimeError) as exc_info:
            await rotate_identities(db_session, env="live")

        assert "Rotation pre-flight check failed" in str(exc_info.value)
        assert "Expected 2 demo API clients, found 1" in str(exc_info.value)

    async def test_incorrect_analyst_client_association_causes_rollback(self, db_session):
        await provision_identities(db_session, env="live")

        # Cross-wire client analyst_id
        analyst = (await db_session.execute(select(Analyst).where(Analyst.username == "viva_analyst"))).scalar_one()
        sensor_client = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-sysmon-forwarder"))).scalar_one()
        sensor_client.analyst_id = analyst.id
        await db_session.commit()

        with pytest.raises(RuntimeError) as exc_info:
            await rotate_identities(db_session, env="live")

        assert "Rotation pre-flight check failed" in str(exc_info.value)
        assert "Client 'viva-sysmon-forwarder' is associated with analyst ID" in str(exc_info.value)

    async def test_incorrect_global_role_causes_rollback(self, db_session):
        await provision_identities(db_session, env="live")

        # Tamper with global role
        analyst = (await db_session.execute(select(Analyst).where(Analyst.username == "viva_analyst"))).scalar_one()
        analyst.global_role = "analyst_tier_2"
        await db_session.commit()

        with pytest.raises(RuntimeError) as exc_info:
            await rotate_identities(db_session, env="live")

        assert "Rotation pre-flight check failed" in str(exc_info.value)
        assert "has global role 'analyst_tier_2', expected 'analyst_tier_1'" in str(exc_info.value)

    async def test_token_prefix_collision_causes_rollback(self, db_session, monkeypatch):
        await provision_identities(db_session, env="live")

        # Insert a third-party client with a specific prefix
        third_party_analyst = Analyst(
            id=uuid.uuid4(),
            username="external_service",
            email="ext@aisop.local",
            global_role=GlobalRole.INGEST.value,
            is_active=True,
        )
        db_session.add(third_party_analyst)
        await db_session.flush()

        colliding_prefix = "aaaaaaaaaaaaaaaa"
        third_party_client = AnalystApiClient(
            id=uuid.uuid4(),
            analyst_id=third_party_analyst.id,
            client_name="external-collector",
            token_prefix=colliding_prefix,
            hashed_secret="b" * 64,
            is_active=True,
        )
        db_session.add(third_party_client)
        await db_session.commit()

        # Monkeypatch generate_canonical_credential to return the colliding prefix on the 2nd identity
        call_count = 0
        from backend.scripts import provision_demo_identities

        def mock_generate(env="live"):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                # Force collision on second identity
                return (f"aisop_{env}_{colliding_prefix}_{'c'*64}", colliding_prefix, "c" * 64)
            return (f"aisop_{env}_{'d'*16}_{'d'*64}", "d" * 16, "d" * 64)

        monkeypatch.setattr(provision_demo_identities, "generate_canonical_credential", mock_generate)

        # Capture analyst prefix before rotation attempt
        analyst_client_before = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-tier1-workstation"))).scalar_one()
        orig_prefix = analyst_client_before.token_prefix

        with pytest.raises(RuntimeError) as exc_info:
            await rotate_identities(db_session, env="live")

        assert "Unexpected token prefix collision during rotation" in str(exc_info.value)

        # Verify rollback: 1st identity's token was also rolled back
        analyst_client_after = (await db_session.execute(select(AnalystApiClient).where(AnalystApiClient.client_name == "viva-tier1-workstation"))).scalar_one()
        assert analyst_client_after.token_prefix == orig_prefix

    async def test_plaintext_credentials_never_persisted(self, db_session):
        await provision_identities(db_session, env="live")
        rotated = await rotate_identities(db_session, env="live")
        analyst_token = next(r["raw_token"] for r in rotated if r["username"] == "viva_analyst")

        client_stmt = select(AnalystApiClient)
        client_res = await db_session.execute(client_stmt)
        clients = client_res.scalars().all()

        for c in clients:
            assert len(c.token_prefix) == 16
            assert len(c.hashed_secret) == 64
            # Plaintext raw token string must NEVER exist in any database column
            assert analyst_token not in c.token_prefix
            assert analyst_token not in c.hashed_secret
            assert "aisop_" not in c.token_prefix
            assert "aisop_" not in c.hashed_secret

    async def test_conflicting_cli_flags_rejected(self, monkeypatch):
        # Test --rotate combined with --revoke
        monkeypatch.setattr("sys.argv", ["provision_demo_identities.py", "--rotate", "--revoke"])
        ret = await main_async()
        assert ret == 1

        # Test --rotate combined with --status
        monkeypatch.setattr("sys.argv", ["provision_demo_identities.py", "--rotate", "--status"])
        ret = await main_async()
        assert ret == 1

        # Test --revoke combined with --status
        monkeypatch.setattr("sys.argv", ["provision_demo_identities.py", "--revoke", "--status"])
        ret = await main_async()
        assert ret == 1

    async def test_status_mode_remains_read_only(self, db_session, monkeypatch):
        await provision_identities(db_session, env="live")

        # Mock session_factory in provision_demo_identities to use db_session
        from backend.scripts import provision_demo_identities
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_session_ctx():
            yield db_session

        monkeypatch.setattr(provision_demo_identities, "get_session_factory", lambda: mock_session_ctx)
        monkeypatch.setattr("sys.argv", ["provision_demo_identities.py", "--status"])

        # Capture state before
        analysts_before = (await db_session.execute(select(Analyst))).scalars().all()
        clients_before = (await db_session.execute(select(AnalystApiClient))).scalars().all()

        ret = await main_async()
        assert ret == 0

        # State after must be identical
        analysts_after = (await db_session.execute(select(Analyst))).scalars().all()
        clients_after = (await db_session.execute(select(AnalystApiClient))).scalars().all()

        assert len(analysts_before) == len(analysts_after)
        assert len(clients_before) == len(clients_after)
        assert [a.updated_at for a in analysts_before] == [a.updated_at for a in analysts_after]


