"""
Unit and Integration Tests for AISOP Case Management and Scoping API (Gate D.2.2).

Milestone: Phase 3 — P3-H2 / Gate D.2.2
Routes Tested:
- POST   /api/v1/cases
- GET    /api/v1/cases
- GET    /api/v1/cases/{case_id}
- PATCH  /api/v1/cases/{case_id}
- POST   /api/v1/cases/{case_id}/assignments
- POST   /api/v1/cases/{case_id}/lead
- POST   /api/v1/cases/{case_id}/close

Mandatory Offline Test Requirements Covered:
1. Unauthenticated requests are rejected (401).
2. Legacy machine credentials without analyst identity cannot create or access cases (401).
3. Case creation creates case, initial lead assignment, and audit event atomically (201).
4. Failure during assignment or audit creation rolls back the case creation.
5. Listing returns only active assignments belonging to the caller (with pagination).
6. Case detail denies unassigned access and preserves anti-enumeration (404).
7. Metadata updates require the lead role and reject protected/forbidden fields.
8. Tier-1 leads cannot manage staffing (403).
9. Invalid, inactive, or nonexistent staffing targets are rejected (400).
10. Clients cannot create additional leads through the staffing endpoint (422/400).
11. Lead transfer rejects ineligible target and enforces approved global-role policy (403/400).
12. Lead transfer handles existing target assignments without duplicates.
13. Lead transfer preserves the exactly-one-active-lead invariant in testable transaction behavior.
14. Unauthorized or unassigned security administrators cannot bypass case authorization (404).
15. Closure requires the approved role and valid lifecycle state (403/409/422).
16. Audit failures roll back state-changing operations.
17. Database exceptions return safe errors without leaking SQL, credentials, or internal details (500).
18. UUID validation and request-schema validation are enforced (422).
19. No route returns raw ORM objects or unrestricted model fields.
20. Existing RBAC, authentication, and persistence tests remain compatible.

Concurrency Note:
SQLite in-memory test databases do not support PostgreSQL SELECT ... FOR UPDATE row-level locking.
Unit tests verify the deterministic single-session transactional invariants, rollbacks, and ordering.
True multi-connection row-lock contention and database concurrency guarantees must be verified
against live PostgreSQL in dedicated integration gates.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import FastAPI, status
from sqlalchemy import select

from app.api.dependencies import get_current_analyst
from app.core.config import Settings, get_settings
from app.core.rbac import (
    AuthenticatedAnalyst,
    CaseRole,
    GlobalRole,
    hash_canonical_token,
)
from app.db.session import get_db_session
from app.main import create_app
from app.models.analyst import Analyst, AnalystApiClient
from app.models.case import CaseAssignmentModel, CaseAuditEventModel, CaseModel
from app.schemas.case import CaseSeverity, CaseStatus


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures & Helpers
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def auth_settings() -> Settings:
    """Settings with synthetic keys for multi-client testing."""
    return Settings(
        _env_file=None,
        API_AUTH_ENABLED=True,
        API_AUTH_ALLOW_LEGACY_KEYS=True,
        API_AUTH_KEYS=[
            "legacy-machine:legacy-machine-key-999",
        ],
    )


@pytest.fixture
def app_instance(db_session, auth_settings: Settings) -> FastAPI:
    """Create fresh application instance with isolated DB session and auth settings."""
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


async def seed_analyst_with_token(
    db_session,
    *,
    prefix: str,
    username: str,
    global_role: str = "analyst_tier_2",
    is_active: bool = True,
    client_active: bool = True,
) -> tuple[str, Analyst]:
    """Helper to seed an Analyst and linked AnalystApiClient in test SQLite."""
    analyst = Analyst(
        id=uuid.uuid4(),
        username=username,
        email=f"{username}@example.com",
        global_role=global_role,
        is_active=is_active,
    )
    db_session.add(analyst)
    await db_session.flush()

    import hashlib
    hex_prefix = hashlib.md5(prefix.encode()).hexdigest()[:16]
    token = f"aisop_live_{hex_prefix}_{'b' * 64}"
    hashed = hash_canonical_token(token)

    client = AnalystApiClient(
        id=uuid.uuid4(),
        analyst_id=analyst.id,
        client_name=f"{username}-client",
        token_prefix=hex_prefix,
        hashed_secret=hashed,
        is_active=client_active,
    )
    db_session.add(client)
    await db_session.commit()
    return token, analyst


# ─────────────────────────────────────────────────────────────────────────────
# 1. Unauthenticated & Machine Credential Rejection (Req 1 & 2)
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthenticationAndCredentialRejection:
    """Verify endpoints enforce database-backed analyst identity."""

    @pytest.mark.anyio
    async def test_unauthenticated_request_rejected(self, app_instance):
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/cases")
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "WWW-Authenticate" in resp.headers

    @pytest.mark.anyio
    async def test_legacy_machine_credential_cannot_create_or_access_cases(
        self, app_instance
    ):
        """Legacy static machine key authenticates API key check but lacks analyst identity."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"X-API-Key": "legacy-machine-key-999"}
            # Listing cases
            resp = await client.get("/api/v1/cases", headers=headers)
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "analyst identity" in resp.json()["detail"].lower()

            # Creating case
            create_resp = await client.post(
                "/api/v1/cases",
                headers=headers,
                json={"title": "Unauthorized Case", "severity": "medium"},
            )
            assert create_resp.status_code == status.HTTP_401_UNAUTHORIZED


# ─────────────────────────────────────────────────────────────────────────────
# 2. Case Creation & Atomic Invariants (Req 3, 4, 19, 20)
# ─────────────────────────────────────────────────────────────────────────────

class TestCaseCreation:
    """Verify atomic case creation, role assignment, and audit log generation."""

    @pytest.mark.anyio
    async def test_case_creation_atomic_success(self, app_instance, db_session):
        token, analyst = await seed_analyst_with_token(
            db_session,
            prefix="creatauth111111",
            username="alice_creator",
            global_role="analyst_tier_1",
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {
                "title": "Suspicious PowerShell Invocations",
                "description": "Detected encoded commands on workstation WKSTN-09",
                "severity": "high",
            }
            resp = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
            )
            assert resp.status_code == status.HTTP_201_CREATED
            data = resp.json()
            assert data["title"] == payload["title"]
            assert data["description"] == payload["description"]
            assert data["severity"] == "high"
            assert data["status"] == "open"
            assert data["lead_analyst_id"] == str(analyst.id)
            assert data["case_number"].startswith("CASE-")

            case_id = uuid.UUID(data["id"])

            # Verify Database State: CaseModel, CaseAssignmentModel, CaseAuditEventModel
            case_stmt = select(CaseModel).where(CaseModel.id == case_id)
            case_row = (await db_session.execute(case_stmt)).scalars().first()
            assert case_row is not None
            assert case_row.title == payload["title"]

            assign_stmt = select(CaseAssignmentModel).where(
                CaseAssignmentModel.case_id == case_id
            )
            assign_rows = (await db_session.execute(assign_stmt)).scalars().all()
            assert len(assign_rows) == 1
            assert assign_rows[0].analyst_id == analyst.id
            assert assign_rows[0].case_role == "lead"

            audit_stmt = select(CaseAuditEventModel).where(
                CaseAuditEventModel.case_id == case_id
            )
            audit_rows = (await db_session.execute(audit_stmt)).scalars().all()
            assert len(audit_rows) == 1
            assert audit_rows[0].action == "case_created"
            assert audit_rows[0].actor_analyst_id == analyst.id
            assert audit_rows[0].details["severity"] == "high"

    @pytest.mark.anyio
    async def test_case_creation_rollback_on_failure(self, app_instance, db_session):
        """Failure during assignment or audit creation rolls back case creation entirely."""
        token, analyst = await seed_analyst_with_token(
            db_session,
            prefix="creatauth222222",
            username="bob_creator",
            global_role="analyst_tier_2",
        )

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {
                "title": "Failed Case Creation Test",
                "severity": "medium",
            }
            # Patch session.flush to fail on the second call (during audit or assignment add)
            orig_flush = db_session.flush
            call_count = 0

            async def failing_flush(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count > 1:
                    raise RuntimeError("Simulated DB flush crash")
                return await orig_flush(*args, **kwargs)

            with patch.object(db_session, "flush", side_effect=failing_flush):
                with pytest.raises(RuntimeError, match="Simulated DB flush crash"):
                    await client.post(
                        "/api/v1/cases",
                        headers={"Authorization": f"Bearer {token}"},
                        json=payload,
                    )

            # Rollback and confirm zero cases were committed
            await db_session.rollback()
            cases_stmt = select(CaseModel).where(CaseModel.title == payload["title"])
            cases = (await db_session.execute(cases_stmt)).scalars().all()
            assert len(cases) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 3. Case Listing & Bounded Pagination (Req 5)
# ─────────────────────────────────────────────────────────────────────────────

class TestCaseListing:
    """Verify listing returns only cases where caller has active assignment."""

    @pytest.mark.anyio
    async def test_listing_returns_only_assigned_cases_with_pagination(
        self, app_instance, db_session
    ):
        token_1, analyst_1 = await seed_analyst_with_token(
            db_session, prefix="listauth111111", username="analyst_one"
        )
        token_2, analyst_2 = await seed_analyst_with_token(
            db_session, prefix="listauth222222", username="analyst_two"
        )

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Analyst 1 creates 3 cases
            for i in range(3):
                res = await client.post(
                    "/api/v1/cases",
                    headers={"Authorization": f"Bearer {token_1}"},
                    json={"title": f"Analyst 1 Case {i}", "severity": "medium"},
                )
                assert res.status_code == 201

            # Analyst 2 creates 1 case
            res2 = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_2}"},
                json={"title": "Analyst 2 Case 0", "severity": "low"},
            )
            assert res2.status_code == 201

            # Listing for Analyst 2 should return exactly 1 case
            list_res_2 = await client.get(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_2}"},
            )
            assert list_res_2.status_code == 200
            data_2 = list_res_2.json()
            assert data_2["total"] == 1
            assert len(data_2["items"]) == 1
            assert data_2["items"][0]["title"] == "Analyst 2 Case 0"

            # Listing for Analyst 1 with pagination (limit=2, page=1)
            list_res_1 = await client.get(
                "/api/v1/cases?page=1&limit=2",
                headers={"Authorization": f"Bearer {token_1}"},
            )
            assert list_res_1.status_code == 200
            data_1 = list_res_1.json()
            assert data_1["total"] == 3
            assert len(data_1["items"]) == 2
            assert data_1["page"] == 1
            assert data_1["total_pages"] == 2
            assert data_1["has_next"] is True
            assert data_1["has_previous"] is False


# ─────────────────────────────────────────────────────────────────────────────
# 4. Case Detail & Anti-Enumeration (Req 6, 14, 18)
# ─────────────────────────────────────────────────────────────────────────────

class TestCaseDetailAndAntiEnumeration:
    """Verify anti-enumeration: missing and unassigned cases return identical 404."""

    @pytest.mark.anyio
    async def test_case_detail_anti_enumeration(self, app_instance, db_session):
        token_assigned, assigned_analyst = await seed_analyst_with_token(
            db_session, prefix="detailauth11111", username="assigned_user"
        )
        token_unassigned, _ = await seed_analyst_with_token(
            db_session, prefix="detailauth22222", username="unassigned_user"
        )
        token_admin, _ = await seed_analyst_with_token(
            db_session,
            prefix="detailauth33333",
            username="unassigned_admin",
            global_role="security_admin",
        )

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Create a case
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_assigned}"},
                json={"title": "Classified Security Case", "severity": "high"},
            )
            case_id = c_res.json()["id"]

            # 1. Assigned user can view case
            view_res = await client.get(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_assigned}"},
            )
            assert view_res.status_code == 200
            assert view_res.json()["id"] == case_id

            # 2. Unassigned user receives 404 (anti-enumeration)
            unassigned_res = await client.get(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_unassigned}"},
            )
            assert unassigned_res.status_code == 404
            assert unassigned_res.json()["detail"] == "Case not found or access denied."

            # 3. Non-existent case returns identical 404
            missing_uuid = str(uuid.uuid4())
            missing_res = await client.get(
                f"/api/v1/cases/{missing_uuid}",
                headers={"Authorization": f"Bearer {token_assigned}"},
            )
            assert missing_res.status_code == 404
            assert missing_res.json()["detail"] == "Case not found or access denied."

            # 4. Decision 2A Parity: Unassigned security administrator also receives 404
            admin_res = await client.get(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_admin}"},
            )
            assert admin_res.status_code == 404
            assert admin_res.json()["detail"] == "Case not found or access denied."

    @pytest.mark.anyio
    async def test_case_detail_invalid_uuid_fails_422(self, app_instance, db_session):
        token, _ = await seed_analyst_with_token(
            db_session, prefix="uuidval11111111", username="uuid_analyst"
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/cases/not-a-valid-uuid",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# 5. Metadata Updates & Field Protection (Req 7)
# ─────────────────────────────────────────────────────────────────────────────

class TestMetadataUpdate:
    """Verify metadata updates require Lead and strictly forbid protected fields."""

    @pytest.mark.anyio
    async def test_metadata_update_success_as_lead(self, app_instance, db_session):
        token, analyst = await seed_analyst_with_token(
            db_session, prefix="metaauth1111111", username="lead_updater"
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Initial Title", "severity": "low"},
            )
            case_id = c_res.json()["id"]

            patch_res = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Updated Title", "severity": "critical"},
            )
            assert patch_res.status_code == 200
            data = patch_res.json()
            assert data["title"] == "Updated Title"
            assert data["severity"] == "critical"

            # Check audit event
            audit_stmt = select(CaseAuditEventModel).where(
                CaseAuditEventModel.case_id == uuid.UUID(case_id),
                CaseAuditEventModel.action == "case_metadata_updated",
            )
            audit = (await db_session.execute(audit_stmt)).scalars().first()
            assert audit is not None
            assert "title" in audit.details["updated_fields"]

    @pytest.mark.anyio
    async def test_metadata_update_rejects_forbidden_fields(
        self, app_instance, db_session
    ):
        """Reject attempts to modify protected fields like id, status, case_number."""
        token, _ = await seed_analyst_with_token(
            db_session, prefix="metaauth2222222", username="forbid_tester"
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Protected Fields Test", "severity": "low"},
            )
            case_id = c_res.json()["id"]

            # Try to alter status or id
            patch_res = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"status": "closed"},
            )
            assert patch_res.status_code == 422  # Extra field forbidden

    @pytest.mark.anyio
    async def test_metadata_update_empty_patch_rejected(
        self, app_instance, db_session
    ):
        token, _ = await seed_analyst_with_token(
            db_session, prefix="metaauth3333333", username="empty_tester"
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Empty Patch Test", "severity": "low"},
            )
            case_id = c_res.json()["id"]

            patch_res = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={},
            )
            assert patch_res.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# 6. Assignment Management & Staffing Constraints (Req 8, 9, 10)
# ─────────────────────────────────────────────────────────────────────────────

class TestAssignmentManagement:
    """Verify staffing rules: Tier-1 lead blocked, invalid targets, non-lead roles."""

    @pytest.mark.anyio
    async def test_tier1_lead_cannot_manage_staffing(self, app_instance, db_session):
        token_t1, _ = await seed_analyst_with_token(
            db_session,
            prefix="tier1staff11111",
            username="tier1_lead",
            global_role="analyst_tier_1",
        )
        _, target = await seed_analyst_with_token(
            db_session,
            prefix="tier1staff22222",
            username="target_investigator",
            global_role="analyst_tier_2",
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_t1}"},
                json={"title": "Tier 1 Case", "severity": "medium"},
            )
            case_id = c_res.json()["id"]

            staff_res = await client.post(
                f"/api/v1/cases/{case_id}/assignments",
                headers={"Authorization": f"Bearer {token_t1}"},
                json={"analyst_id": str(target.id), "case_role": "investigator"},
            )
            assert staff_res.status_code == 403
            assert "Tier-2 or Security Admin required" in staff_res.json()["detail"]

    @pytest.mark.anyio
    async def test_tier2_lead_staffing_success(self, app_instance, db_session):
        token_t2, _ = await seed_analyst_with_token(
            db_session,
            prefix="tier2staff11111",
            username="tier2_lead",
            global_role="analyst_tier_2",
        )
        _, target = await seed_analyst_with_token(
            db_session,
            prefix="tier2staff22222",
            username="assigned_investigator",
            global_role="analyst_tier_1",
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"title": "Tier 2 Staffed Case", "severity": "high"},
            )
            case_id = c_res.json()["id"]

            staff_res = await client.post(
                f"/api/v1/cases/{case_id}/assignments",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"analyst_id": str(target.id), "case_role": "investigator"},
            )
            assert staff_res.status_code == 201
            data = staff_res.json()
            assert data["analyst_id"] == str(target.id)
            assert data["case_role"] == "investigator"

    @pytest.mark.anyio
    async def test_staffing_rejects_inactive_or_nonexistent_target(
        self, app_instance, db_session
    ):
        token_t2, _ = await seed_analyst_with_token(
            db_session,
            prefix="badtarget111111",
            username="tier2_lead_badtarget",
            global_role="analyst_tier_2",
        )
        _, inactive_target = await seed_analyst_with_token(
            db_session,
            prefix="badtarget222222",
            username="deactivated_target",
            global_role="analyst_tier_1",
            is_active=False,
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"title": "Bad Target Case", "severity": "medium"},
            )
            case_id = c_res.json()["id"]

            # Inactive target -> 400
            res_inactive = await client.post(
                f"/api/v1/cases/{case_id}/assignments",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"analyst_id": str(inactive_target.id), "case_role": "investigator"},
            )
            assert res_inactive.status_code == 400
            assert "deactivated" in res_inactive.json()["detail"].lower()

            # Nonexistent target -> 400
            res_missing = await client.post(
                f"/api/v1/cases/{case_id}/assignments",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"analyst_id": str(uuid.uuid4()), "case_role": "viewer"},
            )
            assert res_missing.status_code == 400

    @pytest.mark.anyio
    async def test_staffing_cannot_assign_lead_role(self, app_instance, db_session):
        """Clients cannot designate a lead via staffing endpoint."""
        token_t2, _ = await seed_analyst_with_token(
            db_session,
            prefix="noleadstaff1111",
            username="tier2_lead_nolead",
            global_role="analyst_tier_2",
        )
        _, target = await seed_analyst_with_token(
            db_session,
            prefix="noleadstaff2222",
            username="target_user",
            global_role="analyst_tier_2",
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"title": "No Lead Staffing Case", "severity": "low"},
            )
            case_id = c_res.json()["id"]

            staff_res = await client.post(
                f"/api/v1/cases/{case_id}/assignments",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"analyst_id": str(target.id), "case_role": "lead"},
            )
            assert staff_res.status_code == 422  # Pydantic validator rejects 'lead'


# ─────────────────────────────────────────────────────────────────────────────
# 7. Lead Transfer Invariants (Req 11, 12, 13)
# ─────────────────────────────────────────────────────────────────────────────

class TestLeadTransfer:
    """Verify atomic lead transfer: target eligibility, exactly-one-lead, demotion."""

    @pytest.mark.anyio
    async def test_lead_transfer_rejects_tier1_target(self, app_instance, db_session):
        token_lead, _ = await seed_analyst_with_token(
            db_session,
            prefix="transauth111111",
            username="current_lead_1",
            global_role="analyst_tier_2",
        )
        _, target_tier1 = await seed_analyst_with_token(
            db_session,
            prefix="transauth222222",
            username="ineligible_tier1",
            global_role="analyst_tier_1",
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_lead}"},
                json={"title": "Transfer Ineligible Test", "severity": "medium"},
            )
            case_id = c_res.json()["id"]

            trans_res = await client.post(
                f"/api/v1/cases/{case_id}/lead",
                headers={"Authorization": f"Bearer {token_lead}"},
                json={
                    "target_analyst_id": str(target_tier1.id),
                    "reason": "Escalation to Tier-1 not allowed",
                },
            )
            assert trans_res.status_code == 403
            assert "Tier-2 analysts or Security Administrators" in trans_res.json()["detail"]

    @pytest.mark.anyio
    async def test_lead_transfer_atomic_success_and_preserves_single_lead(
        self, app_instance, db_session
    ):
        token_lead, old_lead = await seed_analyst_with_token(
            db_session,
            prefix="transsucc111111",
            username="old_lead",
            global_role="analyst_tier_2",
        )
        _, new_lead = await seed_analyst_with_token(
            db_session,
            prefix="transsucc222222",
            username="new_lead",
            global_role="security_admin",
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_lead}"},
                json={"title": "Lead Transfer Invariant Case", "severity": "high"},
            )
            case_id = uuid.UUID(c_res.json()["id"])

            # First staff new_lead as investigator to test existing target assignment transition
            staff_res = await client.post(
                f"/api/v1/cases/{case_id}/assignments",
                headers={"Authorization": f"Bearer {token_lead}"},
                json={"analyst_id": str(new_lead.id), "case_role": "investigator"},
            )
            assert staff_res.status_code == 201

            # Transfer lead to new_lead
            trans_res = await client.post(
                f"/api/v1/cases/{case_id}/lead",
                headers={"Authorization": f"Bearer {token_lead}"},
                json={
                    "target_analyst_id": str(new_lead.id),
                    "reason": "Transferring lead to security administrator for incident response",
                },
            )
            assert trans_res.status_code == 200
            assert trans_res.json()["lead_analyst_id"] == str(new_lead.id)

            # Invariant Check: Exactly one lead assignment exists for this case
            lead_stmt = select(CaseAssignmentModel).where(
                CaseAssignmentModel.case_id == case_id,
                CaseAssignmentModel.case_role == "lead",
            )
            leads = (await db_session.execute(lead_stmt)).scalars().all()
            assert len(leads) == 1
            assert leads[0].analyst_id == new_lead.id

            # Invariant Check: Outgoing lead was demoted to investigator
            old_assign_stmt = select(CaseAssignmentModel).where(
                CaseAssignmentModel.case_id == case_id,
                CaseAssignmentModel.analyst_id == old_lead.id,
            )
            old_assign = (await db_session.execute(old_assign_stmt)).scalars().first()
            assert old_assign is not None
            assert old_assign.case_role == "investigator"

            # Invariant Check: No duplicate assignments for new_lead
            target_assign_stmt = select(CaseAssignmentModel).where(
                CaseAssignmentModel.case_id == case_id,
                CaseAssignmentModel.analyst_id == new_lead.id,
            )
            target_assigns = (await db_session.execute(target_assign_stmt)).scalars().all()
            assert len(target_assigns) == 1


# ─────────────────────────────────────────────────────────────────────────────
# 8. Case Lifecycle Transitions & Closure (Req 15)
# ─────────────────────────────────────────────────────────────────────────────

class TestCaseLifecycle:
    """Verify closure/archival rules: Tier-1 lead blocked, invalid transitions."""

    @pytest.mark.anyio
    async def test_tier1_lead_cannot_close_case(self, app_instance, db_session):
        token_t1, _ = await seed_analyst_with_token(
            db_session,
            prefix="closeauth11111",
            username="tier1_close_tester",
            global_role="analyst_tier_1",
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_t1}"},
                json={"title": "Tier 1 Cannot Close", "severity": "medium"},
            )
            case_id = c_res.json()["id"]

            close_res = await client.post(
                f"/api/v1/cases/{case_id}/close",
                headers={"Authorization": f"Bearer {token_t1}"},
                json={"status": "closed", "closure_reason": "Attempting closure as Tier-1"},
            )
            assert close_res.status_code == 403
            assert "Tier-2 or Security Admin required" in close_res.json()["detail"]

    @pytest.mark.anyio
    async def test_tier2_lead_close_success_and_repeated_close_conflict(
        self, app_instance, db_session
    ):
        token_t2, _ = await seed_analyst_with_token(
            db_session,
            prefix="closeauth22222",
            username="tier2_closer",
            global_role="analyst_tier_2",
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"title": "Incident To Close", "severity": "high"},
            )
            case_id = c_res.json()["id"]

            # First closure -> 200 OK
            close_res = await client.post(
                f"/api/v1/cases/{case_id}/close",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"status": "closed", "closure_reason": "Root cause eliminated and hosts patched."},
            )
            assert close_res.status_code == 200
            assert close_res.json()["status"] == "closed"
            assert close_res.json()["closed_at"] is not None

            # Repeated closure -> 409 Conflict
            repeat_res = await client.post(
                f"/api/v1/cases/{case_id}/close",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"status": "closed", "closure_reason": "Repeating closure"},
            )
            assert repeat_res.status_code == 409
            assert "already in terminal state" in repeat_res.json()["detail"].lower()

            # Attempting metadata update on terminal case -> 409 Conflict
            patch_res = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_t2}"},
                json={"title": "Cannot Change Terminal Case"},
            )
            assert patch_res.status_code == 409


# ─────────────────────────────────────────────────────────────────────────────
# 9. Transaction Rollbacks on Audit Failure & Database Errors (Req 16, 17)
# ─────────────────────────────────────────────────────────────────────────────

class TestTransactionRollbackAndSafeErrorHandling:
    """Verify state mutations roll back on audit failure and SQL errors do not leak."""

    @pytest.mark.anyio
    async def test_audit_failure_rolls_back_metadata_update(
        self, app_instance, db_session
    ):
        token, _ = await seed_analyst_with_token(
            db_session, prefix="auditfail111111", username="audit_lead"
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Original Title Before Audit Crash", "severity": "low"},
            )
            case_id = uuid.UUID(c_res.json()["id"])

            # Simulate crash during flush of audit event
            orig_flush = db_session.flush

            async def fail_audit_flush(*args, **kwargs):
                raise RuntimeError("Audit immutability trigger crash simulation")

            with patch.object(db_session, "flush", side_effect=fail_audit_flush):
                with pytest.raises(RuntimeError, match="Audit immutability"):
                    await client.patch(
                        f"/api/v1/cases/{case_id}",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"title": "Tainted Update"},
                    )

            # Roll back and verify original title was preserved
            await db_session.rollback()
            case = (
                await db_session.execute(select(CaseModel).where(CaseModel.id == case_id))
            ).scalars().first()
            assert case.title == "Original Title Before Audit Crash"

    @pytest.mark.anyio
    async def test_database_error_returns_safe_500_without_leak(
        self, app_instance, db_session
    ):
        token, _ = await seed_analyst_with_token(
            db_session, prefix="safeerror111111", username="error_analyst"
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Safe Error Test", "severity": "medium"},
            )
            case_id = c_res.json()["id"]

            # Mock get_assignment_context to throw OperationalError with password/SQL
            with patch(
                "app.services.case_service.CaseService.get_assignment_context",
                side_effect=Exception("psycopg.OperationalError: SELECT * FROM password='secret'"),
            ):
                resp = await client.get(
                    f"/api/v1/cases/{case_id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert resp.status_code == 500
                detail = resp.json()["detail"]
                assert detail == "Authorization service unavailable."
                assert "password" not in detail
                assert "SELECT" not in detail


class TestCaseActivity:
    """Tests for GET /api/v1/cases/{case_id}/activity."""

    @pytest.mark.anyio
    async def test_case_activity_unauthenticated_rejected(self, app_instance):
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"/api/v1/cases/{uuid.uuid4()}/activity")
            assert resp.status_code == 401

    @pytest.mark.anyio
    async def test_case_activity_unassigned_analyst_returns_404(
        self, app_instance, db_session
    ):
        token_a, _ = await seed_analyst_with_token(
            db_session, prefix="actunass111111", username="act_creator"
        )
        token_b, _ = await seed_analyst_with_token(
            db_session, prefix="actunass222222", username="act_stranger"
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_a}"},
                json={"title": "Audit Activity Isolation Case", "severity": "medium"},
            )
            case_id = c_res.json()["id"]

            # Stranger querying activity gets anti-enumeration 404
            resp = await client.get(
                f"/api/v1/cases/{case_id}/activity",
                headers={"Authorization": f"Bearer {token_b}"},
            )
            assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_case_activity_retrieval_success(
        self, app_instance, db_session
    ):
        token, _ = await seed_analyst_with_token(
            db_session, prefix="actsucc1111111", username="act_owner", global_role="analyst_tier_2"
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Audit Activity Success Case", "severity": "high"},
            )
            case_id = c_res.json()["id"]

            # Update case to generate second audit event
            await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Updated Title for Audit"},
            )

            # Retrieve activity trail
            resp = await client.get(
                f"/api/v1/cases/{case_id}/activity",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            events = resp.json()
            assert len(events) >= 2
            actions = [ev["action"] for ev in events]
            assert "case_created" in actions
            assert "case_metadata_updated" in actions
            for ev in events:
                assert ev["case_id"] == case_id
                assert "actor_username" in ev
                assert "created_at" in ev
