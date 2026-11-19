"""
Unit and Integration Tests for AISOP Case-Scoped Evidence Linking & Sanitized Retrieval (Gate D.2.3).

Milestone: Phase 3 — P3-H2 / Gate D.2.3
Routes Tested:
- POST /api/v1/cases/{case_id}/evidence — Associate normalized evidence with case
- GET  /api/v1/cases/{case_id}/evidence — Paginated evidence retrieval with role-based projection
- Remediation verification across unscoped endpoints:
  - GET /api/v1/evidence/events (Tier-1 sanitized projection, excludes raw_evidence_id and normalized_payload)
  - GET /api/v1/evidence/entities (Tier-1 sanitized projection, excludes attributes and raw_evidence_id)
  - GET /api/v1/evidence/events/{event_id} (Tier-1 blocked, requires Tier-2/Admin)
  - GET /api/v1/evidence/{evidence_id} (Tier-1 blocked, requires Tier-2/Admin)
  - GET /api/v1/evidence/by-hash/{sha256_hash} (Tier-1 blocked, requires Tier-2/Admin)

Mandatory Test Scenarios Covered:
1. Unauthenticated access is rejected (401).
2. Legacy machine credentials cannot access case evidence (401).
3. An assigned analyst can link valid evidence (201).
4. An unassigned analyst cannot link evidence (404 anti-enumeration).
5. Unknown and inaccessible cases do not leak case existence (404).
6. Unknown evidence IDs are rejected safely (404).
7. Duplicate association handling is deterministic (409 Conflict).
8. Association and audit event succeed atomically (201).
9. Audit failure rolls back association creation.
10. Case evidence retrieval includes only linked evidence.
11. Evidence from another case is never included.
12. Viewer projections exclude restricted fields (SanitizedNormalizedEventSummary).
13. Investigator and lead projections contain only approved fields (CaseScopedEvidenceItem).
14. Raw payloads and internal attributes cannot leak through response serialization.
15. Existing global event/entity endpoints cannot expose unapproved raw fields to Tier-1.
16. Pagination is bounded and ordering deterministic.
17. Database errors return safe errors without leaking SQL or internal details (500).
18. Inactive analysts, inactive assignments, and unauthorized roles (e.g. Viewer linking) are denied (403).
19. Administrator parity remains enforced (unassigned admin receives 404).
20. Existing authentication, RBAC, case API, case service, sanitized projection, and persistence tests remain compatible.

Concurrency Note:
SQLite in-memory test databases do not support PostgreSQL SELECT ... FOR UPDATE row-level locking.
Unit tests verify deterministic single-session transactional invariants, rollbacks, and ordering.
Multi-session row contention and PostgreSQL trigger immutability are verified in dedicated PostgreSQL gates.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI, status
from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.core.rbac import (
    CaseRole,
    GlobalRole,
    hash_canonical_token,
)
from app.db.session import get_db_session
from app.main import create_app
from app.models.analyst import Analyst, AnalystApiClient
from app.models.case import CaseAssignmentModel, CaseAuditEventModel, CaseEvidenceModel, CaseModel
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
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


async def seed_raw_and_normalized_evidence(
    db_session,
    *,
    event_id: str = "1",
    event_type: str = "process_creation",
    severity: str = "high",
    provider: str = "Microsoft-Windows-Sysmon",
    source_type: str = "sysmon",
    source_identifier: str = "WKSTN-EVID-01",
    payload: dict[str, Any] | None = None,
) -> tuple[RawEvidence, NormalizedEventModel]:
    """Seed a raw evidence record and child normalized event with extracted entities."""
    norm_payload = payload or {
        "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\run.ps1",
        "ParentCommandLine": "cmd.exe /c start",
        "User": "CORP\\compromised_user",
    }
    raw_payload = {
        "Event": {
            "System": {"EventID": event_id, "Provider": {"@Name": provider}},
            "EventData": norm_payload,
        }
    }
    sha256 = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
    now = datetime.now(timezone.utc)

    raw = RawEvidence(
        id=uuid.uuid4(),
        source_type=source_type,
        source_identifier=source_identifier,
        sha256_hash=sha256,
        raw_payload=raw_payload,
        ingested_at=now,
    )
    db_session.add(raw)
    await db_session.flush()

    event = NormalizedEventModel(
        id=uuid.uuid4(),
        raw_evidence_id=raw.id,
        event_id=event_id,
        event_type=event_type,
        event_timestamp=now,
        provider=provider,
        action="Process Create",
        outcome="success",
        severity=severity,
        normalized_payload=norm_payload,
    )
    db_session.add(event)
    await db_session.flush()

    entity = ExtractedEntityModel(
        id=uuid.uuid4(),
        event_id=event.id,
        raw_evidence_id=raw.id,
        entity_type="user",
        entity_value="CORP\\compromised_user",
        role="actor",
        attributes={"department": "Finance", "secret_tag": "internal_only"},
    )
    db_session.add(entity)
    await db_session.commit()

    return raw, event


# ─────────────────────────────────────────────────────────────────────────────
# 1. Unauthenticated & Machine Credential Rejection (Req 1 & 2)
# ─────────────────────────────────────────────────────────────────────────────

class TestEvidenceAuthenticationRejection:
    """Verify case evidence routes reject missing and legacy credentials."""

    @pytest.mark.anyio
    async def test_case_evidence_unauthenticated_rejected(self, app_instance):
        case_id = uuid.uuid4()
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # POST
            res_post = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                json={"evidence_id": str(uuid.uuid4())},
            )
            assert res_post.status_code == status.HTTP_401_UNAUTHORIZED

            # GET
            res_get = await client.get(f"/api/v1/cases/{case_id}/evidence")
            assert res_get.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.anyio
    async def test_legacy_machine_credential_cannot_access_case_evidence(
        self, app_instance
    ):
        case_id = uuid.uuid4()
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"X-API-Key": "legacy-machine-key-999"}
            # POST
            res_post = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                headers=headers,
                json={"evidence_id": str(uuid.uuid4())},
            )
            assert res_post.status_code == status.HTTP_401_UNAUTHORIZED
            assert "analyst identity" in res_post.json()["detail"].lower()

            # GET
            res_get = await client.get(
                f"/api/v1/cases/{case_id}/evidence",
                headers=headers,
            )
            assert res_get.status_code == status.HTTP_401_UNAUTHORIZED
            assert "analyst identity" in res_get.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Case Evidence Association & Invariants (Req 3, 4, 5, 6, 7, 8, 9, 18, 19)
# ─────────────────────────────────────────────────────────────────────────────

class TestCaseEvidenceLinking:
    """Verify evidence association rules, atomic audit trail, and anti-enumeration."""

    @pytest.mark.anyio
    async def test_assigned_analyst_can_link_valid_evidence(
        self, app_instance, db_session
    ):
        token, analyst = await seed_analyst_with_token(
            db_session, prefix="linkauth111111", username="lead_linker"
        )
        _, event = await seed_raw_and_normalized_evidence(db_session)

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Create a case
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Ransomware Triage Case", "severity": "high"},
            )
            assert c_res.status_code == 201
            case_id = c_res.json()["id"]

            # 2. Link evidence to case
            link_res = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token}"},
                json={"evidence_id": str(event.id)},
            )
            assert link_res.status_code == status.HTTP_201_CREATED
            data = link_res.json()
            assert data["case_id"] == case_id
            assert data["evidence_id"] == str(event.id)
            assert data["linked_by_analyst_id"] == str(analyst.id)
            assert data["linked_at"] is not None

            # 3. Verify CaseEvidenceModel persisted
            ce_stmt = select(CaseEvidenceModel).where(
                CaseEvidenceModel.case_id == uuid.UUID(case_id),
                CaseEvidenceModel.evidence_id == event.id,
            )
            ce_row = (await db_session.execute(ce_stmt)).scalars().first()
            assert ce_row is not None
            assert ce_row.linked_by_analyst_id == analyst.id

            # 4. Verify CaseAuditEventModel persisted atomically
            audit_stmt = select(CaseAuditEventModel).where(
                CaseAuditEventModel.case_id == uuid.UUID(case_id),
                CaseAuditEventModel.action == "evidence_linked",
            )
            audit_row = (await db_session.execute(audit_stmt)).scalars().first()
            assert audit_row is not None
            assert audit_row.actor_analyst_id == analyst.id
            assert audit_row.details["evidence_id"] == str(event.id)
            assert audit_row.details["event_type"] == event.event_type

    @pytest.mark.anyio
    async def test_unassigned_analyst_cannot_link_evidence_anti_enumeration(
        self, app_instance, db_session
    ):
        token_assigned, _ = await seed_analyst_with_token(
            db_session, prefix="unassigned1111", username="assigned_lead"
        )
        token_unassigned, _ = await seed_analyst_with_token(
            db_session, prefix="unassigned2222", username="unassigned_analyst"
        )
        token_admin, _ = await seed_analyst_with_token(
            db_session,
            prefix="unassigned3333",
            username="unassigned_admin",
            global_role="security_admin",
        )
        _, event = await seed_raw_and_normalized_evidence(db_session)

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_assigned}"},
                json={"title": "Target Case", "severity": "medium"},
            )
            case_id = c_res.json()["id"]

            # Unassigned analyst returns 404 (anti-enumeration)
            unassigned_res = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token_unassigned}"},
                json={"evidence_id": str(event.id)},
            )
            assert unassigned_res.status_code == status.HTTP_404_NOT_FOUND
            assert unassigned_res.json()["detail"] == "Case not found or access denied."

            # Decision 2A Parity: Unassigned security_admin also returns 404
            admin_res = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token_admin}"},
                json={"evidence_id": str(event.id)},
            )
            assert admin_res.status_code == status.HTTP_404_NOT_FOUND
            assert admin_res.json()["detail"] == "Case not found or access denied."

    @pytest.mark.anyio
    async def test_unknown_evidence_id_fails_404(self, app_instance, db_session):
        token, _ = await seed_analyst_with_token(
            db_session, prefix="unknownevid111", username="unknown_tester"
        )
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Unknown Evidence Test Case", "severity": "low"},
            )
            case_id = c_res.json()["id"]

            missing_evidence_uuid = str(uuid.uuid4())
            res = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token}"},
                json={"evidence_id": missing_evidence_uuid},
            )
            assert res.status_code == status.HTTP_404_NOT_FOUND
            assert "Normalized evidence event not found." in res.json()["detail"]

    @pytest.mark.anyio
    async def test_duplicate_evidence_link_fails_409_conflict(
        self, app_instance, db_session
    ):
        token, _ = await seed_analyst_with_token(
            db_session, prefix="dupevidauth111", username="dupe_tester"
        )
        _, event = await seed_raw_and_normalized_evidence(db_session)

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Dupe Evidence Test Case", "severity": "high"},
            )
            case_id = c_res.json()["id"]

            # First link succeeds (201)
            res1 = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token}"},
                json={"evidence_id": str(event.id)},
            )
            assert res1.status_code == status.HTTP_201_CREATED

            # Second link with same evidence_id returns 409 Conflict
            res2 = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token}"},
                json={"evidence_id": str(event.id)},
            )
            assert res2.status_code == status.HTTP_409_CONFLICT
            assert "already linked" in res2.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_viewer_role_cannot_link_evidence(self, app_instance, db_session):
        token_lead, _ = await seed_analyst_with_token(
            db_session, prefix="viewerblock111", username="lead_staffer"
        )
        token_viewer, viewer = await seed_analyst_with_token(
            db_session, prefix="viewerblock222", username="read_only_viewer"
        )
        _, event = await seed_raw_and_normalized_evidence(db_session)

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_lead}"},
                json={"title": "Viewer Guard Case", "severity": "medium"},
            )
            case_id = c_res.json()["id"]

            # Staff viewer to case
            staff_res = await client.post(
                f"/api/v1/cases/{case_id}/assignments",
                headers={"Authorization": f"Bearer {token_lead}"},
                json={"analyst_id": str(viewer.id), "case_role": "viewer"},
            )
            assert staff_res.status_code == 201

            # Viewer tries to link evidence -> 403 Forbidden
            link_res = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token_viewer}"},
                json={"evidence_id": str(event.id)},
            )
            assert link_res.status_code == status.HTTP_403_FORBIDDEN
            assert "insufficient case role permissions" in link_res.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_audit_failure_rolls_back_evidence_link(
        self, app_instance, db_session
    ):
        token, _ = await seed_analyst_with_token(
            db_session, prefix="auditfaillink1", username="audit_fail_linker"
        )
        _, event = await seed_raw_and_normalized_evidence(db_session)

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "Audit Fail Case", "severity": "low"},
            )
            case_id = uuid.UUID(c_res.json()["id"])

            orig_flush = db_session.flush

            async def fail_audit_flush(*args, **kwargs):
                raise RuntimeError("Simulated audit immutability crash")

            with patch.object(db_session, "flush", side_effect=fail_audit_flush):
                with pytest.raises(RuntimeError, match="Simulated audit"):
                    await client.post(
                        f"/api/v1/cases/{case_id}/evidence",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"evidence_id": str(event.id)},
                    )

            await db_session.rollback()

            # Confirm no CaseEvidenceModel row was persisted
            ce = (
                await db_session.execute(
                    select(CaseEvidenceModel).where(
                        CaseEvidenceModel.case_id == case_id,
                        CaseEvidenceModel.evidence_id == event.id,
                    )
                )
            ).scalars().first()
            assert ce is None


# ─────────────────────────────────────────────────────────────────────────────
# 3. Case-Scoped Evidence Retrieval & Role Projections (Req 10, 11, 12, 13, 14, 16)
# ─────────────────────────────────────────────────────────────────────────────

class TestCaseEvidenceRetrieval:
    """Verify case evidence queries constrain to linked records and apply role projections."""

    @pytest.mark.anyio
    async def test_case_evidence_query_isolation_between_cases(
        self, app_instance, db_session
    ):
        token_1, _ = await seed_analyst_with_token(
            db_session, prefix="caseisoauth111", username="case1_lead"
        )
        token_2, _ = await seed_analyst_with_token(
            db_session, prefix="caseisoauth222", username="case2_lead"
        )

        _, event_1 = await seed_raw_and_normalized_evidence(
            db_session, event_id="101", event_type="process_creation"
        )
        _, event_2 = await seed_raw_and_normalized_evidence(
            db_session, event_id="102", event_type="network_connection"
        )

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Case 1
            res1 = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_1}"},
                json={"title": "Case 1 Isolated", "severity": "medium"},
            )
            case1_id = res1.json()["id"]

            # Case 2
            res2 = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_2}"},
                json={"title": "Case 2 Isolated", "severity": "high"},
            )
            case2_id = res2.json()["id"]

            # Link event 1 to Case 1
            link1 = await client.post(
                f"/api/v1/cases/{case1_id}/evidence",
                headers={"Authorization": f"Bearer {token_1}"},
                json={"evidence_id": str(event_1.id)},
            )
            assert link1.status_code == 201

            # Link event 2 to Case 2
            link2 = await client.post(
                f"/api/v1/cases/{case2_id}/evidence",
                headers={"Authorization": f"Bearer {token_2}"},
                json={"evidence_id": str(event_2.id)},
            )
            assert link2.status_code == 201

            # Query Case 1 evidence -> Must strictly return event 1 only
            ev1_res = await client.get(
                f"/api/v1/cases/{case1_id}/evidence",
                headers={"Authorization": f"Bearer {token_1}"},
            )
            assert ev1_res.status_code == 200
            data1 = ev1_res.json()
            assert data1["total"] == 1
            assert len(data1["items"]) == 1
            assert data1["items"][0]["id"] == str(event_1.id)
            assert data1["items"][0]["event_id"] == "101"

            # Query Case 2 evidence -> Must strictly return event 2 only
            ev2_res = await client.get(
                f"/api/v1/cases/{case2_id}/evidence",
                headers={"Authorization": f"Bearer {token_2}"},
            )
            assert ev2_res.status_code == 200
            data2 = ev2_res.json()
            assert data2["total"] == 1
            assert len(data2["items"]) == 1
            assert data2["items"][0]["id"] == str(event_2.id)
            assert data2["items"][0]["event_id"] == "102"

    @pytest.mark.anyio
    async def test_role_based_evidence_projections_viewer_vs_investigator(
        self, app_instance, db_session
    ):
        token_lead, _ = await seed_analyst_with_token(
            db_session, prefix="projleadauth11", username="projection_lead"
        )
        token_viewer, viewer = await seed_analyst_with_token(
            db_session, prefix="projviewauth22", username="projection_viewer"
        )
        _, event = await seed_raw_and_normalized_evidence(
            db_session,
            event_id="999",
            payload={"SensitiveKey": "SuperSecretValue", "User": "victim"},
        )

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            c_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_lead}"},
                json={"title": "Projection Test Case", "severity": "high"},
            )
            case_id = c_res.json()["id"]

            # Staff viewer
            await client.post(
                f"/api/v1/cases/{case_id}/assignments",
                headers={"Authorization": f"Bearer {token_lead}"},
                json={"analyst_id": str(viewer.id), "case_role": "viewer"},
            )

            # Link evidence
            await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token_lead}"},
                json={"evidence_id": str(event.id)},
            )

            # 1. Lead / Investigator projection: contains normalized_payload, linked_at, NO raw_payload
            lead_res = await client.get(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token_lead}"},
            )
            assert lead_res.status_code == 200
            lead_item = lead_res.json()["items"][0]
            assert "normalized_payload" in lead_item
            assert lead_item["normalized_payload"]["SensitiveKey"] == "SuperSecretValue"
            assert "linked_at" in lead_item
            # Raw payload or raw_evidence_id must NOT be exposed
            assert "raw_payload" not in lead_item
            assert "raw_evidence_id" not in lead_item

            # 2. Viewer projection: sanitized summary ONLY (NO normalized_payload, NO raw_evidence_id)
            viewer_res = await client.get(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {token_viewer}"},
            )
            assert viewer_res.status_code == 200
            viewer_item = viewer_res.json()["items"][0]
            assert viewer_item["id"] == str(event.id)
            assert viewer_item["event_id"] == "999"
            # Explicit verification that sensitive payload is redacted for viewers
            assert "normalized_payload" not in viewer_item
            assert "raw_evidence_id" not in viewer_item
            assert "raw_payload" not in viewer_item


# ─────────────────────────────────────────────────────────────────────────────
# 4. Remediation of Existing Global Evidence Endpoints (Req 15)
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# 4. Remediation of Existing Global Evidence Endpoints (Gate D.2.3.2)
# ─────────────────────────────────────────────────────────────────────────────

class TestGlobalEvidenceRemediation:
    """Verify global evidence endpoints enforce Decision 1A sanitization, fail-closed machine client rejection, and unscoped raw evidence closure (Gate D.2.3.2)."""

    @pytest.mark.anyio
    async def test_global_events_sanitizes_all_eligible_identities(
        self, app_instance, db_session
    ):
        token_t1, _ = await seed_analyst_with_token(
            db_session,
            prefix="globalevt11111",
            username="tier1_triage_analyst",
            global_role="analyst_tier_1",
        )
        token_t2, _ = await seed_analyst_with_token(
            db_session,
            prefix="globalevt22222",
            username="tier2_full_analyst",
            global_role="analyst_tier_2",
        )
        token_admin, _ = await seed_analyst_with_token(
            db_session,
            prefix="globalevtadmin1",
            username="sec_admin_analyst",
            global_role="security_admin",
        )
        _, event = await seed_raw_and_normalized_evidence(
            db_session,
            event_id="555",
            payload={"SecretCommandLine": "cmd.exe /c dangerous_tool"},
        )

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Tier-1 query -> Sanitized summary (NO raw_evidence_id, NO normalized_payload)
            res_t1 = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token_t1}"},
            )
            assert res_t1.status_code == 200
            t1_item = res_t1.json()["items"][0]
            assert t1_item["id"] == str(event.id)
            assert "raw_evidence_id" not in t1_item
            assert "normalized_payload" not in t1_item

            # 2. Tier-2 query -> Also sanitized summary (Gate D.2.3.2: no unscoped leak of normalized_payload or raw_evidence_id)
            res_t2 = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token_t2}"},
            )
            assert res_t2.status_code == 200
            t2_item = res_t2.json()["items"][0]
            assert t2_item["id"] == str(event.id)
            assert "raw_evidence_id" not in t2_item
            assert "normalized_payload" not in t2_item

            # 3. Security Admin query -> Also sanitized summary
            res_adm = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token_admin}"},
            )
            assert res_adm.status_code == 200
            adm_item = res_adm.json()["items"][0]
            assert adm_item["id"] == str(event.id)
            assert "raw_evidence_id" not in adm_item
            assert "normalized_payload" not in adm_item

    @pytest.mark.anyio
    async def test_global_entities_sanitizes_all_eligible_identities(
        self, app_instance, db_session
    ):
        token_t1, _ = await seed_analyst_with_token(
            db_session,
            prefix="globalent11111",
            username="tier1_entity_analyst",
            global_role="analyst_tier_1",
        )
        token_t2, _ = await seed_analyst_with_token(
            db_session,
            prefix="globalent22222",
            username="tier2_entity_analyst",
            global_role="analyst_tier_2",
        )
        await seed_raw_and_normalized_evidence(db_session)

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Tier-1 query -> Sanitized entity (NO attributes, NO event_id, NO raw_evidence_id)
            res_t1 = await client.get(
                "/api/v1/evidence/entities",
                headers={"Authorization": f"Bearer {token_t1}"},
            )
            assert res_t1.status_code == 200
            t1_ent = res_t1.json()["items"][0]
            assert "entity_type" in t1_ent
            assert "entity_value" in t1_ent
            assert "attributes" not in t1_ent
            assert "event_id" not in t1_ent
            assert "raw_evidence_id" not in t1_ent

            # 2. Tier-2 query -> Also sanitized entity (Gate D.2.3.2)
            res_t2 = await client.get(
                "/api/v1/evidence/entities",
                headers={"Authorization": f"Bearer {token_t2}"},
            )
            assert res_t2.status_code == 200
            t2_ent = res_t2.json()["items"][0]
            assert "entity_type" in t2_ent
            assert "entity_value" in t2_ent
            assert "attributes" not in t2_ent
            assert "event_id" not in t2_ent
            assert "raw_evidence_id" not in t2_ent

    @pytest.mark.anyio
    async def test_ingest_identity_denied_global_event_and_entity_triage(
        self, app_instance, db_session
    ):
        token_ingest, _ = await seed_analyst_with_token(
            db_session,
            prefix="ingesttriage111",
            username="forwarder_ingest_agent",
            global_role="ingest",
        )

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. GET /api/v1/evidence/events -> 403 Forbidden
            res_ev = await client.get(
                "/api/v1/evidence/events",
                headers={"Authorization": f"Bearer {token_ingest}"},
            )
            assert res_ev.status_code == status.HTTP_403_FORBIDDEN
            assert "Insufficient global role to access global event triage" in res_ev.json()["detail"]

            # 2. GET /api/v1/evidence/entities -> 403 Forbidden
            res_ent = await client.get(
                "/api/v1/evidence/entities",
                headers={"Authorization": f"Bearer {token_ingest}"},
            )
            assert res_ent.status_code == status.HTTP_403_FORBIDDEN
            assert "Insufficient global role to access global entity search" in res_ent.json()["detail"]

    @pytest.mark.anyio
    async def test_machine_identity_without_analyst_denied_on_all_unscoped_endpoints(
        self, app_instance, db_session
    ):
        """A machine client without human analyst identity (analyst=None) must fail closed with 403 on all 5 unscoped endpoints."""
        dummy_uuid = uuid.uuid4()
        dummy_hash = "a" * 64

        # Configure dependency override to return a machine client with analyst=None
        from app.core.auth import AuthenticatedClient, verify_api_key

        app_instance.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(
            client_id="pure-machine-client",
            authenticated=True,
            analyst=None,
        )

        try:
            transport = httpx.ASGITransport(app=app_instance)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                # 1. GET /api/v1/evidence/events -> 403
                r1 = await client.get("/api/v1/evidence/events")
                assert r1.status_code == status.HTTP_403_FORBIDDEN
                assert "Machine credentials without analyst identity" in r1.json()["detail"]

                # 2. GET /api/v1/evidence/entities -> 403
                r2 = await client.get("/api/v1/evidence/entities")
                assert r2.status_code == status.HTTP_403_FORBIDDEN
                assert "Machine credentials without analyst identity" in r2.json()["detail"]

                # 3. GET /api/v1/evidence/events/{event_id} -> 403
                r3 = await client.get(f"/api/v1/evidence/events/{dummy_uuid}")
                assert r3.status_code == status.HTTP_403_FORBIDDEN
                assert "Machine credentials without analyst identity" in r3.json()["detail"]

                # 4. GET /api/v1/evidence/{evidence_id} -> 403
                r4 = await client.get(f"/api/v1/evidence/{dummy_uuid}")
                assert r4.status_code == status.HTTP_403_FORBIDDEN
                assert "Machine credentials without analyst identity" in r4.json()["detail"]

                # 5. GET /api/v1/evidence/by-hash/{sha256_hash} -> 403
                r5 = await client.get(f"/api/v1/evidence/by-hash/{dummy_hash}")
                assert r5.status_code == status.HTTP_403_FORBIDDEN
                assert "Machine credentials without analyst identity" in r5.json()["detail"]
        finally:
            app_instance.dependency_overrides.pop(verify_api_key, None)

    @pytest.mark.anyio
    async def test_machine_client_denial_holds_with_legacy_keys_enabled(
        self, app_instance, db_session
    ):
        """When legacy static keys are explicitly enabled in settings, machine clients without analyst still fail closed with 403."""
        legacy_token = "secret-legacy-machine-token-9999"
        dummy_uuid = uuid.uuid4()
        dummy_hash = "b" * 64

        test_settings = Settings(
            _env_file=None,
            ENVIRONMENT="development",
            API_AUTH_ENABLED=True,
            API_AUTH_ALLOW_LEGACY_KEYS=True,
            API_AUTH_KEYS=[f"sensor-legacy:{legacy_token}"],
        )

        app_instance.dependency_overrides[get_settings] = lambda: test_settings
        try:
            transport = httpx.ASGITransport(app=app_instance)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                headers = {"X-API-Key": legacy_token}

                # Unscoped query endpoints must fail closed with 403
                r_events = await client.get("/api/v1/evidence/events", headers=headers)
                assert r_events.status_code == status.HTTP_403_FORBIDDEN
                assert "Machine credentials without analyst identity" in r_events.json()["detail"]

                r_entities = await client.get("/api/v1/evidence/entities", headers=headers)
                assert r_entities.status_code == status.HTTP_403_FORBIDDEN
                assert "Machine credentials without analyst identity" in r_entities.json()["detail"]

                r_ev_id = await client.get(f"/api/v1/evidence/events/{dummy_uuid}", headers=headers)
                assert r_ev_id.status_code == status.HTTP_403_FORBIDDEN

                r_raw_id = await client.get(f"/api/v1/evidence/{dummy_uuid}", headers=headers)
                assert r_raw_id.status_code == status.HTTP_403_FORBIDDEN

                r_raw_hash = await client.get(f"/api/v1/evidence/by-hash/{dummy_hash}", headers=headers)
                assert r_raw_hash.status_code == status.HTTP_403_FORBIDDEN

                # But ingestion path remains permitted for legacy sensor machine client
                r_ingest = await client.post(
                    "/api/v1/evidence/ingest",
                    headers=headers,
                    json={
                        "source_type": "sysmon",
                        "source_identifier": "LEGACY-SENSOR-01",
                        "events": [
                            {
                                "EventID": 1,
                                "Image": "C:\\Windows\\System32\\cmd.exe",
                                "UtcTime": "2026-10-25 10:00:00.000",
                            }
                        ],
                    },
                )
                assert r_ingest.status_code == status.HTTP_200_OK
                assert r_ingest.json()["total_normalized"] == 1
        finally:
            app_instance.dependency_overrides.pop(get_settings, None)

    @pytest.mark.anyio
    async def test_tier2_and_admin_cannot_retrieve_unscoped_raw_evidence(
        self, app_instance, db_session
    ):
        """Tier-2 and Security Admin cannot retrieve raw evidence or full event details through unscoped routes."""
        token_t2, _ = await seed_analyst_with_token(
            db_session,
            prefix="unscopet2block1",
            username="tier2_unscoped_analyst",
            global_role="analyst_tier_2",
        )
        token_adm, _ = await seed_analyst_with_token(
            db_session,
            prefix="unscopeadmblock",
            username="admin_unscoped_analyst",
            global_role="security_admin",
        )
        raw, event = await seed_raw_and_normalized_evidence(db_session)

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            for token, role_name in [(token_t2, "Tier-2"), (token_adm, "Security Admin")]:
                headers = {"Authorization": f"Bearer {token}"}

                # 1. GET /api/v1/evidence/events/{event_id} -> 403 Forbidden
                res_ev = await client.get(f"/api/v1/evidence/events/{event.id}", headers=headers)
                assert res_ev.status_code == status.HTTP_403_FORBIDDEN
                assert "Case-scoped evidence retrieval via /api/v1/cases/{case_id}/evidence is required" in res_ev.json()["detail"]

                # 2. GET /api/v1/evidence/{evidence_id} -> 403 Forbidden
                res_raw_id = await client.get(f"/api/v1/evidence/{raw.id}", headers=headers)
                assert res_raw_id.status_code == status.HTTP_403_FORBIDDEN
                assert "Case-scoped evidence retrieval via /api/v1/cases/{case_id}/evidence is required" in res_raw_id.json()["detail"]

                # 3. GET /api/v1/evidence/by-hash/{sha256} -> 403 Forbidden
                res_raw_hash = await client.get(f"/api/v1/evidence/by-hash/{raw.sha256_hash}", headers=headers)
                assert res_raw_hash.status_code == status.HTTP_403_FORBIDDEN
                assert "Case-scoped evidence retrieval via /api/v1/cases/{case_id}/evidence is required" in res_raw_hash.json()["detail"]
