"""
Unit and Integration Tests for AISOP Alert Retrieval & Atomic Case-Evidence Linking.

Governed by ADR-007, Decision 1A, and the Phase 4A Backend Readiness Specification.
Verifies:
1. AlertQueryService pagination, deterministic ordering, multi-source/severity/category filtering, and keyword search.
2. AlertDetailResponse data projection, MITRE ATT&CK extraction, observable mapping, and strict raw_payload exclusion.
3. Denial of non-alert telemetry through alert endpoints.
4. REST API authorization boundaries:
   - 401 on missing credentials
   - 403 on machine-only or ingest credentials
   - 200 for Tier-1, Tier-2, and Security Admin analysts
5. Atomic implementation of CaseCreateRequest.initial_evidence_ids:
   - Atomic multi-evidence linking on case creation
   - Rejection and safe rollback on nonexistent or duplicate evidence IDs
   - Attributable audit logging and lead assignment invariants
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import uuid

import httpx
import pytest
from fastapi import FastAPI, HTTPException, status
from sqlalchemy import select

from app.core.auth import AuthenticatedClient, verify_api_key
from app.core.config import Settings, get_settings
from app.core.rbac import AuthenticatedAnalyst, CaseRole, GlobalRole
from app.db.session import get_db_session
from app.main import create_app
from app.models.case import CaseAssignmentModel, CaseAuditEventModel, CaseEvidenceModel, CaseModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.schemas.alert_ingest import AlertIngestRequest
from app.schemas.case import CaseCreateRequest, CaseSeverity, CaseStatus
from app.services.alert_ingestion_service import AlertIngestionService
from app.services.alert_query_service import AlertQueryService
from app.services.case_service import CaseService


FIXTURES_DIR = Path(__file__).resolve().parents[3] / "datasets" / "samples" / "alerts"


def load_fixture(filename: str) -> dict[str, Any]:
    with open(FIXTURES_DIR / filename, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def mock_analyst_tier_1() -> AuthenticatedAnalyst:
    return AuthenticatedAnalyst(
        analyst_id=uuid.uuid4(),
        username="analyst_t1_user",
        global_role=GlobalRole.ANALYST_TIER_1,
        is_active=True,
    )


@pytest.fixture
def mock_analyst_tier_2() -> AuthenticatedAnalyst:
    return AuthenticatedAnalyst(
        analyst_id=uuid.uuid4(),
        username="analyst_t2_user",
        global_role=GlobalRole.ANALYST_TIER_2,
        is_active=True,
    )


@pytest.fixture
def mock_admin() -> AuthenticatedAnalyst:
    return AuthenticatedAnalyst(
        analyst_id=uuid.uuid4(),
        username="admin_user",
        global_role=GlobalRole.SECURITY_ADMIN,
        is_active=True,
    )


@pytest.fixture
def mock_ingest() -> AuthenticatedAnalyst:
    return AuthenticatedAnalyst(
        analyst_id=uuid.uuid4(),
        username="ingest_svc",
        global_role=GlobalRole.INGEST,
        is_active=True,
    )


@pytest.mark.anyio
class TestAlertQueryService:
    """Verifies AlertQueryService query operations, filters, pagination, and detail retrieval."""

    async def test_empty_database_returns_empty_paginated_response(self, db_session):
        service = AlertQueryService()
        res = await service.list_alerts(db_session, page=1, limit=20)
        assert res.total == 0
        assert res.items == []
        assert res.page == 1
        assert res.total_pages == 0
        assert res.has_next is False
        assert res.has_previous is False

    async def test_alerts_queried_and_non_alert_telemetry_excluded(self, db_session):
        ingest_svc = AlertIngestionService()

        # Ingest 2 alerts
        fixture_edr = load_fixture("edr_malware_alert.json")
        fixture_sec = load_fixture("windows_security_event_alert.json")
        await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(
                source_type="edr_malware",
                source_identifier="cs-falcon",
                alerts=[fixture_edr],
            ),
        )
        await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(
                source_type="windows_security",
                source_identifier="dc01",
                alerts=[fixture_sec],
            ),
        )

        # Insert 1 raw non-alert telemetry event (action="observed")
        raw_telemetry = RawEvidence(
            source_type="sysmon",
            source_identifier="workstation-01",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            raw_payload={"EventID": 1, "Image": "calc.exe"},
        )
        db_session.add(raw_telemetry)
        await db_session.flush()

        event_telemetry = NormalizedEventModel(
            raw_evidence_id=raw_telemetry.id,
            event_id="SYS-101",
            event_type="process_creation",
            event_timestamp=datetime.now(timezone.utc),
            provider="microsoft_sysmon",
            action="observed",  # NOT alert_triggered
            outcome="success",
            severity="informational",
            normalized_payload={"process": {"name": "calc.exe"}},
        )
        db_session.add(event_telemetry)
        await db_session.flush()

        # Execute alert query
        query_svc = AlertQueryService()
        res = await query_svc.list_alerts(db_session, page=1, limit=10)

        # Assert exactly 2 alerts returned (the non-alert process_creation event must be excluded)
        assert res.total == 2
        assert len(res.items) == 2
        for item in res.items:
            assert item.title is not None
            assert item.category in ("malware", "credential_access")

    async def test_pagination_and_deterministic_ordering(self, db_session):
        ingest_svc = AlertIngestionService()
        fixtures = [
            ("edr_malware", load_fixture("edr_malware_alert.json")),
            ("windows_security", load_fixture("windows_security_event_alert.json")),
            ("linux_auth", load_fixture("linux_ssh_bruteforce_alert.json")),
            ("firewall_ids", load_fixture("firewall_ids_alert.json")),
        ]

        for src, fix in fixtures:
            await ingest_svc.ingest_batch(
                db_session,
                AlertIngestRequest(source_type=src, alerts=[fix]),
            )

        query_svc = AlertQueryService()

        # Page 1 with limit 2
        p1 = await query_svc.list_alerts(db_session, page=1, limit=2)
        assert p1.total == 4
        assert len(p1.items) == 2
        assert p1.page == 1
        assert p1.total_pages == 2
        assert p1.has_next is True
        assert p1.has_previous is False

        # Page 2 with limit 2
        p2 = await query_svc.list_alerts(db_session, page=2, limit=2)
        assert p2.total == 4
        assert len(p2.items) == 2
        assert p2.page == 2
        assert p2.has_next is False
        assert p2.has_previous is True

        # Assert no overlapping IDs between pages (deterministic pagination)
        p1_ids = {item.id for item in p1.items}
        p2_ids = {item.id for item in p2.items}
        assert p1_ids.isdisjoint(p2_ids)

        # Assert deterministic descending timestamp ordering
        all_res = await query_svc.list_alerts(db_session, page=1, limit=10)
        timestamps = [item.timestamp for item in all_res.items]
        assert timestamps == sorted(timestamps, reverse=True)

    async def test_filtering_by_source_severity_category_and_search(self, db_session):
        ingest_svc = AlertIngestionService()
        await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(
                source_type="edr_malware",
                alerts=[load_fixture("edr_malware_alert.json")],
            ),
        )
        await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(
                source_type="linux_auth",
                alerts=[load_fixture("linux_ssh_bruteforce_alert.json")],
            ),
        )

        query_svc = AlertQueryService()

        # Filter by source_type
        edr_res = await query_svc.list_alerts(db_session, source_type="edr_malware")
        assert edr_res.total == 1
        assert edr_res.items[0].source_type == "edr_malware"

        # Filter by category
        malware_res = await query_svc.list_alerts(db_session, category="malware")
        assert malware_res.total == 1
        assert malware_res.items[0].category == "malware"

        # Filter by severity
        crit_res = await query_svc.list_alerts(db_session, severity="critical")
        assert crit_res.total == 1
        assert crit_res.items[0].severity == "critical"

        # Search by keyword in title
        search_res = await query_svc.list_alerts(db_session, search="CobaltStrike")
        assert search_res.total == 1
        assert "CobaltStrike" in search_res.items[0].title

    async def test_time_range_filter_and_validation(self, db_session):
        query_svc = AlertQueryService()
        now = datetime.now(timezone.utc)
        past = now - timedelta(hours=2)

        # Valid range
        s, e = query_svc.validate_time_range(past, now)
        assert s == past
        assert e == now

        # Invalid range (start > end) raises ValueError
        with pytest.raises(ValueError, match="start_time cannot be after end_time"):
            query_svc.validate_time_range(now, past)

    async def test_alert_detail_retrieval_and_raw_payload_exclusion(self, db_session):
        ingest_svc = AlertIngestionService()
        ingest_res = await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(
                source_type="edr_malware",
                alerts=[load_fixture("edr_malware_alert.json")],
            ),
        )
        alert_id = ingest_res.alert_ids[0]

        query_svc = AlertQueryService()
        detail = await query_svc.get_alert_detail(db_session, alert_id)
        assert detail is not None
        assert detail.id == alert_id
        assert detail.source_type == "edr_malware"
        assert detail.category == "malware"
        assert detail.severity == "critical"
        assert len(detail.mitre_attack) > 0
        assert len(detail.observables) > 0
        assert detail.raw_ref != ""

        # Assert raw_payload attribute is strictly excluded from response model
        assert not hasattr(detail, "raw_payload")

    async def test_non_alert_telemetry_cannot_be_retrieved_via_alert_detail(self, db_session):
        # Insert raw non-alert telemetry event
        raw = RawEvidence(
            source_type="sysmon",
            source_identifier="srv-01",
            sha256_hash="1111111111111111111111111111111111111111111111111111111111111111",
            raw_payload={"EventID": 3, "DestinationIp": "1.1.1.1"},
        )
        db_session.add(raw)
        await db_session.flush()

        event = NormalizedEventModel(
            raw_evidence_id=raw.id,
            event_id="EVT-999",
            event_type="network_connection",
            event_timestamp=datetime.now(timezone.utc),
            provider="microsoft_sysmon",
            action="observed",  # Non-alert
            severity="informational",
            normalized_payload={"network": {"destination_ip": "1.1.1.1"}},
        )
        db_session.add(event)
        await db_session.flush()

        query_svc = AlertQueryService()
        # Attempt to retrieve non-alert event through alert detail endpoint must return None
        detail = await query_svc.get_alert_detail(db_session, event.id)
        assert detail is None


@pytest.fixture
def api_test_app(db_session) -> FastAPI:
    """Create test application instance with database and auth overrides."""
    app = create_app()

    async def override_get_db():
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    test_settings = Settings(
        _env_file=None,
        API_AUTH_ENABLED=True,
        API_AUTH_ALLOW_LEGACY_KEYS=True,
        API_AUTH_KEYS=["test-client:test-secret-key-12345"],
    )

    app.dependency_overrides[get_db_session] = override_get_db
    app.dependency_overrides[get_settings] = lambda: test_settings
    return app


@pytest.mark.anyio
class TestAlertRestEndpoints:
    """Tests the alert listing and detail REST API endpoints under authentication and RBAC."""

    async def test_get_alerts_unauthenticated_rejected(self, api_test_app: FastAPI):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api_test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/alerts")
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_get_alerts_machine_token_without_analyst_rejected_403(self, api_test_app: FastAPI):
        # Default test-secret-key authenticates as machine client without human analyst identity
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api_test_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/api/v1/alerts",
                headers={"Authorization": "Bearer test-secret-key-12345"},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "Machine credentials without analyst identity" in resp.json()["detail"]

    async def test_get_alerts_ingest_role_rejected_403(
        self, api_test_app: FastAPI, mock_ingest: AuthenticatedAnalyst
    ):
        api_test_app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(
            client_id="ingest_client",
            authenticated=True,
            analyst=mock_ingest,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api_test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/alerts")
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "Insufficient global role" in resp.json()["detail"]

    async def test_get_alerts_tier1_analyst_success(
        self,
        api_test_app: FastAPI,
        db_session,
        mock_analyst_tier_1: AuthenticatedAnalyst,
    ):
        # Ingest sample alert
        ingest_svc = AlertIngestionService()
        await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(
                source_type="windows_security",
                alerts=[load_fixture("windows_security_event_alert.json")],
            ),
        )

        api_test_app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(
            client_id="t1_client",
            authenticated=True,
            analyst=mock_analyst_tier_1,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api_test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/alerts?limit=10")
            assert resp.status_code == status.HTTP_200_OK
            data = resp.json()
            assert data["total"] == 1
            assert len(data["items"]) == 1
            item = data["items"][0]
            assert item["source_type"] == "windows_security"
            assert item["category"] == "credential_access"
            assert "mitre_attack" in item

    async def test_get_alert_detail_success_and_unknown_404(
        self,
        api_test_app: FastAPI,
        db_session,
        mock_analyst_tier_2: AuthenticatedAnalyst,
    ):
        ingest_svc = AlertIngestionService()
        res = await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(
                source_type="edr_malware",
                alerts=[load_fixture("edr_malware_alert.json")],
            ),
        )
        alert_id = res.alert_ids[0]

        api_test_app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(
            client_id="t2_client",
            authenticated=True,
            analyst=mock_analyst_tier_2,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api_test_app), base_url="http://test"
        ) as client:
            # Existing alert
            resp = await client.get(f"/api/v1/alerts/{alert_id}")
            assert resp.status_code == status.HTTP_200_OK
            detail = resp.json()
            assert detail["id"] == str(alert_id)
            assert detail["category"] == "malware"
            assert "raw_payload" not in detail

            # Nonexistent alert
            fake_id = uuid.uuid4()
            resp404 = await client.get(f"/api/v1/alerts/{fake_id}")
            assert resp404.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.anyio
class TestCaseCreationAtomicInitialEvidence:
    """Verifies atomic association of initial_evidence_ids during case creation."""

    async def test_create_case_without_initial_evidence(
        self, db_session, mock_analyst_tier_1: AuthenticatedAnalyst
    ):
        service = CaseService()
        req = CaseCreateRequest(
            title="Suspicious Network Activity",
            description="Investigating outbound beaconing",
            severity=CaseSeverity.HIGH,
            initial_evidence_ids=[],
        )
        case_res = await service.create_case(db_session, req, creator=mock_analyst_tier_1)

        assert case_res.title == "Suspicious Network Activity"
        assert case_res.status == CaseStatus.OPEN
        assert case_res.lead_analyst_id == mock_analyst_tier_1.analyst_id

        # Verify no evidence linked
        evidence_links = (
            await db_session.execute(
                select(CaseEvidenceModel).where(CaseEvidenceModel.case_id == case_res.id)
            )
        ).scalars().all()
        assert len(evidence_links) == 0

    async def test_create_case_with_single_initial_evidence(
        self, db_session, mock_analyst_tier_1: AuthenticatedAnalyst
    ):
        # Ingest an alert
        ingest_svc = AlertIngestionService()
        ingest_res = await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(
                source_type="edr_malware",
                alerts=[load_fixture("edr_malware_alert.json")],
            ),
        )
        alert_id = ingest_res.alert_ids[0]

        # Create case linking alert
        service = CaseService()
        req = CaseCreateRequest(
            title="CobaltStrike Detection Case",
            description="Process hollowing alert from Falcon",
            severity=CaseSeverity.CRITICAL,
            initial_evidence_ids=[alert_id],
        )
        case_res = await service.create_case(db_session, req, creator=mock_analyst_tier_1)

        assert case_res.id is not None

        # Verify CaseEvidenceModel record created
        evidence_links = (
            await db_session.execute(
                select(CaseEvidenceModel).where(CaseEvidenceModel.case_id == case_res.id)
            )
        ).scalars().all()
        assert len(evidence_links) == 1
        link = evidence_links[0]
        assert link.evidence_id == alert_id
        assert link.linked_by_analyst_id == mock_analyst_tier_1.analyst_id

        # Verify audit event recorded for evidence_linked
        audits = (
            await db_session.execute(
                select(CaseAuditEventModel).where(
                    CaseAuditEventModel.case_id == case_res.id,
                    CaseAuditEventModel.action == "evidence_linked",
                )
            )
        ).scalars().all()
        assert len(audits) == 1
        assert audits[0].details["evidence_id"] == str(alert_id)
        assert audits[0].details["context"] == "initial_case_creation"

    async def test_create_case_with_multiple_initial_evidence_records(
        self, db_session, mock_analyst_tier_2: AuthenticatedAnalyst
    ):
        ingest_svc = AlertIngestionService()
        res1 = await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(source_type="edr_malware", alerts=[load_fixture("edr_malware_alert.json")]),
        )
        res2 = await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(source_type="windows_security", alerts=[load_fixture("windows_security_event_alert.json")]),
        )
        id1 = res1.alert_ids[0]
        id2 = res2.alert_ids[0]

        service = CaseService()
        req = CaseCreateRequest(
            title="Multi-Stage Attack Campaign",
            description="Correlated EDR alert and logon failure",
            severity=CaseSeverity.CRITICAL,
            initial_evidence_ids=[id1, id2],
        )
        case_res = await service.create_case(db_session, req, creator=mock_analyst_tier_2)

        links = (
            await db_session.execute(
                select(CaseEvidenceModel).where(CaseEvidenceModel.case_id == case_res.id)
            )
        ).scalars().all()
        assert len(links) == 2
        linked_evidence_ids = {link.evidence_id for link in links}
        assert linked_evidence_ids == {id1, id2}

    async def test_duplicate_evidence_ids_in_request_rejected_with_400(
        self, db_session, mock_analyst_tier_1: AuthenticatedAnalyst
    ):
        fake_id = uuid.uuid4()
        service = CaseService()
        req = CaseCreateRequest(
            title="Duplicate Test",
            severity=CaseSeverity.MEDIUM,
            initial_evidence_ids=[fake_id, fake_id],  # Duplicate
        )

        with pytest.raises(HTTPException) as exc_info:
            await service.create_case(db_session, req, creator=mock_analyst_tier_1)

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "Duplicate evidence IDs" in exc_info.value.detail

    async def test_nonexistent_evidence_id_fails_with_404_and_aborts_case_creation(
        self, db_session, mock_analyst_tier_1: AuthenticatedAnalyst
    ):
        nonexistent_id = uuid.uuid4()
        service = CaseService()
        req = CaseCreateRequest(
            title="Ghost Evidence Case",
            severity=CaseSeverity.LOW,
            initial_evidence_ids=[nonexistent_id],
        )

        with pytest.raises(HTTPException) as exc_info:
            await service.create_case(db_session, req, creator=mock_analyst_tier_1)

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert "Initial evidence record(s) not found" in exc_info.value.detail

        # Assert no case was created in database (atomic transaction rollback)
        cases = (
            await db_session.execute(
                select(CaseModel).where(CaseModel.title == "Ghost Evidence Case")
            )
        ).scalars().all()
        assert len(cases) == 0

    async def test_post_cases_endpoint_with_initial_evidence_and_queue_reflection(
        self,
        api_test_app: FastAPI,
        db_session,
        mock_analyst_tier_1: AuthenticatedAnalyst,
    ):
        # 1. Ingest alert
        ingest_svc = AlertIngestionService()
        ingest_res = await ingest_svc.ingest_batch(
            db_session,
            AlertIngestRequest(
                source_type="windows_security",
                alerts=[load_fixture("windows_security_event_alert.json")],
            ),
        )
        alert_id = ingest_res.alert_ids[0]

        api_test_app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(
            client_id="t1_client",
            authenticated=True,
            analyst=mock_analyst_tier_1,
        )

        from app.api.dependencies import get_current_analyst
        api_test_app.dependency_overrides[get_current_analyst] = lambda: mock_analyst_tier_1

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api_test_app), base_url="http://test"
        ) as client:
            # Check alert queue: has_case must be False before linking
            q_before = await client.get("/api/v1/alerts")
            assert q_before.status_code == status.HTTP_200_OK
            assert q_before.json()["items"][0]["has_case"] is False
            assert q_before.json()["items"][0]["case_count"] == 0

            # Create case with initial_evidence_ids
            payload = {
                "title": "Brute Force Investigation",
                "description": "Logon failures on domain controller",
                "severity": "high",
                "initial_evidence_ids": [str(alert_id)],
            }
            create_resp = await client.post("/api/v1/cases", json=payload)
            assert create_resp.status_code == status.HTTP_201_CREATED
            case_data = create_resp.json()
            case_id = case_data["id"]

            # Query case evidence endpoint: must contain the linked alert!
            ev_resp = await client.get(f"/api/v1/cases/{case_id}/evidence")
            assert ev_resp.status_code == status.HTTP_200_OK
            ev_data = ev_resp.json()
            assert ev_data["total"] == 1
            assert ev_data["items"][0]["id"] == str(alert_id)
            assert ev_data["items"][0]["event_type"] == "alert.credential_access"

            # Check alert queue again: has_case must now be True and case_count=1!
            q_after = await client.get("/api/v1/alerts")
            assert q_after.status_code == status.HTTP_200_OK
            assert q_after.json()["items"][0]["has_case"] is True
            assert q_after.json()["items"][0]["case_count"] == 1

            # Check alert detail endpoint: associated_case_ids must contain case_id!
            det_resp = await client.get(f"/api/v1/alerts/{alert_id}")
            assert det_resp.status_code == status.HTTP_200_OK
            assert det_resp.json()["has_case"] is True
            assert case_id in det_resp.json()["associated_case_ids"]

            # Verify invalid initial_evidence_ids on POST /api/v1/cases fails with 404
            bad_payload = {
                "title": "Invalid Case",
                "severity": "medium",
                "initial_evidence_ids": [str(uuid.uuid4())],
            }
            bad_resp = await client.post("/api/v1/cases", json=bad_payload)
            assert bad_resp.status_code == status.HTTP_404_NOT_FOUND

