"""
AISOP Multi-Tenant BOLA/IDOR Security Regression Suite.

Milestone: Phase 3 / Phase 4 Defense-in-Depth Authorization Hardening
Security Standards: OWASP API1:2023 (Broken Object Level Authorization),
OWASP API3:2023 (Broken Object Property Level Authorization),
OWASP API5:2023 (Broken Function Level Authorization / BFLA).

Invariants Verified:
1. Multi-Tenant Case Boundary: Analysts assigned to Case A cannot view, modify,
   staff, or close Case B (HTTP 404 anti-enumeration).
2. Strict Anti-Enumeration: Unassigned cases and non-existent case UUIDs return
   identical HTTP 404 ("Case not found or access denied.") responses with identical timing profiles.
3. Administrator Parity (Decision 2A): Security Administrators possess zero implicit bypass;
   unassigned admin access to cases, evidence, or synthesis returns HTTP 404.
4. Tier-1 Least Privilege (Decision 3A): Tier-1 leads cannot manage investigator staffing
   or close/archive cases (HTTP 403 Forbidden).
5. Read-Only Viewer Enforcement: Viewers cannot modify metadata, link evidence,
   manage staffing, close cases, or execute AI synthesis (HTTP 403 Forbidden).
6. Evidence Scoping & Cross-Contamination Prevention: Evidence associated with Case B
   is strictly absent from Case A queries, even if both cases share host telemetry.
7. Nested Path & Identifier Manipulation: Sequential IDs, forged UUIDs, and malformed
   parameters are rejected at the schema validation boundary (HTTP 422).
8. Legacy Unscoped Route Decommissioning (Gate D.2.4): Direct unscoped evidence,
   investigation, and report endpoints fail closed (HTTP 403 Forbidden).
"""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncGenerator
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI, status
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import (
    get_case_service,
    get_current_analyst,
    get_db_session,
    get_knowledge_retriever,
    get_threat_intel_engine,
)
from app.api.v1.endpoints.cases import get_case_llm_provider
from app.core.config import Settings, get_settings
from app.core.rbac import (
    CaseRole,
    GlobalRole,
    hash_canonical_token,
)
from app.db.session import get_db_session_factory
from app.main import create_app
from app.models.analyst import Analyst, AnalystApiClient
from app.models.case import CaseAssignmentModel, CaseAuditEventModel, CaseEvidenceModel, CaseModel
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.ai.guardrails import GuardrailDecision, InvestigationValidationResult
from app.modules.ai.llm.protocol import LLMProvider
from app.schemas.ai import LLMRequest, LLMResponse, ProviderHealthResponse, TokenUsage
from app.schemas.case import CaseSeverity, CaseStatus
from app.schemas.investigation import (
    ClaimCategory,
    FactualClaimItem,
    GroundingStatus,
    StructuredInvestigationOutput,
)
from tests.conftest import AsyncSessionAdapter


def _no_rid(body: dict) -> dict:
    """Drop the per-request correlation id so two responses can be compared for enumeration oracles (Phase 2.2)."""
    err = {k: v for k, v in body.get('error', {}).items() if k != 'request_id'}
    return {**body, 'error': err}



# ─────────────────────────────────────────────────────────────────────────────
# Test Fixtures, Mock LLM & Data Seeding
# ─────────────────────────────────────────────────────────────────────────────

class MockCaseLLMProvider(LLMProvider):
    """Deterministic in-memory mock LLM provider for offline test execution."""

    def __init__(self, model: str = "llama3.1:8b") -> None:
        self.model = model
        self.calls: list[LLMRequest] = []

    @property
    def model_name(self) -> str:
        return self.model

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        return LLMResponse(
            content="{}",
            model=self.model,
            finish_reason="stop",
            usage=TokenUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20, duration_ms=1.0),
        )

    async def health(self) -> ProviderHealthResponse:
        return ProviderHealthResponse(status="healthy", model=self.model, provider="mock", latency_ms=1.0)


class InstrumentedSession(AsyncSessionAdapter):
    """Instrumented test session supporting isolated session lifecycle."""

    def __init__(self, sync_session: Any, tracker: InstrumentedSessionFactory) -> None:
        super().__init__(sync_session)
        self.tracker = tracker
        self.is_closed = False
        self.tracker.active_sessions.append(self)

    async def close(self) -> None:
        if not self.is_closed:
            self.is_closed = True
            if self in self.tracker.active_sessions:
                self.tracker.active_sessions.remove(self)
        await super().close()


class InstrumentedSessionFactory:
    """Instrumented session factory for multi-phase transaction testing."""

    def __init__(self, sync_factory: sessionmaker) -> None:
        self.sync_factory = sync_factory
        self.active_sessions: list[InstrumentedSession] = []

    def __call__(self) -> InstrumentedSession:
        sync_sess = self.sync_factory()
        return InstrumentedSession(sync_sess, self)


@pytest.fixture
def auth_settings() -> Settings:
    """Configure strict API authentication settings for unit testing."""
    return Settings(
        _env_file=None,
        API_AUTH_ENABLED=True,
        API_AUTH_ALLOW_LEGACY_KEYS=True,
        API_AUTH_KEYS=["legacy-machine:legacy-machine-key-999"],
        RATE_LIMIT_ENABLED=False,  # Disable rate limiting in authorization matrix tests
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

    sync_factory = sessionmaker(bind=db_session._sync.bind)
    instrumented_factory = InstrumentedSessionFactory(sync_factory)

    app.dependency_overrides[get_db_session] = override_get_db
    app.dependency_overrides[get_db_session_factory] = lambda: instrumented_factory
    app.dependency_overrides[get_settings] = lambda: auth_settings
    app.dependency_overrides[get_case_llm_provider] = lambda: MockCaseLLMProvider()
    app.dependency_overrides[get_threat_intel_engine] = lambda: None
    app.dependency_overrides[get_knowledge_retriever] = lambda: None
    return app


async def seed_analyst_with_token(
    db_session,
    *,
    prefix: str,
    username: str,
    global_role: str = "analyst_tier_1",
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


async def seed_evidence(
    db_session,
    *,
    event_id: str,
    source_identifier: str,
    summary: str = "Suspicious process execution",
) -> tuple[RawEvidence, NormalizedEventModel]:
    """Helper to seed a raw evidence and normalized event pair."""
    now = datetime.now(timezone.utc)
    raw = RawEvidence(
        id=uuid.uuid4(),
        source_type="sysmon",
        source_identifier=source_identifier,
        sha256_hash=hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest(),
        raw_payload={"Event": {"System": {"EventID": event_id}}},
        ingested_at=now,
    )
    db_session.add(raw)
    await db_session.flush()

    event = NormalizedEventModel(
        id=uuid.uuid4(),
        raw_evidence_id=raw.id,
        event_id=event_id,
        event_type="process_creation",
        event_timestamp=now,
        provider="Microsoft-Windows-Sysmon",
        action="Process Create",
        outcome="success",
        severity="high",
        normalized_payload={"CommandLine": f"test-process-{event_id}.exe", "Summary": summary},
    )
    db_session.add(event)
    await db_session.flush()
    return raw, event


@dataclass
class BolaTestContext:
    """Composite synthetic multi-tenant test environment."""
    admin_token: str
    admin_analyst: Analyst
    lead_token: str
    lead_analyst: Analyst
    analyst_a_token: str
    analyst_a: Analyst
    analyst_b_token: str
    analyst_b: Analyst
    readonly_token: str
    readonly_analyst: Analyst

    case_101: CaseModel
    case_202: CaseModel
    unassigned_case: CaseModel

    raw_101: RawEvidence
    event_101: NormalizedEventModel
    raw_202: RawEvidence
    event_202: NormalizedEventModel
    raw_unlinked: RawEvidence
    event_unlinked: NormalizedEventModel


@pytest.fixture
async def bola_context(db_session) -> BolaTestContext:
    """
    Seed a complete multi-tenant security testing model:
    - Admin: security_admin (no assignments)
    - Lead: analyst_tier_2 (Lead on Case 101)
    - Analyst A: analyst_tier_1 (Investigator on Case 101)
    - Analyst B: analyst_tier_1 (Lead on Case 202)
    - ReadOnly: analyst_tier_1 (Viewer on Case 101)
    - Case 101: Assigned to Lead, Analyst A, ReadOnly
    - Case 202: Assigned to Analyst B
    - Unassigned Case: Assigned to nobody
    - Evidence 101: Linked to Case 101
    - Evidence 202: Linked to Case 202
    - Evidence Unlinked: Not linked to any case
    """
    admin_token, admin_analyst = await seed_analyst_with_token(
        db_session, prefix="adm", username="admin_sec", global_role="security_admin"
    )
    lead_token, lead_analyst = await seed_analyst_with_token(
        db_session, prefix="lead", username="lead_soc", global_role="analyst_tier_2"
    )
    analyst_a_token, analyst_a = await seed_analyst_with_token(
        db_session, prefix="ana", username="analyst_a", global_role="analyst_tier_1"
    )
    analyst_b_token, analyst_b = await seed_analyst_with_token(
        db_session, prefix="anb", username="analyst_b", global_role="analyst_tier_1"
    )
    readonly_token, readonly_analyst = await seed_analyst_with_token(
        db_session, prefix="ro", username="viewer_auditor", global_role="analyst_tier_1"
    )

    # Seed Evidence Records
    raw_101, event_101 = await seed_evidence(db_session, event_id="101", source_identifier="WKSTN-ALPHA")
    raw_202, event_202 = await seed_evidence(db_session, event_id="202", source_identifier="WKSTN-BETA")
    raw_unlinked, event_unlinked = await seed_evidence(db_session, event_id="303", source_identifier="WKSTN-GAMMA")

    # Seed Case 101
    now = datetime.now(timezone.utc)
    case_101 = CaseModel(
        id=uuid.uuid4(),
        case_number="CASE-20261031-0101",
        title="Incident 101 - Alpha Breach",
        description="Investigation Alpha description",
        severity="high",
        status="open",
        created_at=now,
        updated_at=now,
    )
    db_session.add(case_101)
    await db_session.flush()

    # Case 101 Assignments
    db_session.add(CaseAssignmentModel(case_id=case_101.id, analyst_id=lead_analyst.id, case_role="lead", assigned_at=now))
    db_session.add(CaseAssignmentModel(case_id=case_101.id, analyst_id=analyst_a.id, case_role="investigator", assigned_at=now))
    db_session.add(CaseAssignmentModel(case_id=case_101.id, analyst_id=readonly_analyst.id, case_role="viewer", assigned_at=now))

    # Link Evidence 101 to Case 101
    db_session.add(CaseEvidenceModel(
        id=uuid.uuid4(),
        case_id=case_101.id,
        evidence_id=event_101.id,
        linked_by_analyst_id=lead_analyst.id,
        linked_at=now,
    ))

    # Seed Case 202
    case_202 = CaseModel(
        id=uuid.uuid4(),
        case_number="CASE-20261031-0202",
        title="Incident 202 - Beta Malware",
        description="Investigation Beta description",
        severity="medium",
        status="open",
        created_at=now,
        updated_at=now,
    )
    db_session.add(case_202)
    await db_session.flush()

    # Case 202 Assignments (Tier-1 Lead)
    db_session.add(CaseAssignmentModel(case_id=case_202.id, analyst_id=analyst_b.id, case_role="lead", assigned_at=now))

    # Link Evidence 202 to Case 202
    db_session.add(CaseEvidenceModel(
        id=uuid.uuid4(),
        case_id=case_202.id,
        evidence_id=event_202.id,
        linked_by_analyst_id=analyst_b.id,
        linked_at=now,
    ))

    # Seed Unassigned Case (created by an external analyst not in our testing pool)
    unassigned_case = CaseModel(
        id=uuid.uuid4(),
        case_number="CASE-20261031-9999",
        title="Unassigned Case Omega",
        description="Isolated case without test assignments",
        severity="low",
        status="open",
        created_at=now,
        updated_at=now,
    )
    db_session.add(unassigned_case)
    await db_session.commit()

    return BolaTestContext(
        admin_token=admin_token,
        admin_analyst=admin_analyst,
        lead_token=lead_token,
        lead_analyst=lead_analyst,
        analyst_a_token=analyst_a_token,
        analyst_a=analyst_a,
        analyst_b_token=analyst_b_token,
        analyst_b=analyst_b,
        readonly_token=readonly_token,
        readonly_analyst=readonly_analyst,
        case_101=case_101,
        case_202=case_202,
        unassigned_case=unassigned_case,
        raw_101=raw_101,
        event_101=event_101,
        raw_202=raw_202,
        event_202=event_202,
        raw_unlinked=raw_unlinked,
        event_unlinked=event_unlinked,
    )


def auth_header(token: str) -> dict[str, str]:
    """Helper to construct standard Bearer Authorization header."""
    return {"Authorization": f"Bearer {token}"}


# ─────────────────────────────────────────────────────────────────────────────
# SECTION A: Case Access BOLA / Anti-Enumeration
# ─────────────────────────────────────────────────────────────────────────────

class TestBolaCaseAccess:
    """Verify object-level authorization across case endpoints."""

    @pytest.mark.anyio
    async def test_analyst_a_cannot_read_case_202(self, app_instance, bola_context: BolaTestContext):
        """Analyst A (assigned to Case 101) must receive HTTP 404 when querying Case 202."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.case_202.id}",
                headers=auth_header(bola_context.analyst_a_token),
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND
            assert "access denied" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_analyst_b_cannot_read_case_101(self, app_instance, bola_context: BolaTestContext):
        """Analyst B (assigned to Case 202) must receive HTTP 404 when querying Case 101."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.case_101.id}",
                headers=auth_header(bola_context.analyst_b_token),
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND
            assert "access denied" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_analyst_cannot_read_unassigned_case(self, app_instance, bola_context: BolaTestContext):
        """Analyst attempting to read a completely unassigned case receives HTTP 404 anti-enumeration."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.unassigned_case.id}",
                headers=auth_header(bola_context.analyst_a_token),
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND
            assert "access denied" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_unauthenticated_request_rejected(self, app_instance, bola_context: BolaTestContext):
        """Unauthenticated request must be rejected with HTTP 401."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"/api/v1/cases/{bola_context.case_101.id}")
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
            assert "WWW-Authenticate" in resp.headers

    @pytest.mark.anyio
    async def test_readonly_viewer_cannot_update_case_metadata(self, app_instance, bola_context: BolaTestContext):
        """Viewer assigned to Case 101 cannot modify case metadata (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.patch(
                f"/api/v1/cases/{bola_context.case_101.id}",
                headers=auth_header(bola_context.readonly_token),
                json={"title": "Unauthorized Title Override"},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "case role" in resp.json()["detail"].lower() or "permissions" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_investigator_cannot_update_case_metadata(self, app_instance, bola_context: BolaTestContext):
        """Investigator assigned to Case 101 cannot modify case metadata; strictly requires Lead (HTTP 403)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.patch(
                f"/api/v1/cases/{bola_context.case_101.id}",
                headers=auth_header(bola_context.analyst_a_token),
                json={"title": "Investigator Title Override"},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.anyio
    async def test_readonly_viewer_cannot_close_case(self, app_instance, bola_context: BolaTestContext):
        """Viewer cannot close or archive a case (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/close",
                headers=auth_header(bola_context.readonly_token),
                json={"status": "closed", "closure_reason": "Attempted viewer closure"},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.anyio
    async def test_readonly_viewer_cannot_manage_assignments(self, app_instance, bola_context: BolaTestContext):
        """Viewer cannot staff analysts to a case (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/assignments",
                headers=auth_header(bola_context.readonly_token),
                json={"analyst_id": str(bola_context.analyst_b.id), "case_role": "viewer"},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.anyio
    async def test_tier1_lead_cannot_manage_assignments(self, app_instance, bola_context: BolaTestContext):
        """Decision 3A: Tier-1 lead on Case 202 cannot manage staffing (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_202.id}/assignments",
                headers=auth_header(bola_context.analyst_b_token),
                json={"analyst_id": str(bola_context.analyst_a.id), "case_role": "investigator"},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "tier-2 or security admin" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_tier1_lead_cannot_close_case(self, app_instance, bola_context: BolaTestContext):
        """Decision 3A: Tier-1 lead on Case 202 cannot close case (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_202.id}/close",
                headers=auth_header(bola_context.analyst_b_token),
                json={"status": "closed", "closure_reason": "Tier-1 attempted closure"},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "tier-2 or security admin" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_unassigned_admin_cannot_read_case(self, app_instance, bola_context: BolaTestContext):
        """Decision 2A: Security Administrator possesses zero implicit bypass; unassigned read returns HTTP 404."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.case_101.id}",
                headers=auth_header(bola_context.admin_token),
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND
            assert "access denied" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_unassigned_admin_cannot_update_case(self, app_instance, bola_context: BolaTestContext):
        """Decision 2A: Security Administrator cannot modify an unassigned case (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.patch(
                f"/api/v1/cases/{bola_context.case_101.id}",
                headers=auth_header(bola_context.admin_token),
                json={"title": "Admin Override Attempt"},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND


# ─────────────────────────────────────────────────────────────────────────────
# SECTION B: Evidence Access BOLA / Cross-Case Scoping
# ─────────────────────────────────────────────────────────────────────────────

class TestBolaEvidenceAccess:
    """Verify evidence scoping and association authorization boundaries."""

    @pytest.mark.anyio
    async def test_analyst_a_cannot_list_case_202_evidence(self, app_instance, bola_context: BolaTestContext):
        """Analyst A cannot list evidence associated with Case 202 (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.case_202.id}/evidence",
                headers=auth_header(bola_context.analyst_a_token),
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_analyst_b_cannot_list_case_101_evidence(self, app_instance, bola_context: BolaTestContext):
        """Analyst B cannot list evidence associated with Case 101 (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.case_101.id}/evidence",
                headers=auth_header(bola_context.analyst_b_token),
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_analyst_cannot_list_unassigned_case_evidence(self, app_instance, bola_context: BolaTestContext):
        """Analyst cannot list evidence of unassigned case (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.unassigned_case.id}/evidence",
                headers=auth_header(bola_context.analyst_a_token),
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_analyst_a_cannot_link_evidence_to_case_202(self, app_instance, bola_context: BolaTestContext):
        """Analyst A cannot link evidence to Case 202 (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_202.id}/evidence",
                headers=auth_header(bola_context.analyst_a_token),
                json={"evidence_id": str(bola_context.event_unlinked.id)},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_analyst_b_cannot_link_evidence_to_case_101(self, app_instance, bola_context: BolaTestContext):
        """Analyst B cannot link evidence to Case 101 (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/evidence",
                headers=auth_header(bola_context.analyst_b_token),
                json={"evidence_id": str(bola_context.event_unlinked.id)},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_evidence_from_another_case_never_appears_in_case_evidence_list(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Listing evidence for Case 101 returns strictly Case 101 evidence and never leaks Case 202 evidence."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.case_101.id}/evidence",
                headers=auth_header(bola_context.lead_token),
            )
            assert resp.status_code == status.HTTP_200_OK
            data = resp.json()
            returned_ids = [item["id"] for item in data["items"]]

            # Confirmed present
            assert str(bola_context.event_101.id) in returned_ids
            # Confirmed absent (Cross-case boundary)
            assert str(bola_context.event_202.id) not in returned_ids
            assert str(bola_context.event_unlinked.id) not in returned_ids

    @pytest.mark.anyio
    async def test_readonly_viewer_cannot_link_evidence_to_case(self, app_instance, bola_context: BolaTestContext):
        """Viewer on Case 101 is prohibited from linking evidence (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/evidence",
                headers=auth_header(bola_context.readonly_token),
                json={"evidence_id": str(bola_context.event_unlinked.id)},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "insufficient case role permissions" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_unassigned_admin_cannot_list_case_evidence(self, app_instance, bola_context: BolaTestContext):
        """Decision 2A: Unassigned Security Administrator cannot inspect case evidence (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.case_101.id}/evidence",
                headers=auth_header(bola_context.admin_token),
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_unassigned_admin_cannot_link_case_evidence(self, app_instance, bola_context: BolaTestContext):
        """Decision 2A: Unassigned Security Administrator cannot link case evidence (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/evidence",
                headers=auth_header(bola_context.admin_token),
                json={"evidence_id": str(bola_context.event_unlinked.id)},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND


# ─────────────────────────────────────────────────────────────────────────────
# SECTION C: Investigation & Reporting Access BOLA
# ─────────────────────────────────────────────────────────────────────────────

class TestBolaInvestigationAndReportingAccess:
    """Verify investigation synthesis and reporting authorization boundaries."""

    @pytest.mark.anyio
    async def test_analyst_a_cannot_synthesize_investigation_for_case_202(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Analyst A cannot trigger AI synthesis on unauthorized Case 202 (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_202.id}/investigations/synthesize",
                headers=auth_header(bola_context.analyst_a_token),
                json={},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND
            assert "access denied" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_analyst_a_cannot_synthesize_investigation_alias_for_case_202(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Analyst A cannot trigger synthesis via alias route on unauthorized Case 202 (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_202.id}/synthesize",
                headers=auth_header(bola_context.analyst_a_token),
                json={},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_analyst_a_cannot_synthesize_reports_for_case_202(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Analyst A cannot trigger report synthesis on unauthorized Case 202 (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_202.id}/reports/synthesize",
                headers=auth_header(bola_context.analyst_a_token),
                json={},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_analyst_cannot_synthesize_on_unassigned_case(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Analyst cannot synthesize on an unassigned case (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.unassigned_case.id}/investigations/synthesize",
                headers=auth_header(bola_context.analyst_a_token),
                json={},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_readonly_viewer_cannot_synthesize_investigation(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Viewer assigned to Case 101 is prohibited from AI investigation synthesis (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/investigations/synthesize",
                headers=auth_header(bola_context.readonly_token),
                json={},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "investigator" in resp.json()["detail"].lower() or "permissions" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_readonly_viewer_cannot_synthesize_reports(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Viewer assigned to Case 101 is prohibited from report synthesis (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/reports/synthesize",
                headers=auth_header(bola_context.readonly_token),
                json={},
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.anyio
    async def test_unassigned_admin_cannot_synthesize_case_investigation(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Decision 2A: Unassigned Security Administrator cannot synthesize case investigation (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/investigations/synthesize",
                headers=auth_header(bola_context.admin_token),
                json={},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_unassigned_admin_cannot_synthesize_case_reports(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Decision 2A: Unassigned Security Administrator cannot synthesize case reports (HTTP 404)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/reports/synthesize",
                headers=auth_header(bola_context.admin_token),
                json={},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_report_format_with_unassigned_case_id_rejected(
        self, app_instance, bola_context: BolaTestContext
    ):
        """POST /api/v1/reports/format referencing an unassigned case_id returns HTTP 404 (BOLA protection)."""
        now = datetime(2026, 10, 24, 0, 0, 0, tzinfo=timezone.utc)
        output = StructuredInvestigationOutput(
            investigation_id=uuid.uuid4(),
            generated_at=now,
            model_identifier="mock_llm",
            investigation_summary="Suspicious PowerShell command execution detected on workstation.",
            claims=[],
            mitre_attack_hypotheses=[],
            alternative_explanations=[],
            recommended_analyst_actions=["Review endpoint PowerShell transcription logs"],
            uncertainty_and_data_gaps=[],
            overall_grounding_score=1.0,
        )
        val_res = InvestigationValidationResult(
            decision=GuardrailDecision.PASS,
            is_valid=True,
            output=output,
            violations=[],
            context_sha256="0" * 64,
            validated_at_utc=now,
        )
        payload = {
            "validation_result": json.loads(val_res.model_dump_json()),
            "case_id": str(bola_context.case_202.id),  # Analyst A not assigned to Case 202
        }

        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/reports/format",
                headers=auth_header(bola_context.analyst_a_token),
                json=payload,
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND
            assert "access denied" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_direct_unscoped_investigation_synthesis_rejected(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Gate D.2.4: Direct unscoped investigation synthesis is permanently disabled (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/investigations/synthesize",
                headers=auth_header(bola_context.analyst_a_token),
                json={
                    "time_window_start": "2026-10-31T00:00:00Z",
                    "time_window_end": "2026-10-31T01:00:00Z",
                },
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "case-scoped synthesis" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_direct_unscoped_report_synthesis_rejected(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Gate D.2.4: Direct unscoped report synthesis is permanently disabled (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/reports/synthesize",
                headers=auth_header(bola_context.analyst_a_token),
                json={
                    "time_window_start": "2026-10-31T00:00:00Z",
                    "time_window_end": "2026-10-31T01:00:00Z",
                },
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "case-scoped report synthesis" in resp.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# SECTION D: Alternate Authorization Paths & List Filtering
# ─────────────────────────────────────────────────────────────────────────────

class TestBolaAlternateAuthorizationPaths:
    """Verify list and lookup endpoints cannot be abused as backdoors to unauthorized cases."""

    @pytest.mark.anyio
    async def test_list_cases_does_not_expose_unauthorized_cases_for_analyst_a(
        self, app_instance, bola_context: BolaTestContext
    ):
        """GET /api/v1/cases for Analyst A returns ONLY Case 101; Case 202 is completely omitted."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/cases", headers=auth_header(bola_context.analyst_a_token))
            assert resp.status_code == status.HTTP_200_OK
            data = resp.json()
            returned_ids = [c["id"] for c in data["items"]]

            assert str(bola_context.case_101.id) in returned_ids
            assert str(bola_context.case_202.id) not in returned_ids
            assert str(bola_context.unassigned_case.id) not in returned_ids

    @pytest.mark.anyio
    async def test_list_cases_does_not_expose_unauthorized_cases_for_analyst_b(
        self, app_instance, bola_context: BolaTestContext
    ):
        """GET /api/v1/cases for Analyst B returns ONLY Case 202; Case 101 is completely omitted."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/cases", headers=auth_header(bola_context.analyst_b_token))
            assert resp.status_code == status.HTTP_200_OK
            data = resp.json()
            returned_ids = [c["id"] for c in data["items"]]

            assert str(bola_context.case_202.id) in returned_ids
            assert str(bola_context.case_101.id) not in returned_ids
            assert str(bola_context.unassigned_case.id) not in returned_ids

    @pytest.mark.anyio
    async def test_list_cases_for_unassigned_admin_returns_empty(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Security Admin without active case assignments receives an empty list (zero global case leak)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/cases", headers=auth_header(bola_context.admin_token))
            assert resp.status_code == status.HTTP_200_OK
            data = resp.json()
            assert data["total"] == 0
            assert data["items"] == []

    @pytest.mark.anyio
    async def test_direct_unscoped_event_detail_endpoint_blocked(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Direct unscoped event retrieval is disabled; callers cannot bypass case authorization (HTTP 403)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/evidence/events/{bola_context.event_101.id}",
                headers=auth_header(bola_context.analyst_a_token),
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN
            assert "case-scoped evidence retrieval" in resp.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_direct_unscoped_raw_evidence_by_uuid_blocked(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Direct raw evidence retrieval by UUID is disabled (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/evidence/{bola_context.raw_101.id}",
                headers=auth_header(bola_context.analyst_a_token),
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.anyio
    async def test_direct_unscoped_raw_evidence_by_hash_blocked(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Direct raw evidence retrieval by SHA-256 hash is disabled (HTTP 403 Forbidden)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/evidence/by-hash/{bola_context.raw_101.sha256_hash}",
                headers=auth_header(bola_context.analyst_a_token),
            )
            assert resp.status_code == status.HTTP_403_FORBIDDEN


# ─────────────────────────────────────────────────────────────────────────────
# SECTION E: Identifier Manipulation & Fuzzing
# ─────────────────────────────────────────────────────────────────────────────

class TestBolaIdentifierManipulation:
    """Verify input validation, sequential ID rejection, and schema enforcement."""

    @pytest.mark.anyio
    async def test_sequential_integer_id_rejected_with_422(self, app_instance, bola_context: BolaTestContext):
        """Substituting a sequential integer ('101') for UUID path parameter fails validation with HTTP 422."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/cases/101", headers=auth_header(bola_context.analyst_a_token))
            assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.anyio
    async def test_sequential_integer_in_nested_route_rejected_with_422(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Sequential integer in nested evidence route is rejected with HTTP 422."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/cases/101/evidence", headers=auth_header(bola_context.analyst_a_token))
            assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.anyio
    async def test_invalid_string_id_rejected_with_422(self, app_instance, bola_context: BolaTestContext):
        """Non-UUID arbitrary string parameter is rejected with HTTP 422."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/cases/admin-override-bypass", headers=auth_header(bola_context.analyst_a_token))
            assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.anyio
    async def test_nonexistent_uuid_returns_404_identical_to_unassigned(
        self, app_instance, bola_context: BolaTestContext
    ):
        """
        Anti-enumeration invariant: Querying a non-existent UUID returns identical HTTP 404
        status and error body as an unauthorized case query.
        """
        random_uuid = uuid.uuid4()
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp_nonexistent = await client.get(
                f"/api/v1/cases/{random_uuid}",
                headers=auth_header(bola_context.analyst_a_token),
            )
            resp_unassigned = await client.get(
                f"/api/v1/cases/{bola_context.case_202.id}",
                headers=auth_header(bola_context.analyst_a_token),
            )
            assert resp_nonexistent.status_code == status.HTTP_404_NOT_FOUND
            assert resp_unassigned.status_code == status.HTTP_404_NOT_FOUND
            assert _no_rid(resp_nonexistent.json()) == _no_rid(resp_unassigned.json())  # per-request id legitimately differs

    @pytest.mark.anyio
    async def test_link_evidence_with_invalid_uuid_in_body_rejected_with_422(
        self, app_instance, bola_context: BolaTestContext
    ):
        """POST /cases/{case_id}/evidence with non-UUID body parameter fails validation with HTTP 422."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/evidence",
                headers=auth_header(bola_context.lead_token),
                json={"evidence_id": "malformed-evidence-id-not-uuid"},
            )
            assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.anyio
    async def test_link_evidence_with_nonexistent_uuid_returns_404(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Linking a non-existent evidence UUID returns HTTP 404 (Evidence not found)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/cases/{bola_context.case_101.id}/evidence",
                headers=auth_header(bola_context.lead_token),
                json={"evidence_id": str(uuid.uuid4())},
            )
            assert resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.anyio
    async def test_case_list_query_params_negative_page_rejected_with_422(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Negative page query parameter is rejected with HTTP 422."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/cases?page=-1", headers=auth_header(bola_context.analyst_a_token))
            assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.anyio
    async def test_nested_evidence_query_params_zero_page_rejected_with_422(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Page=0 query parameter on nested evidence route is rejected with HTTP 422 (ge=1)."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.case_101.id}/evidence?page=0",
                headers=auth_header(bola_context.lead_token),
            )
            assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.anyio
    async def test_nested_evidence_query_params_excessive_limit_rejected_with_422(
        self, app_instance, bola_context: BolaTestContext
    ):
        """Limit parameter exceeding MAX_PAGE_SIZE (200) is rejected with HTTP 422."""
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/api/v1/cases/{bola_context.case_101.id}/evidence?limit=1000",
                headers=auth_header(bola_context.lead_token),
            )
            assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
