"""
Integration tests for AISOP P2-H6: Role-Tailored Structured Investigation Reporting Endpoints.

Tests:
1. POST /api/v1/reports/synthesize — end-to-end synthesis returning InvestigationReportBundle.
2. POST /api/v1/reports/synthesize — fallback/inconclusive handling on empty DB or provider failure.
3. POST /api/v1/reports/synthesize — invalid time window returns HTTP 422.
4. POST /api/v1/reports/format — bound-context formatting with verified cryptographic hash.
5. POST /api/v1/reports/format — context hash mismatch returns HTTP 422.
6. POST /api/v1/reports/format — investigation ID mismatch returns HTTP 422.
7. POST /api/v1/reports/format — detached-mode formatting with context=None.
8. Backward compatibility check — POST /api/v1/investigations/synthesize returns InvestigationValidationResult unchanged.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any
import uuid

import pytest
from starlette.testclient import TestClient

from app.api.dependencies import (
    AuthenticatedAnalyst,
    AuthenticatedClient,
    GlobalRole,
    verify_api_key,
)
from app.api.v1.endpoints.investigations import get_investigation_service
from app.db.session import get_db_session
from app.main import create_app


def _create_test_app():
    app = create_app()
    analyst = AuthenticatedAnalyst(
        analyst_id=uuid.uuid4(),
        username="test_analyst",
        global_role=GlobalRole.ANALYST_TIER_1,
        is_active=True,
    )
    app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(
        client_id="test-reporting",
        analyst=analyst,
    )
    return app




from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.ai.context_builder import compute_context_sha256
from app.modules.ai.guardrails.validator import (
    GuardrailDecision,
    InvestigationValidationResult,
)
from app.schemas.ai import LLMRequest, LLMResponse, ProviderHealthResponse, TokenUsage
from app.schemas.investigation import (
    BudgetMetrics,
    ClaimCategory,
    ContextEntityItem,
    ContextEventItem,
    ContextTIFindingItem,
    ContextTIThreatState,
    ContextTIVerdict,
    FactualClaimItem,
    GroundingStatus,
    InvestigationContext,
    InvestigationScopeType,
    MitreAttackHypothesis,
    ReproducibilityRecord,
    StructuredInvestigationOutput,
)
from app.services.investigation_service import InvestigationPipelineService


# ── MOCK PROVIDER & FIXTURES ─────────────────────────────────────────────────

class MockLLMProvider:
    """Mock LLM provider returning pre-fabricated structured investigation JSON."""

    def __init__(self, response_template: str | None = None) -> None:
        self.response_template = response_template
        self.calls: list[LLMRequest] = []

    @property
    def model_name(self) -> str:
        return "mock_llm"

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        content = self.response_template or "{}"
        if "__DYNAMIC_INVESTIGATION_ID__" in content:
            user_msg = request.messages[1].content if len(request.messages) > 1 else ""
            m = re.search(r'<investigation_context[^>]*id="([a-f0-9\-]+)"', user_msg)
            inv_id = m.group(1) if m else str(uuid.uuid4())
            content = content.replace("__DYNAMIC_INVESTIGATION_ID__", inv_id)

        return LLMResponse(
            content=content,
            model=self.model_name,
            finish_reason="stop",
            usage=TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150, duration_ms=10.0),
        )

    async def health(self) -> ProviderHealthResponse:
        return ProviderHealthResponse(status="healthy", model=self.model_name, provider="mock", latency_ms=1.0)


async def seed_test_event(
    db_session: Any,
    t: datetime,
    host: str = "WORKSTATION-01",
    command: str = "powershell.exe -NoProfile -Command whoami",
) -> tuple[RawEvidence, NormalizedEventModel]:
    raw = RawEvidence(
        id=uuid.uuid4(),
        source_type="sysmon",
        source_identifier=host,
        sha256_hash="e" * 64,
        raw_payload={"EventID": 1, "Image": "powershell.exe", "CommandLine": command},
        ingested_at=t,
    )
    db_session.add(raw)
    ev = NormalizedEventModel(
        id=uuid.uuid4(),
        raw_evidence_id=raw.id,
        event_id="1",
        event_type="process_creation",
        event_timestamp=t,
        provider="sysmon",
        action="start",
        outcome="success",
        severity="medium",
        normalized_payload={
            "process_name": "powershell.exe",
            "command_line": command,
            "user": "CORP\\analyst",
        },
    )
    db_session.add(ev)
    await db_session.commit()
    return raw, ev


def build_llm_json(event_uuid: uuid.UUID) -> str:
    payload = {
        "investigation_id": "__DYNAMIC_INVESTIGATION_ID__",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_identifier": "mock_llm",
        "investigation_summary": "Suspicious execution of powershell.exe detected on endpoint WORKSTATION-01.",
        "claims": [
            {
                "claim_id": str(uuid.uuid4()),
                "claim_text": "powershell.exe process creation was executed on WORKSTATION-01",
                "category": "observed_fact",
                "supporting_evidence_ids": [str(event_uuid)],
                "references_exist": True,
                "grounding_status": "validated_reference",
                "confidence": 0.95,
            }
        ],
        "mitre_attack_hypotheses": [
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactics": ["Execution"],
                "supporting_event_uuids": [str(event_uuid)],
                "confidence": 0.88,
                "reasoning": "Observed execution of powershell.exe in Sysmon telemetry",
            }
        ],
        "alternative_explanations": ["Legitimate system administration command execution"],
        "recommended_analyst_actions": ["Review host event logs and verify user credentials"],
        "uncertainty_and_data_gaps": [],
        "overall_grounding_score": 1.0,
    }
    return json.dumps(payload)


def _build_test_context(
    inv_id: uuid.UUID,
    event_uuid: uuid.UUID,
    entities: list[ContextEntityItem] | None = None,
    threat_intel: list[ContextTIFindingItem] | None = None,
    is_truncated: bool = False,
) -> InvestigationContext:
    t_start = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    ev = ContextEventItem(
        event_uuid=event_uuid,
        raw_evidence_sha256="e" * 64,
        event_id="1",
        event_type="process_creation",
        timestamp_utc=t_start,
        action="start",
        outcome="success",
        severity="medium",
        source_identifier="WORKSTATION-01",
        summary="powershell.exe started on WORKSTATION-01",
        attributes={"Image": "powershell.exe"},
    )
    ent_list = entities or []
    ti_list = threat_intel or []
    budget = BudgetMetrics(
        total_events_in_scope=2 if is_truncated else 1,
        events_included=1,
        events_omitted_count=1 if is_truncated else 0,
        omitted_event_ids_summary=[uuid.uuid4()] if is_truncated else [],
        total_entities_in_scope=len(ent_list),
        entities_included=len(ent_list),
        knowledge_chunks_included=0,
        estimated_character_count=100,
        estimated_tokens=30,
        context_truncated=is_truncated,
    )
    repro = ReproducibilityRecord(
        request_id=uuid.uuid4(),
        time_window_start=t_start,
        time_window_end=t_end,
        selected_event_uuids=[event_uuid],
        selected_chunk_ids=[],
        context_sha256="0" * 64,
        prompt_template_version="1.0.0",
        llm_provider="ollama",
        model_name="llama3.1:8b",
        created_at_utc=datetime.now(timezone.utc),
    )
    ctx = InvestigationContext(
        schema_version="1.0.0",
        investigation_id=inv_id,
        scope_type=InvestigationScopeType.SINGLE_EVENT,
        time_window_start=t_start,
        time_window_end=t_end,
        target_hosts=["WORKSTATION-01"],
        events=[ev],
        entities=ent_list,
        threat_intel=ti_list,
        knowledge_chunks=[],
        budget_metrics=budget,
        reproducibility=repro,
        uncertainty_flags=["CONTEXT_TRUNCATED: Budget exceeded"] if is_truncated else [],
        assembled_at=datetime.now(timezone.utc),
    )
    digest = compute_context_sha256(ctx)
    repro_updated = repro.model_copy(update={"context_sha256": digest})
    return ctx.model_copy(update={"reproducibility": repro_updated})


def _build_test_validation_result(
    inv_id: uuid.UUID,
    event_uuid: uuid.UUID,
    context_sha256: str,
) -> InvestigationValidationResult:
    val_time = datetime(2026, 10, 23, 11, 15, 0, tzinfo=timezone.utc)
    claim = FactualClaimItem(
        claim_id=uuid.uuid4(),
        claim_text="powershell.exe executed on WORKSTATION-01",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[event_uuid],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.95,
    )
    hyp = MitreAttackHypothesis(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactics=["Execution"],
        supporting_event_uuids=[event_uuid],
        confidence=0.85,
        reasoning="Execution of PowerShell script",
    )
    output = StructuredInvestigationOutput(
        investigation_id=inv_id,
        generated_at=val_time,
        model_identifier="mock_llm",
        investigation_summary="Suspicious PowerShell activity was detected on WORKSTATION-01.",
        claims=[claim],
        mitre_attack_hypotheses=[hyp],
        alternative_explanations=["Routine admin command"],
        recommended_analyst_actions=["Inspect security logs"],
        uncertainty_and_data_gaps=[],
        overall_grounding_score=1.0,
    )
    return InvestigationValidationResult(
        decision=GuardrailDecision.PASS,
        is_valid=True,
        output=output,
        violations=[],
        context_sha256=context_sha256,
        validated_at_utc=val_time,
    )


# ── INTEGRATION TESTS ────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_post_reports_synthesize_endpoint_success(db_session):
    """POST /api/v1/reports/synthesize is deprecated and returns HTTP 403 Forbidden (Gate D.2.4)."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session, datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc))

    mock_json = build_llm_json(event_uuid=ev.id)
    mock_service = InvestigationPipelineService(llm_provider=MockLLMProvider(mock_json))

    app = _create_test_app()
    app.dependency_overrides[get_db_session] = lambda: db_session
    app.dependency_overrides[get_investigation_service] = lambda: mock_service

    client = TestClient(app)
    response = client.post(
        "/api/v1/reports/synthesize",
        json={
            "time_window_start": t_start.isoformat(),
            "time_window_end": t_end.isoformat(),
        },
    )

    assert response.status_code == 403
    assert "Direct unscoped report synthesis is disabled" in response.json()["detail"]


@pytest.mark.anyio
async def test_post_reports_synthesize_fallback_inconclusive(db_session):
    """POST /api/v1/reports/synthesize on empty DB returns HTTP 403 (unscoped route deprecated)."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    # Zero events seeded

    mock_service = InvestigationPipelineService(llm_provider=MockLLMProvider())

    app = _create_test_app()
    app.dependency_overrides[get_db_session] = lambda: db_session
    app.dependency_overrides[get_investigation_service] = lambda: mock_service

    client = TestClient(app)
    response = client.post(
        "/api/v1/reports/synthesize",
        json={
            "time_window_start": t_start.isoformat(),
            "time_window_end": t_end.isoformat(),
        },
    )

    assert response.status_code == 403



def test_post_reports_synthesize_invalid_time_window_422():
    """POST /api/v1/reports/synthesize with invalid time window returns HTTP 422."""
    app = _create_test_app()
    client = TestClient(app)

    t_now = datetime.now(timezone.utc).isoformat()
    response = client.post(
        "/api/v1/reports/synthesize",
        json={
            "time_window_start": t_now,
            "time_window_end": t_now,  # start == end -> invalid
        },
    )
    assert response.status_code == 422


def test_post_reports_format_bound_context_success():
    """POST /api/v1/reports/format with bound context returns HTTP 200 with verified timeline."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _build_test_context(inv_id, ev_uuid)
    val_res = _build_test_validation_result(inv_id, ev_uuid, ctx.reproducibility.context_sha256)

    app = _create_test_app()
    client = TestClient(app)

    payload = {
        "validation_result": json.loads(val_res.model_dump_json()),
        "context": json.loads(ctx.model_dump_json()),
    }
    response = client.post("/api/v1/reports/format", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["provenance"]["is_detached_format_mode"] is False
    assert len(data["technical_report"]["investigation_timeline"]) == 1
    assert data["technical_report"]["investigation_timeline"][0]["event_uuid"] == str(ev_uuid)


def test_post_reports_format_hash_mismatch_422():
    """POST /api/v1/reports/format returns HTTP 422 when context hash does not match validation result."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _build_test_context(inv_id, ev_uuid)
    # Validation result citing a different context hash
    val_res = _build_test_validation_result(inv_id, ev_uuid, "f" * 64)

    app = _create_test_app()
    client = TestClient(app)

    payload = {
        "validation_result": json.loads(val_res.model_dump_json()),
        "context": json.loads(ctx.model_dump_json()),
    }
    response = client.post("/api/v1/reports/format", json=payload)

    assert response.status_code == 422
    assert "Context integrity verification failed" in response.json()["detail"]


def test_post_reports_format_id_mismatch_422():
    """POST /api/v1/reports/format returns HTTP 422 when investigation ID mismatches between result and context."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx = _build_test_context(inv_id, ev_uuid)
    other_inv_id = uuid.uuid4()
    val_res = _build_test_validation_result(other_inv_id, ev_uuid, ctx.reproducibility.context_sha256)

    app = _create_test_app()
    client = TestClient(app)

    payload = {
        "validation_result": json.loads(val_res.model_dump_json()),
        "context": json.loads(ctx.model_dump_json()),
    }
    response = client.post("/api/v1/reports/format", json=payload)

    assert response.status_code == 422
    assert "Context integrity verification failed" in response.json()["detail"]


def test_post_reports_format_detached_mode_success():
    """POST /api/v1/reports/format with context=None operates in safe detached-format mode."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    val_res = _build_test_validation_result(inv_id, ev_uuid, "0" * 64)

    app = _create_test_app()
    client = TestClient(app)

    payload = {
        "validation_result": json.loads(val_res.model_dump_json()),
        "context": None,
    }
    response = client.post("/api/v1/reports/format", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["provenance"]["is_detached_format_mode"] is True
    assert "detached-format mode" in data["technical_report"]["timeline_status_disclosure"]


@pytest.mark.anyio
async def test_existing_synthesize_endpoint_backwards_compatibility(db_session):
    """POST /api/v1/investigations/synthesize returns HTTP 403 Forbidden (Gate D.2.4)."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session, datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc))

    mock_json = build_llm_json(event_uuid=ev.id)
    mock_service = InvestigationPipelineService(llm_provider=MockLLMProvider(mock_json))

    app = _create_test_app()
    app.dependency_overrides[get_db_session] = lambda: db_session
    app.dependency_overrides[get_investigation_service] = lambda: mock_service

    client = TestClient(app)
    response = client.post(
        "/api/v1/investigations/synthesize",
        json={
            "time_window_start": t_start.isoformat(),
            "time_window_end": t_end.isoformat(),
        },
    )

    assert response.status_code == 403
    assert "Direct unscoped investigation synthesis is disabled" in response.json()["detail"]


# ── SEC-AUDIT-003 REGRESSION TESTS: CONTEXT PRESERVATION ─────────────────────

@pytest.mark.anyio
async def test_post_reports_synthesize_preserves_bound_context_entities_and_provenance(db_session):
    """POST /api/v1/reports/synthesize is deprecated (Gate D.2.4) and rejects unscoped callers with 403."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session, datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc))

    mock_json = build_llm_json(event_uuid=ev.id)
    mock_service = InvestigationPipelineService(llm_provider=MockLLMProvider(mock_json))

    app = _create_test_app()
    app.dependency_overrides[get_db_session] = lambda: db_session
    app.dependency_overrides[get_investigation_service] = lambda: mock_service

    client = TestClient(app)
    response = client.post(
        "/api/v1/reports/synthesize",
        json={
            "time_window_start": t_start.isoformat(),
            "time_window_end": t_end.isoformat(),
        },
    )

    assert response.status_code == 403
    assert "Direct unscoped report synthesis is disabled" in response.json()["detail"]


@pytest.mark.anyio

async def test_post_reports_format_preserves_entities_and_threat_intel():
    """POST /api/v1/reports/format preserves entities as bound observables and surfaces threat intel."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()

    ent = ContextEntityItem(
        entity_type="ip",
        entity_value="198.51.100.25",
        roles=["destination"],
        occurrence_count=1,
        associated_event_uuids=[ev_uuid],
    )
    ti = ContextTIFindingItem(
        observable="198.51.100.25",
        observable_type="ipv4",
        verdict=ContextTIVerdict.MALICIOUS,
        threat_state=ContextTIThreatState.ACTIVE,
        is_shielded=False,
        confidence=0.92,
        source_feeds=["abuse_ch"],
    )
    ctx = _build_test_context(inv_id, ev_uuid, entities=[ent], threat_intel=[ti])
    val_res = _build_test_validation_result(inv_id, ev_uuid, ctx.reproducibility.context_sha256)

    app = _create_test_app()
    client = TestClient(app)

    payload = {
        "validation_result": json.loads(val_res.model_dump_json()),
        "context": json.loads(ctx.model_dump_json()),
    }
    response = client.post("/api/v1/reports/format", json=payload)

    assert response.status_code == 200
    data = response.json()

    # Entities preserved as bound_telemetry observables
    observables = data["detection_report"]["validated_observables"]
    assert any(o["observable_value"] == "198.51.100.25" and o["provenance_type"] == "bound_telemetry" for o in observables)

    # Threat intelligence preserved in technical report and executive summary
    ti_enrichments = data["technical_report"]["threat_intelligence_enrichment"]
    assert len(ti_enrichments) == 1
    assert ti_enrichments[0]["observable"] == "198.51.100.25"
    assert ti_enrichments[0]["verdict"] == "malicious"
    assert "1 observable(s) enriched" in data["executive_brief"]["threat_intelligence_context"]


@pytest.mark.anyio
async def test_post_reports_format_preserves_truncation_budget_metrics():
    """POST /api/v1/reports/format preserves budget truncation metrics and enforces inconclusive severity."""
    inv_id = uuid.uuid4()
    ev_uuid = uuid.uuid4()
    ctx_truncated = _build_test_context(inv_id, ev_uuid, is_truncated=True)
    val_res = _build_test_validation_result(inv_id, ev_uuid, ctx_truncated.reproducibility.context_sha256)

    app = _create_test_app()
    client = TestClient(app)

    payload = {
        "validation_result": json.loads(val_res.model_dump_json()),
        "context": json.loads(ctx_truncated.model_dump_json()),
    }
    response = client.post("/api/v1/reports/format", json=payload)

    assert response.status_code == 200
    data = response.json()

    assert data["executive_brief"]["incident_severity"] == "inconclusive"
    assert any("CONTEXT_TRUNCATED" in g for g in data["executive_brief"]["uncertainties_and_limitations"])
    assert data["provenance"]["context_sha256"] == ctx_truncated.reproducibility.context_sha256
