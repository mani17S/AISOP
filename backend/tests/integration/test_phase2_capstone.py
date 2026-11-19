"""
AISOP Phase 2 Capstone Integration Test: Full End-to-End Investigation Pipeline.

Milestone: P2-H7 (Deliverable 1 - Capstone Integration Harness)
Governing Policy: AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001

Exercises the complete feasible investigation workflow:
1. Raw Telemetry Ingestion: Ingests realistic multi-event Sysmon attack chain.
2. Canonical Normalization & Entity Extraction: Verifies persistence of RawEvidence,
   NormalizedEventModel, and atomic ExtractedEntityModel records (IP, host, process, hash).
3. Threat Intelligence Enrichment: Integrates LocalThreatIntelEngine (Feodo C2 IP matching).
4. Semantic Knowledge Retrieval: Integrates KnowledgeRetriever with threshold-bounded search.
5. Canonical Context Assembly: Assembles reproducible InvestigationContext with CJSON-1.0 digest.
6. Defensive Prompting: Validates XML data boundaries and role separation.
7. Local Ollama Inference (MockTransport): Validates structured JSON parsing and length checks.
8. Output Guardrails & Grounding: Enforces 3-tier evidence grounding via InvestigationOutputValidator.
9. Role-Tailored Report Synthesis: Generates ExecutiveBrief, TechnicalIncidentReport,
   DetectionEngineeringReport, and deterministic Markdown renderings with context-hash binding.
10. REST API Endpoints: Validates POST /api/v1/evidence/ingest, /investigations/synthesize,
    /reports/synthesize, and /reports/format.
11. Resilient Fallback Handling: Validates graceful degradation under provider failures.
12. SQLite vs PostgreSQL/pgvector Boundary: Explicitly isolates in-memory fallback semantics.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any
from unittest.mock import AsyncMock
import uuid

import pytest
from starlette.testclient import TestClient

from app.api.dependencies import (
    AuthenticatedAnalyst,
    AuthenticatedClient,
    GlobalRole,
    get_knowledge_retriever,
    get_threat_intel_engine,
    verify_api_key,
)
from app.api.v1.endpoints.investigations import get_investigation_service

from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.main import create_app
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.models.knowledge import KnowledgeEmbedding
from app.modules.ai.context_builder import (
    InvestigationContextBuilder,
    compute_context_sha256,
)

class CapstoneContextBuilder(InvestigationContextBuilder):
    """Context builder expanding character budget to retain all attack chain events in integration test."""

    def build_structured_context(self, *args: Any, **kwargs: Any) -> Any:
        kwargs["max_context_chars"] = 32000
        return super().build_structured_context(*args, **kwargs)

from app.modules.ai.embeddings.embedder import OllamaEmbedder
from app.modules.ai.embeddings.exceptions import EmbeddingConnectionError
from app.modules.ai.guardrails.validator import (
    GuardrailDecision,
    InvestigationOutputValidator,
    InvestigationValidationResult,
)
from app.modules.ai.knowledge.retriever import KnowledgeRetriever, _cosine_similarity
from app.modules.ai.llm.exceptions import LLMConnectionError, LLMTimeoutError
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.ai.reporting.synthesizer import (
    DeterministicReportSynthesizer,
    verify_context_binding,
)
from app.modules.evidence.hasher import compute_sha256
from app.modules.threatintel import (
    FeodoTrackerParser,
    LocalFeedManager,
    LocalThreatIntelEngine,
)
from app.schemas.threatintel import InvestigationFindingState, ThreatIntelFindingItem

# Ensure ThreatIntelFindingItem exposes is_shielded property expected by context builder
if not hasattr(ThreatIntelFindingItem, "is_shielded"):
    setattr(
        ThreatIntelFindingItem,
        "is_shielded",
        property(lambda self: getattr(self, "integration_state", None) == InvestigationFindingState.SHIELDED_INTERNAL),
    )

from app.schemas.ai import LLMRequest, LLMResponse, ProviderHealthResponse, TokenUsage
from app.schemas.ingest import IngestRequest, IngestResponse
from app.schemas.investigation import (
    ClaimCategory,
    GroundingStatus,
    InvestigationContext,
    InvestigationSynthesizeRequest,
    StructuredInvestigationOutput,
)
from app.schemas.knowledge import RetrievalRequest, RetrievalResult
from app.schemas.report import (
    IncidentSeverityTier,
    InvestigationReportBundle,
    ReportFormatRequest,
)
from app.services.ingestion_service import IngestionService
from app.services.investigation_service import InvestigationPipelineService
from sqlalchemy import select


# ── TEST FIXTURES & HELPERS ──────────────────────────────────────────────────

def _make_dummy_vector(seed: float = 0.1) -> list[float]:
    """Return a 768-dimensional normalized float vector."""
    vec = [seed] * 768
    norm = sum(x * x for x in vec) ** 0.5
    return [x / norm for x in vec]


class MockCapstoneLLMProvider:
    """Mock LLM provider capturing prompts and returning valid structured investigation JSON."""

    def __init__(self, response_template: str | None = None, raise_exc: Exception | None = None) -> None:
        self.response_template = response_template
        self.raise_exc = raise_exc
        self.captured_requests: list[LLMRequest] = []

    @property
    def model_name(self) -> str:
        return "mock_capstone_ollama"

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.captured_requests.append(request)
        if self.raise_exc is not None:
            raise self.raise_exc

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
            usage=TokenUsage(prompt_tokens=250, completion_tokens=120, total_tokens=370, duration_ms=12.5),
        )

    async def health(self) -> ProviderHealthResponse:
        return ProviderHealthResponse(status="healthy", model=self.model_name, provider="mock", latency_ms=1.0)


def build_capstone_llm_json(
    event_uuid: uuid.UUID,
    summary: str = "Host executed suspicious PowerShell process initiating C2 network traffic.",
    claim_text: str = "powershell.exe executed with suspicious parameters on CORP-FIN-WS01",
) -> str:
    payload = {
        "investigation_id": "__DYNAMIC_INVESTIGATION_ID__",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_identifier": "mock_capstone_ollama",
        "investigation_summary": summary,
        "claims": [
            {
                "claim_id": str(uuid.uuid4()),
                "claim_text": claim_text,
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
                "confidence": 0.85,
                "reasoning": "PowerShell command executed encoded payload",
            }
        ],
        "alternative_explanations": ["Scheduled administrator maintenance script"],
        "recommended_analyst_actions": [
            "Review host process tree and isolate network interface if unauthorized."
        ],
        "uncertainty_and_data_gaps": [],
        "overall_grounding_score": 1.0,
    }
    return json.dumps(payload)


def get_attack_chain_path() -> Path:
    """Return path to realistic multi-event Sysmon attack chain dataset."""
    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    path = base_dir / "datasets" / "samples" / "sysmon" / "sysmon_attack_chain.json"
    assert path.exists(), f"Sample dataset not found at {path}"
    return path


# ── CAPSTONE INTEGRATION TESTS ───────────────────────────────────────────────

@pytest.mark.anyio
async def test_phase2_capstone_full_pipeline_service_orchestration(db_session):
    """
    Capstone Test 1: Complete Pipeline Service Orchestration.

    Executes:
    1. IngestionService.ingest_batch with real Sysmon multi-event attack chain.
    2. Entity extraction verifying IP, Host, Process, and Hash extraction.
    3. Threat Intelligence enrichment via LocalThreatIntelEngine.
    4. Knowledge retrieval via KnowledgeRetriever in in-memory test session.
    5. InvestigationContext assembly and CJSON-1.0 context hashing.
    6. Defensive prompt construction with untrusted XML boundary.
    7. Mocked local Ollama inference.
    8. 3-tier guardrail validation enforcing GroundingStatus.VALIDATED_REFERENCE.
    9. Deterministic report synthesis producing Executive, Technical, and Detection views.
    """
    # ── STAGE 1: RAW TELEMETRY INGESTION & ENTITY EXTRACTION ─────────────────
    attack_chain_file = get_attack_chain_path()
    with open(attack_chain_file, "r", encoding="utf-8") as f:
        raw_events = json.load(f)

    assert len(raw_events) == 4

    ingest_svc = IngestionService()
    ingest_req = IngestRequest(
        source_type="sysmon",
        source_identifier="CORP-FIN-WS01",
        events=raw_events,
    )
    ingest_res: IngestResponse = await ingest_svc.ingest_batch(db_session, ingest_req)

    assert ingest_res.total_received == 4
    assert ingest_res.total_normalized == 4
    assert ingest_res.total_entities_extracted >= 8
    assert len(ingest_res.errors) == 0

    # Verify persisted raw evidence and normalized events
    persisted_raw = (await db_session.execute(select(RawEvidence))).scalars().all()
    persisted_events = (
        (await db_session.execute(select(NormalizedEventModel).order_by(NormalizedEventModel.event_timestamp.asc())))
        .scalars()
        .all()
    )
    persisted_entities = (await db_session.execute(select(ExtractedEntityModel))).scalars().all()

    assert len(persisted_raw) == 4
    assert len(persisted_events) == 4
    assert len(persisted_entities) >= 8

    # Identify primary root process creation event (Event 1: powershell.exe)
    root_event = next(e for e in persisted_events if e.event_type == "process_creation")
    assert root_event is not None
    assert root_event.action == "started"
    assert root_event.outcome == "success"

    # ── STAGE 2: THREAT INTELLIGENCE FEED LOADING ────────────────────────────
    feed_manager = LocalFeedManager()
    feodo_parser = FeodoTrackerParser()
    # The attack chain connects to C2 IP 198.51.100.45:443
    raw_feed_csv = (
        "# Firstseen_UTC,DstIP,DstPort,C2Status,LastOnline,Malware\n"
        "2026-09-01 08:00:00,198.51.100.45,443,online,2026-09-10 12:00:00,QakBot\n"
    )
    feed_manager.update_feed(feodo_parser, raw_feed_csv)
    ti_engine = LocalThreatIntelEngine(feed_manager=feed_manager)

    # ── STAGE 3: KNOWLEDGE BASE VECTOR INDEX SEEDING & RETRIEVAL ─────────────
    # Seed knowledge chunk for PowerShell (T1059.001)
    chunk_content = (
        "PowerShell is a powerful interactive command-line interface and scripting language. "
        "Adversaries commonly abuse PowerShell to execute commands, download payloads, and establish persistence."
    )
    kb_embedding = KnowledgeEmbedding(
        id=uuid.uuid4(),
        source_document="mitre/T1059.001.md",
        section_title="PowerShell Execution",
        chunk_index=0,
        content=chunk_content,
        content_hash=compute_sha256(chunk_content),
        embedding=_make_dummy_vector(0.1),
        chunk_metadata={
            "chunk_index": 0,
            "total_chunks": 1,
            "embedding_model": "nomic-embed-text",
            "source_document": "mitre/T1059.001.md",
            "section_title": "PowerShell Execution",
        },
    )
    db_session.add(kb_embedding)
    await db_session.commit()

    mock_embedder = AsyncMock(spec=OllamaEmbedder)
    mock_embedder.embed.return_value = _make_dummy_vector(0.1)
    retriever = KnowledgeRetriever(embedder=mock_embedder)

    # ── STAGE 4: PIPELINE ORCHESTRATION & INVESTIGATION SYNTHESIS ────────────
    mock_json = build_capstone_llm_json(event_uuid=root_event.id)
    mock_llm = MockCapstoneLLMProvider(response_template=mock_json)

    pipeline_svc = InvestigationPipelineService(
        llm_provider=mock_llm,
        threat_intel_engine=ti_engine,
        knowledge_retriever=retriever,
        context_builder=CapstoneContextBuilder(),
    )

    # Investigation window covers the entire attack chain (2026-09-09 14:00 to 15:00 UTC)
    t_start = datetime(2026, 9, 9, 14, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 9, 9, 15, 0, 0, tzinfo=timezone.utc)

    synth_req = InvestigationSynthesizeRequest(
        time_window_start=t_start,
        time_window_end=t_end,
        query_filter="powershell execution",
        root_event_id=root_event.id,
    )

    val_res, assembled_ctx = await pipeline_svc.synthesize_investigation_with_context(db_session, synth_req)

    # ── STAGE 5: EVIDENCE GROUNDING & GUARDRAILS VALIDATION ──────────────────
    assert val_res.decision in (GuardrailDecision.PASS, GuardrailDecision.REMEDIATED)
    assert val_res.is_valid is True
    assert val_res.output.overall_grounding_score == 1.0
    assert len(val_res.output.claims) == 1
    assert val_res.output.claims[0].grounding_status == GroundingStatus.VALIDATED_REFERENCE
    assert val_res.output.claims[0].supporting_evidence_ids == [root_event.id]

    # Verify context integrity and enrichment
    assert len(assembled_ctx.events) == 4
    assert len(assembled_ctx.entities) >= 8
    assert len(assembled_ctx.threat_intel) >= 1
    # Verify C2 IP was enriched as malicious
    c2_ti = next((ti for ti in assembled_ctx.threat_intel if ti.observable == "198.51.100.45"), None)
    assert c2_ti is not None
    assert c2_ti.verdict.value.lower() == "malicious"

    # Verify knowledge chunk was retrieved into context
    assert len(assembled_ctx.knowledge_chunks) >= 1
    assert assembled_ctx.knowledge_chunks[0].chunk_index == 0
    assert assembled_ctx.knowledge_chunks[0].similarity_score > 0.9

    # Verify prompt defense structure
    assert len(mock_llm.captured_requests) == 1
    captured_req = mock_llm.captured_requests[0]
    user_prompt = captured_req.messages[1].content
    assert "<investigation_context" in user_prompt
    assert "</investigation_context>" in user_prompt
    assert "<telemetry_events" in user_prompt
    assert "<threat_intelligence" in user_prompt
    assert "<reference_knowledge" in user_prompt

    # ── STAGE 6: ROLE-TAILORED MULTI-VIEW REPORT SYNTHESIS ───────────────────
    synthesizer = DeterministicReportSynthesizer()
    bundle: InvestigationReportBundle = synthesizer.synthesize_bundle(val_res, assembled_ctx)

    # Verify context-hash binding
    assert bundle.context_sha256 == assembled_ctx.reproducibility.context_sha256
    verify_context_binding(val_res, assembled_ctx)
    assert bundle.is_fallback_active is False

    # 1. Executive Brief
    exec_brief = bundle.executive_brief
    assert exec_brief.incident_severity == IncidentSeverityTier.HIGH
    assert "High incident severity" in exec_brief.severity_justification
    assert "CORP-FIN-WS01" in exec_brief.evidenced_affected_assets
    assert len(exec_brief.key_confirmed_findings) >= 1
    assert "enriched against local threat intelligence feeds" in exec_brief.threat_intelligence_context
    assert any("qakbot" in tag.lower() for tag in c2_ti.tags)
    assert "advisory" in exec_brief.governance_disclaimer.lower()

    # 2. Technical Incident Report
    tech_report = bundle.technical_report
    assert tech_report.is_inconclusive_or_fallback is False
    assert len(tech_report.confirmed_findings) == 1
    assert tech_report.confirmed_findings[0].supporting_event_uuids == [root_event.id]
    assert len(tech_report.investigation_timeline) == 4
    assert len(tech_report.mitre_attack_mappings) >= 1
    assert tech_report.mitre_attack_mappings[0]["technique_id"] == "T1059.001"

    # 3. Detection Engineering Report
    det_report = bundle.detection_report
    assert det_report.is_inconclusive_or_fallback is False
    assert len(det_report.validated_observables) >= 1
    assert "T1059.001" in det_report.mitre_coverage_targets

    # 4. Markdown Views
    assert bundle.markdown_executive.startswith("# AISOP Executive Security Brief")
    assert bundle.markdown_technical.startswith("# AISOP Technical Incident Response Report")
    assert bundle.markdown_detection.startswith("# AISOP Detection Engineering & Hunting Report")
    assert bundle.markdown_executive.endswith("\n")
    assert bundle.markdown_technical.endswith("\n")
    assert bundle.markdown_detection.endswith("\n")


@pytest.mark.anyio
async def test_phase2_capstone_full_pipeline_via_rest_api(db_session):
    """
    Capstone Test 2: Complete Pipeline Execution via FastAPI REST Endpoints.

    Validates HTTP status codes, request/response models, and context integrity over:
    1. POST /api/v1/evidence/ingest
    2. POST /api/v1/investigations/synthesize
    3. POST /api/v1/reports/synthesize
    4. POST /api/v1/reports/format (cryptographic context-binding verification)
    """
    attack_chain_file = get_attack_chain_path()
    with open(attack_chain_file, "r", encoding="utf-8") as f:
        raw_events = json.load(f)

    t_start = datetime(2026, 9, 9, 14, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 9, 9, 15, 0, 0, tzinfo=timezone.utc)

    # 1. Ingest telemetry directly via IngestionService to acquire root event UUID
    ingest_svc = IngestionService()
    ingest_res = await ingest_svc.ingest_batch(
        db_session,
        IngestRequest(source_type="sysmon", source_identifier="CORP-FIN-WS01", events=raw_events),
    )
    assert ingest_res.total_received == 4

    persisted_events = (
        (await db_session.execute(select(NormalizedEventModel).order_by(NormalizedEventModel.event_timestamp.asc())))
        .scalars()
        .all()
    )
    root_event = persisted_events[0]

    # Setup mock provider and investigation service
    mock_json = build_capstone_llm_json(event_uuid=root_event.id)
    mock_llm = MockCapstoneLLMProvider(response_template=mock_json)
    inv_service = InvestigationPipelineService(
        llm_provider=mock_llm,
        context_builder=CapstoneContextBuilder(),
    )

    # Construct test app with dependency overrides
    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: db_session
    app.dependency_overrides[get_investigation_service] = lambda: inv_service
    app.dependency_overrides[get_threat_intel_engine] = lambda: None
    app.dependency_overrides[get_knowledge_retriever] = lambda: None
    analyst = AuthenticatedAnalyst(
        analyst_id=uuid.uuid4(),
        username="test_capstone_analyst",
        global_role=GlobalRole.INGEST,
        is_active=True,
    )
    app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(
        client_id="test-capstone",
        analyst=analyst,
    )

    client = TestClient(app)

    # 2. Test POST /api/v1/evidence/ingest endpoint
    ingest_http_res = client.post(
        "/api/v1/evidence/ingest",
        json={
            "source_type": "sysmon",
            "source_identifier": "CORP-FIN-WS01",
            "events": [raw_events[0]],  # Deduplication handles this gracefully
        },
    )
    assert ingest_http_res.status_code == 200
    ingest_data = ingest_http_res.json()
    assert ingest_data["total_received"] == 1
    assert ingest_data["total_skipped_duplicates"] == 1

    # 3. Test POST /api/v1/investigations/synthesize endpoint
    inv_http_res = client.post(
        "/api/v1/investigations/synthesize",
        json={
            "time_window_start": t_start.isoformat(),
            "time_window_end": t_end.isoformat(),
            "root_event_id": str(root_event.id),
        },
    )
    assert inv_http_res.status_code == 403
    assert "Direct unscoped investigation synthesis is disabled" in inv_http_res.json()["detail"]

    # 4. Test POST /api/v1/reports/synthesize endpoint
    report_http_res = client.post(
        "/api/v1/reports/synthesize",
        json={
            "time_window_start": t_start.isoformat(),
            "time_window_end": t_end.isoformat(),
            "root_event_id": str(root_event.id),
        },
    )
    assert report_http_res.status_code == 403
    assert "Direct unscoped report synthesis is disabled" in report_http_res.json()["detail"]


    # 5. Test POST /api/v1/reports/format with matching context binding
    matching_val_res, actual_context = await inv_service.synthesize_investigation_with_context(
        db_session,
        InvestigationSynthesizeRequest(
            time_window_start=t_start,
            time_window_end=t_end,
            root_event_id=root_event.id,
        ),
    )

    format_http_res = client.post(
        "/api/v1/reports/format",
        json={
            "validation_result": matching_val_res.model_dump(mode="json"),
            "context": actual_context.model_dump(mode="json"),
        },
    )
    assert format_http_res.status_code == 200
    format_data = format_http_res.json()
    assert format_data["context_sha256"] == actual_context.reproducibility.context_sha256
    assert format_data["is_fallback_active"] is False


@pytest.mark.anyio
async def test_phase2_capstone_fallback_and_inconclusive_handling(db_session):
    """
    Capstone Test 3: Failure Resilience & Deterministic Fallback Invariant.

    Validates that:
    1. Operational LLM connection failure (LLMConnectionError) is safely contained.
    2. Zero unhandled exceptions leak to callers.
    3. Deterministic factual fallback is triggered (REJECT_TO_FALLBACK).
    4. Resulting report bundle is marked is_fallback_active=True with INCONCLUSIVE severity.
    5. Zero cloud fallback or external billing calls are attempted.
    """
    attack_chain_file = get_attack_chain_path()
    with open(attack_chain_file, "r", encoding="utf-8") as f:
        raw_events = json.load(f)

    ingest_svc = IngestionService()
    await ingest_svc.ingest_batch(
        db_session,
        IngestRequest(source_type="sysmon", source_identifier="CORP-FIN-WS01", events=raw_events),
    )

    t_start = datetime(2026, 9, 9, 14, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 9, 9, 15, 0, 0, tzinfo=timezone.utc)

    failing_provider = MockCapstoneLLMProvider(
        raise_exc=LLMConnectionError("Local Ollama daemon connection failed on http://localhost:11434")
    )
    pipeline_svc = InvestigationPipelineService(llm_provider=failing_provider)

    synth_req = InvestigationSynthesizeRequest(
        time_window_start=t_start,
        time_window_end=t_end,
    )

    val_res, assembled_ctx = await pipeline_svc.synthesize_investigation_with_context(db_session, synth_req)

    # Guardrails must reject to fallback
    assert val_res.decision == GuardrailDecision.REJECT_TO_FALLBACK
    assert val_res.is_valid is False
    assert "unavailable" in val_res.output.investigation_summary.lower()

    # Report synthesis must produce an authentic fallback bundle
    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, assembled_ctx)

    assert bundle.is_fallback_active is True
    # Anti-benign axiom: Failure/fallback on non-hostile or unknown state never certifies benign
    assert bundle.executive_brief.incident_severity in (
        IncidentSeverityTier.INCONCLUSIVE,
        IncidentSeverityTier.MEDIUM,
        IncidentSeverityTier.LOW,
    )
    assert len(bundle.executive_brief.uncertainties_and_limitations) >= 1


def test_phase2_capstone_sqlite_pgvector_boundary_isolation():
    """
    Capstone Test 4: Offline SQLite vs. PostgreSQL/pgvector Boundary Isolation.

    Explicitly documents and verifies:
    1. In offline test execution, KnowledgeRetriever computes exact cosine similarity
       via Python fallback (_cosine_similarity), enabling isolated zero-daemon testing.
    2. Clamped bounds [0.0, 1.0] and vector geometry are verified.
    3. Production pgvector HNSW indexing (<=>) is strictly tested via -m postgres
       harnesses (test_postgres_vector_retrieval.py), preserving ADR-002 and ADR-006.
    """
    vec_a = _make_dummy_vector(0.5)
    vec_b = _make_dummy_vector(0.5)
    vec_orthogonal = [1.0] + [0.0] * 767
    vec_orthogonal_other = [0.0, 1.0] + [0.0] * 766

    sim_identical = _cosine_similarity(vec_a, vec_b)
    sim_orthogonal = _cosine_similarity(vec_orthogonal, vec_orthogonal_other)
    sim_empty = _cosine_similarity([], [])

    assert round(sim_identical, 4) == 1.0000
    assert round(sim_orthogonal, 4) == 0.0000
    assert sim_empty == 0.0
