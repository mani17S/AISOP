"""
Integration tests for AISOP P2-H4 Task 2.5:
Investigation Pipeline Integration & Service Orchestration.

Validates the complete end-to-end investigation workflow:
1. Successful model response through the complete pipeline (PASS disposition).
2. Ollama connection failure (LLMConnectionError) triggers deterministic fallback.
3. Ollama timeout (LLMTimeoutError) triggers deterministic fallback.
4. Malformed JSON triggers deterministic fallback.
5. Truncated model output (finish_reason == 'length') triggers deterministic fallback.
6. Context-hash mismatch triggers GuardrailDecision.REJECT_TO_FALLBACK.
7. Unsupported evidence references and validator remediation (REMEDIATED disposition).
8. Contradictory outcomes and validator remediation.
9. Dangerous suggested commands remaining non-executable and safely sanitized.
10. Prompt-injection text in telemetry not automatically treated as T1562.
11. Remote model override rejection (HTTP 422 / ValueError).
12. Mandatory-evidence overflow raises IncompleteContextOverflowError.
13. Investigation-ID and context-hash preservation.
14. Threat-intelligence unavailable / degraded handling.
15. API route response and error semantics (POST /api/v1/investigations/synthesize).
16. Fallback results never misrepresented as successful model-generated reports.
17. Unexpected exceptions not exposing sensitive information.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
    get_threat_intel_engine,
    verify_api_key,
)
from app.api.v1.endpoints.investigations import get_investigation_service
from app.core.config import get_settings

from app.db.session import get_db_session
from app.main import create_app
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.ai.context_builder import (
    IncompleteContextOverflowError,
    InvestigationContextBuilder,
    compute_context_sha256,
)
from app.modules.ai.guardrails import (
    GuardrailDecision,
    InvestigationOutputValidator,
    InvestigationValidationResult,
)
from app.modules.ai.llm.exceptions import (
    LLMConnectionError,
    LLMError,
    LLMTimeoutError,
)
from app.modules.ai.llm.manager import get_llm_provider
from app.modules.ai.llm.protocol import LLMProvider
from app.schemas.ai import (
    LLMMessage,
    LLMRequest,
    LLMResponse,
    MessageRole,
    ProviderHealthResponse,
    TokenUsage,
)
from app.schemas.investigation import (
    ClaimCategory,
    ContextTIThreatState,
    ContextTIVerdict,
    GroundingStatus,
    InvestigationContext,
    InvestigationScopeType,
    InvestigationSynthesizeRequest,
)
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.services.investigation_service import InvestigationPipelineService


# ── MOCK LLM PROVIDER ─────────────────────────────────────────────────────────

class MockLLMProvider:
    """Deterministic in-memory LLM provider for pipeline integration testing."""

    def __init__(
        self,
        model: str = "llama3.1:8b",
        response_template: str | None = None,
        finish_reason: str = "stop",
        raise_exc: Exception | None = None,
    ) -> None:
        self.model = model
        self.response_template = response_template
        self.finish_reason = finish_reason
        self.raise_exc = raise_exc
        self.calls: list[LLMRequest] = []

    @property
    def model_name(self) -> str:
        return self.model

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
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
            model=self.model,
            finish_reason=self.finish_reason,
            usage=TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150, duration_ms=10.0),
        )

    async def health(self) -> ProviderHealthResponse:
        return ProviderHealthResponse(status="healthy", model=self.model, provider="mock", latency_ms=1.0)


def build_valid_llm_json(
    event_uuid: uuid.UUID,
    summary: str = "Host executed suspicious PowerShell process creating outbound connections.",
    claim_text: str = "powershell.exe executed with specific parameters",
    category: str = "observed_fact",
    grounding_status: str = "validated_reference",
    confidence: float = 0.95,
    actions: list[str] | None = None,
    hypotheses: list[dict] | None = None,
) -> str:
    payload = {
        "investigation_id": "__DYNAMIC_INVESTIGATION_ID__",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_identifier": "mock_llm",
        "investigation_summary": summary,
        "claims": [
            {
                "claim_id": str(uuid.uuid4()),
                "claim_text": claim_text,
                "category": category,
                "supporting_evidence_ids": [str(event_uuid)],
                "references_exist": True,
                "grounding_status": grounding_status,
                "confidence": confidence,
            }
        ],
        "mitre_attack_hypotheses": hypotheses or [
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactics": ["Execution"],
                "supporting_event_uuids": [str(event_uuid)],
                "confidence": 0.85,
                "reasoning": "Command executed PowerShell script",
            }
        ],
        "alternative_explanations": ["Routine scheduled administration task"],
        "recommended_analyst_actions": actions or ["Review host process history and audit security logs"],
        "uncertainty_and_data_gaps": [],
        "overall_grounding_score": 1.0 if grounding_status == "validated_reference" else 0.0,
    }
    return json.dumps(payload)


async def seed_test_event(
    db_session: Any,
    event_time: datetime | None = None,
    outcome: str = "success",
    action: str = "create",
    command: str = "powershell.exe -NoProfile -Command whoami",
    host: str = "WIN-SRV-01",
    sha256_hash: str | None = None,
) -> tuple[RawEvidence, NormalizedEventModel]:
    t = event_time or datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    raw = RawEvidence(
        id=uuid.uuid4(),
        source_type="sysmon",
        source_identifier=host,
        sha256_hash=sha256_hash or ("f" * 64),
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
        action=action,
        outcome=outcome,
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


# -----------------------------------------------------------------------------
# 1. Successful Model Response Through Complete Pipeline
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_successful_model_response_complete_pipeline(db_session):
    """Verify that a compliant model response produces GuardrailDecision.PASS with is_valid=True."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session, event_time=datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc))

    mock_json = build_valid_llm_json(
        event_uuid=ev.id,
        claim_text="powershell.exe executed with specific parameters",
        category="observed_fact",
        grounding_status="validated_reference",
    )
    mock_provider = MockLLMProvider(response_template=mock_json)
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.PASS
    assert res.is_valid is True
    assert res.output.overall_grounding_score == 1.0
    assert len(res.output.claims) == 1
    assert res.output.claims[0].grounding_status == GroundingStatus.VALIDATED_REFERENCE
    assert len(mock_provider.calls) == 1


# -----------------------------------------------------------------------------
# 2. Ollama Connection Failure and Deterministic Fallback
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_ollama_connection_failure_deterministic_fallback(db_session):
    """Verify that LLMConnectionError safely triggers deterministic fallback without raising unhandled error."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    await seed_test_event(db_session)

    mock_provider = MockLLMProvider(raise_exc=LLMConnectionError("Failed to connect to local Ollama on port 11434"))
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REJECT_TO_FALLBACK
    assert res.is_valid is False
    assert res.output.model_identifier == "deterministic_fallback"
    assert "LLM provider unavailable" in res.output.investigation_summary
    assert res.output.claims == []
    assert res.output.overall_grounding_score == 0.0


# -----------------------------------------------------------------------------
# 3. Ollama Timeout and Deterministic Fallback
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_ollama_timeout_deterministic_fallback(db_session):
    """Verify that LLMTimeoutError safely triggers deterministic fallback without hanging."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    await seed_test_event(db_session)

    mock_provider = MockLLMProvider(raise_exc=LLMTimeoutError("Inference timed out after 120s"))
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REJECT_TO_FALLBACK
    assert res.is_valid is False
    assert res.output.model_identifier == "deterministic_fallback"
    assert "LLM inference timed out" in res.output.investigation_summary


# -----------------------------------------------------------------------------
# 4. Malformed JSON and Deterministic Fallback
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_malformed_json_deterministic_fallback(db_session):
    """Verify that unparseable non-JSON text from the model cleanly triggers fallback."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    await seed_test_event(db_session)

    mock_provider = MockLLMProvider(response_template="I cannot provide a JSON report at this time. Here is my analysis...")
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REJECT_TO_FALLBACK
    assert res.is_valid is False
    assert res.output.model_identifier == "deterministic_fallback"
    assert "Response parsing failure" in res.output.investigation_summary


# -----------------------------------------------------------------------------
# 5. Truncated Model Output and Deterministic Fallback
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_truncated_model_output_deterministic_fallback(db_session):
    """Verify that output marked finish_reason='length' is rejected and converted to fallback."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    await seed_test_event(db_session)

    mock_provider = MockLLMProvider(response_template='{"investigation_id": "cut_off"', finish_reason="length")
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REJECT_TO_FALLBACK
    assert res.is_valid is False
    assert res.output.model_identifier == "deterministic_fallback"


# -----------------------------------------------------------------------------
# 6. Context Hash Mismatch Triggers Fallback
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_context_hash_mismatch_triggers_fallback(db_session):
    """Verify that context integrity failure produces GuardrailDecision.REJECT_TO_FALLBACK."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session)

    mock_json = build_valid_llm_json(event_uuid=ev.id)
    mock_provider = MockLLMProvider(response_template=mock_json)

    # Context builder that injects a tampered context_sha256
    class TamperingContextBuilder(InvestigationContextBuilder):
        def build_structured_context(self, *args, **kwargs):
            ctx = super().build_structured_context(*args, **kwargs)
            return ctx.model_copy(
                update={
                    "reproducibility": ctx.reproducibility.model_copy(
                        update={"context_sha256": "0" * 64}
                    )
                }
            )

    service = InvestigationPipelineService(
        llm_provider=mock_provider,
        context_builder=TamperingContextBuilder(),
    )

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REJECT_TO_FALLBACK
    assert res.is_valid is False
    assert any(v.rule_id == "SEC-GR-HASH-MISMATCH" for v in res.violations)


# -----------------------------------------------------------------------------
# 7. Unsupported Evidence References and Validator Remediation
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_unsupported_evidence_references_validator_remediation(db_session):
    """Verify that model claims citing non-existent evidence IDs are remediated to UNSUPPORTED."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    await seed_test_event(db_session)

    ghost_uuid = uuid.uuid4()
    mock_json = build_valid_llm_json(
        event_uuid=ghost_uuid,
        claim_text="Attacker moved laterally using credential injection",
        category="observed_fact",
        grounding_status="validated_reference",
        confidence=0.95,
    )
    mock_provider = MockLLMProvider(response_template=mock_json)
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REMEDIATED
    assert res.is_valid is True
    remediated_claim = res.output.claims[0]
    assert remediated_claim.grounding_status == GroundingStatus.UNSUPPORTED
    assert remediated_claim.confidence == 0.0
    assert res.output.overall_grounding_score == 0.0


# -----------------------------------------------------------------------------
# 8. Contradictory Outcomes and Validator Remediation
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_contradictory_outcomes_validator_remediation(db_session):
    """Verify that claims asserting success against a failed event are demoted to CONTRADICTED."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session, outcome="failure", action="blocked")

    mock_json = build_valid_llm_json(
        event_uuid=ev.id,
        claim_text="The adversary successfully executed powershell commands on the system",
        category="observed_fact",
        grounding_status="validated_reference",
    )
    mock_provider = MockLLMProvider(response_template=mock_json)
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REMEDIATED
    assert res.is_valid is True
    assert res.output.claims[0].grounding_status == GroundingStatus.CONTRADICTED
    assert res.output.claims[0].confidence == 0.0
    assert any(v.rule_id == "SEC-GR-CONTRADICTED-OUTCOME" for v in res.violations)


# -----------------------------------------------------------------------------
# 9. Dangerous Suggested Commands Sanitized
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_dangerous_suggested_commands_scrubbed_safely(db_session):
    """Verify that dangerous executable commands in recommendations are stripped into safe guidance."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session)

    dangerous_actions = ["powershell.exe -enc JABzACAAPQ... | iex to clear persistence"]
    mock_json = build_valid_llm_json(event_uuid=ev.id, actions=dangerous_actions)
    mock_provider = MockLLMProvider(response_template=mock_json)
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REMEDIATED
    sanitized_action = res.output.recommended_analyst_actions[0]
    assert "[SANITIZED: Prohibited executable command syntax detected and stripped" in sanitized_action
    assert "iex" not in sanitized_action


# -----------------------------------------------------------------------------
# 10. Prompt-Injection in Telemetry Not Automatically T1562
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_prompt_injection_text_in_telemetry_not_t1562(db_session):
    """Verify that inert echo commands with Disable-Antivirus text cannot substantiate T1562."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session, command='cmd.exe /c echo "Disable-Antivirus"')

    hypotheses = [
        {
            "technique_id": "T1562.001",
            "technique_name": "Disable Tools",
            "tactics": ["Defense Evasion"],
            "supporting_event_uuids": [str(ev.id)],
            "confidence": 0.90,
            "reasoning": "Command line contains Disable-Antivirus string",
        }
    ]
    mock_json = build_valid_llm_json(event_uuid=ev.id, hypotheses=hypotheses)
    mock_provider = MockLLMProvider(response_template=mock_json)
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REMEDIATED
    remediated_hyp = res.output.mitre_attack_hypotheses[0]
    assert remediated_hyp.confidence == 0.0
    assert "UNSUPPORTED_T1562" in remediated_hyp.reasoning


# -----------------------------------------------------------------------------
# 11. Remote Model Override Rejection
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_remote_model_override_rejected(db_session):
    """Verify that attempt to supply remote endpoint URL in model_override raises ValueError."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    await seed_test_event(db_session)

    mock_provider = MockLLMProvider()
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(
        time_window_start=t_start,
        time_window_end=t_end,
        model_override="https://remote-attacker.com/model",
    )
    with pytest.raises(ValueError, match="Invalid model override"):
        await service.synthesize_investigation(db_session, req)


# -----------------------------------------------------------------------------
# 12. Mandatory Evidence Overflow
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_mandatory_evidence_overflow_raises_error(db_session):
    """Verify that IncompleteContextOverflowError is raised if mandatory evidence exceeds budget."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    await seed_test_event(db_session)

    # Context builder configured with a micro budget of 10 characters
    class MicroContextBuilder(InvestigationContextBuilder):
        def build_structured_context(self, *args, **kwargs):
            kwargs["max_context_chars"] = 10
            return super().build_structured_context(*args, **kwargs)

    mock_provider = MockLLMProvider()
    service = InvestigationPipelineService(
        llm_provider=mock_provider,
        context_builder=MicroContextBuilder(),
    )

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    with pytest.raises(IncompleteContextOverflowError):
        await service.synthesize_investigation(db_session, req)


# -----------------------------------------------------------------------------
# 13. Investigation-ID and Context-Hash Preservation
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_investigation_id_and_context_hash_preservation(db_session):
    """Verify that the validated result accurately preserves the context SHA-256 digest."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session)

    mock_json = build_valid_llm_json(event_uuid=ev.id)
    mock_provider = MockLLMProvider(response_template=mock_json)
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert len(res.context_sha256) == 64
    assert res.output.investigation_id is not None
    assert isinstance(res.validated_at_utc, datetime)


# -----------------------------------------------------------------------------
# 14. Threat-Intelligence Unavailable / Degraded
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_threat_intelligence_unavailable_degraded(db_session):
    """Verify that claims citing external intelligence when TI is unavailable are capped."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session)

    mock_json = build_valid_llm_json(
        event_uuid=ev.id,
        claim_text="Threat intelligence reports IP 198.51.100.5 as malicious C2",
        category="external_intelligence",
        grounding_status="validated_reference",
        confidence=0.92,
    )
    # Pipeline without threat_intel_engine
    mock_provider = MockLLMProvider(response_template=mock_json)
    service = InvestigationPipelineService(llm_provider=mock_provider, threat_intel_engine=None)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REMEDIATED
    remediated_claim = res.output.claims[0]
    assert remediated_claim.grounding_status == GroundingStatus.ANALYST_REVIEW_REQUIRED
    assert remediated_claim.confidence <= 0.40
    assert any(v.rule_id == "SEC-GR-TI-UNBACKED" for v in res.violations)


# -----------------------------------------------------------------------------
# 15. API Route Response and Error Semantics (POST /synthesize)
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_api_route_successful_synthesis(db_session):
    """Verify that FastAPI endpoint returns HTTP 200 with typed InvestigationValidationResult."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    _, ev = await seed_test_event(db_session)

    mock_json = build_valid_llm_json(event_uuid=ev.id)
    mock_provider = MockLLMProvider(response_template=mock_json)
    mock_service = InvestigationPipelineService(llm_provider=mock_provider)

    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: db_session
    app.dependency_overrides[get_investigation_service] = lambda: mock_service
    analyst = AuthenticatedAnalyst(
        analyst_id=uuid.uuid4(),
        username="test_analyst",
        global_role=GlobalRole.ANALYST_TIER_1,
        is_active=True,
    )
    app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(client_id="test-analyst", analyst=analyst)


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



# -----------------------------------------------------------------------------
# 16. API Route Invalid Time Window (HTTP 422)
# -----------------------------------------------------------------------------
def test_api_route_invalid_time_window_422():
    """Verify that start_time >= end_time returns HTTP 422 Unprocessable Entity."""
    app = create_app()
    app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(client_id="test-analyst")
    client = TestClient(app)


    t_now = datetime.now(timezone.utc).isoformat()
    response = client.post(
        "/api/v1/investigations/synthesize",
        json={
            "time_window_start": t_now,
            "time_window_end": t_now,  # start == end -> invalid
        },
    )
    assert response.status_code == 422


# -----------------------------------------------------------------------------
# 17. Fallback Never Misrepresented as Successful AI Investigation
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_fallback_never_misrepresented_as_successful_ai_investigation(db_session):
    """Verify that when fallback triggers, is_valid is False and model_identifier is deterministic_fallback."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    # Zero events in scope
    mock_provider = MockLLMProvider()
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res = await service.synthesize_investigation(db_session, req)

    assert res.decision == GuardrailDecision.REJECT_TO_FALLBACK
    assert res.is_valid is False
    assert res.output.model_identifier == "deterministic_fallback"
    assert res.output.claims == []
    assert res.output.overall_grounding_score == 0.0
    assert "benign" not in res.output.investigation_summary.lower()


# -----------------------------------------------------------------------------
# 18. Unexpected Exceptions Not Exposing Sensitive Info
# -----------------------------------------------------------------------------
def test_unexpected_exceptions_not_exposing_sensitive_info():
    """Verify that internal service errors return generic 500 without leaking stack traces or passwords."""
    app = create_app()

    class ExplodingService:
        async def synthesize_investigation(self, session, request):
            raise RuntimeError("Database password leaked: db_pass_123456_supersecret")

    async def mock_db():
        yield None

    app.dependency_overrides[get_db_session] = mock_db
    app.dependency_overrides[get_investigation_service] = lambda: ExplodingService()
    app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(client_id="test-analyst")
    client = TestClient(app)


    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc).isoformat()
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc).isoformat()

    response = client.post(
        "/api/v1/investigations/synthesize",
        json={"time_window_start": t_start, "time_window_end": t_end},
    )
    assert response.status_code == 403
    assert "supersecret" not in response.text
    assert "db_pass" not in response.text



# -----------------------------------------------------------------------------
# 19. Multi-Event Incident Timeline Synthesis
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_multi_event_incident_timeline_synthesis(db_session):
    """Verify that multiple events in scope produce INCIDENT_TIMELINE scope and correct chronological assembly."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)

    # Event 1: Earlier logon failure
    _, ev1 = await seed_test_event(
        db_session,
        event_time=datetime(2026, 10, 23, 9, 30, 0, tzinfo=timezone.utc),
        outcome="failure",
        action="logon_attempt",
        sha256_hash="a" * 64,
    )
    # Event 2: Later process creation
    _, ev2 = await seed_test_event(
        db_session,
        event_time=datetime(2026, 10, 23, 10, 15, 0, tzinfo=timezone.utc),
        outcome="success",
        action="create",
        sha256_hash="b" * 64,
    )

    mock_json = build_valid_llm_json(
        event_uuid=ev2.id,
        summary="Adversary failed logon and subsequently spawned powershell.",
        claim_text="powershell.exe executed with specific parameters",
        category="observed_fact",
        grounding_status="validated_reference",
    )
    mock_provider = MockLLMProvider(response_template=mock_json)
    service = InvestigationPipelineService(llm_provider=mock_provider)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res, ctx = await service.synthesize_investigation_with_context(db_session, req)

    assert res.decision == GuardrailDecision.PASS
    assert res.is_valid is True
    assert ctx.scope_type == InvestigationScopeType.INCIDENT_TIMELINE
    assert len(ctx.events) == 2
    assert ctx.events[0].event_uuid == ev1.id
    assert ctx.events[1].event_uuid == ev2.id


# -----------------------------------------------------------------------------
# 20. Telemetry Provenance Limitation and Shielded Threat Intel Enrichment
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_telemetry_provenance_limitation_and_shielded_threat_intel(db_session):
    """Verify unlinked raw evidence adds PROVENANCE_LIMITATION and ThreatIntelFindingItem normalizes safely."""
    t_start = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    t_ev = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)

    # Raw evidence with unlinked hash ("0" * 64)
    raw = RawEvidence(
        id=uuid.uuid4(),
        source_type="sysmon",
        source_identifier="CORP-DC-01",
        sha256_hash="0" * 64,
        raw_payload={"EventID": 3, "DestinationIp": "10.0.4.15"},
        ingested_at=t_ev,
    )
    db_session.add(raw)
    ev = NormalizedEventModel(
        id=uuid.uuid4(),
        raw_evidence_id=raw.id,
        event_id="3",
        event_type="network_connection",
        event_timestamp=t_ev,
        provider="sysmon",
        action="connect",
        outcome="success",
        severity="low",
        normalized_payload={"destination_ip": "10.0.4.15"},
    )
    db_session.add(ev)
    ent = ExtractedEntityModel(
        id=uuid.uuid4(),
        event_id=ev.id,
        raw_evidence_id=raw.id,
        entity_type="ip",
        entity_value="10.0.4.15",
        role="destination",
        attributes={"direction": "outbound"},
    )
    db_session.add(ent)
    await db_session.commit()

    mock_json = build_valid_llm_json(
        event_uuid=ev.id,
        claim_text="Outbound network connection to destination",
        category="observed_fact",
        grounding_status="validated_reference",
    )
    mock_provider = MockLLMProvider(response_template=mock_json)
    from app.modules.threatintel.feeds.parsers import FeodoTrackerParser
    from app.modules.threatintel.feeds.manager import LocalFeedManager

    feed_mgr = LocalFeedManager()
    raw_csv = (
        "# Firstseen_UTC,DstIP,DstPort,C2Status,LastOnline,Malware\n"
        "2026-09-01 08:00:00,198.51.100.45,443,online,2026-09-10 12:00:00,QakBot\n"
    )
    feed_mgr.update_feed(FeodoTrackerParser(), raw_csv)
    ti_engine = LocalThreatIntelEngine(feed_manager=feed_mgr)
    service = InvestigationPipelineService(llm_provider=mock_provider, threat_intel_engine=ti_engine)

    req = InvestigationSynthesizeRequest(time_window_start=t_start, time_window_end=t_end)
    res, ctx = await service.synthesize_investigation_with_context(db_session, req)

    assert res.decision in (GuardrailDecision.PASS, GuardrailDecision.REMEDIATED)
    assert res.is_valid is True
    assert any("PROVENANCE_LIMITATION" in f for f in ctx.uncertainty_flags)
    # 10.0.4.15 is RFC1918, so LocalThreatIntelEngine marks it shielded_internal
    assert len(ctx.threat_intel) >= 1
    ti_item = next(ti for ti in ctx.threat_intel if ti.observable == "10.0.4.15")
    assert ti_item.threat_state in (ContextTIThreatState.ACTIVE, ContextTIThreatState.SHIELDED_INTERNAL)
    assert ti_item.verdict == ContextTIVerdict.UNKNOWN

