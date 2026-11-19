"""
Unit and Integration Tests for AISOP Qwen-Powered AI Investigation Synthesis.

Validates:
1. Successful Qwen JSON synthesis with valid schema and grounding.
2. Truncated JSON response triggering bounded retry (max 1 retry).
3. Deterministic fallback activation after retry failure.
4. Invalid JSON response handling without endless retries.
5. Evidence grounding and epistemic validation.
6. Case and evidence preservation (immutability of evidence, IDs, and hashes).
7. Prompt builder configuration (think=False, max_tokens=2048).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any
import uuid

import pytest

from app.modules.ai.guardrails.validator import (
    GuardrailDecision,
    InvestigationOutputValidator,
    InvestigationValidationResult,
)
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.ai.prompt_builder.builder import DEFAULT_MAX_TOKENS, InvestigationPromptBuilder
from app.modules.ai.response_parser.parser import InvestigationResponseParser, ResponseParsingError
from app.schemas.ai import LLMRequest, LLMResponse, ProviderHealthResponse, TokenUsage
from app.schemas.investigation import (
    GroundingStatus,
    InvestigationContext,
    StructuredInvestigationOutput,
)
from tests.unit.test_output_guardrails_p2 import make_test_context


# ─────────────────────────────────────────────────────────────────────────────
# Test Helpers & Mock Providers
# ─────────────────────────────────────────────────────────────────────────────

def build_valid_qwen_json(
    inv_id: str | uuid.UUID,
    event_uuid: uuid.UUID,
    summary: str = "Suspicious execution of powershell.exe detected on host WIN-HOST-01.",
    model_name: str = "qwen3:4b",
) -> str:
    payload = {
        "investigation_id": str(inv_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_identifier": model_name,
        "investigation_summary": summary,
        "claims": [
            {
                "claim_id": str(uuid.uuid4()),
                "claim_text": "powershell.exe executed with encoded command.",
                "category": "observed_fact",
                "supporting_evidence_ids": [str(event_uuid)],
                "references_exist": True,
                "grounding_status": "validated_reference",
                "confidence": 1.0,
            }
        ],
        "mitre_attack_hypotheses": [
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactics": ["Execution"],
                "supporting_event_uuids": [str(event_uuid)],
                "confidence": 0.90,
                "reasoning": "powershell.exe execution observed in event telemetry.",
            }
        ],
        "alternative_explanations": ["Routine administrator automation script"],
        "recommended_analyst_actions": [
            "Isolate host WIN-HOST-01 from network.",
            "Review PowerShell script block logs for decoded commands.",
        ],
        "uncertainty_and_data_gaps": [],
        "overall_grounding_score": 1.0,
    }
    return json.dumps(payload)


def _build_test_fallback_result(
    ctx: InvestigationContext,
    reason: str,
    parser: InvestigationResponseParser,
    validator: InvestigationOutputValidator,
) -> InvestigationValidationResult:
    fallback = parser.build_deterministic_fallback(ctx, reason)
    val = validator.validate(fallback, ctx)
    return InvestigationValidationResult(
        decision=GuardrailDecision.REJECT_TO_FALLBACK,
        is_valid=False,
        output=val.output,
        violations=val.violations,
        context_sha256=ctx.reproducibility.context_sha256,
        validated_at_utc=datetime.now(timezone.utc),
    )


class SequenceMockLLM(LLMProvider):
    """Mock LLM returning responses in sequence to test retries and fallback."""

    def __init__(self, responses: list[LLMResponse | Exception], model: str = "qwen3:4b") -> None:
        self._responses = list(responses)
        self._model = model
        self.calls: list[LLMRequest] = []

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        if not self._responses:
            raise RuntimeError("No more mock responses configured.")
        resp = self._responses.pop(0)
        if isinstance(resp, Exception):
            raise resp

        # Inject dynamic investigation_id if needed
        content = resp.content
        if "__DYNAMIC_INVESTIGATION_ID__" in content:
            user_msg = request.messages[1].content if len(request.messages) > 1 else ""
            m = re.search(r'<investigation_context[^>]*id="([a-f0-9\-]+)"', user_msg)
            inv_id = m.group(1) if m else str(uuid.uuid4())
            content = content.replace("__DYNAMIC_INVESTIGATION_ID__", inv_id)
            return LLMResponse(
                content=content,
                model=resp.model,
                finish_reason=resp.finish_reason,
                usage=resp.usage,
                raw_response=resp.raw_response,
            )
        return resp

    async def health(self) -> ProviderHealthResponse:
        return ProviderHealthResponse(status="healthy", model=self._model, provider="ollama", latency_ms=1.0)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Prompt Builder Configuration Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_prompt_builder_qwen_parameters():
    """Verify that PromptBuilder sets think=False and max_tokens=2048 for Qwen."""
    ctx = make_test_context()
    builder = InvestigationPromptBuilder(default_model="qwen3:4b")

    req = builder.build_request(ctx)
    assert req.model == "qwen3:4b"
    assert req.think is False
    assert req.max_tokens == DEFAULT_MAX_TOKENS
    assert req.max_tokens == 2048
    assert req.json_mode is True
    assert req.temperature == 0.0

    # Retry request also maintains think=False and adds brevity directive
    retry_req = builder.build_retry_request(ctx)
    assert retry_req.think is False
    assert retry_req.max_tokens == 2048
    assert "RETRY DIRECTIVE" in retry_req.messages[1].content


# ─────────────────────────────────────────────────────────────────────────────
# 2. Successful Qwen JSON Synthesis
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_successful_qwen_json_synthesis():
    """Verify end-to-end synthesis when Qwen returns valid structured JSON."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid
    valid_json = build_valid_qwen_json(inv_id=ctx.investigation_id, event_uuid=ev_uuid)

    mock_resp = LLMResponse(
        content=valid_json,
        model="qwen3:4b",
        finish_reason="stop",
        usage=TokenUsage(prompt_tokens=450, completion_tokens=320, total_tokens=770, duration_ms=45.0),
    )

    parser = InvestigationResponseParser()
    validator = InvestigationOutputValidator()

    parsed = parser.parse(mock_resp, ctx)
    val_res = validator.validate(parsed, ctx)

    assert val_res.is_valid is True
    assert val_res.decision in (GuardrailDecision.PASS, GuardrailDecision.REMEDIATED)
    assert val_res.output.model_identifier == "qwen3:4b"
    assert val_res.output.investigation_id == ctx.investigation_id
    assert len(val_res.output.claims) == 1
    assert val_res.output.claims[0].supporting_evidence_ids == [ev_uuid]
    assert val_res.output.overall_grounding_score == 1.0


# ─────────────────────────────────────────────────────────────────────────────
# 3. Truncated JSON Response Triggers Bounded Retry
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_truncated_json_response_triggers_bounded_retry():
    """Verify that a truncated response (finish_reason='length') triggers 1 bounded retry and succeeds."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid

    # Attempt 0: Truncated JSON
    truncated_resp = LLMResponse(
        content='{"investigation_id": "' + str(ctx.investigation_id) + '", "investigation_summary": "Incomplete',
        model="qwen3:4b",
        finish_reason="length",
        usage=TokenUsage(prompt_tokens=450, completion_tokens=1024, total_tokens=1474, duration_ms=60.0),
        raw_response={"done_reason": "length"},
    )

    # Attempt 1: Complete valid JSON on retry
    retry_valid_json = build_valid_qwen_json(inv_id=ctx.investigation_id, event_uuid=ev_uuid)
    success_resp = LLMResponse(
        content=retry_valid_json,
        model="qwen3:4b",
        finish_reason="stop",
        usage=TokenUsage(prompt_tokens=500, completion_tokens=250, total_tokens=750, duration_ms=30.0),
    )

    mock_llm = SequenceMockLLM([truncated_resp, success_resp])
    prompt_builder = InvestigationPromptBuilder(default_model="qwen3:4b")
    parser = InvestigationResponseParser()
    validator = InvestigationOutputValidator()

    max_attempts = 2
    validation_result = None

    for attempt in range(max_attempts):
        llm_req = (
            prompt_builder.build_request(ctx)
            if attempt == 0
            else prompt_builder.build_retry_request(ctx)
        )
        raw_resp = await mock_llm.generate(llm_req)
        is_length_truncated = getattr(raw_resp, "finish_reason", None) == "length"

        try:
            parsed = parser.parse(raw_resp, ctx)
            validation_result = validator.validate(parsed, ctx)
            break
        except ResponseParsingError as exc:
            err_msg = str(exc).lower()
            is_truncated_parse = (
                is_length_truncated
                or "truncated" in err_msg
                or "length" in err_msg
                or "unterminated" in err_msg
            )
            if attempt == 0 and is_truncated_parse:
                continue
            validation_result = _build_test_fallback_result(ctx, str(exc), parser, validator)
            break

    # Verify retry occurred
    assert len(mock_llm.calls) == 2
    assert "RETRY DIRECTIVE" in mock_llm.calls[1].messages[1].content
    assert validation_result is not None
    assert validation_result.is_valid is True
    assert validation_result.output.model_identifier == "qwen3:4b"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Truncation Retry Failure Activates Deterministic Fallback
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_truncation_retry_failure_activates_deterministic_fallback():
    """Verify that if retry also truncates, deterministic fallback is activated."""
    ctx = make_test_context()

    # Attempt 0: Truncated JSON
    truncated_resp_1 = LLMResponse(
        content='{"investigation_id": "' + str(ctx.investigation_id) + '", "claims": [',
        model="qwen3:4b",
        finish_reason="length",
        usage=TokenUsage(prompt_tokens=450, completion_tokens=1024, total_tokens=1474, duration_ms=60.0),
        raw_response={"done_reason": "length"},
    )
    # Attempt 1: Truncated again
    truncated_resp_2 = LLMResponse(
        content='{"investigation_id": "' + str(ctx.investigation_id) + '", "investigation_summary": "',
        model="qwen3:4b",
        finish_reason="length",
        usage=TokenUsage(prompt_tokens=500, completion_tokens=1024, total_tokens=1524, duration_ms=60.0),
        raw_response={"done_reason": "length"},
    )

    mock_llm = SequenceMockLLM([truncated_resp_1, truncated_resp_2])
    prompt_builder = InvestigationPromptBuilder(default_model="qwen3:4b")
    parser = InvestigationResponseParser()
    validator = InvestigationOutputValidator()

    max_attempts = 2
    validation_result = None

    for attempt in range(max_attempts):
        llm_req = (
            prompt_builder.build_request(ctx)
            if attempt == 0
            else prompt_builder.build_retry_request(ctx)
        )
        raw_resp = await mock_llm.generate(llm_req)
        is_length_truncated = getattr(raw_resp, "finish_reason", None) == "length"

        try:
            parsed = parser.parse(raw_resp, ctx)
            validation_result = validator.validate(parsed, ctx)
            break
        except ResponseParsingError as exc:
            err_msg = str(exc).lower()
            is_truncated_parse = (
                is_length_truncated
                or "truncated" in err_msg
                or "length" in err_msg
                or "unterminated" in err_msg
            )
            if attempt == 0 and is_truncated_parse:
                continue
            validation_result = _build_test_fallback_result(ctx, str(exc), parser, validator)
            break

    # Exactly 2 calls made (bounded retry exhausted)
    assert len(mock_llm.calls) == 2
    assert validation_result is not None
    assert validation_result.is_valid is False
    assert validation_result.decision == GuardrailDecision.REJECT_TO_FALLBACK
    assert validation_result.output.model_identifier == "deterministic_fallback"
    assert "truncated" in validation_result.output.investigation_summary.lower() or "length" in validation_result.output.investigation_summary.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 5. Invalid JSON Response Activates Fallback Immediately
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_invalid_json_response_activates_fallback_without_retry():
    """Verify that non-truncation syntax errors do not trigger retry and immediately fallback."""
    ctx = make_test_context()

    # Invalid non-JSON response (e.g. model returned conversational refusal or garbage)
    invalid_resp = LLMResponse(
        content="I am sorry, I cannot output JSON for this request.",
        model="qwen3:4b",
        finish_reason="stop",
        usage=TokenUsage(prompt_tokens=450, completion_tokens=30, total_tokens=480, duration_ms=5.0),
    )

    mock_llm = SequenceMockLLM([invalid_resp])
    prompt_builder = InvestigationPromptBuilder(default_model="qwen3:4b")
    parser = InvestigationResponseParser()
    validator = InvestigationOutputValidator()

    max_attempts = 2
    validation_result = None

    for attempt in range(max_attempts):
        llm_req = (
            prompt_builder.build_request(ctx)
            if attempt == 0
            else prompt_builder.build_retry_request(ctx)
        )
        raw_resp = await mock_llm.generate(llm_req)
        is_length_truncated = getattr(raw_resp, "finish_reason", None) == "length"

        try:
            parsed = parser.parse(raw_resp, ctx)
            validation_result = validator.validate(parsed, ctx)
            break
        except ResponseParsingError as exc:
            err_msg = str(exc).lower()
            is_truncated_parse = (
                is_length_truncated
                or "truncated" in err_msg
                or "length" in err_msg
                or "unterminated" in err_msg
            )
            if attempt == 0 and is_truncated_parse:
                continue
            validation_result = _build_test_fallback_result(ctx, str(exc), parser, validator)
            break

    # Exactly 1 call made (no retry on non-truncated syntax error)
    assert len(mock_llm.calls) == 1
    assert validation_result is not None
    assert validation_result.is_valid is False
    assert validation_result.decision == GuardrailDecision.REJECT_TO_FALLBACK
    assert validation_result.output.model_identifier == "deterministic_fallback"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Evidence Grounding and Validation
# ─────────────────────────────────────────────────────────────────────────────

def test_evidence_grounding_rejects_hallucinated_uuids():
    """Verify that hallucinated evidence UUIDs in claims and MITRE hypotheses are zeroed out."""
    ctx = make_test_context()
    fake_uuid = uuid.uuid4()

    hallucinated_payload = {
        "investigation_id": str(ctx.investigation_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_identifier": "qwen3:4b",
        "investigation_summary": "Analysis with hallucinated citations.",
        "claims": [
            {
                "claim_id": str(uuid.uuid4()),
                "claim_text": "Adversary exfiltrated data to foreign IP.",
                "category": "observed_fact",
                "supporting_evidence_ids": [str(fake_uuid)],  # NOT IN CONTEXT
                "references_exist": True,
                "grounding_status": "validated_reference",
                "confidence": 0.99,
            }
        ],
        "mitre_attack_hypotheses": [
            {
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "tactics": ["Exfiltration"],
                "supporting_event_uuids": [str(fake_uuid)],  # NOT IN CONTEXT
                "confidence": 0.95,
                "reasoning": "Data was exfiltrated.",
            }
        ],
        "alternative_explanations": [],
        "recommended_analyst_actions": ["Review firewall logs."],
        "uncertainty_and_data_gaps": [],
        "overall_grounding_score": 1.0,
    }

    parser = InvestigationResponseParser()
    resp = LLMResponse(content=json.dumps(hallucinated_payload), model="qwen3:4b")
    parsed = parser.parse(resp, ctx)

    # Epistemic validation: hallucinated references zeroed and marked UNSUPPORTED
    claim = parsed.claims[0]
    assert claim.confidence == 0.0
    assert claim.references_exist is False
    assert claim.grounding_status == GroundingStatus.UNSUPPORTED
    assert "[UNSUPPORTED: Cited evidence UUIDs not found in context]" in (claim.analyst_notes or "")

    hyp = parsed.mitre_attack_hypotheses[0]
    assert hyp.confidence == 0.0
    assert hyp.supporting_event_uuids == []
    assert "[UNSUPPORTED:" in hyp.reasoning

    # Overall grounding score recomputed to 0.0
    assert parsed.overall_grounding_score == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# 7. Existing Case and Evidence Preservation
# ─────────────────────────────────────────────────────────────────────────────

def test_existing_case_and_evidence_preservation():
    """Verify that context construction does not alter event hashes or timestamps."""
    ctx = make_test_context()
    orig_hash = ctx.events[0].raw_evidence_sha256
    orig_uuid = ctx.events[0].event_uuid
    orig_context_sha = ctx.reproducibility.context_sha256

    builder = InvestigationPromptBuilder()
    formatted_payload = builder.format_evidence_payload(ctx)

    # Telemetry and context remain bitwise identical
    assert ctx.events[0].raw_evidence_sha256 == orig_hash
    assert ctx.events[0].event_uuid == orig_uuid
    assert ctx.reproducibility.context_sha256 == orig_context_sha
    assert str(orig_uuid) in formatted_payload
