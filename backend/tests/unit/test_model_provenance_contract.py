"""
Unit tests for authoritative model provenance contract in InvestigationResponseParser.

Validates AISOP Gate D.2.5.36 implementation:
- Model-generated persona ("AISOP SOC Assistant") cannot override provider model ("llama3.1:8b").
- Arbitrary model-generated identifiers cannot spoof provider identity.
- Missing or empty provider metadata falls back to configured reproducibility target metadata.
- Missing provider and target metadata produce the documented "unknown_model" value.
- Deterministic fallback output strictly identifies its producer as "deterministic_fallback".
- Claim-ID normalization and evidence-grounding invariants remain intact alongside authoritative provenance.
- Downstream report synthesizer and markdown output reflect the authoritative model identifier.
- Canonical output hashing (compute_validation_output_sha256) is deterministic and incorporates authoritative model provenance.
"""

from datetime import datetime, timezone
import json
from typing import Any
import uuid

import pytest

from app.modules.ai.context_builder.hasher import compute_validation_output_sha256
from app.modules.ai.guardrails.validator import (
    GuardrailDecision,
    InvestigationOutputValidator,
    InvestigationValidationResult,
)
from app.modules.ai.reporting.synthesizer import DeterministicReportSynthesizer
from app.modules.ai.response_parser.parser import (
    InvestigationResponseParser,
    ResponseParsingError,
)
from app.schemas.ai import LLMResponse
from app.schemas.investigation import (
    ClaimCategory,
    GroundingStatus,
    InvestigationContext,
    ReproducibilityRecord,
    StructuredInvestigationOutput,
)
from tests.unit.test_output_guardrails_p2 import make_test_context


def _build_raw_payload(
    ctx: InvestigationContext,
    model_identifier: str = "AISOP SOC Assistant",
    claims: list[dict[str, Any]] | None = None,
    summary: str = "Suspicious execution of powershell.exe detected on WIN-HOST-01.",
) -> str:
    """Build a serialized valid JSON investigation payload with configurable model_identifier and claims."""
    if claims is None:
        ev_uuid = ctx.events[0].event_uuid
        claims = [
            {
                "claim_id": str(uuid.uuid4()),
                "claim_text": "powershell.exe executed with encoded command.",
                "category": "observed_fact",
                "supporting_evidence_ids": [str(ev_uuid)],
                "references_exist": True,
                "grounding_status": "validated_reference",
                "confidence": 1.0,
                "analyst_notes": None,
            }
        ]

    payload: dict[str, Any] = {
        "investigation_id": str(ctx.investigation_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_identifier": model_identifier,
        "investigation_summary": summary,
        "claims": claims,
        "mitre_attack_hypotheses": [],
        "alternative_explanations": ["Routine administration."],
        "recommended_analyst_actions": ["Isolate host WIN-HOST-01."],
        "uncertainty_and_data_gaps": [],
        "overall_grounding_score": 1.0,
    }
    return json.dumps(payload)


def test_persona_cannot_override_provider_model():
    """Verify that a model-generated persona like 'AISOP SOC Assistant' cannot override provider metadata."""
    ctx = make_test_context()
    raw_json = _build_raw_payload(ctx, model_identifier="AISOP SOC Assistant")
    resp = LLMResponse(content=raw_json, model="llama3.1:8b")

    parser = InvestigationResponseParser()
    parsed = parser.parse(resp, ctx)

    assert parsed.model_identifier == "llama3.1:8b", (
        f"Expected provider model 'llama3.1:8b', got untrusted model string '{parsed.model_identifier}'"
    )


def test_arbitrary_spoofed_model_identifier_overridden():
    """Verify that an arbitrary spoofed identifier cannot override provider metadata."""
    ctx = make_test_context()
    raw_json = _build_raw_payload(ctx, model_identifier="adversarial-gpt4-forgery")
    resp = LLMResponse(content=raw_json, model="llama3.1:8b")

    parser = InvestigationResponseParser()
    parsed = parser.parse(resp, ctx)

    assert parsed.model_identifier == "llama3.1:8b"


def test_missing_or_empty_model_identifier_bound_to_provider():
    """Verify that when the model omits or supplies an empty model_identifier, provider metadata is bound."""
    ctx = make_test_context()
    raw_json = _build_raw_payload(ctx, model_identifier="")
    resp = LLMResponse(content=raw_json, model="llama3.1:8b")

    parser = InvestigationResponseParser()
    parsed = parser.parse(resp, ctx)

    assert parsed.model_identifier == "llama3.1:8b"


def test_missing_provider_metadata_falls_back_to_target_metadata():
    """Verify that when provider metadata is empty, parser falls back to context reproducibility model_name."""
    ctx = make_test_context()
    # Update reproducibility model_name to a known target model
    repro = ctx.reproducibility.model_copy(update={"model_name": "llama3.1:8b"})
    ctx_custom = ctx.model_copy(update={"reproducibility": repro})

    raw_json = _build_raw_payload(ctx_custom, model_identifier="AISOP SOC Assistant")
    resp = LLMResponse(content=raw_json, model="")

    parser = InvestigationResponseParser()
    parsed = parser.parse(resp, ctx_custom)

    assert parsed.model_identifier == "llama3.1:8b"


def test_missing_provider_and_target_metadata_produces_unknown_model():
    """Verify that when neither provider nor target metadata is available, parser produces 'unknown_model'."""
    ctx = make_test_context()
    repro = ctx.reproducibility.model_copy(update={"model_name": ""})
    ctx_custom = ctx.model_copy(update={"reproducibility": repro})

    raw_json = _build_raw_payload(ctx_custom, model_identifier="AISOP SOC Assistant")
    resp = LLMResponse(content=raw_json, model="")

    parser = InvestigationResponseParser()
    parsed = parser.parse(resp, ctx_custom)

    assert parsed.model_identifier == "unknown_model"


def test_deterministic_fallback_retains_fallback_identifier():
    """Verify that deterministic fallback output always identifies its producer as 'deterministic_fallback'."""
    ctx = make_test_context()
    parser = InvestigationResponseParser()
    fallback = parser.build_deterministic_fallback(ctx, "Inference timed out after 180s")

    assert fallback.model_identifier == "deterministic_fallback"
    assert "Inference timed out after 180s" in fallback.investigation_summary


def test_claim_id_normalization_and_grounding_preserved_with_provenance_fix():
    """Verify claim-ID normalization and evidence grounding remain intact alongside authoritative provenance."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid

    claims_data = [
        {
            "claim_id": "claim-1",  # Malformed string identifier
            "claim_text": "powershell.exe executed with encoded command.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 1.0,
            "analyst_notes": None,
        }
    ]

    raw_json = _build_raw_payload(ctx, model_identifier="AISOP SOC Assistant", claims=claims_data)
    resp = LLMResponse(content=raw_json, model="llama3.1:8b")

    parser = InvestigationResponseParser()
    parsed = parser.parse(resp, ctx)

    # 1. Authoritative model bound
    assert parsed.model_identifier == "llama3.1:8b"

    # 2. Claim-ID normalized to valid deterministic UUID
    assert len(parsed.claims) == 1
    assert isinstance(parsed.claims[0].claim_id, uuid.UUID)

    # 3. Grounding status and score preserved
    assert parsed.claims[0].grounding_status == GroundingStatus.VALIDATED_REFERENCE
    assert parsed.overall_grounding_score == 1.0


def test_downstream_report_bundle_reflects_authoritative_model():
    """Verify that downstream ReportSynthesizer propagates the authoritative model to bundle provenance and markdown."""
    ctx = make_test_context()
    raw_json = _build_raw_payload(ctx, model_identifier="AISOP SOC Assistant")
    resp = LLMResponse(content=raw_json, model="llama3.1:8b")

    parser = InvestigationResponseParser()
    parsed = parser.parse(resp, ctx)

    validator = InvestigationOutputValidator()
    val_res = validator.validate(parsed, ctx)
    assert val_res.decision == GuardrailDecision.PASS
    assert val_res.is_valid is True

    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(val_res, ctx)

    # Check bundle provenance
    assert bundle.is_fallback_active is False
    assert bundle.provenance.model_identifier == "llama3.1:8b"
    assert bundle.technical_report.model_identifier == "llama3.1:8b"

    # Check markdown rendering
    assert "**Inference Model:** `llama3.1:8b`" in bundle.markdown_technical


def test_canonical_output_hashing_incorporates_authoritative_model():
    """Verify that compute_validation_output_sha256 cryptographically binds the authoritative model identifier."""
    ctx = make_test_context()
    raw_json_a = _build_raw_payload(ctx, model_identifier="AISOP SOC Assistant")
    resp_llama = LLMResponse(content=raw_json_a, model="llama3.1:8b")
    resp_qwen = LLMResponse(content=raw_json_a, model="qwen3:4b")

    parser = InvestigationResponseParser()
    parsed_llama = parser.parse(resp_llama, ctx)
    parsed_qwen = parser.parse(resp_qwen, ctx)

    validator = InvestigationOutputValidator()
    val_llama = validator.validate(parsed_llama, ctx)
    val_qwen = validator.validate(parsed_qwen, ctx)

    hash_llama_1 = compute_validation_output_sha256(val_llama)
    hash_llama_2 = compute_validation_output_sha256(val_llama)
    hash_qwen = compute_validation_output_sha256(val_qwen)

    # Determinism
    assert hash_llama_1 == hash_llama_2
    assert len(hash_llama_1) == 64

    # Model discrimination in digest
    assert hash_llama_1 != hash_qwen, (
        "Hashes must differ when authoritative model identifiers differ"
    )


def test_audit_provenance_distinguishes_producer_and_target():
    """Verify that audit provenance logic cleanly records authoritative producer and target model."""
    ctx = make_test_context()
    from app.modules.ai.context_builder.hasher import compute_context_sha256
    repro = ctx.reproducibility.model_copy(update={"model_name": "llama3.1:8b"})
    ctx_custom = ctx.model_copy(update={"reproducibility": repro})
    valid_hash = compute_context_sha256(ctx_custom)
    repro_final = repro.model_copy(update={"context_sha256": valid_hash})
    ctx_custom = ctx_custom.model_copy(update={"reproducibility": repro_final})

    # Case 1: Live successful model output with persona in content
    raw_json = _build_raw_payload(ctx_custom, model_identifier="AISOP SOC Assistant")
    resp = LLMResponse(content=raw_json, model="llama3.1:8b")

    parser = InvestigationResponseParser()
    parsed = parser.parse(resp, ctx_custom)
    val_res = InvestigationOutputValidator().validate(parsed, ctx_custom)

    actual_model = val_res.output.model_identifier
    target_model = ctx_custom.reproducibility.model_name

    assert actual_model == "llama3.1:8b"
    assert target_model == "llama3.1:8b"

    # Case 2: Deterministic fallback
    fallback = parser.build_deterministic_fallback(ctx_custom, "Inference failure")
    val_fallback = InvestigationOutputValidator().validate(fallback, ctx_custom)

    fallback_actual = val_fallback.output.model_identifier
    fallback_target = ctx_custom.reproducibility.model_name

    assert fallback_actual == "deterministic_fallback"
    assert fallback_target == "llama3.1:8b"

