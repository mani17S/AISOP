"""
Unit tests for deterministic claim identifier normalization in InvestigationResponseParser.

Validates AISOP Gate D.2.5.32 implementation:
- Valid unique UUID preservation
- Malformed identifier normalization (claim-1, c1, integer, etc.)
- Missing, null, and empty claim_id handling
- Cross-run deterministic reproducibility
- Cross-investigation UUID isolation
- Collision-free duplicate handling for both malformed and valid UUIDs
- Strict segregation from evidence reference validation (ungrounded claims remain unsupported)
- Downstream report synthesizer compatibility
- Fallback preservation on other validation defects
"""

from datetime import datetime, timezone
import json
from typing import Any
import uuid

import pytest

from app.modules.ai.guardrails.validator import (
    GuardrailDecision,
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
    StructuredInvestigationOutput,
)
from tests.unit.test_prompt_and_inference_p2 import make_test_context


def _build_raw_payload(
    ctx: InvestigationContext,
    claims: list[dict[str, Any]],
    summary: str = "Suspicious execution of powershell.exe detected on WIN-HOST-01.",
) -> str:
    """Build a serialized valid JSON investigation payload with customizable claims."""
    payload = {
        "investigation_id": str(ctx.investigation_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_identifier": "llama3.1:8b",
        "investigation_summary": summary,
        "claims": claims,
        "mitre_attack_hypotheses": [],
        "alternative_explanations": ["Routine administration."],
        "recommended_analyst_actions": ["Isolate host WIN-HOST-01."],
        "uncertainty_and_data_gaps": [],
        "overall_grounding_score": 1.0,
    }
    return json.dumps(payload)


def test_valid_unique_uuid_is_preserved():
    """Verify that a valid RFC 4122 UUID claim_id is preserved exactly without alteration."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid
    expected_uuid = uuid.uuid4()

    claims = [
        {
            "claim_id": str(expected_uuid),
            "claim_text": "powershell.exe executed with encoded command.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 1.0,
            "analyst_notes": None,
        }
    ]

    parser = InvestigationResponseParser()
    resp = LLMResponse(content=_build_raw_payload(ctx, claims), model="llama3.1:8b")
    parsed = parser.parse(resp, ctx)

    assert parsed.claims[0].claim_id == expected_uuid
    assert len(parser.last_normalized_claim_ids) == 0


def test_malformed_string_identifiers_normalized():
    """Verify that 'claim-1', 'c1', and arbitrary non-UUID string IDs are normalized to valid UUIDs."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid

    claims = [
        {
            "claim_id": "claim-1",
            "claim_text": "powershell.exe spawned encoded process.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.95,
            "analyst_notes": None,
        },
        {
            "claim_id": "c2",
            "claim_text": "Network connection initiated to external IP.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.90,
            "analyst_notes": None,
        },
    ]

    parser = InvestigationResponseParser()
    resp = LLMResponse(content=_build_raw_payload(ctx, claims), model="llama3.1:8b")
    parsed = parser.parse(resp, ctx)

    assert isinstance(parsed.claims[0].claim_id, uuid.UUID)
    assert isinstance(parsed.claims[1].claim_id, uuid.UUID)
    assert parsed.claims[0].claim_id != parsed.claims[1].claim_id
    assert 0 in parser.last_normalized_claim_ids
    assert 1 in parser.last_normalized_claim_ids
    assert parser.last_normalized_claim_ids[0]["original"] == "claim-1"


def test_missing_null_and_empty_identifiers():
    """Verify that null, empty string, and omitted claim_id fields are deterministically normalized."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid

    claims = [
        {
            # claim_id key omitted entirely
            "claim_text": "First claim with omitted identifier.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.95,
            "analyst_notes": None,
        },
        {
            "claim_id": None,
            "claim_text": "Second claim with null identifier.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.90,
            "analyst_notes": None,
        },
        {
            "claim_id": "   ",
            "claim_text": "Third claim with whitespace identifier.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.85,
            "analyst_notes": None,
        },
    ]

    parser = InvestigationResponseParser()
    resp = LLMResponse(content=_build_raw_payload(ctx, claims), model="llama3.1:8b")
    parsed = parser.parse(resp, ctx)

    assert len(parsed.claims) == 3
    for c in parsed.claims:
        assert isinstance(c.claim_id, uuid.UUID)
    assert len({c.claim_id for c in parsed.claims}) == 3


def test_deterministic_reproducibility_identical_input():
    """Verify that reprocessing identical input with the same investigation UUID yields bit-for-bit identical claim IDs."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid

    claims = [
        {
            "claim_id": "claim-1",
            "claim_text": "powershell.exe executed with encoded command.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.95,
            "analyst_notes": None,
        }
    ]

    raw_json = _build_raw_payload(ctx, claims)
    parser = InvestigationResponseParser()

    parsed_run_1 = parser.parse(LLMResponse(content=raw_json, model="llama3.1:8b"), ctx)
    parsed_run_2 = parser.parse(LLMResponse(content=raw_json, model="llama3.1:8b"), ctx)

    assert parsed_run_1.claims[0].claim_id == parsed_run_2.claims[0].claim_id


def test_cross_investigation_uuid_isolation():
    """Verify that different investigation UUIDs produce different generated claim IDs for equivalent malformed tokens."""
    inv_id_1 = uuid.uuid4()
    inv_id_2 = uuid.uuid4()
    ctx_1 = make_test_context(inv_id_1)
    ctx_2 = make_test_context(inv_id_2)

    claim_dict = {
        "claim_id": "claim-1",
        "claim_text": "Atomic observation.",
        "category": "observed_fact",
        "supporting_evidence_ids": [str(ctx_1.events[0].event_uuid)],
        "references_exist": True,
        "grounding_status": "validated_reference",
        "confidence": 0.95,
        "analyst_notes": None,
    }

    parser = InvestigationResponseParser()
    resp_1 = LLMResponse(content=_build_raw_payload(ctx_1, [claim_dict]), model="llama3.1:8b")
    claim_dict_2 = dict(claim_dict, supporting_evidence_ids=[str(ctx_2.events[0].event_uuid)])
    resp_2 = LLMResponse(content=_build_raw_payload(ctx_2, [claim_dict_2]), model="llama3.1:8b")

    parsed_1 = parser.parse(resp_1, ctx_1)
    parsed_2 = parser.parse(resp_2, ctx_2)

    assert parsed_1.claims[0].claim_id != parsed_2.claims[0].claim_id


def test_duplicate_malformed_identifiers_produce_unique_ids():
    """Verify that multiple claims with identical malformed 'claim-1' identifiers receive unique, distinct UUIDs."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid

    claims = [
        {
            "claim_id": "claim-1",
            "claim_text": "First statement.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.9,
            "analyst_notes": None,
        },
        {
            "claim_id": "claim-1",
            "claim_text": "Second statement reusing same moniker.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.8,
            "analyst_notes": None,
        },
    ]

    parser = InvestigationResponseParser()
    resp = LLMResponse(content=_build_raw_payload(ctx, claims), model="llama3.1:8b")
    parsed = parser.parse(resp, ctx)

    assert len(parsed.claims) == 2
    assert parsed.claims[0].claim_id != parsed.claims[1].claim_id


def test_duplicate_valid_uuids_explicitly_disambiguated():
    """Verify that duplicate valid UUIDs across multiple claims are detected and deterministically disambiguated."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid
    shared_uuid = uuid.uuid4()

    claims = [
        {
            "claim_id": str(shared_uuid),
            "claim_text": "Claim 0 holding original UUID.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.9,
            "analyst_notes": None,
        },
        {
            "claim_id": str(shared_uuid),
            "claim_text": "Claim 1 colliding with Claim 0 UUID.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.8,
            "analyst_notes": None,
        },
    ]

    parser = InvestigationResponseParser()
    resp = LLMResponse(content=_build_raw_payload(ctx, claims), model="llama3.1:8b")
    parsed = parser.parse(resp, ctx)

    # First claim keeps the original valid UUID
    assert parsed.claims[0].claim_id == shared_uuid
    # Second claim is disambiguated to a distinct valid UUID
    assert parsed.claims[1].claim_id != shared_uuid
    assert isinstance(parsed.claims[1].claim_id, uuid.UUID)
    assert 1 in parser.last_normalized_claim_ids
    assert parser.last_normalized_claim_ids[1]["action"] == "disambiguated_duplicate_uuid"


def test_evidence_reference_grounding_unweakened_by_normalization():
    """Verify that normalizing 'claim-1' never validates an ungrounded or non-existent telemetry reference."""
    ctx = make_test_context()
    fake_ev_uuid = uuid.uuid4()  # Not present in ctx.events

    claims = [
        {
            "claim_id": "claim-1",
            "claim_text": "Fabricated statement citing unknown event.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(fake_ev_uuid)],
            "references_exist": True,  # Untrusted LLM claims it exists
            "grounding_status": "validated_reference",  # Untrusted LLM claims validated
            "confidence": 0.95,
            "analyst_notes": None,
        }
    ]

    parser = InvestigationResponseParser()
    resp = LLMResponse(content=_build_raw_payload(ctx, claims), model="llama3.1:8b")
    parsed = parser.parse(resp, ctx)

    # Claim-ID was normalized safely
    assert isinstance(parsed.claims[0].claim_id, uuid.UUID)
    # BUT grounding invariants were strictly enforced: reference demoted to UNSUPPORTED, confidence 0.0
    assert parsed.claims[0].references_exist is False
    assert parsed.claims[0].grounding_status == GroundingStatus.UNSUPPORTED
    assert parsed.claims[0].confidence == 0.0
    assert parsed.overall_grounding_score == 0.0
    assert "[UNSUPPORTED: Cited evidence UUIDs not found in context]" in (parsed.claims[0].analyst_notes or "")


def test_claim_attributes_preserved_without_side_effects():
    """Verify that normalization preserves claim_text, confidence, category, and evidence IDs untouched."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid

    claims = [
        {
            "claim_id": "claim-xyz",
            "claim_text": "powershell.exe -enc execution confirmed on host.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.8765,
            "analyst_notes": "Custom analyst annotation.",
        }
    ]

    parser = InvestigationResponseParser()
    resp = LLMResponse(content=_build_raw_payload(ctx, claims), model="llama3.1:8b")
    parsed = parser.parse(resp, ctx)

    c = parsed.claims[0]
    assert c.claim_text == "powershell.exe -enc execution confirmed on host."
    assert c.category == ClaimCategory.OBSERVED_FACT
    assert c.confidence == 0.8765
    assert c.supporting_evidence_ids == [ev_uuid]
    assert c.analyst_notes == "Custom analyst annotation."
    assert c.references_exist is True
    assert c.grounding_status == GroundingStatus.VALIDATED_REFERENCE


def test_downstream_report_synthesizer_accepts_normalized_claims():
    """Verify that DeterministicReportSynthesizer accepts output with normalized claim IDs without error."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid

    claims = [
        {
            "claim_id": "claim-1",
            "claim_text": "Encoded powershell execution verified.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 0.95,
            "analyst_notes": None,
        }
    ]

    parser = InvestigationResponseParser()
    resp = LLMResponse(content=_build_raw_payload(ctx, claims), model="llama3.1:8b")
    parsed_output = parser.parse(resp, ctx)

    validation_result = InvestigationValidationResult(
        decision=GuardrailDecision.PASS,
        is_valid=True,
        output=parsed_output,
        violations=[],
        context_sha256=ctx.reproducibility.context_sha256,
        validated_at_utc=datetime.now(timezone.utc),
    )

    synthesizer = DeterministicReportSynthesizer()
    bundle = synthesizer.synthesize_bundle(
        validation_result=validation_result,
        context=ctx,
        is_server_verified=True,
    )

    assert bundle.is_fallback_active is False
    assert len(bundle.technical_report.confirmed_findings) == 1
    assert bundle.technical_report.confirmed_findings[0].claim_id == parsed_output.claims[0].claim_id


def test_fallback_behavior_preserved_on_schema_defects():
    """Verify that non-identifier defects (e.g. summary too short) still fail closed to ResponseParsingError."""
    ctx = make_test_context()
    ev_uuid = ctx.events[0].event_uuid

    claims = [
        {
            "claim_id": "claim-1",
            "claim_text": "Valid assertion.",
            "category": "observed_fact",
            "supporting_evidence_ids": [str(ev_uuid)],
            "references_exist": True,
            "grounding_status": "validated_reference",
            "confidence": 1.0,
            "analyst_notes": None,
        }
    ]

    # Investigation summary violates min_length=20 constraint
    short_summary_payload = _build_raw_payload(ctx, claims, summary="Too short")
    parser = InvestigationResponseParser()
    resp = LLMResponse(content=short_summary_payload, model="llama3.1:8b")

    with pytest.raises(ResponseParsingError) as exc_info:
        parser.parse(resp, ctx)

    assert "Response failed schema validation" in str(exc_info.value)

    # Verify fallback generation still functions deterministically
    fallback = parser.build_deterministic_fallback(ctx, "Validation failed")
    assert fallback.model_identifier == "deterministic_fallback"
    assert fallback.overall_grounding_score == 0.0
