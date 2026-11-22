"""
AI latency pins (docs/06_AI/AI_Latency.md).

On a CPU-only host the model call is dominated by output tokens, so the structured-output schema is bounded and the
platform-owned fields are withheld from the model. These tests pin that behaviour and prove the safety rules still hold:
the gate runs before any model call, claim verification still runs, and the deterministic fallback still works.
Synchronous style (``asyncio.run``); there is no pytest-asyncio in this project.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid

from app.modules.ai.guardrails.validator import InvestigationOutputValidator
from app.modules.ai.prompt_builder.builder import (
    BOUNDED_MAX_TOKENS,
    DEFAULT_MAX_TOKENS,
    OUTPUT_LIST_LIMITS,
    InvestigationPromptBuilder,
)
from app.modules.ai.response_parser.parser import InvestigationResponseParser
from app.modules.correlation.workflow import run_workflow
from app.schemas.ai import LLMResponse, TokenUsage
from tests.unit.test_multisource_workflow import ASSETS, SCENARIOS, ScriptedProvider, intrusion_chain
from tests.unit.test_output_guardrails_p2 import make_test_context

PLATFORM_OWNED_CLAIM_FIELDS = ("verification", "claim_id")


def _request():
    ctx = make_test_context()
    return ctx, InvestigationPromptBuilder(structured_assertions=True).build_request(ctx, model_override="qwen3:4b")


def _all_refs(node) -> set[str]:
    return set(re.findall(r"#/\$defs/(\w+)", json.dumps(node)))


def test_schema_bounds_list_sizes_and_string_lengths():
    _, req = _request()
    props = req.response_schema["properties"]
    for name, limit in OUTPUT_LIST_LIMITS.items():
        assert props[name]["maxItems"] == limit, name
    assert props["claims"]["maxItems"] == 2 and props["mitre_attack_hypotheses"]["maxItems"] == 1
    assert props["recommended_analyst_actions"]["maxItems"] == 2
    assert props["investigation_summary"]["maxLength"] > 0
    defs = req.response_schema["$defs"]
    assert defs["FactualClaimItem"]["properties"]["claim_text"]["maxLength"] > 0
    assert defs["MitreAttackHypothesis"]["properties"]["reasoning"]["maxLength"] > 0


def test_model_cannot_author_platform_owned_fields_but_keeps_pinned_ids():
    ctx, req = _request()
    schema = req.response_schema
    claim = schema["$defs"]["FactualClaimItem"]
    hypothesis = schema["$defs"]["MitreAttackHypothesis"]
    for field in PLATFORM_OWNED_CLAIM_FIELDS:
        assert field not in claim["properties"] and field not in claim.get("required", [])
    assert "taxonomy" not in hypothesis["properties"]
    assert "generated_at" not in schema["properties"] and "generated_at" not in schema.get("required", [])
    # System-owned identity fields stay pinned to their known values (unchanged behaviour).
    assert schema["properties"]["investigation_id"]["const"] == str(ctx.investigation_id)
    assert schema["properties"]["model_identifier"]["const"] == "qwen3:4b"
    # The fields the model must author are still required.
    assert {"investigation_summary", "recommended_analyst_actions", "overall_grounding_score"} <= set(schema["required"])
    assert {"claim_text", "category", "references_exist", "grounding_status", "confidence"} <= set(claim["required"])


def test_schema_has_no_dangling_or_unused_definitions():
    _, req = _request()
    schema = req.response_schema
    defs = schema["$defs"]
    reachable = _all_refs({k: v for k, v in schema.items() if k != "$defs"})
    frontier = set(reachable)
    while frontier:
        name = frontier.pop()
        new = _all_refs(defs[name]) - reachable
        reachable |= new
        frontier |= new
    assert reachable <= set(defs)           # every $ref resolves
    assert set(defs) <= reachable           # nothing unreachable is sent to the sampler
    assert "ClaimVerification" not in defs and "TechniqueTaxonomyStatus" not in defs


def test_retry_request_uses_the_same_bounded_schema():
    ctx = make_test_context()
    builder = InvestigationPromptBuilder(structured_assertions=True)
    first, retry = builder.build_request(ctx), builder.build_retry_request(ctx)
    assert first.response_schema == retry.response_schema
    assert first.max_tokens == DEFAULT_MAX_TOKENS  # shared default unchanged for the other call sites


def test_bounded_model_answer_without_platform_fields_still_parses_and_validates():
    ctx = make_test_context()
    event = ctx.events[0]
    answer = {
        "investigation_id": str(ctx.investigation_id), "model_identifier": "qwen3:4b",
        "investigation_summary": "Short bounded summary of the supplied evidence for the analyst.",
        "recommended_analyst_actions": ["Review the cited event."], "overall_grounding_score": 1.0,
        "claims": [{"claim_text": "An event was observed.", "category": "observed_fact", "supporting_evidence_ids": [str(event.event_uuid)],
                    "references_exist": True, "grounding_status": "validated_reference", "confidence": 0.9}],
        "mitre_attack_hypotheses": [],
    }
    raw = LLMResponse(content=json.dumps(answer), model="qwen3:4b", usage=TokenUsage())
    parsed = InvestigationResponseParser().parse(raw, ctx)
    result = InvestigationOutputValidator().validate(parsed, ctx)
    assert result.output.claims and result.output.claims[0].claim_id is not None  # the platform assigns the id


class _CapturingProvider(ScriptedProvider):
    def __init__(self) -> None:
        super().__init__()
        self.requests = []

    async def generate(self, request):
        self.requests.append(request)
        return await super().generate(request)


def test_workflow_makes_one_bounded_call_per_sufficient_incident_and_still_verifies_claims():
    provider = _CapturingProvider()
    res = asyncio.run(run_workflow(intrusion_chain(), ASSETS, provider))
    analysis = res.incidents[0]
    assert provider.calls == 1 == len(provider.requests)                  # no second/retry call when the first answer is valid
    request = provider.requests[0]
    assert request.max_tokens == BOUNDED_MAX_TOKENS < DEFAULT_MAX_TOKENS
    assert request.response_schema["properties"]["claims"]["maxItems"] == 2
    assert analysis.llm_status == "validated" and analysis.llm_result.is_valid
    assert "CLAIM_VERIFY" in [e["step"] for e in res.ledger] and res.ledger_ok


def test_insufficient_evidence_never_reaches_the_model_and_falls_back():
    provider = _CapturingProvider()
    res = asyncio.run(run_workflow(SCENARIOS["05_insufficient_unparseable"]["build"](), {}, provider))
    assert provider.calls == 0 and not provider.requests and res.batch_assessment.abstain


def test_provider_failure_still_falls_back_deterministically_with_bounded_request():
    from app.modules.ai.llm.exceptions import LLMTimeoutError

    class _Down(_CapturingProvider):
        async def generate(self, request):
            self.requests.append(request)
            raise LLMTimeoutError("slow")

    provider = _Down()
    res = asyncio.run(run_workflow(intrusion_chain(), ASSETS, provider))
    analysis = res.incidents[0]
    assert len(provider.requests) == 1                                    # a timeout is not retried inside the workflow
    assert analysis.llm_status == "fallback:LLMTimeoutError" and analysis.llm_result.decision.value == "reject_to_fallback"
    assert "## 2. Timeline" in analysis.markdown


def test_each_sufficient_incident_gets_exactly_one_call_and_the_incident_cap_is_kept():
    provider = _CapturingProvider()
    res = asyncio.run(run_workflow(intrusion_chain(), ASSETS, provider, max_llm_incidents=0))
    assert provider.calls == 0 and res.incidents[0].llm_status == "skipped:llm_incident_limit"
    assert uuid.UUID(str(res.incidents[0].incident.incident_id))
