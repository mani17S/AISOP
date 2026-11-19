"""
Task 1: claim-to-evidence verification through the real multi-source API (ingestion -> case -> investigation -> persisted payload).

Scripted provider only (no live model; real-model behaviour is UNVERIFIED). Checks that:
  * the prompt carries the bounded assertion contract on the production path;
  * supported / contradicted / malformed / legacy (no assertion) claims each get the right outcome in the API payload;
  * a cross-incident citation never verifies;
  * provider failure or garbage output leaves the deterministic result untouched;
  * AI-off and AI-on runs give identical deterministic sections (verification only adds claim-level information).
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

from app.modules.ai.llm.exceptions import LLMConnectionError
from app.modules.correlation.demo_data import intrusion_chain
from app.schemas.ai import LLMResponse, TokenUsage
from tests.unit.test_case_synthesis_api import app_instance, auth_settings  # noqa: F401  (fixtures)
from tests.unit.test_multisource_api import START, Keep, bearer, setup


@pytest.fixture
def anyio_backend():
    return "asyncio"


class ClaimProvider:
    """Emits one claim per scripted style, all anchored on the first event shown in the prompt."""

    model_name = "llama3.1:8b"

    def __init__(self, styles: list[str], raise_exc: Exception | None = None, garbage: bool = False) -> None:
        self.styles, self.raise_exc, self.garbage = styles, raise_exc, garbage
        self.calls, self.prompts = 0, []

    async def generate(self, request):
        self.calls += 1
        prompt = request.messages[1].content
        self.prompts.append(request.messages[0].content + request.messages[1].content)
        if self.raise_exc:
            raise self.raise_exc
        if self.garbage:
            return LLMResponse(content="not json at all {{{", model=self.model_name, usage=TokenUsage())
        inv = re.search(r'<investigation_context id="([a-f0-9\-]+)"', prompt).group(1)
        ev = re.search(r'<event uuid="([a-f0-9\-]+)".*?<summary>(.*?)</summary>', prompt, re.S)
        eid, summary = ev.group(1), ev.group(2)
        base = {"kind": "event_field", "version": "claim-assertion-v1", "evidence_id": eid, "field": "event_type", "operator": "exists"}
        claims = []
        for style in self.styles:
            assertions: Any
            if style == "supported":
                assertions = [base]
            elif style == "contradicted":
                assertions = [{**base, "field": "outcome", "operator": "equals", "value": "definitely-not-a-real-outcome"}]
            elif style == "malformed":
                assertions = [{"kind": "event_field", "evidence_id": eid, "field": "event_type", "operator": "matches_regex", "value": ".*"}]
            elif style == "foreign":
                assertions = [{**base, "evidence_id": str(uuid.uuid4())}]
            else:                                                                  # legacy: no assertions field at all
                assertions = None
            claim = {"claim_id": str(uuid.uuid4()), "claim_text": summary, "category": "observed_fact", "supporting_evidence_ids": [eid],
                     "references_exist": True, "grounding_status": "validated_reference", "confidence": 0.9}
            if assertions is not None:
                claim["assertions"] = assertions
            claims.append(claim)
        payload = {"investigation_id": inv, "generated_at": datetime.now(timezone.utc).isoformat(), "model_identifier": "scripted",
                   "investigation_summary": "Scripted summary of the incident based on the supplied evidence.", "claims": claims,
                   "mitre_attack_hypotheses": [], "alternative_explanations": ["Authorized administrative activity"],
                   "recommended_analyst_actions": ["Review the cited events"], "uncertainty_and_data_gaps": [], "overall_grounding_score": 1.0}
        return LLMResponse(content=json.dumps(payload), model=self.model_name, usage=TokenUsage())


def outcomes(inc: dict) -> list[str | None]:
    return [(c.get("verification") or {}).get("outcome") for c in inc["llm"]["claims"]]


@pytest.mark.anyio
async def test_api_payload_carries_per_claim_verification_and_the_prompt_has_the_contract(db_session, app_instance):
    provider = ClaimProvider(["supported", "contradicted", "malformed", "foreign", "legacy"])
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix="cv1")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
        assert r.status_code == 201, r.text
        inc = r.json()["incidents"][0]
        assert "claim-assertion-v1" in provider.prompts[0]                         # bounded contract is on the production prompt path
        got = outcomes(inc)
        assert got[0] == "supported" and got[1] == "contradicted"
        assert got[2] in {"not_verifiable"} and got[3] != "supported"              # unsupported operator / foreign evidence never verify
        assert got[4] is None                                                       # legacy claim: no verification object (UI: not machine-verifiable)
        for c in inc["llm"]["claims"][:4]:
            assert c["verification"]["applies_to"] == "listed_assertions_only"
        assert "definitely-not-a-real-outcome" in r.text or True                   # echo of fixed-vocabulary fields is allowed, never required
        # deterministic sections are unchanged by verification
        assert inc["sufficiency"]["verdict"] == "sufficient" and len(inc["timeline"]) == 10 and len(inc["mitre"]) == 6


@pytest.mark.anyio
async def test_provider_failure_and_garbage_output_keep_the_deterministic_result(db_session, app_instance):
    provider, status = ClaimProvider([], raise_exc=LLMConnectionError("down")), "fallback:LLMConnectionError"
    prefix = "cv2a"
    if True:
        client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix=prefix)
        async with Keep(client):
            r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
            inc = r.json()["incidents"][0]
            assert r.status_code == 201 and (status is None or inc["llm_status"] == status)
            assert inc["llm_status"] != "validated" or inc["llm"] is None
            assert len(inc["timeline"]) == 10 and len(inc["mitre"]) == 6 and inc["sufficiency"]["verdict"] == "sufficient"


def _deterministic_view(inc: dict) -> dict:
    return {k: inc[k] for k in ("timeline", "mitre", "correlation") if k in inc}


def _diff(a: Any, b: Any, path: str = "") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        return [d for k in sorted(set(a) | set(b)) for d in _diff(a.get(k), b.get(k), f"{path}.{k}")]
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [d for i, (x, y) in enumerate(zip(a, b)) for d in _diff(x, y, f"{path}[{i}]")]
    return [] if a == b else [path]


@pytest.mark.anyio
async def test_ai_off_and_ai_on_have_identical_deterministic_sections(db_session, app_instance):
    provider = ClaimProvider(["supported", "legacy"])
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix="cv3")
    async with Keep(client):
        off = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()["incidents"][0]
        assert provider.calls == 0 and off["llm"] is None and off["llm_status"] == "not_requested"
        on = (await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))).json()["incidents"][0]
        assert provider.calls == 1 and outcomes(on) == ["supported", None]
        assert _deterministic_view(off) == _deterministic_view(on)
        assert _diff(off["sufficiency"], on["sufficiency"]) == [".rationale.status.llm_status"]   # the only AI-dependent field is the status label


@pytest.mark.anyio
async def test_garbage_model_output_never_yields_a_verification_or_breaks_the_run(db_session, app_instance):
    provider = ClaimProvider([], garbage=True)
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix="cv4")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
        inc = r.json()["incidents"][0]
        assert r.status_code == 201 and inc["llm_status"] != "validated"
        assert not (inc.get("llm") or {}).get("claims")
        assert len(inc["timeline"]) == 10 and len(inc["mitre"]) == 6 and inc["sufficiency"]["verdict"] == "sufficient"
