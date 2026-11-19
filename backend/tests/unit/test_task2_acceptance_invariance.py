"""
Task 2 acceptance: expanded deterministic invariance across AI modes (real multisource API, scripted providers, no network).

What is and is not required to be identical (derived from the actual workflow, see the acceptance report 03):
  * extracted entities / IOC links, enrichments, asserted-only techniques, contradictions, analyst statements, hosts/users/stages: deterministic,
    computed before any AI step -> MUST be identical in every mode;
  * ledger: hash-chained. AI runs append LLM_GATE / CLAIM_VERIFY after the deterministic entries, so the HEAD legitimately differs between AI-off and
    AI-on. The valid invariant is: the deterministic prefix (every entry before the LLM entries) is byte-identical (step, details, hashes), and every
    chain verifies. Exact head equality is NOT a valid requirement under the current audit semantics;
  * claim verification: only AI-on modes have claims. For identical scripted claims/assertions/evidence the verification outcomes are identical
    run to run; modes without AI claims carry no verification at all (nothing is fabricated).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import app.modules.ai.llm.manager as manager
from app.api.v1.endpoints.cases import get_case_llm_provider
from app.modules.ai.llm.exceptions import LLMConnectionError
from app.modules.correlation.demo_data import intrusion_chain
from app.schemas.ai import LLMResponse, TokenUsage
from tests.unit.test_case_synthesis_api import app_instance, auth_settings  # noqa: F401  (fixtures)
from tests.unit.test_claim_verification_api import ClaimProvider
from tests.unit.test_local_first_controls import Garbage, RaisingConnect, fresh
from tests.unit.test_multisource_api import START, Keep, ScriptedProvider, bearer, setup

DETERMINISTIC_INCIDENT_FIELDS = (
    "timeline", "mitre", "context_sha256", "severity", "event_count", "link_counts", "links", "weak_link_count", "graph", "enrichments",
    "asserted_only", "contradictions", "analyst_statements", "weakly_related", "hosts", "users", "stages", "first_seen", "last_seen", "escalated",
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _stable_sufficiency(inc: dict[str, Any]) -> dict[str, Any]:
    s = json.loads(json.dumps(inc["sufficiency"]))
    s.get("rationale", {}).get("status", {}).pop("llm_status", None)
    return s


async def _run_all_modes(client, app_instance, token, case, monkeypatch) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    out["off"] = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
    for name, prov in (("on", ClaimProvider(["supported", "contradicted", "legacy"])), ("malformed", Garbage()), ("unavailable", RaisingConnect())):
        app_instance.dependency_overrides[get_case_llm_provider] = lambda p=prov: p
        r = await client.post(START.format(cid=case.id), json={"use_llm": True, "force": True}, headers=bearer(token))
        assert r.status_code == 201, r.text
        out[name] = r.json()
    app_instance.dependency_overrides.pop(get_case_llm_provider, None)
    monkeypatch.setattr(manager, "get_settings", lambda: fresh(LLM_ENABLED=False))
    r = await client.post(START.format(cid=case.id), json={"use_llm": True, "force": True}, headers=bearer(token))
    assert r.status_code == 201, r.text
    out["disabled"] = r.json()
    return out


@pytest.mark.anyio
async def test_ioc_entities_provenance_ledger_prefix_and_verification_across_five_modes(db_session, app_instance, monkeypatch):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=ScriptedProvider(), prefix="acc1")
    async with Keep(client):
        modes = await _run_all_modes(client, app_instance, token, case, monkeypatch)

    base = modes["off"]["incidents"][0]
    assert base["graph"] is not None or base["links"], "fixture must exercise entity extraction"
    # 1. extracted entities / IOC links and every other deterministic field: identical in all five modes
    for name, body in modes.items():
        inc = body["incidents"][0]
        for f in DETERMINISTIC_INCIDENT_FIELDS:
            assert inc.get(f) == base.get(f), f"deterministic field {f!r} changed in mode {name}"
        assert _stable_sufficiency(inc) == _stable_sufficiency(base), f"sufficiency changed in mode {name}"
        assert body["sources"] == modes["off"]["sources"] and body["counts"] == modes["off"]["counts"] and body["contradictions"] == modes["off"]["contradictions"]

    # 2. ledger: exact head equality is not a valid requirement; the replayed deterministic prefix (with chain hashes) and chain validity are
    assert all(body["ledger"]["verified"] is True for body in modes.values())
    off_steps = modes["off"]["ledger"]["steps"]
    assert off_steps and off_steps[-1]["step"] == "REPORT"
    assert modes["off"]["ledger"]["head"] != modes["on"]["ledger"]["head"], "AI execution events legitimately change the head"
    for name in ("on", "malformed", "unavailable", "disabled"):
        steps = modes[name]["ledger"]["steps"]
        assert steps[: len(off_steps) - 1] == off_steps[:-1], f"deterministic ledger prefix (steps and hashes) changed in mode {name}"
        added = [x["step"] for x in steps[len(off_steps) - 1 :]]
        assert added == ["LLM_GATE", "CLAIM_VERIFY", "REPORT"], f"unexpected ledger additions in mode {name}: {added}"

    # 3. claim verification: modes without AI claims carry none; AI-on verification is deterministic
    for name in ("off", "malformed", "unavailable", "disabled"):
        llm = modes[name]["incidents"][0]["llm"]
        assert not llm or all(c.get("verification") is None for c in llm["claims"]), f"verification fabricated in mode {name}"
    on = [(c["category"], (c["verification"] or {}).get("outcome")) for c in modes["on"]["incidents"][0]["llm"]["claims"]]
    assert sorted(on, key=str) == sorted([("observed_fact", "supported"), ("observed_fact", "contradicted"), ("observed_fact", None)], key=str)


@pytest.mark.anyio
async def test_identical_scripted_claims_give_identical_verification_run_to_run(db_session, app_instance):
    prov = ClaimProvider(["supported", "contradicted", "malformed", "legacy"])
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=prov, prefix="acc2")
    async with Keep(client):
        views = []
        for _ in range(2):
            r = await client.post(START.format(cid=case.id), json={"use_llm": True, "force": True}, headers=bearer(token))
            claims = r.json()["incidents"][0]["llm"]["claims"]
            views.append([{k: v for k, v in c.items() if k != "claim_id"} for c in claims])
    assert views[0] == views[1] and any(c["verification"] for c in views[0])


@pytest.mark.anyio
async def test_provenance_survives_disabled_and_unavailable_modes(db_session, app_instance, monkeypatch):
    from sqlalchemy import select

    from app.models.evidence import NormalizedEventModel, RawEvidence

    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=ScriptedProvider(), prefix="acc3")
    async with Keep(client):
        modes = await _run_all_modes(client, app_instance, token, case, monkeypatch)
    stored = {str(e.id): e for e in (await db_session.execute(select(NormalizedEventModel))).scalars().all()}
    raws = {r.id: r for r in (await db_session.execute(select(RawEvidence))).scalars().all()}
    for name in ("disabled", "unavailable", "malformed"):
        timeline = modes[name]["incidents"][0]["timeline"]
        assert timeline == modes["off"]["incidents"][0]["timeline"]
        for t in timeline:                                                                      # every row still maps to preserved raw evidence
            ev = stored[t["event_id"]]
            assert raws[ev.raw_evidence_id].sha256_hash.startswith(t["raw_sha256_prefix"])
