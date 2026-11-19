"""
Implementation Sprint 1: the analyst-visible suff-v4 rationale trace (current semantics only).

Offline, no database, no model. Every test pins one of two things: (1) the trace NEVER changes the existing decision, or (2) the trace and
the rationale built from it describe the CURRENT record-level rule honestly (no entity values, no claim of sensor independence or of
cryptographic authenticity, payload-declared identity labelled as untrusted).
"""

from __future__ import annotations

import json

import pytest

import app.modules.ai.guardrails.sufficiency_gate as gate
from app.modules.ai.guardrails.sufficiency_gate import assess_evidence_sufficiency, evaluate_sufficiency
from app.modules.ai.guardrails.sufficiency_trace import (
    LIMITATIONS,
    MAX_COLLAPSED,
    MAX_PAIRS,
    MAX_UNITS,
    RATIONALE_SCHEMA,
    SufficiencyTrace,
    build_rationale,
)
from app.modules.evidence.independence import EvidenceItem, cluster_evidence, explain_clusters
from app.schemas.sufficiency import SufficiencyVerdict
from tests.unit.test_evidence_sufficiency_gate import GOOD, GOOD_B, ZERO, ent, ev, make

DOMAIN_VALUE = "c2.badcdn.example"
PROCESS_VALUE = "p.exe"
PAIR_ENTS = [ent("process", PROCESS_VALUE, "e0"), ent("domain", DOMAIN_VALUE, "e0", "e1")]


def uid(ctx, key):
    return str(next(e.event_uuid for e in ctx.events if e.summary.endswith(f" {key}")))


def traced(ctx, contradictions=()):
    t = SufficiencyTrace()
    return evaluate_sufficiency(ctx, contradictions, trace=t), t


def scenarios():
    pair = [ev("e0"), ev("e1", etype="network_connection", eid="3", off=5.0)]
    return {
        "sufficient_pair": make(pair, PAIR_ENTS),
        "duplicates": make([ev("e0"), ev("e0_dup")], [ent("process", PROCESS_VALUE, "e0", "e0_dup")]),
        "no_evidence": make([], root=None),
        "no_relevant": make([ev("x0", host="OTHER")], [], root=None, hosts=["HOST-A"]),
        "weak_only": make([ev("e0"), ev("e1", off=5.0, etype="network_connection")], [ent("process", PROCESS_VALUE, "e0"), ent("host", "HOST-A", "e0", "e1")]),
        "same_observation_class": make([ev("e0"), ev("e1", off=60.0, digest=GOOD_B)], [ent("process", PROCESS_VALUE, "e0"), ent("domain", DOMAIN_VALUE, "e0", "e1")]),
        "contradictory": make([ev("e0"), ev("e0_contra", outcome="failure", digest=GOOD_B)], [ent("process", PROCESS_VALUE, "e0", "e0_contra")]),
        "absent_root": make(pair, [ent("domain", DOMAIN_VALUE, "e0", "e1")], root="not-in-context"),
        "unattested": make([ev("e0", digest=ZERO), ev("e1", off=5.0, digest=ZERO)], PAIR_ENTS),
        "no_anchor_pair": make(pair, PAIR_ENTS, root=None),
        "truncated": make(pair, PAIR_ENTS, omitted=3),
        "future_dated_anchor": make(
            [ev("e0", off=1000.0), ev("e1", off=0.0, etype="network_connection", eid="3")],
            [ent("process", PROCESS_VALUE, "e0"), ent("domain", DOMAIN_VALUE, "e0", "e1")],
            window={"start_offset_s": -1.0, "end_offset_s": 2000.0}, assembled=60.0, root="e0"),
    }


# ── 1. The trace never changes a decision ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("name", sorted(scenarios()))
def test_trace_enabled_and_disabled_give_the_identical_assessment(name):
    ctx = scenarios()[name]
    plain = evaluate_sufficiency(ctx)
    with_trace, trace = traced(ctx)
    assert with_trace.model_dump(mode="json") == plain.model_dump(mode="json")
    assert with_trace.assessment_sha256 == plain.assessment_sha256
    assert with_trace.abstain == plain.abstain                                      # model-call eligibility unchanged
    assert trace.stage in ("complete", "no_evidence", "no_relevant_evidence") and trace.error is None


def test_a_disabled_trace_calls_the_core_exactly_as_before(monkeypatch):
    seen = {}

    def core(context, contradictions):                                              # the OLD two-argument contract
        seen["args"] = (context, contradictions)
        return assess_evidence_sufficiency(context, contradictions)

    monkeypatch.setattr(gate, "assess_evidence_sufficiency", core)
    a = evaluate_sufficiency(scenarios()["sufficient_pair"])
    assert a.verdict == SufficiencyVerdict.SUFFICIENT and "args" in seen


def test_a_failing_trace_cannot_alter_or_fail_the_verdict(monkeypatch):
    ctx = scenarios()["duplicates"]
    plain = evaluate_sufficiency(ctx)

    def boom(*_a, **_k):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(gate, "explain_clusters", boom)
    a, t = traced(ctx)
    assert a.model_dump(mode="json") == plain.model_dump(mode="json")
    assert t.error == "RuntimeError"                                                 # exception TYPE only, never the message
    r = build_rationale(t, a)
    assert r["completeness"] == "partial" and "secret detail" not in json.dumps(r)


def test_explaining_clusters_does_not_change_membership_or_order():
    from datetime import datetime, timedelta, timezone
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    items = [
        EvidenceItem("a", t0, GOOD, ("h", "1", "x", "start", "success"), frozenset(), "c"),
        EvidenceItem("b", t0 + timedelta(seconds=1), None, ("h", "1", "x", "start", "success"), frozenset(), "d"),
        EvidenceItem("c", t0 + timedelta(seconds=500), GOOD, ("h", "2", "y", "stop", "success"), frozenset(), "e"),
    ]
    before = cluster_evidence(items)
    explanation = explain_clusters(items, before)
    assert cluster_evidence(items) == before and list(before) == ["a", "b", "c"]
    assert {e["duplicate"] for e in explanation} == {"b", "c"}


# ── 2. Duplicate collapse basis reflects the actual clustering conditions ─────────────────────────────────
def collapse(ctx):
    _a, t = traced(ctx)
    return {(c["duplicate"], c["into"]): c for c in t.collapsed}


def test_same_content_and_near_duplicate_basis():
    ctx = make([ev("e0"), ev("e0_dup")], [ent("process", PROCESS_VALUE, "e0", "e0_dup")])
    (c,) = collapse(ctx).values()
    assert c["into"] == uid(ctx, "e0") and c["duplicate"] == uid(ctx, "e0_dup")
    assert {"same_content", "near_duplicate_within_window"} <= set(c["basis"]) and c["direct"] is True


def test_same_attested_digest_basis():
    ctx = make([ev("e0", digest=GOOD), ev("e1", off=100.0, digest=GOOD, etype="network_connection", eid="3")], [ent("process", PROCESS_VALUE, "e0")])
    (c,) = collapse(ctx).values()
    assert c["basis"] == ["same_digest"]


def test_declared_upstream_id_basis_is_reported_as_such():
    attrs = {"upstream_id": "feed-1"}
    ctx = make([ev("e0", attrs=attrs), ev("e1", off=100.0, etype="network_connection", eid="3", attrs=attrs)], [ent("process", PROCESS_VALUE, "e0")])
    (c,) = collapse(ctx).values()
    assert c["basis"] == ["same_upstream_id"]                                       # a payload-declared id merged them
    r = build_rationale(traced(ctx)[1], traced(ctx)[0])
    assert any("upstream id" in lim and "not verified" in lim for lim in r["limitations"])


def test_transitive_merge_is_reported_as_transitive_not_invented():
    ctx = make([
        ev("e0", digest=GOOD),
        ev("e1", off=100.0, digest=GOOD, etype="network_connection", eid="3"),            # same digest as e0
        ev("e2", off=100.0, digest=GOOD_B, etype="network_connection", eid="3"),          # same content as e1, nothing direct with e0
    ], [ent("process", PROCESS_VALUE, "e0")])
    found = collapse(ctx)
    c = found[(uid(ctx, "e2"), uid(ctx, "e0"))]
    assert c["basis"] == ["transitive_chain"] and c["direct"] is False


# ── 3. Pairs, anchor and exclusions are exactly what the gate used ─────────────────────────────────────
def test_corroborating_pair_matches_the_gate_and_shows_only_type_and_strength():
    ctx = scenarios()["sufficient_pair"]
    a, t = traced(ctx)
    assert a.verdict == SufficiencyVerdict.SUFFICIENT and a.corroborating_events == 1
    corr = [p for p in t.pairs if p["kind"] == "corroborating"]
    assert len(corr) == a.corroborating_events                                       # consistency invariant
    (p,) = corr
    assert {p["unit_a"], p["unit_b"]} == {uid(ctx, "e0"), uid(ctx, "e1")}
    assert {"type": "domain", "strength": "specific"} in p["shared_entities"]
    assert p["tests"]["different_observation_class"] is True and p["tests"]["specific_or_strong_link"] is True
    assert t.anchor_status == "used" and t.anchor_event_id == uid(ctx, "e0")


def test_same_observation_class_is_reported_as_repeated_not_corroborating():
    a, t = traced(scenarios()["same_observation_class"])
    assert a.verdict == SufficiencyVerdict.LIMITED and a.corroborating_events == 0
    assert [p["kind"] for p in t.pairs] == ["repeated"]
    assert {"unit": t.units[1]["unit"], "reason": "repeated_observation"} in t.exclusions


def test_weak_link_only_and_unattested_and_irrelevant_exclusions():
    _a, t = traced(scenarios()["weak_only"])
    assert [p["kind"] for p in t.pairs] == ["weak"] and t.exclusions[0]["reason"] == "weak_link_only"
    _a, t = traced(scenarios()["unattested"])
    assert {e["reason"] for e in t.exclusions} == {"unattested_digest_format"}
    ctx = make([ev("e0"), ev("x0", host="OTHER-HOST", off=3.0)], [ent("process", PROCESS_VALUE, "e0")], hosts=["HOST-A", "OTHER-HOST"])
    _a, t = traced(ctx)
    assert {"unit": uid(ctx, "x0"), "reason": "irrelevant_to_question"} in t.exclusions


def test_missing_anchor_dropped_anchor_and_pairwise_mode_are_represented_accurately():
    ctx = scenarios()["absent_root"]
    a, t = traced(ctx)
    assert t.anchor_status == "absent_from_evidence" and "ROOT_ABSENT" in a.reason_codes
    a, t = traced(scenarios()["future_dated_anchor"])
    assert t.anchor_status == "dropped_temporal_anomaly" and t.pairwise_without_anchor is True and "TEMPORAL_ANOMALY" in a.reason_codes
    a, t = traced(scenarios()["no_anchor_pair"])
    assert t.anchor_status == "none" and t.pairwise_without_anchor is True
    assert a.verdict == evaluate_sufficiency(scenarios()["no_anchor_pair"]).verdict   # same verdict whether or not a trace is requested
    r = build_rationale(t, a)
    assert r["anchor"]["event_id"] is None and r["anchor"]["pairwise_without_anchor"] is True


def test_contradictory_pair_findings_are_in_the_rationale():
    a, t = traced(scenarios()["contradictory"])
    r = build_rationale(t, a)
    assert "CONTRADICTORY_EVIDENCE" in {f["code"] for f in r["findings"]} and r["status"]["verdict"] == "limited"


# ── 4. The rationale is honest, restricted and bounded ──────────────────────────────────────────────────
@pytest.mark.parametrize("name", sorted(scenarios()))
def test_the_rationale_never_contains_entity_values(name):
    a, t = traced(scenarios()[name])
    text = json.dumps(build_rationale(t, a))
    assert DOMAIN_VALUE not in text and PROCESS_VALUE not in text and "HOST-A" not in text.replace("source", "")  # type/strength only
    r = json.loads(text)
    assert r["entity_values"] == "withheld" and r["schema"] == RATIONALE_SCHEMA


def test_the_rationale_does_not_overclaim_independence_or_authenticity():
    a, t = traced(scenarios()["sufficient_pair"])
    r = build_rationale(t, a)
    assert r["independence_notion"] == "record_level" and r["digest_check"] == "format_only"
    blob = json.dumps(r).lower()
    for forbidden in ("verified provenance", "cryptographically verified", "authentic sensor", "trusted sensor", "independent sensors are"):
        assert forbidden not in blob
    assert any("not proof of independent sensors" in x for x in r["limitations"])
    assert any("not authenticity" in x for x in r["limitations"])
    assert len(r["limitations"]) == len(LIMITATIONS)


def test_model_call_eligibility_is_separate_from_report_availability():
    a, t = traced(scenarios()["no_evidence"])
    r = build_rationale(t, a, llm_status="abstained")
    assert r["status"]["model_call_permitted"] is False and r["status"]["deterministic_report_available"] is True
    assert r["completeness"] == "partial" and t.stage == "no_evidence"
    a, t = traced(scenarios()["duplicates"])
    r = build_rationale(t, a, llm_status="fallback:LLMConnectionError")                  # a later model failure cannot rewrite the rationale
    assert r["status"]["model_call_permitted"] is True and r["status"]["llm_status"] == "fallback:LLMConnectionError"
    assert r["units"] and r["collapsed"]


def test_size_is_bounded_and_truncation_is_disclosed():
    a, _ = traced(scenarios()["sufficient_pair"])
    t = SufficiencyTrace(stage="complete")
    t.units = [{"unit": f"u{i}", "members": [f"m{j}" for j in range(30)], "attested_digest_format": True, "relevant": True, "role": "context"} for i in range(MAX_UNITS + 5)]
    t.collapsed = [{"into": "u0", "duplicate": f"d{i}", "basis": ["same_digest"], "direct": True} for i in range(MAX_COLLAPSED + 5)]
    t.pairs = [{"kind": "weak", "unit_a": "a", "unit_b": f"b{i}", "shared_entities": [], "tests": {}} for i in range(MAX_PAIRS + 5)]
    r = build_rationale(t, a)
    assert len(r["units"]) == MAX_UNITS and len(r["collapsed"]) == MAX_COLLAPSED and len(r["corroboration"]) == MAX_PAIRS
    assert all(len(u["members"]) <= 10 and u["members_truncated"] for u in r["units"])
    assert r["truncated"]["units"] and r["truncated"]["collapsed"] and r["truncated"]["corroboration"]


def test_ordering_is_deterministic():
    ctx = scenarios()["sufficient_pair"]
    first = json.dumps(build_rationale(*reversed(traced(ctx))), sort_keys=True)
    second = json.dumps(build_rationale(*reversed(traced(ctx))), sort_keys=True)
    assert first == second
