"""
Stage 3C-R (ADR-008 suff-v3): independence of evidence.

Distinct events are not independent evidence: host-only / user-only links, events from the same
raw record and near-duplicates must not create corroboration or satisfy the multi-evidence rule.
Offline, deterministic; no database, no model.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from app.modules.ai.guardrails.sufficiency_gate import (
    apply_sufficiency_disclosure,
    evaluate_sufficiency,
)
from app.modules.ai.guardrails.validator import InvestigationOutputValidator
from app.modules.evaluation.sufficiency_evaluator import _scripted_output
from app.modules.evidence.independence import (
    LINK_SPECIFIC,
    LINK_WEAK,
    EvidenceItem,
    cluster_evidence,
    entity_link_strength,
    independent_groups,
)
from app.schemas.investigation import (
    ClaimCategory,
    FactualClaimItem,
    GroundingStatus,
    StructuredInvestigationOutput,
)
from app.schemas.sufficiency import SufficiencyVerdict
from tests.unit.test_evidence_sufficiency_gate import GOOD, GOOD_B, ent, ev, make

T0 = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)


def item(key, digest=None, off=0.0, identity=("H", "1", "t", "a", "ok"), entities=(), content=""):
    return EvidenceItem(key=key, timestamp=T0 + timedelta(seconds=off), digest=digest,
                        identity=identity, entities=frozenset(entities), content=content)


# ── primitives ────────────────────────────────────────────────────────────────
def test_link_strength_tiers():
    assert entity_link_strength("file_hash", "ab" * 32) == LINK_SPECIFIC
    assert entity_link_strength("domain", "evil.example") == LINK_SPECIFIC
    assert entity_link_strength("ip", "45.9.148.10") == LINK_SPECIFIC       # public address
    for weak in (("ip", "10.1.4.7"), ("ip", "192.168.0.5"), ("host", "WS-01"), ("user", "jdoe"), ("process", "powershell.exe")):
        assert entity_link_strength(*weak) == LINK_WEAK


def test_clusters_merge_same_digest_but_never_on_unverifiable_digests():
    items = [item("a", digest=GOOD), item("b", digest=GOOD, identity=("H", "2", "t", "a", "ok"), off=60),
             item("c", digest=None, identity=("H", "3", "t", "a", "ok"), off=120),
             item("d", digest=None, identity=("H", "4", "t", "a", "ok"), off=180)]
    cl = cluster_evidence(items)
    assert cl["a"] == cl["b"]            # same attested raw record
    assert len({cl["c"], cl["d"], cl["a"]}) == 3   # unverifiable digests never merge


def test_near_duplicates_merge_within_the_window_only():
    ents = {("ip", "45.9.148.10")}
    items = [item("a", entities=ents, digest=GOOD), item("b", off=0.5, entities=ents, digest=GOOD_B),
             item("c", off=30.0, entities=ents, digest="c" * 64)]
    cl = cluster_evidence(items)
    assert cl["a"] == cl["b"] and cl["c"] != cl["a"]
    assert independent_groups(["a", "b"], cl) == 1 and independent_groups(["a", "c"], cl) == 2


def test_different_outcomes_or_entities_are_not_near_duplicates():
    a = item("a", digest=GOOD, entities={("user", "u")})
    b = item("b", off=0.5, digest=GOOD_B, entities={("user", "v")})
    c = item("c", off=0.5, digest="c" * 64, entities={("user", "u")}, identity=("H", "1", "t", "a", "fail"))
    cl = cluster_evidence([a, b, c])
    assert len(set(cl.values())) == 3


# ── gate: the four misleading relationships are no longer corroboration ───────
def test_host_only_link_is_not_corroboration():
    a = evaluate_sufficiency(make([ev("e0"), ev("e1", off=5.0)], [ent("process", "p.exe", "e0"), ent("host", "HOST-A", "e0", "e1")]))
    assert a.verdict == SufficiencyVerdict.LIMITED
    assert {"UNCORROBORATED_QUESTION", "WEAK_LINK_ONLY"} <= set(a.reason_codes)


def test_user_only_link_is_not_corroboration():
    a = evaluate_sufficiency(make([ev("e0"), ev("e1", off=5.0)], [ent("process", "p.exe", "e0"), ent("user", "CORP\\a", "e0", "e1")]))
    assert a.verdict == SufficiencyVerdict.LIMITED and "WEAK_LINK_ONLY" in a.reason_codes


def test_internal_ip_and_process_name_links_are_weak():
    a = evaluate_sufficiency(make([ev("e0"), ev("e1", off=5.0)],
                                  [ent("process", "powershell.exe", "e0", "e1"), ent("ip", "10.1.4.7", "e0", "e1")]))
    assert a.verdict == SufficiencyVerdict.LIMITED and a.corroborating_events == 0


def test_same_raw_record_counts_once_even_with_a_specific_link():
    events = [ev("e0", digest=GOOD), ev("e1", off=5.0, etype="network_connection", digest=GOOD)]
    a = evaluate_sufficiency(make(events, [ent("process", "p.exe", "e0"), ent("domain", "c2.example", "e0", "e1")]))
    assert a.effective_events == 1 and a.verdict == SufficiencyVerdict.LIMITED
    assert "DUPLICATE_EVIDENCE_COLLAPSED" in a.reason_codes and "UNCORROBORATED_QUESTION" in a.reason_codes


def test_near_duplicate_is_collapsed_and_does_not_corroborate():
    events = [ev("e0"), ev("e0b", off=0.001, digest=GOOD_B)]
    a = evaluate_sufficiency(make(events, [ent("process", "p.exe", "e0", "e0b"), ent("domain", "c2.example", "e0", "e0b")]))
    assert a.effective_events == 1 and a.corroborating_events == 0
    assert a.verdict == SufficiencyVerdict.LIMITED


def test_events_far_apart_with_a_specific_link_are_independent_corroboration():
    events = [ev("e0"), ev("e1", off=120.0, etype="network_connection")]
    a = evaluate_sufficiency(make(events, [ent("process", "p.exe", "e0"), ent("domain", "c2.example", "e0", "e1")]))
    assert a.verdict == SufficiencyVerdict.SUFFICIENT and a.corroborating_events == 1


def test_unverifiable_events_cannot_corroborate():
    zero = "0" * 64
    events = [ev("e0"), ev("e1", off=120.0, etype="network_connection", digest=zero)]
    a = evaluate_sufficiency(make(events, [ent("process", "p.exe", "e0"), ent("domain", "c2.example", "e0", "e1")]))
    assert a.verdict == SufficiencyVerdict.LIMITED and "PROVENANCE_PARTIAL" in a.reason_codes


# ── validator: independent support groups, not distinct UUIDs ─────────────────
def _inference_output(ctx, ids):
    claim = FactualClaimItem(
        claim_id=uuid.uuid4(), claim_text="The activity may indicate a coordinated sequence of actions.",
        category=ClaimCategory.INFERENCE, supporting_evidence_ids=ids, references_exist=True,
        grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED, confidence=0.6,
    )
    return StructuredInvestigationOutput(
        investigation_id=ctx.investigation_id, model_identifier="m", investigation_summary="Scripted output for the demotion rule.",
        claims=[claim], recommended_analyst_actions=["Review."], overall_grounding_score=0.0)


def test_claim_citing_two_near_duplicates_is_still_demoted_under_limited():
    ctx = make([ev("e0"), ev("e0b", off=0.001, digest=GOOD_B)], [ent("process", "p.exe", "e0", "e0b")])
    a = evaluate_sufficiency(ctx)
    assert a.verdict == SufficiencyVerdict.LIMITED
    res = InvestigationOutputValidator().validate(_inference_output(ctx, [e.event_uuid for e in ctx.events]), ctx, a)
    assert any(v.rule_id == "SEC-GR-LIMITED-EVIDENCE-INFERENCE" for v in res.violations)
    assert res.output.claims[0].confidence <= 0.30


def test_claim_citing_two_independent_clusters_is_not_demoted_by_the_limited_rule():
    ctx = make([ev("e0"), ev("e1", off=120.0)], [ent("process", "p.exe", "e0"), ent("host", "HOST-A", "e0", "e1")])
    a = evaluate_sufficiency(ctx)
    assert a.verdict == SufficiencyVerdict.LIMITED            # weak link only
    res = InvestigationOutputValidator().validate(_inference_output(ctx, [e.event_uuid for e in ctx.events]), ctx, a)
    assert not any(v.rule_id == "SEC-GR-LIMITED-EVIDENCE-INFERENCE" for v in res.violations)


# ── disclosure in the final output ────────────────────────────────────────────
def test_limited_disclosure_reaches_the_validated_output_and_is_idempotent():
    ctx = make([ev("e0")], [ent("process", "p.exe", "e0")])
    a = evaluate_sufficiency(ctx)
    result = InvestigationOutputValidator().validate(_scripted_output(ctx), ctx, a)
    assert not any("EVIDENCE_SUFFICIENCY" in f for f in result.output.uncertainty_and_data_gaps)
    disclosed = apply_sufficiency_disclosure(result, a)
    flags = [f for f in disclosed.output.uncertainty_and_data_gaps if f.startswith("EVIDENCE_SUFFICIENCY[suff-v5]=LIMITED")]
    assert len(flags) == 1 and "UNCORROBORATED_QUESTION" in flags[0]
    assert apply_sufficiency_disclosure(disclosed, a) is disclosed          # idempotent
    assert disclosed.decision == result.decision and disclosed.violations == result.violations
    assert apply_sufficiency_disclosure(result, None) is result


def test_abstention_and_clean_sufficient_results_are_left_untouched():
    ctx_ok = make([ev("e0"), ev("e1", off=120.0, etype="network_connection")], [ent("process", "p.exe", "e0"), ent("domain", "c2.example", "e0", "e1")])
    a_ok = evaluate_sufficiency(ctx_ok)
    res = InvestigationOutputValidator().validate(_scripted_output(ctx_ok), ctx_ok, a_ok)
    assert apply_sufficiency_disclosure(res, a_ok) is res
    a_none = evaluate_sufficiency(make([], root=None))
    assert apply_sufficiency_disclosure(res, a_none) is res
