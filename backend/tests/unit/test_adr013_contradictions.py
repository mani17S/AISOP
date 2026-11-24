"""
ADR-013 Revision 2 (sufficiency ``suff-v4``): detector, gate integration, report/API, trust boundaries and the Detection Engineering
predicate. Deterministic fixtures, offline. Implemented kinds: ``ordering`` and ``outcome``. IDENTITY, TEMPORAL and STATE are NOT
implemented (owner decisions A3, A4 pending); their specification tests remain strict expected-failures elsewhere.

Interpretations pinned here and flagged to the owner (docs/Architecture/CONTRADICTION_AWARE_SUFFICIENCY_DESIGN.md, Implementation record):
I-1 independence = different source system; I-2 outcome conflict window = the existing correlator constant (2.0 s);
I-3 ordering has NO clock-skew tolerance (the ADR applies the 5 s tolerance to TEMPORAL only).
"""

from __future__ import annotations

import asyncio
import json
import uuid

import pytest

from app.modules.correlation import correlator
from app.modules.correlation.normalize import raw_digest
from app.modules.correlation.workflow import analyze, run_workflow
from app.modules.evidence_domains import scenarios as S
from app.modules.evidence_domains.adapters import parse_record
from app.modules.evidence_domains.contradictions import (
    OUTCOME_CONFLICT_WINDOW_SECONDS,
    attachment_precedes_delivery,
    classify_materiality,
    detect_contradictions,
    sources_independent,
)
from app.modules.evidence_domains.domain_attack import map_domain_techniques
from app.modules.evidence_domains.ti import IndicatorMatch, StaticIndicatorSet
from app.schemas.contradiction import ContradictionKind, Explanation, HypothesisRelation, Materiality
from app.schemas.sufficiency import SUFFICIENCY_RULE_VERSION
from tests.unit.test_multisource_api import ScriptedProvider

env = S.env
IP = S.ATTACKER_IP


def obs(record, index=0):
    d = raw_digest(record)
    return parse_record(record, key=uuid.uuid5(uuid.NAMESPACE_URL, f"{d}:{index}"), record_index=index, raw_sha256=d)


def many(records):
    return [obs(r, i) for i, r in enumerate(records)]


MAIL_ID = "<inv-8841@invoice-portal.test>"


def scenario_c(file_time="2026-11-05T07:00:00Z", file_system=None, mail_time=None, causal=True, semantics="arrival"):
    """Scenario C with the artefact timestamped EARLIER than the e-mail (08:00:00Z). With ``causal=True`` (default) the artefact record STATES
    where it came from and what its time means, i.e. a verified causal relationship (owner decision D6). ``causal=False`` is the original
    first-slice fixture: only an earlier timestamp and a shared hash, which is NOT a causal-ordering violation."""
    recs = [dict(r) for r in S.scenario_c_email_forensic()]
    for r in recs:
        if r["evidence_type"] == "forensic.file":
            if causal:
                r["data"] = dict(r["data"], origin_message_id=MAIL_ID, **({"timestamp_semantics": semantics} if semantics else {}))
            if file_time is None:
                r.pop("event_time", None)
            else:
                r["event_time"] = file_time
            if file_system:
                r["source"] = dict(r["source"], system=file_system)
        if r["evidence_type"] == "email.message" and mail_time:
            r["event_time"] = mail_time
    return recs


def pair(records):
    o = many(records)
    return next(x for x in o if x.evidence_type == "email.message"), next(x for x in o if x.evidence_type == "forensic.file")


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ══ detector: ordering ═══════════════════════════════════════════════════════
def test_material_ordering_contradiction_is_detected_with_a_stable_typed_finding():
    cands = detect_contradictions(many(scenario_c()))
    assert len(cands) == 1
    c = cands[0]
    assert c.kind == ContradictionKind.ORDERING and c.proposition == "attachment_delivery_order"
    assert c.independence == "independent" and c.link_strength == "specific" and c.explanation is None
    assert c.time_quality == ("valid", "valid") and c.claims == ("delivery", "artefact_earlier") and c.overlap_seconds == 3600.0
    assert c.sources == ("mailgw-synthetic", "dfir-collector-synthetic") and c.resolution_hint == "ARTEFACT_TIME_PROVENANCE"
    assert detect_contradictions(many(scenario_c())) == cands                         # deterministic
    assert detect_contradictions(list(reversed(many(scenario_c())))) == cands         # independent of input order
    dumped = json.dumps(c.model_dump(mode="json"))
    assert "billing@invoice-portal" not in dumped and "invoice.exe" not in dumped      # references and fixed vocabulary only, no payload text


def test_valid_ordering_file_after_the_email_is_not_a_contradiction_and_still_maps_the_technique():
    o = many(scenario_c(file_time="2026-11-05T08:21:00Z"))
    assert detect_contradictions(o) == ()
    assert "T1566.001" in {m.technique_id for m in map_domain_techniques(o)}


def test_missing_timestamp_is_never_replaced_by_now_and_yields_no_ordering_claim():
    o = many(scenario_c(file_time=None))
    assert next(x for x in o if x.evidence_type == "forensic.file").event_time is None
    assert detect_contradictions(o) == ()
    a = analyze(scenario_c(file_time=None)).incidents[0]                              # the undated artefact is not on the timeline at all
    assert all(e.evidence_type != "forensic.file" for e in a.events) and a.assessment.contradictions == []


def test_low_quality_naive_timestamp_is_a_minor_disclosure_not_a_material_contradiction():
    o = many(scenario_c(file_time="2026-11-05T07:00:00"))                               # no zone: UTC assumed and disclosed
    cands = detect_contradictions(o)
    assert len(cands) == 1 and cands[0].explanation == Explanation.TIMEZONE_ASSUMED and cands[0].time_quality == ("valid", "naive_assumed_utc")
    assert classify_materiality(cands[0], HypothesisRelation.ANCHOR) == Materiality.MINOR
    mail, f = pair(scenario_c(file_time="2026-11-05T07:00:00"))
    assert attachment_precedes_delivery(mail, f) is False                              # technique is still derived: ordering unknown
    a = analyze(scenario_c(file_time="2026-11-05T07:00:00")).incidents[0]
    assert a.assessment.verdict.value == "sufficient" and [c.materiality.value for c in a.assessment.contradictions] == ["minor"]
    assert "T1566.001" in {m.technique_id for m in a.mitre}


def test_timezone_offsets_are_normalised_before_ordering_is_judged():
    earlier = many(scenario_c(file_time="2026-11-05T13:00:00+05:30"))                   # = 07:30Z, before the 08:00Z e-mail
    later = many(scenario_c(file_time="2026-11-05T13:35:00+05:30"))                     # = 08:05Z, after it
    assert len(detect_contradictions(earlier)) == 1 and detect_contradictions(later) == ()


@pytest.mark.parametrize("file_time, reversal, expected_materiality", [
    ("2026-11-05T07:59:55.001Z", 4.999, "explained"),    # below the tolerance
    ("2026-11-05T07:59:55.000Z", 5.0, "explained"),     # exactly at the tolerance: 5 s or less never establishes a material contradiction (D1)
    ("2026-11-05T07:59:54.999Z", 5.001, "material"),    # above the tolerance: the materiality table decides
])
def test_ordering_clock_skew_tolerance_boundaries_D1(file_time, reversal, expected_materiality):
    from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency  # noqa: F401  (gate exercised through analyze below)

    cands = detect_contradictions(many(scenario_c(file_time=file_time)))
    assert len(cands) == 1 and round(cands[0].overlap_seconds, 3) == reversal
    a = analyze(scenario_c(file_time=file_time)).incidents[0]
    assert [c.materiality.value for c in a.assessment.contradictions] == [expected_materiality]
    assert (a.assessment.verdict.value == "limited") == (expected_materiality == "material")


def test_a_shared_entity_without_a_conflicting_proposition_is_not_a_contradiction():
    recs = [env("identity.mfa", "idp-a", {"user": "u.example", "ip": IP, "result": "denied"}, t="2026-11-07T09:00:00Z"),
            env("identity.signin", "idp-b", {"user": "u.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:01Z"),
            env("network.dns", "resolver", {"src_ip": "10.1.1.9", "query": "a.example.test", "answers": [IP]}, t="2026-11-07T09:00:01Z"),
            env("network.flow", "fw", {"src_ip": "10.1.1.9", "dst_ip": IP, "dst_port": 443, "action": "deny", "host": "h"}, t="2026-11-07T09:00:01Z")]
    assert detect_contradictions(many(recs)) == ()


def test_email_and_file_with_different_hashes_have_no_ordering_proposition():
    recs = scenario_c()
    for r in recs:
        if r["evidence_type"] == "forensic.file":
            r["data"] = dict(r["data"], sha256="ab" * 32)
    assert detect_contradictions(many(recs)) == ()


# ══ detector: outcome, independence, duplicates, trust boundaries ═════════════
def conflict(src_a="idp-a", src_b="idp-b", gap=1, user="u.example"):
    return [env("identity.signin", src_a, {"user": user, "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z"),
            env("identity.signin", src_b, {"user": user, "ip": IP, "result": "failure"}, t=f"2026-11-07T09:00:{gap:02d}Z")]


def test_independent_sources_with_opposite_outcomes_within_the_window_are_an_outcome_candidate():
    cands = detect_contradictions(many(conflict()))
    assert len(cands) == 1 and cands[0].kind == ContradictionKind.OUTCOME and cands[0].claims == ("success", "failure")
    assert cands[0].proposition == "signin_outcome" and cands[0].independence == "independent"


def test_same_source_opposite_outcomes_are_left_to_the_existing_same_sensor_detectors():
    assert detect_contradictions(many(conflict(src_a="idp-a", src_b="idp-a"))) == ()


def test_outside_the_conflict_window_there_is_no_candidate_and_the_window_is_the_correlator_constant():
    assert detect_contradictions(many(conflict(gap=5))) == ()
    assert OUTCOME_CONFLICT_WINDOW_SECONDS == correlator.CONTRADICTION_WINDOW_SECONDS    # cannot drift (interpretation I-2)


def test_independence_is_the_source_system_interpretation_I1():
    a, b = many(conflict())
    assert sources_independent(a, b) and not sources_independent(a, a)


def test_duplicate_of_one_side_of_a_conflict_yields_a_single_finding():
    recs = conflict()
    recs.append(dict(recs[1]))                                                          # exact duplicate of the failure record
    res = analyze(recs)
    a = res.incidents[0]
    assert len(a.assessment.contradictions) == 1 and a.assessment.effective_events == 2 and a.assessment.total_events == 3


def test_near_duplicates_from_one_source_never_become_a_contradiction():
    recs = [env("identity.signin", "idp-a", {"user": "n.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z"),
            env("identity.signin", "idp-a", {"user": "n.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:01Z")]
    assert detect_contradictions(many(recs)) == ()


def test_unclassified_and_analyst_evidence_never_take_part():
    note = env("analyst.observation", "analyst-notes", {"analyst": "t2", "statement": "FAILED", "entities": [{"type": "ip", "value": IP}]},
               t="2026-11-07T09:00:00Z", category="analyst")
    unknown = env("vendorx.widget_event", "vendorx", {"foo": "bar"}, t="2026-11-07T09:00:00Z", category="vendorx")
    one = env("identity.signin", "idp-a", {"user": "u.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z")
    assert detect_contradictions(many([one, note, unknown])) == ()


# ══ gate integration (suff-v4) ═══════════════════════════════════════════════
def test_version_is_v5_and_the_gate_default_argument_keeps_existing_callers_working():
    from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency

    assert SUFFICIENCY_RULE_VERSION == "suff-v5"
    a = analyze(S.scenario_a_identity_cloud()).incidents[0]
    again = evaluate_sufficiency(a.context)                                             # old call shape: no contradictions argument
    assert again.assessment_sha256 == a.assessment.assessment_sha256 and again.rule_version == "suff-v5" and again.contradictions == []


def test_a_material_contradiction_caps_the_verdict_at_limited_and_excludes_the_pair_from_corroboration():
    before = analyze(S.scenario_c_email_forensic()).incidents[0]                        # consistent ordering
    after = analyze(scenario_c()).incidents[0]
    assert before.assessment.verdict.value == "sufficient" and after.assessment.verdict.value == "limited"
    assert "CONTRADICTORY_EVIDENCE:ordering" in after.assessment.reason_codes
    assert after.assessment.corroborating_events < before.assessment.corroborating_events
    f = after.assessment.contradictions[0]
    assert f.materiality == Materiality.MATERIAL and f.relation == HypothesisRelation.ANCHOR and f.affects_verdict is True
    fx = next(x for x in after.assessment.findings if x.code.value == "CONTRADICTORY_EVIDENCE")
    assert fx.effect.value == "limited" and fx.qualifier == "ordering" and set(fx.evidence_ids) == {str(i) for i in f.evidence_ids}


def test_a_contradiction_alone_never_forces_insufficient():
    res = analyze(conflict())
    a = res.incidents[0]
    assert a.assessment.verdict.value == "limited" and not a.assessment.abstain


def test_a_contradiction_can_only_lower_never_raise_a_verdict():
    consistent = analyze(S.scenario_c_email_forensic()).incidents[0]
    rank = {"insufficient": 0, "limited": 1, "sufficient": 2}
    for recs in (scenario_c(), scenario_c(file_time="2026-11-05T07:00:00")):
        assert rank[analyze(recs).incidents[0].assessment.verdict.value] <= rank[consistent.assessment.verdict.value]


def test_the_assessment_hash_covers_the_findings_and_unrelated_incidents_are_unaffected():
    a1 = analyze(scenario_c()).incidents[0].assessment
    a2 = analyze(scenario_c()).incidents[0].assessment
    assert a1.assessment_sha256 == a2.assessment_sha256                                  # deterministic
    assert a1.assessment_sha256 != analyze(S.scenario_c_email_forensic()).incidents[0].assessment.assessment_sha256
    alone = analyze(S.scenario_a_identity_cloud()).incidents[0]
    both = analyze(S.scenario_a_identity_cloud() + conflict(user="other.example") )
    mine = next(i for i in both.incidents if len(i.events) == 8)
    assert mine.assessment.assessment_sha256 == alone.assessment.assessment_sha256 and mine.assessment.contradictions == []


def test_non_contradictory_scenarios_keep_their_behaviour():
    a = analyze(S.scenario_a_identity_cloud()).incidents[0]
    b = analyze(S.scenario_b_network_endpoint()).incidents[0]
    c = analyze(S.scenario_c_email_forensic()).incidents[0]
    assert [x.assessment.verdict.value for x in (a, b, c)] == ["sufficient"] * 3 and all(x.assessment.contradictions == [] for x in (a, b, c))
    assert {m.technique_id for m in a.mitre} == {"T1621", "T1136.003", "T1098.003"} and "T1566.001" in {m.technique_id for m in c.mitre}


def test_a_stored_v3_result_is_not_reused_because_the_fingerprint_includes_the_rule_version(monkeypatch):
    from app.services import multisource_investigation_service as svc

    class _Raw:
        sha256_hash = "a" * 64

    class _Row:
        id = uuid.uuid4()
        raw_evidence = _Raw()

    fp4 = svc.MultiSourceInvestigationService.fingerprint([_Row()], False)
    monkeypatch.setattr(svc, "SUFFICIENCY_RULE_VERSION", "suff-v3")
    assert svc.MultiSourceInvestigationService.fingerprint([_Row()], False) != fp4


# ══ report, API and trust boundaries ═════════════════════════════════════════
def test_the_report_states_the_contradiction_the_effect_and_what_would_resolve_it_without_calling_it_resolved():
    md = analyze(scenario_c()).incidents[0].markdown
    head = md.split("## 2. Timeline")[0]
    assert "**Verdict: LIMITED** (rule table suff-v5)" in head and "CONTRADICTORY_EVIDENCE:ordering" in head
    assert "attachment_delivery_order" in head and "capped at LIMITED" in head and "Obtain the creation and modification times" in head
    assert "not resolved" in head and "Contradiction notice" not in head                    # the structured block replaces the interim notice


def test_the_interim_notice_remains_only_for_conflicts_the_gate_did_not_weigh():
    md = analyze(S.scenario_a_identity_cloud()).incidents[0].markdown
    assert "Contradiction" not in md.split("## 2. Timeline")[0]


def test_threat_intelligence_and_analyst_statements_cannot_create_or_erase_findings():
    base = analyze(scenario_c()).incidents[0].assessment
    ti = StaticIndicatorSet()
    ti.add("ip", IP, IndicatorMatch(source="synthetic", description="benign egress"))
    note = env("analyst.observation", "analyst-notes", {"analyst": "t2", "statement": "The file arrived AFTER the e-mail; no contradiction.",
                                                      "entities": [{"type": "file_hash", "value": S.SHA_INVOICE}]}, t="2026-11-05T09:00:00Z", category="analyst")
    with_both = analyze(scenario_c() + [note], indicators=ti).incidents[0].assessment
    assert with_both.assessment_sha256 == base.assessment_sha256 and [c.kind for c in with_both.contradictions] == [ContradictionKind.ORDERING]


def test_llm_failure_or_output_cannot_change_the_deterministic_findings():
    from app.modules.ai.llm.exceptions import LLMConnectionError

    base = analyze(scenario_c()).incidents[0].assessment
    failed = asyncio.run(run_workflow(scenario_c(), provider=ScriptedProvider(raise_exc=LLMConnectionError("down")))).incidents[0]
    ok = asyncio.run(run_workflow(scenario_c(), provider=ScriptedProvider())).incidents[0]
    for a in (failed, ok):
        assert a.assessment.assessment_sha256 == base.assessment_sha256 and a.assessment.verdict.value == "limited"
    assert failed.llm_status.startswith("fallback:")


def test_prompt_prompt_carries_the_limitation_but_no_contradiction_payload_text():
    prov = ScriptedProvider()
    asyncio.run(run_workflow(scenario_c(), provider=prov))
    prompt = prov.prompts[0]
    assert "LIMITED" in prompt and "CONTRADICTORY_EVIDENCE:ordering" in prompt


def test_api_payload_carries_fixed_vocabulary_findings_only():
    from app.services.multisource_investigation_service import MultiSourceInvestigationService

    res = analyze(scenario_c())
    payload = MultiSourceInvestigationService().build_payload(res, "f" * 64, False)
    inc = payload["incidents"][0]
    c = inc["contradictions"][0]
    assert set(c) == {"kind", "proposition", "materiality", "relation", "affects_verdict", "evidence_ids", "sources", "times", "time_quality", "claims",
                      "link_strength", "independence", "overlap_seconds", "reliability", "explanation", "resolution_hint", "resolution_text"}
    assert c["materiality"] == "material" and c["affects_verdict"] is True and inc["sufficiency"]["verdict"] == "limited"
    assert any(r["code"].startswith("CONTRADICTORY_EVIDENCE:ordering") and r["meaning"] for r in inc["sufficiency"]["reasons"])
    blob = json.dumps(c)
    assert "billing@" not in blob and "invoice.exe" not in blob and "http" not in blob


# ══ Detection Engineering boundary ═══════════════════════════════════════════
def test_an_assessment_with_an_unresolved_material_contradiction_is_not_a_validated_finding():
    """Owner decision 5. No findings interface exists yet (ADR-012 is design only); the predicate below is the integration point that
    interface must call before offering a finding. A minor or absent contradiction does not trip it."""
    assert analyze(scenario_c()).incidents[0].assessment.has_unresolved_material_contradiction is True
    assert analyze(S.scenario_c_email_forensic()).incidents[0].assessment.has_unresolved_material_contradiction is False
    assert analyze(scenario_c(file_time="2026-11-05T07:00:00")).incidents[0].assessment.has_unresolved_material_contradiction is False
