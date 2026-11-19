"""
Contradiction-aware sufficiency: the 15-scenario test matrix (ADR-013, PROPOSED). SPECIFICATION ONLY: no production behaviour is changed by
this file. Traceability table: docs/Architecture/CONTRADICTION_TEST_MATRIX.md.

Convention (same as ``test_contradiction_model_spec.py``):
* a plain test pins behaviour that was MEASURED as already correct on 2026-11-12 and must not regress;
* ``xfail(strict=True)`` states the desired behaviour the current engine lacks. When ADR-013 is approved and implemented the marker must be
  removed (strict mode fails the run if a test unexpectedly passes), so the specification cannot be silently forgotten.
Deterministic fixtures only. No evaluation ground-truth label is touched.
"""

from __future__ import annotations

import json

import pytest

from app.modules.correlation.workflow import analyze, run_workflow
from app.modules.evidence_domains import scenarios as S
from app.modules.evidence_domains.ti import IndicatorMatch, StaticIndicatorSet
from tests.unit.test_multisource_api import ScriptedProvider

IP = S.ATTACKER_IP
env = S.env


@pytest.fixture
def anyio_backend():
    return "asyncio"


def one(records):
    res = analyze(records)
    assert len(res.incidents) == 1, "scenario must form exactly one incident"
    return res, res.incidents[0]


def techniques(a):
    return {m.technique_id for m in a.mitre}


def causal_c(file_time="2026-11-05T07:00:00Z", causal=True):
    """Scenario C with the artefact timestamped one hour BEFORE the e-mail. ``causal=True`` adds the source-stated origin and time semantics."""
    recs = [dict(r) for r in S.scenario_c_email_forensic()]
    for r in recs:
        if r["evidence_type"] == "forensic.file":
            r["event_time"] = file_time
            if causal:
                r["data"] = dict(r["data"], origin_message_id="<inv-8841@invoice-portal.test>", timestamp_semantics="arrival")
    return recs


def conflict_pair():
    return [env("network.firewall", "fw-a", {"src_ip": "10.1.1.5", "dst_ip": S.C2_IP, "dst_port": 443, "action": "deny", "host": "h5"}, t="2026-11-07T09:00:00Z"),
            env("network.flow", "flow-b", {"src_ip": "10.1.1.5", "dst_ip": S.C2_IP, "dst_port": 443, "action": "allow", "host": "h5"}, t="2026-11-07T09:00:01Z")]


# S1 ── independent sources corroborate the same event ──────────────────────────
def test_s1_independent_sources_corroborate_the_same_event():
    res, a = one([env("identity.signin", "idp-a", {"user": "u1.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z"),
                  env("identity.signin", "idp-b", {"user": "u1.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:01Z")])
    assert a.assessment.corroborating_events == 1 and a.assessment.verdict.value == "sufficient" and res.correlation.contradictions == []


# S2 ── duplicate evidence from two ingestion paths ─────────────────────────────
def test_s2_the_same_record_arriving_twice_is_one_evidence_unit():
    rec = env("identity.signin", "idp-a", {"user": "u2.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z")
    res, a = one([rec, dict(rec)])
    assert a.assessment.effective_events == 1 and a.assessment.total_events == 2 and a.assessment.corroborating_events == 0
    assert "DUPLICATE_EVIDENCE_COLLAPSED" in a.assessment.reason_codes and res.correlation.contradictions == []


# S3 ── near-duplicate observations ─────────────────────────────────────────────
def test_s3_near_duplicates_from_one_source_collapse_and_never_corroborate():
    res, a = one([env("identity.signin", "idp-a", {"user": "n.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z"),
                  env("identity.signin", "idp-a", {"user": "n.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:01Z")])
    assert a.assessment.effective_events == 1 and a.assessment.corroborating_events == 0 and res.correlation.contradictions == []


# S4 ── conflicting identity attribution ────────────────────────────────────────
def identity_conflict_records(second_principal="P-200", second_issuer="corp-dir", session_issuer="idp-a"):
    """VALID identity fixture (owner decision D3): an IdP issues session s-1 to canonical principal P-100; a cloud audit record names that same
    ISSUER-SCOPED session (session_issuer = idp-a) but attributes the activity to a different canonical principal of the SAME directory."""
    return [env("identity.signin", "idp-a", {"user": "alice.example", "ip": IP, "session_id": "s-1", "result": "success",
                                              "canonical_id": "P-100", "canonical_id_issuer": "corp-dir"}, t="2026-11-07T09:00:00Z"),
            env("cloud.api_call", "cloud-a", {"actor": "bob.example", "action": "ListBuckets", "resource": "bucket/x", "source_ip": IP,
                                               "session_id": "s-1", "session_issuer": session_issuer,
                                               "canonical_id": second_principal, "canonical_id_issuer": second_issuer}, t="2026-11-07T09:00:30Z")]


def test_s4_one_session_attributed_to_two_users_is_a_material_identity_contradiction():
    # Fixture corrected 2026-11-12 (ADR-013 D3): the first draft used a bare local session id string in two systems with different user
    # names, which asserts an identity linkage nothing states. Assertions are unchanged in strength (and extended with the verdict).
    res, a = one(identity_conflict_records())
    assert any("IDENTITY" in c.reason for c in res.correlation.contradictions)
    assert "CONTRADICTORY_EVIDENCE:identity" in a.assessment.reason_codes and a.assessment.verdict.value != "sufficient"

# S5 ── conflicting network observations ─────────────────────────────────────────
def test_s5_conflicting_network_observations_are_visible_in_the_correlator_graph_and_report():
    # Updated 2026-11-12 (ADR-013 implemented): the interim "Contradiction notice" is replaced by the structured contradiction block.
    res, a = one(conflict_pair())
    assert res.correlation.contradictions and a.graph.contradictions
    assert "**Contradictions (ADR-013).**" in a.markdown and "Contradiction notice" not in a.markdown


def test_s5_conflicting_network_observations_cap_the_verdict_and_do_not_corroborate():
    _res, a = one(conflict_pair())
    assert a.assessment.verdict.value == "limited" and "CONTRADICTORY_EVIDENCE:outcome" in a.assessment.reason_codes
    assert a.assessment.corroborating_events == 0


# S6 ── timestamps differing by clock skew ──────────────────────────────────────
def test_s6_small_clock_skew_between_independent_sources_is_not_a_contradiction():
    res, a = one([env("identity.signin", "idp-a", {"user": "k.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z", eid="n1"),
                  env("identity.signin", "idp-b", {"user": "k.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:04Z", eid="n1")])
    assert res.correlation.contradictions == [] and a.assessment.corroborating_events == 1


def test_s6_timestamps_hours_apart_for_one_native_event_are_a_temporal_contradiction():
    # Fixture corrected 2026-11-12 (ADR-013 D4): the first draft relied on one source-native event id, which is source-scoped provenance and
    # does not prove two observations describe the same event. The valid fixture states an ISSUER-SCOPED correlation id shared by two
    # independent sources. Assertion unchanged in strength (and extended with the verdict).
    corr = {"issuer": "gateway-1", "id": "req-77"}
    res, a = one([env("cloud.api_call", "ct-a", {"actor": "u4.example", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T09:00:00Z", correlation=corr),
                  env("cloud.api_call", "ct-b", {"actor": "u4.example", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T13:00:00Z", correlation=corr)])
    assert any("TEMPORAL" in c.reason or "TIMESTAMP" in c.reason for c in res.correlation.contradictions)
    assert "CONTRADICTORY_EVIDENCE:temporal" in a.assessment.reason_codes and a.assessment.verdict.value != "sufficient"

# S7 ── contradictory event ordering (artefact predates its claimed cause) ──────
def test_s7_a_file_older_than_the_email_cannot_support_attachment_delivery():
    # Fixture corrected 2026-11-12 (ADR-013 D6): the artefact record now STATES its origin e-mail and that its time is an arrival time (a verified
    # causal-ordering requirement). The original fixture (earlier timestamp + shared hash only) is kept below as the NEGATIVE case.
    _res, a = one(causal_c())
    assert "T1566.001" not in techniques(a) and a.assessment.verdict.value == "limited"
    assert "CONTRADICTORY_EVIDENCE:ordering" in a.assessment.reason_codes


def test_s7_negative_a_pre_existing_file_with_no_causal_relationship_is_not_a_contradiction():
    res, a = one(causal_c(causal=False))
    assert res.correlation.contradictions == [] and a.assessment.contradictions == []
    assert "T1566.001" in techniques(a) and a.assessment.verdict.value == "sufficient"

# S8 ── benign explanation for an apparent contradiction ────────────────────────
def test_s8_failure_then_success_by_retry_is_explainable_not_a_contradiction():
    res, _a = one([env("identity.signin", "idp-a", {"user": "u6.example", "ip": IP, "result": "failure"}, t="2026-11-07T09:00:00Z"),
                   env("identity.signin", "idp-a", {"user": "u6.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:40Z")])
    assert res.correlation.contradictions == []


# S9 ── stale evidence conflicting with fresh evidence ──────────────────────────
def test_s9_stale_failure_three_days_before_a_fresh_success_is_neither_linked_nor_a_contradiction():
    res = analyze([env("identity.signin", "idp-a", {"user": "st.example", "ip": IP, "result": "failure"}, t="2026-11-04T09:00:00Z"),
                   env("identity.signin", "idp-b", {"user": "st.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z")])
    assert len(res.incidents) == 2 and res.correlation.contradictions == []
    assert all(i.assessment.corroborating_events == 0 for i in res.incidents)


# S10 ── unclassified evidence alongside valid evidence ─────────────────────────
def test_s10_unclassified_evidence_changes_neither_verdict_nor_corroboration_but_is_disclosed():
    base = analyze(S.scenario_a_identity_cloud()).incidents[0]
    mixed = analyze(S.scenario_a_identity_cloud() + S.negative_unknown_type()).incidents[0]
    assert mixed.assessment.verdict == base.assessment.verdict and mixed.assessment.corroborating_events == base.assessment.corroborating_events
    assert any(f.startswith("UNCLASSIFIED_EVIDENCE") for f in mixed.context.uncertainty_flags)


# S11 ── analyst statement contradicting technical evidence ──────────────────────
def test_s11_an_analyst_statement_that_disagrees_with_telemetry_changes_nothing_and_stays_visible():
    note = env("analyst.observation", "analyst-notes", {"analyst": "t2", "statement": "The sign-in for alice.example FAILED; no access occurred.",
                                                      "entities": [{"type": "user", "value": "alice.example"}, {"type": "ip", "value": IP}]},
               t="2026-11-03T10:00:00Z", category="analyst")
    a = analyze(S.scenario_a_identity_cloud()).incidents[0]
    b = analyze(S.scenario_a_identity_cloud() + [note]).incidents[0]
    assert a.assessment.assessment_sha256 == b.assessment.assessment_sha256 and techniques(a) == techniques(b)
    assert b.analyst_notes and "Analyst statements (context only" in b.markdown


# S12 ── threat intelligence contradicting observed telemetry ────────────────────
def test_s12_intelligence_that_calls_an_observed_address_benign_cannot_change_the_verdict():
    ti = StaticIndicatorSet()
    ti.add("ip", IP, IndicatorMatch(source="synthetic-feed", description="Listed as a corporate VPN egress (benign)"))
    plain = analyze(S.scenario_a_identity_cloud()).incidents[0]
    enriched = analyze(S.scenario_a_identity_cloud(), indicators=ti).incidents[0]
    assert plain.assessment.assessment_sha256 == enriched.assessment.assessment_sha256 and techniques(plain) == techniques(enriched)
    assert enriched.enrichments and enriched.enrichments[0].trust_class == "ti_context"


# S13 ── AI hypothesis contradicting raw evidence ────────────────────────────────
@pytest.mark.anyio
async def test_s13_an_ai_claim_never_alters_the_deterministic_verdict_and_is_labelled_as_ai():
    class Contradicting(ScriptedProvider):
        async def generate(self, request):
            resp = await super().generate(request)
            p = json.loads(resp.content)
            p["claims"][0]["claim_text"] = "The sign-in FAILED and no account was accessed."
            resp = resp.model_copy(update={"content": json.dumps(p)})
            return resp

    base = analyze(S.scenario_a_identity_cloud()).incidents[0]
    res = await run_workflow(S.scenario_a_identity_cloud(), provider=Contradicting())
    a = res.incidents[0]
    assert a.assessment.assessment_sha256 == base.assessment.assessment_sha256
    assert a.llm_status == "validated" and "## 6. AI-assisted investigation" in a.markdown


@pytest.mark.anyio
async def test_s13_a_claim_whose_text_contradicts_its_cited_event_is_demoted_by_the_existing_validator():
    class Contradicting(ScriptedProvider):
        async def generate(self, request):
            resp = await super().generate(request)
            p = json.loads(resp.content)
            p["claims"][0]["claim_text"] = "Every cited sign-in FAILED; no account was accessed."
            resp = resp.model_copy(update={"content": json.dumps(p)})
            return resp

    res = await run_workflow(S.scenario_a_identity_cloud(), provider=Contradicting())
    a = res.incidents[0]
    claims = a.llm_result.output.claims
    # MEASURED 2026-11-12 (after fixing a test bug that had forced a fallback): the existing validator demotes such a claim to
    # analyst_review_required (rule SEC-GR-TIER2-NO-EVIDENCE-MATCH); a claim that contradicts the cited event's OUTCOME is marked
    # "contradicted" (SEC-GR-CONTRADICTED-OUTCOME). Semantic checking is therefore partly present; its coverage is not exhaustive (UNVERIFIED).
    assert a.llm_result.decision.value == "remediated" and claims and all(c.grounding_status.value != "validated_reference" for c in claims)


# S14 ── a contradiction that does not touch the hypothesis ──────────────────────
def test_s14_an_unrelated_conflicting_pair_does_not_change_the_other_incidents_assessment():
    extra = [env("network.firewall", "fw-x", {"src_ip": "10.7.7.7", "dst_ip": "45.9.9.9", "dst_port": 80, "action": "deny", "host": "hz"}, t="2026-11-03T09:10:00Z"),
             env("network.flow", "flow-y", {"src_ip": "10.7.7.7", "dst_ip": "45.9.9.9", "dst_port": 80, "action": "allow", "host": "hz"}, t="2026-11-03T09:10:01Z")]
    alone = analyze(S.scenario_a_identity_cloud()).incidents[0]
    both = analyze(S.scenario_a_identity_cloud() + extra)
    mine = next(i for i in both.incidents if len(i.events) == 8)
    assert mine.assessment.assessment_sha256 == alone.assessment.assessment_sha256 and "Contradiction notice" not in mine.markdown


# S15 ── a contradiction that materially undermines the hypothesis ───────────────
def test_s15_a_conflict_on_the_corroborating_evidence_of_a_hypothesis_caps_the_verdict():
    # Scenario A's decisive pair is sign-in (idp) + cloud call sharing the attacker IP. A second IdP reports the SAME sign-in as a failure 1 s apart.
    recs = S.scenario_a_identity_cloud() + [env("identity.signin", "idp-b", {"user": "alice.example", "ip": ATTACKER, "result": "failure"}, t="2026-11-03T09:07:01Z")]
    res = analyze(recs)
    inc = max(res.incidents, key=lambda i: len(i.events))
    assert inc.assessment.verdict.value == "limited" and "CONTRADICTORY_EVIDENCE:outcome" in inc.assessment.reason_codes


ATTACKER = IP
