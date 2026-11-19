"""
Stage 6 (ADR-011): end-to-end deterministic investigation scenarios built from source-agnostic evidence only
(no SIEM alert, no Sysmon event), plus the negative scenarios. Offline, synthetic data, no network.

Integration points exercised here: ``analyze`` / ``run_workflow`` (existing 3C-R workflow), the evidence-sufficiency
gate (``evaluate_sufficiency`` through ``build_incident_context``), ``GatedGenerator`` and the claim verifier for the
optional LLM step, and the report renderer.
"""

from __future__ import annotations

import json

import pytest

from app.modules.correlation.workflow import analyze, run_workflow
from app.modules.evidence_domains import scenarios as S
from app.modules.evidence_domains.model import EvidenceFamily
from app.modules.ai.llm.exceptions import LLMConnectionError
from tests.unit.test_multisource_api import ScriptedProvider


@pytest.fixture
def anyio_backend():
    return "asyncio"


def techniques(a) -> set[str]:
    return {m.technique_id for m in a.mitre}


# ── Scenario A: identity + cloud ─────────────────────────────────────────────
def test_scenario_a_identity_and_cloud_form_one_incident_without_any_alert():
    res = analyze(S.scenario_a_identity_cloud())
    assert res.normalization.rejected == [] and len(res.incidents) == 1
    a = res.incidents[0]
    assert {e.source_type for e in a.events} == {"idp-synthetic", "cloudaudit-synthetic"}   # two independent sources
    assert a.assessment.verdict.value == "sufficient" and a.assessment.corroborating_events >= 1
    assert techniques(a) == {"T1621", "T1136.003", "T1098.003"}
    assert all(e.evidence_type for e in a.events)                                           # no SIEM/Sysmon-shaped event anywhere
    assert not any(e.source_type in ("sysmon", "windows_security", "generic_siem", "firewall_ids") for e in a.events)
    kinds = {(e.subject[0], e.predicate, e.obj[0]) for e in a.graph.edges}
    assert ("user", "AUTHENTICATED_FROM", "ip") in kinds and ("user", "CREATED", "cloud_resource") in kinds
    strong = [c for c in a.graph.correlations if c.strength != "weak"]
    assert strong and all("not shared by accident" in c.rationale or "authenticated" in c.rationale for c in strong)


def test_scenario_a_report_is_evidence_linked_and_labels_what_it_is():
    md = analyze(S.scenario_a_identity_cloud()).incidents[0].markdown
    for needle in ("## 1. Evidence sufficiency", "## 2. Timeline", "## 4. ATT&CK mapping", "## 4b. Entity graph", "## 4c. External intelligence (context only",
                   "## 4d. Analyst statements", "Not requested. Everything above is deterministic", "T1621", "MAP-T1098.003-CLOUD-ROLE-ASSIGNED"):
        assert needle in md
    assert md == analyze(S.scenario_a_identity_cloud()).incidents[0].markdown               # byte-identical on re-run (deterministic)


def test_scenario_a_timeline_is_chronological_and_every_row_traces_to_a_raw_digest():
    a = analyze(S.scenario_a_identity_cloud()).incidents[0]
    times = [t.timestamp for t in a.timeline]
    assert times == sorted(times) and all(len(t.raw_sha256_prefix) == 12 for t in a.timeline)
    assert {t.stage for t in a.timeline} == {"unclassified"}                                 # no kill-chain stage is invented


# ── Scenario B: network + endpoint ───────────────────────────────────────────
def test_scenario_b_network_and_endpoint_correlate_through_ip_and_hash_not_through_host_name():
    res = analyze(S.scenario_b_network_endpoint())
    assert len(res.incidents) == 1
    a = res.incidents[0]
    shared = {e for lk in res.correlation.links if lk.strength != "weak" for e in lk.shared_entities}
    assert ("ip", S.C2_IP) in shared and ("file_hash", S.SHA_TOOL) in shared
    assert a.assessment.verdict.value in ("sufficient", "limited")
    assert techniques(a) == set()                                                           # no rule matched: none invented
    assert "No technique could be derived" in a.markdown
    rels = {(e.subject[0], e.predicate, e.obj[0]) for e in a.graph.edges}
    assert ("domain", "RESOLVED_TO", "ip") in rels and ("process", "CONNECTED_TO", "ip") in rels and ("ip", "CONNECTED_TO", "ip") in rels


def test_scenario_b_temporal_constraint_two_days_apart_is_not_joined_by_a_specific_link_window():
    recs = S.scenario_b_network_endpoint()
    recs[3] = dict(recs[3], event_time="2026-11-10T10:00:09Z")                              # flow 6 days later
    res = analyze(recs)
    # the flow is outside the 24 h specific-link window of the earlier records, so it cannot corroborate them
    flow_key = next(o.key for o in res.observations if o.evidence_type == "network.flow")
    inc_keys = {k for i in res.incidents for k in i.incident.event_keys if len(i.incident.event_keys) > 1}
    assert flow_key not in inc_keys


# ── Scenario C: e-mail + forensic ────────────────────────────────────────────
def test_scenario_c_email_and_forensic_artefacts_with_provenance_and_analyst_context():
    res = analyze(S.scenario_c_email_forensic())
    a = res.incidents[0]
    assert techniques(a) == {"T1566.001", "T1566.002", "T1547.001", "T1055"}
    note = a.analyst_notes[0]
    assert note.counts_for_corroboration is False and note.family == EvidenceFamily.ANALYST
    assert note.key not in {e.event_key for e in a.events}                                  # analyst statement is not an event
    md = a.markdown
    assert "Analyst statements (context only, never corroboration)" in md and "did not count toward the sufficiency verdict" in md
    assert "TOOL_ASSERTED_ONLY" in md and "forensic memory tool" in md
    obs_by_type = {o.evidence_type: o for o in res.observations}
    assert obs_by_type["forensic.memory_finding"].trust_class.value == "tool_asserted"
    assert obs_by_type["email.message"].trust_class.value == "raw_observed"
    assert all(len(o.raw_sha256) == 64 for o in res.observations)


def test_scenario_c_sufficiency_is_identical_with_and_without_the_analyst_statement():
    with_note = analyze(S.scenario_c_email_forensic())
    without = analyze([r for r in S.scenario_c_email_forensic() if r["evidence_type"] != "analyst.observation"])
    a, b = with_note.incidents[0], without.incidents[0]
    assert a.assessment.assessment_sha256 == b.assessment.assessment_sha256
    assert a.context.reproducibility.context_sha256 == b.context.reproducibility.context_sha256


# ── negative scenarios ───────────────────────────────────────────────────────
def test_duplicate_and_near_duplicate_records_do_not_inflate_corroboration():
    res = analyze(S.negative_duplicates())
    a = res.incidents[0]
    assert a.assessment.effective_events == 1 and a.assessment.total_events == 3
    assert a.assessment.corroborating_events == 0 and "UNCORROBORATED_QUESTION" in a.assessment.reason_codes
    assert "DUPLICATE_EVIDENCE_COLLAPSED" in a.assessment.reason_codes
    assert a.assessment.verdict.value != "sufficient"
    assert a.timeline[0].duplicates_collapsed == 2


def test_analyst_assertion_is_not_independent_technical_evidence():
    res = analyze(S.negative_analyst_only())
    assert len(res.incidents) == 1 and res.incidents[0].assessment.corroborating_events == 0
    assert res.incidents[0].assessment.verdict.value != "sufficient"
    assert res.incidents[0].analyst_notes and techniques(res.incidents[0]) == set()
    only_note = analyze([S.negative_analyst_only()[1]])
    assert only_note.incidents == [] and only_note.batch_assessment.verdict.value == "insufficient"


def test_contradictory_evidence_is_represented_not_dropped():
    res = analyze(S.negative_contradiction())
    assert [c.reason for c in res.correlation.contradictions] == ["OUTCOME_CONFLICT_WITHIN_2S"]
    a = res.incidents[0]
    assert a.graph.contradictions[0]["reason"] == "OUTCOME_CONFLICT_WITHIN_2S"
    assert {o.outcome for o in a.observations} == {"success", "failure"}                    # both statements are kept


def test_unrelated_observations_are_not_joined():
    res = analyze(S.negative_unrelated())
    assert len(res.incidents) == 3 and all(len(i.incident.event_keys) == 1 for i in res.incidents)
    assert not [lk for lk in res.correlation.links if lk.strength != "weak"]


def test_missing_invalid_and_out_of_range_times_are_never_fabricated():
    res = analyze(S.negative_bad_times())
    assert res.incidents == [] and res.batch_assessment.verdict.value == "insufficient"
    assert "undated" in res.batch_markdown and "none was invented" in res.batch_markdown
    assert {o.time_status.value for o in res.observations} == {"missing", "invalid", "out_of_range"}
    assert all(o.event_time is None for o in res.observations)


def test_undated_evidence_beside_dated_evidence_is_disclosed_in_the_context_flags():
    res = analyze(S.scenario_a_identity_cloud() + S.negative_bad_times())
    flags = res.incidents[0].context.uncertainty_flags
    assert any(f.startswith("UNDATED_OBSERVATIONS: 3") for f in flags)
    assert not any(t.timestamp.year < 2000 for t in res.incidents[0].timeline)


def test_unknown_but_valid_evidence_is_preserved_and_disclosed():
    res = analyze(S.negative_unknown_type())
    assert len(res.observations) == 1 and res.normalization.rejected == []
    assert res.incidents == [] and res.batch_assessment.verdict.value == "insufficient"
    assert any(u["kind"] == "UNCLASSIFIED_EVIDENCE" for u in res.batch_graph.uncertainties)
    mixed = analyze(S.scenario_a_identity_cloud() + S.negative_unknown_type())
    assert any(f.startswith("UNCLASSIFIED_EVIDENCE") for f in mixed.incidents[0].context.uncertainty_flags)


def test_insufficient_evidence_yields_an_explicit_abstention_report():
    res = analyze([])
    assert res.batch_assessment.verdict.value == "insufficient" and "NO_EVIDENCE" in res.batch_assessment.reason_codes
    assert "Analyst abstention" in res.batch_markdown


def test_unsupported_attack_mapping_is_not_generated():
    for recs in (S.scenario_b_network_endpoint(), S.negative_duplicates(), S.negative_unrelated(), S.negative_analyst_only()):
        assert all(techniques(i) == set() for i in analyze(recs).incidents)


def test_mixed_batch_of_valid_malformed_and_unknown_records_is_handled_per_record():
    recs = S.scenario_a_identity_cloud() + S.malformed_records() + S.negative_unknown_type()
    res = analyze(recs)
    assert len(res.normalization.rejected) == 5 and len(res.incidents) == 1
    assert res.summary()["domain_observations"] == len(S.scenario_a_identity_cloud()) + 1
    assert res.ledger_ok and [e["step"] for e in res.ledger][:3] == ["NORMALIZE", "DOMAIN_EVIDENCE", "CORRELATE"]


def test_legacy_alert_flow_is_unchanged_when_no_domain_evidence_is_present():
    from app.modules.correlation.demo_data import intrusion_chain

    res = analyze(intrusion_chain())
    assert res.observations == [] and res.batch_graph is None
    assert "DOMAIN_EVIDENCE" not in [e["step"] for e in res.ledger]
    assert all(i.graph is None for i in res.incidents) and "## 4b." not in res.incidents[0].markdown


def test_siem_alerts_and_domain_evidence_can_be_investigated_together():
    from app.modules.correlation.demo_data import intrusion_chain

    res = analyze(intrusion_chain() + S.scenario_a_identity_cloud())
    assert len(res.observations) == len(S.scenario_a_identity_cloud())
    assert any(e.evidence_type == "" for e in res.normalization.events) and any(e.evidence_type for e in res.normalization.events)


# ── optional LLM step: gate, claim verification, failure isolation ───────────
@pytest.mark.anyio
async def test_llm_path_goes_through_the_gate_and_claim_verifier():
    provider = ScriptedProvider()
    res = await run_workflow(S.scenario_a_identity_cloud(), provider=provider)
    a = res.incidents[0]
    assert provider.calls == 1 and a.llm_status == "validated"
    assert a.llm_result.output.claims and "## 6. AI-assisted investigation" in a.markdown
    assert any(e["step"] == "LLM_GATE" for e in res.ledger) and any(e["step"] == "CLAIM_VERIFY" for e in res.ledger)
    assert res.ledger_ok


@pytest.mark.anyio
async def test_llm_failure_does_not_break_the_deterministic_investigation():
    baseline = analyze(S.scenario_a_identity_cloud()).incidents[0]
    res = await run_workflow(S.scenario_a_identity_cloud(), provider=ScriptedProvider(raise_exc=LLMConnectionError("down")))
    a = res.incidents[0]
    assert a.llm_status.startswith("fallback:")
    assert a.assessment.assessment_sha256 == baseline.assessment.assessment_sha256
    assert techniques(a) == techniques(baseline) and [t.title for t in a.timeline] == [t.title for t in baseline.timeline]
    assert "Status: **fallback" in a.markdown and "## 4b. Entity graph" in a.markdown


@pytest.mark.anyio
async def test_provider_is_never_called_when_there_is_no_usable_evidence():
    provider = ScriptedProvider()
    res = await run_workflow(S.negative_bad_times() + S.negative_unknown_type(), provider=provider)
    assert provider.calls == 0 and res.incidents == [] and res.batch_assessment.verdict.value == "insufficient"


@pytest.mark.anyio
async def test_llm_disabled_is_the_default_and_output_is_json_safe():
    res = await run_workflow(S.scenario_c_email_forensic(), provider=None)
    assert res.incidents[0].llm_status == "not_requested"
    json.dumps(res.incidents[0].graph.to_view())


def test_cross_sensor_contradiction_now_limits_the_verdict_and_is_explained_next_to_it():
    """Replaces the Stage 6 closure test that documented the gap (SUFFICIENT beside a cross-sensor conflict, interim notice).
    ADR-013 Revision 2 (suff-v4): the gate weighs the conflict, caps the verdict at LIMITED and the report explains it."""
    a = analyze(S.negative_contradiction()).incidents[0]
    assert a.assessment.verdict.value == "limited" and "CONTRADICTORY_EVIDENCE:outcome" in a.assessment.reason_codes
    assert a.assessment.corroborating_events == 0 and a.assessment.contradictions[0].affects_verdict is True
    head = a.markdown.split("## 2. Timeline")[0]
    assert "**Contradictions (ADR-013).**" in head and "capped at LIMITED" in head and "Contradiction notice" not in head
    assert "Contradiction" not in analyze(S.scenario_a_identity_cloud()).incidents[0].markdown.split("## 2. Timeline")[0]
