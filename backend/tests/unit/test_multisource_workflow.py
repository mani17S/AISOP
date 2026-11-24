"""
Stage 3C-R vertical slice (ADR-009): multi-source normalization, correlation, timeline, deterministic
ATT&CK mapping, hash-chained ledger and the end-to-end investigation workflow, with and without an LLM.

Offline and deterministic: synthetic records only, no database, no network, no real model (a scripted
call-counting provider stands in for the LLM).
"""

from __future__ import annotations

import copy
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.modules.ai.llm.exceptions import LLMConnectionError
from app.modules.correlation import analyze, correlate, normalize_records, run_workflow, verify_chain
from app.modules.correlation.correlator import ESCALATION_MIN_STAGES, build_clusters
from app.modules.correlation.demo_data import ASSETS, SCENARIOS, intrusion_chain
from app.modules.correlation.mitre import asserted_only_techniques, map_techniques
from app.modules.correlation.models import CorrelationEvent
from app.modules.correlation.normalize import EVENT_NAMESPACE, normalize_user, raw_digest
from app.modules.correlation.timeline import build_timeline
from app.modules.correlation.workflow import workflow_audit_details
from app.schemas.ai import LLMResponse, TokenUsage
from app.schemas.sufficiency import SufficiencyVerdict


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _events(name: str):
    sc = SCENARIOS[name]
    return normalize_records(sc["build"](), assets=sc["assets"]).events


# ── normalization ─────────────────────────────────────────────────────────────
def test_every_source_type_is_normalized_with_provenance():
    res = normalize_records(intrusion_chain(), assets=ASSETS)
    assert not res.rejected and len(res.events) == 10
    assert {e.source_type for e in res.events} == {"windows_security", "generic_siem", "sysmon", "firewall_ids"}
    for e in res.events:
        assert len(e.raw_sha256) == 64 and e.event_key == uuid.uuid5(EVENT_NAMESPACE, f"{e.raw_sha256}:{e.record_index}")


def test_identity_process_dns_and_network_fields_are_extracted():
    by = {(e.source_type, e.source_event_id): e for e in _events("01_intrusion_chain")}
    ok = by[("windows_security", "4624")]
    assert ok.outcome == "success" and ok.user == "jdoe" and ok.host == "ws-fin-07" and ok.src_ip == "185.220.101.4"
    assert ("logon_session", "ws-fin-07:0x5a1b") in ok.entities
    assert by[("windows_security", "4625")].outcome == "failure"
    ps = by[("sysmon", "1")]
    assert ps.process_name == "powershell.exe" and ps.user == "jdoe" and ps.process_guid and ps.parent_process_guid
    assert ("logon_session", "ws-fin-07:0x5a1b") in ps.entities and ps.file_hashes == ("ab" * 32,)
    dns = by[("sysmon", "22")]
    assert dns.domain == "update.badcdn.example" and dns.dst_ip == "91.240.118.172"
    assert by[("sysmon", "3")].dst_ip == "91.240.118.172"


def test_asset_inventory_attributes_network_only_records_and_is_labelled():
    fw = next(e for e in _events("01_intrusion_chain") if e.source_type == "firewall_ids" and e.source_event_id == "2001")
    assert fw.host == "ws-fin-07" and fw.host_source == "asset_inventory"
    no_assets = normalize_records([intrusion_chain()[-1]]).events[0]
    assert no_assets.host is None and no_assets.host_source == "none"


def test_user_identity_is_normalized_across_formats():
    assert normalize_user("CORP\\JDoe") == normalize_user("jdoe@corp.local") == normalize_user("jdoe") == "jdoe"
    assert normalize_user(None) is None and normalize_user("  ") is None


def test_unparseable_records_are_rejected_with_fixed_reasons_and_the_batch_continues():
    good = intrusion_chain()[0]
    res = normalize_records([{"foo": "bar"}, "not json", 42, good, json.dumps(good)])
    reasons = {r.record_index: r.reason for r in res.rejected}
    assert reasons == {0: "NO_ADAPTER", 1: "NOT_AN_OBJECT", 2: "NOT_AN_OBJECT"}
    assert len(res.events) == 2                      # the dict and the JSON-string copy of the same record
    assert res.events[0].raw_sha256 == res.events[1].raw_sha256 == raw_digest(good)


def test_adapter_failures_are_classified_without_leaking_messages(monkeypatch):
    from app.modules.alerts.adapter_protocol import get_default_registry

    reg = get_default_registry()
    adapter = reg.find_matching_adapter(intrusion_chain()[0])

    def boom(*_a, **_k):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(type(adapter), "adapt", boom)
    res = normalize_records([intrusion_chain()[0]], registry=reg)
    assert res.rejected[0].reason == "ADAPTER_ERROR:RuntimeError" and "secret" not in res.rejected[0].model_dump_json()


# ── correlation ───────────────────────────────────────────────────────────────
def test_full_chain_forms_one_incident_through_strong_and_specific_links():
    corr = correlate(_events("01_intrusion_chain"))
    assert len(corr.incidents) == 1
    inc = corr.incidents[0]
    assert len(inc.event_keys) == 10 and not inc.weak_context_clusters
    assert inc.link_counts["strong"] >= 2 and inc.link_counts["specific"] >= 3
    assert {"credential-access", "initial-access", "execution", "command-and-control"} <= set(inc.stages)


def test_duplicates_exact_and_near_are_collapsed_before_correlation():
    events = _events("02_duplicates_near_duplicates")
    clusters, cid = build_clusters(events)
    assert len(events) == 14 and len(clusters) == 10
    assert max(len(c.members) for c in clusters) >= 3          # the SIEM alert seen three times
    assert len(correlate(events).incidents) == 1


def test_a_failed_logon_recorded_just_after_the_success_is_a_contradiction():
    corr = correlate(_events("03_contradictory_evidence"))
    assert len(corr.contradictions) == 1 and corr.contradictions[0].reason == "OUTCOME_CONFLICT_WITHIN_2S"
    assert not correlate(_events("01_intrusion_chain")).contradictions


def test_weak_links_attach_a_lone_event_as_context_but_never_merge_groups():
    corr = correlate(_events("04_unrelated_and_weak_context"))
    main = corr.incidents[0]
    assert len(main.core_clusters) == 10 and len(main.weak_context_clusters) == 1
    others = corr.incidents[1:]
    assert len(others) == 3 and all(len(i.event_keys) == 1 for i in others)
    assert {"ws-hr-02"} == {h for i in others for h in i.hosts}


def test_two_multi_evidence_groups_sharing_only_host_and_user_stay_separate_but_are_reported_related():
    def rec(eid, rid, t, ip, logon):
        from app.modules.correlation.demo_data import _win
        return _win(eid, rid, t, ip=ip, logon_id=logon)
    a = [rec(4625, 1, "2026-11-10T09:00:00Z", "45.9.148.10", None), rec(4625, 2, "2026-11-10T09:00:10Z", "45.9.148.10", None)]
    b = [rec(4625, 3, "2026-11-10T09:10:00Z", "91.108.4.9", None), rec(4625, 4, "2026-11-10T09:10:10Z", "91.108.4.9", None)]
    corr = correlate(normalize_records(a + b).events)
    assert len(corr.incidents) == 2                       # same host and user, different public IPs: not merged
    assert set(corr.incidents[0].weakly_related) == {corr.incidents[1].incident_id}


def test_three_distinct_kill_chain_stages_in_the_core_raise_severity():
    t0 = datetime(2026, 11, 10, 9, 0, tzinfo=timezone.utc)

    def ev(i, category, sev="low"):
        return CorrelationEvent(
            event_key=uuid.uuid4(), record_index=i, source_type="s", provider="p", timestamp=t0 + timedelta(minutes=i),
            title=f"t{i}", category=category, severity=sev, host="h", raw_sha256=f"{i:064x}",
            entities=(("file_hash", "ab" * 32), ("host", "h")),
        )
    corr = correlate([ev(0, "initial_access"), ev(1, "execution"), ev(2, "command_and_control")])
    inc = corr.incidents[0]
    assert len(inc.stages) == ESCALATION_MIN_STAGES and inc.escalated and inc.severity == "high"
    two = correlate([ev(0, "initial_access"), ev(1, "execution")]).incidents[0]
    assert not two.escalated and two.severity == "low"


def test_correlation_is_deterministic():
    a, b = correlate(_events("01_intrusion_chain")), correlate(_events("01_intrusion_chain"))
    assert a.model_dump() == b.model_dump()


# ── timeline ──────────────────────────────────────────────────────────────────
def test_timeline_is_chronological_provenanced_and_marks_context_duplicates_and_conflicts():
    corr = correlate(_events("04_unrelated_and_weak_context"))
    tl = build_timeline(corr, corr.incidents[0])
    assert [t.timestamp for t in tl] == sorted(t.timestamp for t in tl) and [t.position for t in tl] == list(range(1, len(tl) + 1))
    assert tl[0].membership == "weak_context" and all(t.membership == "core" for t in tl[1:])
    assert all(len(t.raw_sha256_prefix) == 12 for t in tl)
    dup = correlate(_events("02_duplicates_near_duplicates"))
    assert sum(t.duplicates_collapsed for t in build_timeline(dup, dup.incidents[0])) == 4
    con = correlate(_events("03_contradictory_evidence"))
    assert sum(1 for t in build_timeline(con, con.incidents[0]) if t.contradicts) == 2


# ── deterministic ATT&CK mapping ─────────────────────────────────────────────
def test_chain_is_mapped_by_rules_with_evidence_and_limitations():
    maps = {m.technique_id: m for m in map_techniques(_events("01_intrusion_chain"))}
    assert set(maps) == {"T1110", "T1078", "T1059.001", "T1027", "T1564.003", "T1071"}
    assert maps["T1110"].independent_evidence_count == 3 and maps["T1078"].independent_evidence_count == 4
    assert maps["T1110"].vendor_asserted and maps["T1059.001"].vendor_asserted        # the sources also asserted T1110 / T1059
    assert not maps["T1564.003"].vendor_asserted and not maps["T1027"].vendor_asserted   # derived by rule only
    for m in maps.values():
        assert m.rule_id.startswith("MAP-") and m.limitation and m.evidence_keys


def test_duplicates_do_not_inflate_rule_evidence_and_two_failures_are_not_a_brute_force():
    maps = {m.technique_id: m for m in map_techniques(_events("02_duplicates_near_duplicates"))}
    assert maps["T1110"].independent_evidence_count == 3
    two_fail = normalize_records(intrusion_chain()[:2]).events
    assert map_techniques(two_fail) == []


def test_vendor_assertions_without_a_derivation_are_reported_as_asserted_only():
    events = _events("06_uncorroborated_single_alert")
    maps = map_techniques(events)
    assert maps == [] and asserted_only_techniques(events, maps) == ["T1071"]


# ── ledger ────────────────────────────────────────────────────────────────────
def test_ledger_is_a_verifiable_hash_chain_and_detects_tampering():
    res = analyze(intrusion_chain(), ASSETS)
    assert res.ledger_ok and verify_chain(res.ledger) == (True, None)
    assert [e["step"] for e in res.ledger][0] == "NORMALIZE" and res.ledger[-1]["step"] == "REPORT"
    edited = copy.deepcopy(res.ledger)
    edited[1]["details"]["incidents"] = []
    assert verify_chain(edited) == (False, 1)
    removed = copy.deepcopy(res.ledger)
    del removed[2]
    assert verify_chain(removed)[0] is False
    reordered = copy.deepcopy(res.ledger)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    assert verify_chain(reordered)[0] is False


# ── end-to-end deterministic workflow (no LLM) ────────────────────────────────
def test_end_to_end_without_an_llm_produces_a_complete_analyst_report():
    res = analyze(intrusion_chain(), ASSETS)
    a = res.incidents[0]
    assert a.llm_status == "not_requested" and a.assessment.verdict == SufficiencyVerdict.SUFFICIENT
    md = a.markdown
    for needle in ("## 1. Evidence sufficiency", "**Verdict: SUFFICIENT**", "## 2. Timeline", "## 4. ATT&CK mapping",
                   "T1110 Brute Force", "Not requested. Everything above is deterministic", str(a.context.reproducibility.context_sha256),
                   res.ledger_head):
        assert needle in md, needle
    assert md.count("| core |") == 10 and "windows_security" in md and "firewall_ids" in md and "sysmon" in md and "generic_siem" in md


def test_workflow_output_is_byte_for_byte_deterministic():
    a, b = analyze(intrusion_chain(), ASSETS), analyze(intrusion_chain(), ASSETS)
    assert a.incidents[0].markdown == b.incidents[0].markdown and a.ledger_head == b.ledger_head


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_demo_scenario_meets_its_engineering_expectations(name):
    sc = SCENARIOS[name]
    res = analyze(sc["build"](), sc["assets"])
    exp = sc["expect"]
    assert res.ledger_ok
    if "incidents" in exp:
        assert len(res.incidents) == exp["incidents"]
    if "rejected" in exp:
        assert len(res.normalization.rejected) == exp["rejected"]
    if "duplicates_collapsed" in exp:
        assert res.summary()["duplicates_collapsed"] == exp["duplicates_collapsed"]
    if "contradictions" in exp:
        assert len(res.correlation.contradictions) == exp["contradictions"]
    if "min_sources" in exp:
        assert len({e.source_type for e in res.incidents[0].events}) >= exp["min_sources"]
    if "techniques" in exp:
        assert sorted(m.technique_id for m in res.incidents[0].mitre) == exp["techniques"]
    if "main_incident_events" in exp:
        main = res.incidents[0]
        assert len(main.events) == exp["main_incident_events"] and len(main.incident.weak_context_clusters) == exp["weak_context_events"]
        assert len(res.incidents) - 1 == exp["separate_incidents"]
    if "verdict" in exp:
        verdict = (res.batch_assessment or res.incidents[0].assessment).verdict.value
        assert verdict == exp["verdict"]
    if "code" in exp:
        assert exp["code"] in res.incidents[0].assessment.reason_codes


def test_insufficient_batch_abstains_with_a_report_and_no_incident():
    res = analyze(SCENARIOS["05_insufficient_unparseable"]["build"](), {})
    assert not res.incidents and res.batch_assessment.abstain
    assert "Analyst abstention" in res.batch_markdown and "NO_ADAPTER" in res.batch_markdown and "NOT_AN_OBJECT" in res.batch_markdown


def test_workflow_audit_details_are_fixed_shape_and_payload_free():
    res = analyze(intrusion_chain(), ASSETS)
    d = workflow_audit_details(res.incidents[0], res)
    assert {"workflow", "incident_id", "sufficiency_verdict", "abstained", "ledger_head", "context_sha256", "techniques"} <= set(d)
    blob = json.dumps(d)
    assert "powershell" not in blob.lower() and "185.220" not in blob and "jdoe" not in blob


# ── optional LLM through the gate ────────────────────────────────────────────
class ScriptedProvider:
    """Call-counting provider that answers with a schema-valid, grounded JSON built from the prompt."""

    model_name = "llama3.1:8b"

    def __init__(self, raise_exc: Exception | None = None, observed_claim: bool = True) -> None:
        self.calls = 0
        self.prompts: list[str] = []
        self.raise_exc = raise_exc
        self.observed_claim = observed_claim

    async def generate(self, request):
        self.calls += 1
        prompt = request.messages[1].content
        self.prompts.append(prompt)
        if self.raise_exc:
            raise self.raise_exc
        inv = re.search(r'<investigation_context id="([a-f0-9\-]+)"', prompt).group(1)
        ev = re.search(r'<event uuid="([a-f0-9\-]+)".*?<summary>(.*?)</summary>', prompt, re.S)
        payload = {
            "investigation_id": inv, "generated_at": datetime.now(timezone.utc).isoformat(), "model_identifier": "scripted",
            "investigation_summary": "Scripted summary of the incident based on the supplied evidence.",
            "claims": [{"claim_id": str(uuid.uuid4()), "claim_text": ev.group(2), "category": "observed_fact",
                        "supporting_evidence_ids": [ev.group(1)], "references_exist": True,
                        "grounding_status": "validated_reference", "confidence": 0.9}] if self.observed_claim else [],
            "mitre_attack_hypotheses": [], "alternative_explanations": ["Authorized administrative activity"],
            "recommended_analyst_actions": ["Review the cited events"], "uncertainty_and_data_gaps": [],
            "overall_grounding_score": 1.0 if self.observed_claim else 0.0,
        }
        return LLMResponse(content=json.dumps(payload), model=self.model_name, usage=TokenUsage())


@pytest.mark.anyio
async def test_sufficient_incident_reaches_the_model_and_claims_are_verified():
    provider = ScriptedProvider()
    res = await run_workflow(intrusion_chain(), ASSETS, provider)
    a = res.incidents[0]
    assert provider.calls == 1 and a.llm_status == "validated"
    assert "EVIDENCE LIMITATION" not in provider.prompts[0]
    claim = a.llm_result.output.claims[0]
    assert claim.grounding_status.value == "validated_reference" and claim.supporting_evidence_ids[0] in {e.event_key for e in a.events}
    assert "| observed_fact | validated_reference |" in a.markdown
    steps = [e["step"] for e in res.ledger]
    assert steps[-3:] == ["LLM_GATE", "CLAIM_VERIFY", "REPORT"] and res.ledger_ok


@pytest.mark.anyio
async def test_limited_incident_gets_a_limitation_note_and_the_disclosure_reaches_the_report():
    provider = ScriptedProvider()
    res = await run_workflow(SCENARIOS["06_uncorroborated_single_alert"]["build"](), {}, provider)
    a = res.incidents[0]
    assert provider.calls == 1 and "[EVIDENCE LIMITATION - system generated]" in provider.prompts[0]
    gaps = a.llm_result.output.uncertainty_and_data_gaps
    assert any(g.startswith("EVIDENCE_SUFFICIENCY[suff-v5]=LIMITED") and "UNCORROBORATED_QUESTION" in g for g in gaps)
    assert "EVIDENCE_SUFFICIENCY[suff-v5]=LIMITED" in a.markdown          # in the analyst-facing report, not just the prompt


@pytest.mark.anyio
async def test_gate_failure_fails_closed_and_the_provider_is_never_called(monkeypatch):
    import app.modules.ai.guardrails.sufficiency_gate as gate

    monkeypatch.setattr(gate, "assess_evidence_sufficiency", lambda _c: (_ for _ in ()).throw(RuntimeError("detail")))
    provider = ScriptedProvider()
    res = await run_workflow(intrusion_chain(), ASSETS, provider)
    a = res.incidents[0]
    assert provider.calls == 0 and a.llm_status == "abstained" and a.assessment.reason_codes == ["GATE_EVALUATION_ERROR"]
    assert "detail" not in a.markdown and "insufficient" in a.markdown.lower()


@pytest.mark.anyio
async def test_an_insufficient_batch_never_invokes_the_provider():
    provider = ScriptedProvider()
    res = await run_workflow(SCENARIOS["05_insufficient_unparseable"]["build"](), {}, provider)
    assert provider.calls == 0 and not res.incidents and res.batch_assessment.abstain


@pytest.mark.anyio
async def test_provider_failure_falls_back_to_the_deterministic_report():
    provider = ScriptedProvider(raise_exc=LLMConnectionError("down"))
    res = await run_workflow(intrusion_chain(), ASSETS, provider)
    a = res.incidents[0]
    assert provider.calls == 1 and a.llm_status == "fallback:LLMConnectionError"
    assert a.llm_result.decision.value == "reject_to_fallback" and "## 2. Timeline" in a.markdown and res.ledger_ok
