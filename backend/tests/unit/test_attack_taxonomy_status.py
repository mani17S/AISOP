"""
Offline tests for the per-hypothesis ATT&CK taxonomy status and its independence from evidence confidence.

Covers the eight states, per-hypothesis isolation, serialization and historical compatibility, forged model-supplied status,
confidence/evidence independence, the report consumers that must not accept obsolete ids, and the live ``run_workflow``
composition boundary (scripted provider; no ``.env``, database, app start, network or model).
"""

from __future__ import annotations

import ast
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.modules.ai.guardrails import attack_policy as ap
from app.modules.ai.guardrails.validator import GuardrailDecision, InvestigationOutputValidator
from app.modules.ai.reporting.synthesizer import DeterministicReportSynthesizer
from app.modules.attack_reference import CatalogueLoadResult, ErrorCode
from app.modules.correlation import run_workflow
from app.modules.correlation.demo_data import ASSETS, intrusion_chain
from app.schemas.ai import LLMResponse, TokenUsage
from app.schemas.attack_taxonomy import SuccessorCandidate, TaxonomyState, TechniqueTaxonomyStatus
from app.schemas.investigation import MitreAttackHypothesis, StructuredInvestigationOutput
from tests.unit.test_attack_guardrail_lifecycle import (
    CLOCK, OLD_TO_NEW, SHARED_T1685, ev_1102, guardrail_document, hyp, make_event, run,
)
from tests.unit.test_attack_reference_loader import SENTINEL, base_document, mem
from tests.unit.test_deterministic_report_synthesizer import _make_sample_context, _make_sample_validation_result
from tests.unit.test_output_guardrails_p2 import make_test_context, make_test_output

BACKEND = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def cat():
    return mem(guardrail_document())


@pytest.fixture
def anyio_backend():
    return "asyncio"


def state_of(res, i=0):
    return res.output.mitre_attack_hypotheses[i].taxonomy


UNAVAILABLE = CatalogueLoadResult(catalogue=None, error_code=ErrorCode.PATH_MISSING, message="missing")


# ── the eight states, each hypothesis with its own ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("tid,source,expected,reason", [
    ("T1059.001", "cat", TaxonomyState.CURRENT_VALID, "CATALOGUE_CURRENT"),
    ("T1070.001", "cat", TaxonomyState.REVOKED, "CATALOGUE_REVOKED"),
    ("T1043", "cat", TaxonomyState.DEPRECATED, "CATALOGUE_DEPRECATED"),
    ("T9999", "cat", TaxonomyState.UNKNOWN, "NOT_IN_PINNED_ENTERPRISE_CATALOGUE"),
    ("T12", "cat", TaxonomyState.INVALID, "INVALID_SYNTAX"),
    ("T1404", "cat", TaxonomyState.WRONG_DOMAIN, "OTHER_DOMAIN"),
    ("T1078", None, TaxonomyState.NOT_CONFIGURED, "NO_CATALOGUE_CONFIGURED"),
    ("T1078", "unavailable", TaxonomyState.CATALOGUE_UNAVAILABLE, "CATALOGUE_UNAVAILABLE"),
])
def test_each_taxonomy_state_is_produced_by_the_validator(cat, tid, source, expected, reason):
    src = {"cat": cat, "unavailable": UNAVAILABLE, None: None}[source]
    e = make_event()
    _, res, _ = run(src, [hyp(tid, [e], conf=0.6)], [e])
    t = state_of(res)
    assert t.state == expected and t.reason_code == reason
    assert t.technique_id == (None if expected == TaxonomyState.INVALID else tid)           # normalised only when safely parsed
    if source == "cat" and expected != TaxonomyState.INVALID:
        assert (t.catalogue_domain, t.catalogue_release) == ("enterprise-attack", "20.1") and len(t.catalogue_sha256) == 64
    if source != "cat":
        assert t.catalogue_release is None and t.canonical_name is None                       # nothing is claimed without a catalogue
    if expected in (TaxonomyState.CURRENT_VALID, TaxonomyState.REVOKED, TaxonomyState.DEPRECATED):
        assert t.canonical_name and t.lifecycle


def test_hypotheses_in_one_investigation_get_their_own_independent_status(cat):
    e = make_event()
    ids = ["T1059.001", "T1070.001", "T9999", "T12", "T1404", "T1043", "T1110"]
    _, res, _ = run(cat, [hyp(t, [e]) for t in ids], [e])
    got = [(h.technique_id, h.taxonomy.state) for h in res.output.mitre_attack_hypotheses]
    assert got == [("T1059.001", TaxonomyState.CURRENT_VALID), ("T1070.001", TaxonomyState.REVOKED), ("T9999", TaxonomyState.UNKNOWN),
                   ("T12", TaxonomyState.INVALID), ("T1404", TaxonomyState.WRONG_DOMAIN), ("T1043", TaxonomyState.DEPRECATED),
                   ("T1110", TaxonomyState.CURRENT_VALID)]                                  # input order preserved
    for h in res.output.mitre_attack_hypotheses:
        assert h.taxonomy.technique_id in (h.technique_id, None)                            # never copied from a neighbour


# ── successors: suggestions only, preserved exactly ─────────────────────────────────────────────────────────────
def test_revoked_status_carries_the_exact_successor_candidates_and_ambiguity(cat):
    e = make_event()
    _, res, _ = run(cat, [hyp("T1070.001", [e]), hyp("T1562", [e]), hyp("T1562.001", [e]), hyp("T1562.006", [e])], [e])
    one, *shared = [h.taxonomy for h in res.output.mitre_attack_hypotheses]
    assert [s.attack_id for s in one.successors] == ["T1685.005"] and one.successor_ambiguous is False
    for t, old in zip(shared, SHARED_T1685):
        assert [s.attack_id for s in t.successors] == ["T1685"] and t.successor_ambiguous is True
        assert set(t.successors[0].shared_with) == set(SHARED_T1685) - {old}
    assert [h.technique_id for h in res.output.mitre_attack_hypotheses] == ["T1070.001", "T1562", "T1562.001", "T1562.006"]  # no T1685 added


def test_multiple_replacement_targets_are_all_preserved_and_flagged_ambiguous():
    low = mem(base_document())                                                              # T1562.003 has two explicit targets here
    e = make_event()
    _, res, _ = run(low, [hyp("T1562.003", [e])], [e])
    t = state_of(res)
    assert [s.attack_id for s in t.successors] == ["T1685.005", "T1690"] and t.successor_ambiguous is True


def test_the_status_object_is_bounded_and_carries_no_descriptions_or_raw_text(cat):
    e = make_event()
    _, res, _ = run(cat, [hyp("T1562", [e], reasoning="RAW-MODEL-TEXT-MARKER")], [e])
    t = state_of(res)
    dump = t.model_dump(mode="json")
    assert set(dump) == {"state", "technique_id", "catalogue_domain", "catalogue_release", "catalogue_sha256", "canonical_name",
                         "lifecycle", "successors", "successor_ambiguous", "unresolved_successor_refs", "reference", "reason_code"}
    assert set(dump["successors"][0]) == {"attack_id", "name", "lifecycle", "shared_with"}
    blob = json.dumps(dump)
    assert SENTINEL not in blob and "RAW-MODEL-TEXT-MARKER" not in blob


# ── serialization and historical compatibility ──────────────────────────────────────────────────────────────────
def test_status_round_trips_through_json(cat):
    e = make_event()
    _, res, _ = run(cat, [hyp("T1070.001", [e]), hyp("T9999", [e])], [e])
    again = StructuredInvestigationOutput.model_validate_json(res.output.model_dump_json())
    assert again == res.output and again.mitre_attack_hypotheses[0].taxonomy.state == TaxonomyState.REVOKED


def test_historical_hypotheses_without_the_field_load_and_are_never_read_as_valid():
    old = {"technique_id": "T1070.001", "technique_name": "Clear Windows Event Logs", "tactics": ["Defense Evasion"],
           "supporting_event_uuids": [], "confidence": 0.7, "reasoning": "recorded before the taxonomy field existed"}
    h = MitreAttackHypothesis.model_validate(old)
    assert h.taxonomy is None and h.confidence == 0.7                                         # absent = not recorded, not valid
    assert "taxonomy" in h.model_dump() and h.model_dump()["taxonomy"] is None


def test_a_model_cannot_supply_or_keep_its_own_taxonomy_status(cat):
    forged = TechniqueTaxonomyStatus(state=TaxonomyState.CURRENT_VALID, technique_id="T1070.001", canonical_name="Forged", reason_code="FORGED")
    e = make_event()
    bad = [hyp(t, [e]).model_copy(update={"taxonomy": forged}) for t in ("T1070.001", "T9999")]
    _, res, _ = run(cat, bad, [e])
    assert [h.taxonomy.state for h in res.output.mitre_attack_hypotheses] == [TaxonomyState.REVOKED, TaxonomyState.UNKNOWN]
    assert all(h.taxonomy.canonical_name != "Forged" and h.taxonomy.reason_code != "FORGED" for h in res.output.mitre_attack_hypotheses)
    _, res2, _ = run(None, bad, [e])                                                          # and without any catalogue
    assert all(h.taxonomy.state == TaxonomyState.NOT_CONFIGURED for h in res2.output.mitre_attack_hypotheses)


def test_revalidation_overwrites_status_deterministically(cat):
    e = make_event()
    ctx = make_test_context(events=[e])
    out = make_test_output(ctx, mitre_hypotheses=[hyp("T1070.001", [e], conf=0.8)])
    v = InvestigationOutputValidator(clock=lambda: CLOCK, attack_reference=cat)
    first = v.validate(out, ctx)
    second = v.validate(first.output, ctx)
    assert state_of(first) == state_of(second) and second.output.mitre_attack_hypotheses[0].confidence == 0.8


# ── confidence and evidence independence ────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("tid,src", [("T1070.001", "cat"), ("T1562", "cat"), ("T1043", "cat"), ("T9999", "cat"),
                                     ("T1404", "cat"), ("T1078", "unavailable"), ("T1078", None)])
def test_taxonomy_lifecycle_alone_never_changes_evidence_confidence(cat, tid, src):
    s = {"cat": cat, "unavailable": UNAVAILABLE, None: None}[src]
    e = make_event()
    _, res, _ = run(s, [hyp(tid, [e], conf=0.73)], [e])
    assert res.output.mitre_attack_hypotheses[0].confidence == 0.73                           # taxonomy status is not confidence


def test_revoked_status_does_not_mean_absent_evidence_or_benign(cat):
    e = ev_1102()
    _, res, _ = run(cat, [hyp("T1070.001", [e], conf=0.9)], [e])
    h = res.output.mitre_attack_hypotheses[0]
    assert h.confidence == 0.9 and h.supporting_event_uuids == [e.event_uuid]                 # evidence and its citation intact
    assert "benign" not in h.reasoning.lower().replace("not benign", "")
    assert res.decision == GuardrailDecision.REMEDIATED and res.is_valid                       # an annotation happened; not a fallback


def test_a_valid_id_can_be_taxonomy_valid_but_evidence_unsupported_and_vice_versa(cat):
    weak, strong = make_event(), ev_1102()
    _, res, _ = run(cat, [hyp("T1685.001", [weak], conf=0.8), hyp("T1685.005", [strong], conf=0.7)], [weak, strong])
    a, b = res.output.mitre_attack_hypotheses
    assert a.taxonomy.state == TaxonomyState.CURRENT_VALID and a.confidence == 0.0 and ap.MARK_UNSUPPORTED in a.reasoning
    assert b.taxonomy.state == TaxonomyState.CURRENT_VALID and b.confidence == 0.7 and ap.MARK_UNSUPPORTED not in b.reasoning


def test_taxonomy_does_not_change_sufficiency_claims_or_corroboration_fields(cat):
    e = make_event()
    hyps = [hyp("T1070.001", [e]), hyp("T9999", [e]), hyp("T1059.001", [e])]
    ctx = make_test_context(events=[e])                                                       # one shared context for both runs
    out = make_test_output(ctx, mitre_hypotheses=hyps)
    res_a = InvestigationOutputValidator(clock=lambda: CLOCK, attack_reference=cat).validate(out, ctx)
    res_b = InvestigationOutputValidator(clock=lambda: CLOCK).validate(out, ctx)
    for f in ("claims", "investigation_summary", "alternative_explanations", "recommended_analyst_actions",
              "uncertainty_and_data_gaps", "overall_grounding_score"):
        assert getattr(res_a.output, f) == getattr(res_b.output, f)
    assert res_a.is_valid == res_b.is_valid and res_a.context_sha256 == res_b.context_sha256


def test_every_inconclusive_taxonomy_outcome_says_not_benign(cat):
    e = make_event()
    for src, tid in ((cat, "T9999"), (UNAVAILABLE, "T1078")):
        _, res, _ = run(src, [hyp(tid, [e])], [e])
        assert "inconclusive, not benign" in res.output.mitre_attack_hypotheses[0].reasoning


def test_invalid_syntax_keeps_only_the_pre_existing_syntax_rule(cat):
    e = make_event()
    _, res, _ = run(cat, [hyp("T12", [e], conf=0.6)], [e])
    h = res.output.mitre_attack_hypotheses[0]
    assert h.taxonomy.state == TaxonomyState.INVALID and h.confidence == 0.0                   # zero comes from SEC-GR-MITRE-SYNTAX
    assert [v.rule_id for v in res.violations if "MITRE" in v.rule_id or "ATTACK" in v.rule_id] == ["SEC-GR-MITRE-SYNTAX"]


# ── report consumers must not accept obsolete ids (behaviour formerly provided by zeroed confidence) ───────────────
def _fixed():
    inv, ev = uuid.uuid4(), uuid.uuid4()
    return inv, ev, _make_sample_context(inv, ev)


def _bundle(tid, taxonomy, conf=0.9, tactics=("Execution",), fixed=None):
    inv, ev, ctx = fixed or _fixed()
    h = MitreAttackHypothesis(technique_id=tid, technique_name="Some Technique", tactics=list(tactics), supporting_event_uuids=[ev],
                              confidence=conf, reasoning="Model reasoning.", taxonomy=taxonomy)
    vr = _make_sample_validation_result(inv, ev, ctx.reproducibility.context_sha256, hypotheses=[h])
    return DeterministicReportSynthesizer().synthesize_bundle(vr, ctx)


def tax(state, **kw):
    return TechniqueTaxonomyStatus(state=state, technique_id=kw.pop("technique_id", "T1070.001"), reason_code="X", **kw)


REVOKED = tax(TaxonomyState.REVOKED, lifecycle="revoked",
              successors=(SuccessorCandidate(attack_id="T1685.005", name="Clear Windows Event Logs", lifecycle="current"),))


def test_revoked_hypothesis_is_not_an_accepted_mapping_for_targets_detection_hunting_or_severity():
    fixed = _fixed()
    current = _bundle("T1059.001", None, fixed=fixed)
    revoked = _bundle("T1070.001", REVOKED, fixed=fixed)
    zeroed_baseline = _bundle("T1070.001", None, conf=0.0, fixed=fixed)                       # the previous mechanism
    assert "T1059.001" in current.detection_report.mitre_coverage_targets
    assert "T1070.001" not in revoked.detection_report.mitre_coverage_targets
    assert not any("T1070.001" in c for c in revoked.detection_report.candidate_detection_hypotheses)
    assert not any("T1070.001" in c for c in revoked.detection_report.candidate_hunting_pseudocode)
    assert revoked.executive_brief.incident_severity == zeroed_baseline.executive_brief.incident_severity       # behaviour preserved
    assert revoked.executive_brief.incident_severity != current.executive_brief.incident_severity
    assert revoked.executive_brief.severity_justification == zeroed_baseline.executive_brief.severity_justification


def test_unknown_taxonomy_keeps_the_existing_consumer_behaviour_and_is_flagged():
    unknown = _bundle("T9999", tax(TaxonomyState.UNKNOWN, technique_id="T9999"))
    plain = _bundle("T9999", None)
    assert "T9999" in unknown.detection_report.mitre_coverage_targets                         # unchanged by instruction
    assert unknown.executive_brief.incident_severity == plain.executive_brief.incident_severity
    assert unknown.technical_report.mitre_attack_mappings[0]["taxonomy_state"] == "UNKNOWN"


def test_report_exposes_additive_status_and_successor_suggestions_for_notable_states_only():
    r = _bundle("T1070.001", REVOKED)
    m = r.technical_report.mitre_attack_mappings[0]
    assert m["taxonomy_state"] == "REVOKED" and m["taxonomy_successors"] == ["T1685.005"] and m["confidence"] == 0.9
    assert "[taxonomy: REVOKED; catalogue successor suggestion (not evidence): T1685.005]" in r.markdown_technical


@pytest.mark.parametrize("taxonomy", [None, tax(TaxonomyState.CURRENT_VALID, technique_id="T1059.001"),
                                      tax(TaxonomyState.NOT_CONFIGURED, technique_id="T1059.001")])
def test_default_and_current_states_leave_reports_byte_identical(taxonomy):
    fixed = _fixed()                                                                          # identical ids and context for both runs
    base = _bundle("T1059.001", None, fixed=fixed)
    other = _bundle("T1059.001", taxonomy, fixed=fixed)
    assert not any(k.startswith("taxonomy") for k in other.technical_report.mitre_attack_mappings[0])
    uuids = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")      # the sample builder mints a new claim id per call
    norm = lambda b: tuple(uuids.sub("<uuid>", t) for t in (b.markdown_technical, b.markdown_executive, b.markdown_detection))  # noqa: E731
    assert norm(other) == norm(base)


# ── live composition boundary: run_workflow with the real production seam ──────────────────────────────────────
class HypothesisProvider:
    """Offline scripted model: one grounded claim plus three technique hypotheses citing the first event."""

    model_name = "llama3.1:8b"

    def __init__(self) -> None:
        self.calls = 0

    async def generate(self, request):
        self.calls += 1
        prompt = request.messages[1].content
        inv = re.search(r'<investigation_context id="([a-f0-9\-]+)"', prompt).group(1)
        ev = re.search(r'<event uuid="([a-f0-9\-]+)".*?<summary>(.*?)</summary>', prompt, re.S)
        hyps = [{"technique_id": t, "technique_name": "Model Name", "tactics": ["Execution"], "supporting_event_uuids": [ev.group(1)],
                 "confidence": 0.8, "reasoning": "Scripted reasoning.",
                 "taxonomy": {"state": "CURRENT_VALID", "reason_code": "FORGED"}}              # a model trying to self-validate
                for t in ("T1070.001", "T1059.001", "T9999")]
        payload = {
            "investigation_id": inv, "generated_at": datetime.now(timezone.utc).isoformat(), "model_identifier": "scripted",
            "investigation_summary": "Scripted summary of the incident based on the supplied evidence.",
            "claims": [{"claim_id": str(uuid.uuid4()), "claim_text": ev.group(2), "category": "observed_fact",
                        "supporting_evidence_ids": [ev.group(1)], "references_exist": True,
                        "grounding_status": "validated_reference", "confidence": 0.9}],
            "mitre_attack_hypotheses": hyps, "alternative_explanations": ["Authorized administrative activity"],
            "recommended_analyst_actions": ["Review the cited events"], "uncertainty_and_data_gaps": [], "overall_grounding_score": 1.0,
        }
        return LLMResponse(content=json.dumps(payload), model=self.model_name, usage=TokenUsage())


async def _states(attack_reference):
    provider = HypothesisProvider()
    res = await run_workflow(intrusion_chain(), ASSETS, provider, attack_reference=attack_reference)
    a = res.incidents[0]
    assert provider.calls == 1 and a.llm_status == "validated"                                  # investigation continues in every case
    return [(h.technique_id, h.taxonomy.state.value, h.confidence) for h in a.llm_result.output.mitre_attack_hypotheses]


@pytest.mark.anyio
async def test_live_workflow_with_a_catalogue_distinguishes_current_revoked_and_unknown(cat):
    assert await _states(cat) == [("T1070.001", "REVOKED", 0.8), ("T1059.001", "CURRENT_VALID", 0.8), ("T9999", "UNKNOWN", 0.8)]


@pytest.mark.anyio
async def test_live_workflow_default_is_explicitly_not_configured_and_forged_status_is_discarded():
    assert {s for _, s, _ in await _states(None)} == {"NOT_CONFIGURED"}


@pytest.mark.anyio
async def test_live_workflow_with_an_unavailable_catalogue_continues_with_an_explicit_state():
    assert {s for _, s, _ in await _states(UNAVAILABLE)} == {"CATALOGUE_UNAVAILABLE"}


# ── production call sites pass the optional reference down (static proof where a database prevents a run) ──────
def _calls(path: str, name: str):
    tree = ast.parse((BACKEND / "app" / path).read_text(encoding="utf-8"))
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", None)) == name]


def test_case_synthesis_builds_its_validator_with_the_resolved_reference():
    calls = _calls("services/case_service.py", "InvestigationOutputValidator")
    assert calls and all(any(k.arg == "attack_reference" for k in c.keywords) for c in calls)
    assert _calls("services/case_service.py", "resolve_attack_reference")


def test_multisource_service_passes_the_reference_to_the_workflow_only_when_a_model_is_used():
    calls = _calls("services/multisource_investigation_service.py", "run_workflow")
    assert len(calls) == 1 and any(k.arg == "attack_reference" for k in calls[0].keywords)
    kw = next(k for k in calls[0].keywords if k.arg == "attack_reference")
    assert isinstance(kw.value, ast.IfExp) and isinstance(kw.value.orelse, ast.Constant) and kw.value.orelse.value is None


def test_the_workflow_passes_the_reference_to_its_validator():
    calls = _calls("modules/correlation/workflow.py", "InvestigationOutputValidator")
    assert len(calls) == 1 and any(k.arg == "attack_reference" for k in calls[0].keywords)


def test_other_validator_constructions_are_unchanged_and_the_unscoped_endpoint_is_not_wired():
    assert all(not c.keywords for c in _calls("services/investigation_service.py", "InvestigationOutputValidator"))
    assert not (BACKEND / "app" / "api" / "v1" / "endpoints" / "investigations.py").read_text(encoding="utf-8").count("attack_reference")
