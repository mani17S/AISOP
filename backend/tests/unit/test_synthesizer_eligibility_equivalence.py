"""
Backlog items 1, 6 and 7 (behaviour-preservation sprint): refactor guard and approved-invariant tests for the
``synthesizer.py`` taxonomy predicate sites.

Offline and synthetic (fixed UUIDs, no ``.env``, database, app start, network or model).

IMPORTANT, read before changing anything here:
* ``GOLDEN`` (``synthesizer_eligibility_golden.json``) is a record of the bundle produced by the synthesizer BEFORE the item 1
  refactor, for a fixed matrix of taxonomy states x tactics x confidences plus multi-hypothesis cases. It is a REFACTOR GUARD,
  not a statement of intended policy. It deliberately pins current behaviour (including behaviour owner decisions O3/O4/O9 may
  later change). A future, owner-approved policy change must regenerate it knowingly; it must never be edited to make a failing
  refactor pass.
* The invariant tests (second half) assert only properties that are already owner-stated or already implemented and approved.
  They do not assert any target severity value and do not decide O3, O4, O9 or the tactic risk table.
"""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from pathlib import Path

import pytest

from app.modules.ai.reporting import synthesizer as synth_mod
from app.modules.ai.reporting.synthesizer import DeterministicReportSynthesizer
from app.schemas.attack_taxonomy import SuccessorCandidate, TaxonomyState, TechniqueTaxonomyStatus
from app.schemas.investigation import ClaimCategory, FactualClaimItem, GroundingStatus, MitreAttackHypothesis
from tests.unit.test_deterministic_report_synthesizer import _make_sample_context, _make_sample_validation_result

GOLDEN_PATH = Path(__file__).with_name("synthesizer_eligibility_golden.json")

INV, EV = uuid.UUID(int=1), uuid.UUID(int=2)
STATES = [None] + [s.value for s in TaxonomyState]
TACTICS = {
    "execution": ["Execution"],
    "defense_evasion": ["Defense Evasion"],
    "impact": ["Impact"],
    "discovery": ["Discovery"],
    "c2": ["Command and Control"],
    "none": [],
    "multi": ["Execution", "Impact"],
}
CONFIDENCES = {"high": 0.9, "mid": 0.45, "edge": 0.39996, "zero": 0.0}


def _tax(state, tid):
    if state is None:
        return None
    succ = (SuccessorCandidate(attack_id="T1685.005", name="Clear Windows Event Logs", lifecycle="current"),) if state == "REVOKED" else ()
    safe_id = None if state == "INVALID" else tid                                      # an invalid id has no safely normalised form
    return TechniqueTaxonomyStatus(state=TaxonomyState(state), technique_id=safe_id, reason_code="X", successors=succ)


def _hyp(tid, state, tactics, conf):
    return MitreAttackHypothesis(technique_id=tid, technique_name="Some Technique", tactics=list(tactics),
                                 supporting_event_uuids=[EV], confidence=conf, reasoning="Model reasoning.", taxonomy=_tax(state, tid))


def _bundle(hypotheses):
    ctx = _make_sample_context(INV, EV)
    claim = FactualClaimItem(claim_id=uuid.UUID(int=3), claim_text="powershell.exe executed on WORKSTATION-01",
                             category=ClaimCategory.OBSERVED_FACT, supporting_evidence_ids=[EV], references_exist=True,
                             grounding_status=GroundingStatus.VALIDATED_REFERENCE, confidence=0.95, analyst_notes=None)
    vr = _make_sample_validation_result(INV, EV, ctx.reproducibility.context_sha256, claims=[claim], hypotheses=list(hypotheses))
    return DeterministicReportSynthesizer().synthesize_bundle(vr, ctx)


def _digest(bundle) -> str:
    return hashlib.sha256(json.dumps(bundle.model_dump(mode="json"), sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def all_cases() -> dict[str, list]:
    """case id -> list of hypotheses. Deterministic."""
    cases: dict[str, list] = {}
    for s in STATES:
        for tname, tacs in TACTICS.items():
            for cname, conf in CONFIDENCES.items():
                cases[f"single/{s}/{tname}/{cname}"] = [_hyp("T1059.001", s, tacs, conf)]
    cases["multi/empty"] = []
    cases["multi/current+revoked+deprecated"] = [_hyp("T1059.001", "CURRENT_VALID", ["Execution"], 0.9),
                                                 _hyp("T1070.001", "REVOKED", ["Defense Evasion"], 0.8),
                                                 _hyp("T1562", "DEPRECATED", ["Defense Evasion"], 0.7)]
    cases["multi/duplicate-technique-current-and-revoked"] = [_hyp("T1070.001", "CURRENT_VALID", ["Defense Evasion"], 0.9),
                                                              _hyp("T1070.001", "REVOKED", ["Defense Evasion"], 0.9)]
    cases["multi/duplicate-technique-two-revoked"] = [_hyp("T1070.001", "REVOKED", ["Execution"], 0.9),
                                                      _hyp("T1070.001", "REVOKED", ["Impact"], 0.5)]
    cases["multi/unknown+none+invalid"] = [_hyp("T9999", "UNKNOWN", ["Discovery"], 0.9),
                                           _hyp("T1082", None, ["Discovery"], 0.6),
                                           _hyp("TX", "INVALID", [], 0.0)]
    cases["multi/all-states-distinct-techniques"] = [_hyp(f"T10{i:02d}", s, ["Execution"], 0.9 - i * 0.05) for i, s in enumerate(STATES)]
    cases["multi/revoked-only-high-impact"] = [_hyp("T1070.001", "REVOKED", ["Impact"], 0.95)]
    return cases


def capture() -> dict[str, str]:
    """Used once, against the unmodified synthesizer, to create the golden file."""
    return {cid: _digest(_bundle(h)) for cid, h in all_cases().items()}


# ── refactor guard ──────────────────────────────────────────────────────────────────────────────────────────
def _golden() -> dict[str, str]:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def test_golden_covers_exactly_the_current_case_matrix():
    assert set(_golden()) == set(all_cases())


@pytest.mark.parametrize("case_id", sorted(all_cases()))
def test_full_bundle_is_identical_to_the_pre_refactor_output(case_id):
    assert _digest(_bundle(all_cases()[case_id])) == _golden()[case_id]


def test_the_obsolete_set_stays_inside_the_set_that_emits_a_state_key():
    """Display contract (kept after Item 2): every obsolete state still emits its ``taxonomy_state`` display key, so an obsolete
    hypothesis is always labelled in the mapping. The detection/hunting predicate no longer depends on this (see below)."""
    assert synth_mod._OBSOLETE_TAXONOMY_VALUES <= synth_mod._NOTABLE_TAXONOMY_VALUES
    assert synth_mod._OBSOLETE_TAXONOMY_VALUES == frozenset({"REVOKED", "DEPRECATED"})


# ── Item 2 (I2): the deferred dict-key predicate is gone; the three predicates keep their distinct contracts ─────
CONF_POINTS = [0.0, 0.2, 0.39996, 0.4, 0.45, 0.9]


@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("conf", CONF_POINTS)
def test_the_three_predicates_keep_their_exact_independent_contracts(state, conf):
    h = _hyp("T1059.001", state, ["Execution"], conf)
    obsolete = state in ("REVOKED", "DEPRECATED")
    assert synth_mod._is_coverage_target(h) is (conf > 0.0 and not obsolete)
    assert synth_mod._is_material_hypothesis(h) is (conf >= 0.40 and not obsolete)
    assert synth_mod._mapping_offered_as_current(h) is (round(conf, 4) >= 0.40 and not obsolete)


def test_the_rounding_edge_0_39996_separates_the_mapping_predicate_from_the_material_predicate():
    h = _hyp("T1059.001", "CURRENT_VALID", ["Execution"], 0.39996)
    assert synth_mod._mapping_offered_as_current(h) is True      # shown as 0.4 in the mapping
    assert synth_mod._is_material_hypothesis(h) is False         # raw value is below 0.40
    assert synth_mod._is_coverage_target(h) is True
    b = _bundle([h])
    assert b.technical_report.mitre_attack_mappings[0]["confidence"] == 0.4
    assert any("T1059.001" in c for c in _ideas(b, "T1059.001")) and _hunts(b, "T1059.001")


def test_the_method_that_used_the_display_key_now_takes_an_explicit_offered_list():
    import ast
    import inspect

    assert list(inspect.signature(DeterministicReportSynthesizer._generate_hunting_guidance).parameters) == ["self", "offered_mappings", "observables"]
    assert list(inspect.signature(synth_mod._mapping_offered_as_current).parameters) == ["hyp"]
    tree = ast.parse(Path(synth_mod.__file__).read_text(encoding="utf-8"))
    readers = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
                    and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "taxonomy_state"):
                readers.append(fn.name)
    assert readers == ["_taxonomy_suffix"]                          # only the display helper still reads the key
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "_generate_hunting_guidance"]
    assert len(calls) == 1 and isinstance(calls[0].args[0], ast.Name) and calls[0].args[0].id == "offered_mappings"


def test_hunting_guidance_no_longer_filters_by_itself_and_keeps_its_fallback():
    synth = DeterministicReportSynthesizer()
    given = [{"technique_id": "T1059.001", "technique_name": "PowerShell", "confidence": 0.1, "taxonomy_state": "REVOKED"}]
    out = synth._generate_hunting_guidance(given, [])
    assert len(out) == 1 and "T1059.001" in out[0]                # eligibility is the caller's decision from the hypothesis
    assert synth._generate_hunting_guidance([], []) == ["// No active hunting pseudocode generated for inconclusive or zero-tactic investigations."]


def test_a_display_key_alone_cannot_exclude_a_hypothesis_from_detection_or_hunting():
    """Obsolescence comes from the hypothesis' taxonomy, not from a key in a dict."""
    b = _bundle([_hyp("T1070.001", "CURRENT_VALID", ["Execution"], 0.9)])
    assert "T1070.001" in _targets(b) and _ideas(b, "T1070.001") and _hunts(b, "T1070.001")
    assert "taxonomy_state" not in b.technical_report.mitre_attack_mappings[0]


# ── invariants that are already approved or owner-stated and already hold (no target severity values) ──────────
def _targets(b):
    return set(b.detection_report.mitre_coverage_targets)


def _ideas(b, tid):
    return [c for c in b.detection_report.candidate_detection_hypotheses if tid in c]


def _hunts(b, tid):
    return [c for c in b.detection_report.candidate_hunting_pseudocode if tid in c]


@pytest.mark.parametrize("state", ["REVOKED", "DEPRECATED"])
def test_revoked_and_deprecated_are_never_offered_as_current_mappings_but_stay_visible(state):
    b = _bundle([_hyp("T1070.001", state, ["Defense Evasion"], 0.9)])
    assert "T1070.001" not in _targets(b) and not _ideas(b, "T1070.001") and not _hunts(b, "T1070.001")
    mapping = b.technical_report.mitre_attack_mappings
    assert [m["technique_id"] for m in mapping] == ["T1070.001"]                    # audit visibility preserved
    assert mapping[0]["taxonomy_state"] == state


@pytest.mark.parametrize("state", [s for s in STATES if s not in ("REVOKED", "DEPRECATED")])
def test_every_other_state_and_absent_taxonomy_is_not_filtered_out_of_the_mapping_list(state):
    b = _bundle([_hyp("T1059.001", state, ["Execution"], 0.9)])
    assert [m["technique_id"] for m in b.technical_report.mitre_attack_mappings] == ["T1059.001"]


@pytest.mark.parametrize("state", [None, "CURRENT_VALID", "NOT_CONFIGURED", "CATALOGUE_UNAVAILABLE", "UNKNOWN", "WRONG_DOMAIN", "INVALID"])
@pytest.mark.parametrize("tname", sorted(TACTICS))
@pytest.mark.parametrize("cname", ["high", "mid", "edge"])
def test_non_obsolete_taxonomy_status_never_changes_severity_or_its_justification(state, tname, cname):
    """Owner-stated direction: unknown/unvalidated taxonomy must not reduce (nor, per 'taxonomy alone cannot assert severity',
    raise) severity. States REVOKED/DEPRECATED are excluded on purpose: they currently leave the severity computation."""
    base = _bundle([_hyp("T1059.001", None, TACTICS[tname], CONFIDENCES[cname])])
    other = _bundle([_hyp("T1059.001", state, TACTICS[tname], CONFIDENCES[cname])])
    assert other.executive_brief.incident_severity == base.executive_brief.incident_severity
    assert other.executive_brief.severity_justification == base.executive_brief.severity_justification


@pytest.mark.parametrize("state", STATES)
def test_taxonomy_status_never_changes_evidence_confidence_or_claims(state):
    b = _bundle([_hyp("T1059.001", state, ["Execution"], 0.9)])
    assert b.technical_report.mitre_attack_mappings[0]["confidence"] == 0.9
    base = _bundle([_hyp("T1059.001", None, ["Execution"], 0.9)])
    assert b.executive_brief.model_dump(mode="json")["key_confirmed_findings"] == base.executive_brief.model_dump(mode="json")["key_confirmed_findings"]


def test_a_missing_taxonomy_is_not_treated_as_obsolete_and_not_as_a_state():
    b = _bundle([_hyp("T1059.001", None, ["Execution"], 0.9)])
    assert "T1059.001" in _targets(b)
    assert "taxonomy_state" not in b.technical_report.mitre_attack_mappings[0]


def test_mixed_report_filters_only_the_obsolete_hypotheses():
    b = _bundle([_hyp("T1059.001", "CURRENT_VALID", ["Execution"], 0.9), _hyp("T1070.001", "REVOKED", ["Execution"], 0.9),
                 _hyp("T1562", "DEPRECATED", ["Execution"], 0.9), _hyp("T9999", "UNKNOWN", ["Execution"], 0.9)])
    assert _targets(b) == {"T1059.001", "T9999"}
    assert len(b.technical_report.mitre_attack_mappings) == 4


def test_bundle_inputs_are_not_mutated_by_synthesis():
    hyps = [_hyp("T1070.001", "REVOKED", ["Execution"], 0.9)]
    before = copy.deepcopy([h.model_dump(mode="json") for h in hyps])
    _bundle(hyps)
    assert [h.model_dump(mode="json") for h in hyps] == before
