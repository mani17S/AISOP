"""
Synthetic benchmark with ground truth by construction (backend/evaluation_tools/synthetic_benchmark.py).

A small instance (12 cases per family) pins the structure of the result: the same seed gives the same numbers; each rule added to the naive baseline can only
reduce false-sufficient calls; the gate makes no false-sufficient call when the vantage is known; and when the vantage is unknown the same-vantage family is
(wrongly) called SUFFICIENT every time, which is the documented limit of the rule. The numbers reported in the documents come from the final run in
docs/10_Research/Evaluation.md, not from this small instance.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location("synthetic_benchmark", _ROOT / "backend" / "evaluation_tools" / "synthetic_benchmark.py")
sb = importlib.util.module_from_spec(_SPEC)
sys.modules["synthetic_benchmark"] = sb
_SPEC.loader.exec_module(sb)  # type: ignore[union-attr]

_ANN = sb.run(7, 12, True)
_UNK = sb.run(7, 12, False)


def _fsr(result, arm):
    return result["arms"][arm]["false_sufficient"]["rate"]


def test_the_same_seed_gives_the_same_result():
    assert sb.run(7, 12, True)["arms"] == _ANN["arms"]


def test_each_added_rule_can_only_reduce_false_sufficient_calls():
    chain = [_fsr(_ANN, a) for a in ("B0", "B1", "B2", "B3", "B4", "AISOP")]
    assert chain == sorted(chain, reverse=True)
    assert chain[0] > 0.5 and chain[-1] == 0.0


def test_with_the_vantage_known_the_gate_makes_no_false_sufficient_call_and_misses_no_corroborated_case():
    assert _ANN["arms"]["AISOP"]["false_sufficient"]["k"] == 0
    assert _ANN["arms"]["AISOP"]["missed_sufficient"]["k"] == 0


def test_every_family_is_fixed_by_the_rule_that_targets_it():
    by = {a: _ANN["arms"][a]["false_sufficient_by_family"] for a in sb.ARMS}
    assert by["B1"]["exact_duplicate"]["rate"] < 0.2 < by["B0"]["exact_duplicate"]["rate"]
    assert by["B2"]["weak_link_only"]["rate"] == 0.0 < by["B1"]["weak_link_only"]["rate"]
    assert by["B2"]["placeholder_artefact"]["rate"] == 0.0 < by["B1"]["placeholder_artefact"]["rate"]
    assert by["B3"]["near_duplicate"]["rate"] == 0.0 < by["B2"]["near_duplicate"]["rate"]
    assert by["B4"]["delayed_copy"]["rate"] == 0.0 < by["B3"]["delayed_copy"]["rate"]
    assert by["AISOP"]["same_vantage"]["rate"] == 0.0 < by["B4"]["same_vantage"]["rate"]
    assert by["AISOP"]["out_of_window"]["rate"] == 0.0 < by["B4"]["out_of_window"]["rate"]


def test_when_the_vantage_is_unknown_the_same_vantage_family_cannot_be_caught():
    assert _UNK["arms"]["AISOP"]["false_sufficient_by_family"]["same_vantage"]["rate"] == 1.0
    assert _UNK["arms"]["AISOP"]["missed_sufficient"]["k"] == 0, "unknown vantage must never lower a corroborated verdict"


def test_no_generated_entity_value_is_empty():
    import random

    rng = random.Random(3)
    for family in sb.FAMILIES:
        case, _ = sb.generate(rng, family, 0)
        assert all(e["entity_value"] for e in case["entities"])
        assert case["question"]["root_event_key"] in {e["key"] for e in case["events"]}
