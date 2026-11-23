"""
Ablation arms B2 to B4 (backend/app/modules/evaluation/baselines.py) against the 67 development cases.

Pinned as behaviour, not accuracy: each added rule can only remove SUFFICIENT calls; the duplicate clustering is the rule that removes the
metamorphic violations; and on these cases four simple rules reproduce the gate's SUFFICIENT set exactly (so what the full gate adds shows up
on the non-sufficient side, the LIMITED tier). Development split only; the held-out split is never read here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location("ablation_sufficiency", _ROOT / "backend" / "evaluation_tools" / "ablation_sufficiency.py")
ab = importlib.util.module_from_spec(_SPEC)
sys.modules["ablation_sufficiency"] = ab
_SPEC.loader.exec_module(ab)  # type: ignore[union-attr]

_CASES = ab.load_cases("dev", ab.DEFAULT_BASE_DIR)
_VERDICTS = {c["case_id"]: ab.verdicts_for(c) for c in _CASES}


def _sufficient(arm: str) -> set[str]:
    return {cid for cid, v in _VERDICTS.items() if v[arm] == "SUFFICIENT"}


def test_each_added_rule_only_removes_sufficient_calls():
    chain = ["B0", "B1", "B2", "B3", "B4"]
    for earlier, later in zip(chain, chain[1:]):
        assert _sufficient(later) <= _sufficient(earlier), f"{later} must not call SUFFICIENT where {earlier} does not"


def test_the_development_counts_are_the_documented_ones():
    assert {a: len(_sufficient(a)) for a in ab.ARMS} == {"B0": 29, "B1": 24, "B2": 12, "B3": 12, "B4": 11, "AISOP": 11}


def test_four_simple_rules_reproduce_the_gates_sufficient_set_on_these_cases():
    assert _sufficient("B4") == _sufficient("AISOP")


def test_the_full_gate_adds_the_limited_tier_on_the_non_sufficient_side():
    not_sufficient_b4 = [cid for cid, v in _VERDICTS.items() if v["B4"] == "INSUFFICIENT"]
    assert {_VERDICTS[cid]["AISOP"] for cid in not_sufficient_b4} == {"LIMITED", "INSUFFICIENT"}
    assert sum(1 for cid in not_sufficient_b4 if _VERDICTS[cid]["AISOP"] == "LIMITED") == 52


def test_duplicate_clustering_is_what_removes_the_metamorphic_violations():
    def breaks(arm: str) -> int:
        total = 0
        for name, mutate, kind in ab.mm.RELATIONS:
            for case in _CASES:
                mutated = mutate(case)
                if mutated is not None and ab.mm.violated(kind, _VERDICTS[case["case_id"]][arm], ab.verdicts_for(mutated)[arm]):
                    total += 1
        return total

    assert breaks("B0") > breaks("B1") > breaks("B2") > 0
    assert breaks("B3") == breaks("B4") == breaks("AISOP") == 0


def test_an_unknown_ablation_arm_is_refused():
    import pytest

    ctx = ab.build_context_from_case(_CASES[0])
    with pytest.raises(ValueError):
        ab.ablation_verdict(ctx, "B9")
