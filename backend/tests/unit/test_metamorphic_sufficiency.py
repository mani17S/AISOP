"""
Metamorphic properties of the sufficiency gate on the 67 development cases (backend/evaluation_tools/metamorphic_sufficiency.py).

These pin what AISOP claims: duplicates, near-duplicates and host-only context never make the verdict stronger; record order and
instruction text inside evidence never change it. They also pin, as a measured fact and not a goal, that the naive baselines DO
break these rules, so the comparison stays meaningful. Development split only; the held-out split is never touched here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location("metamorphic_sufficiency", _ROOT / "backend" / "evaluation_tools" / "metamorphic_sufficiency.py")
mm = importlib.util.module_from_spec(_SPEC)
sys.modules["metamorphic_sufficiency"] = mm
_SPEC.loader.exec_module(mm)  # type: ignore[union-attr]

_CASES = mm.load_cases("dev", mm.DEFAULT_BASE_DIR)


def _count(mutate, kind, arm):
    applicable = violations = 0
    for case in _CASES:
        mutated = mutate(case)
        if mutated is None:
            continue
        applicable += 1
        if mm.violated(kind, mm.verdicts(case)[arm], mm.verdicts(mutated)[arm]):
            violations += 1
    return applicable, violations


def test_the_manifest_is_intact_and_there_are_67_development_cases():
    mm.verify_manifest(mm.DEFAULT_BASE_DIR)
    assert len(_CASES) == 67


@pytest.mark.parametrize("name,mutate,kind", mm.RELATIONS, ids=[r[0] for r in mm.RELATIONS])
def test_the_gate_never_breaks_a_relation(name, mutate, kind):
    applicable, violations = _count(mutate, kind, "AISOP")
    assert applicable > 0
    assert violations == 0, f"{name}: AISOP broke the relation on {violations} of {applicable} cases"


def test_the_naive_baselines_do_break_the_duplicate_relations():
    # B0 counts every copy as corroboration; B1 removes only byte-identical copies, so a near-duplicate fools it.
    assert _count(mm.exact_duplicate, "not_higher", "B0")[1] > 0
    assert _count(mm.near_duplicate, "not_higher", "B1")[1] > 0
    assert _count(mm.weak_context_only, "not_higher", "B0")[1] > 0


def test_a_mutation_never_changes_the_original_case():
    case = _CASES[0]
    before = repr(case)
    for _, mutate, _ in mm.RELATIONS:
        mutate(case)
    assert repr(case) == before
