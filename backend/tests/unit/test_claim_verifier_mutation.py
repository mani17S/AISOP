"""
Mutation evaluation of the claim verifier (backend/evaluation_tools/claim_verifier_mutation.py) on the 67 development contexts.

Pinned: every assertion that is true by construction is accepted; no assertion that is false by construction is ever called SUPPORTED; no exception
escapes. These are behaviour facts about the checker's contract on structured assertions, not a measure of how often a model's claims are right.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location("claim_verifier_mutation", _ROOT / "backend" / "evaluation_tools" / "claim_verifier_mutation.py")
cm = importlib.util.module_from_spec(_SPEC)
sys.modules["claim_verifier_mutation"] = cm
_SPEC.loader.exec_module(cm)  # type: ignore[union-attr]

_RESULT = cm.evaluate(cm.load_cases("dev", cm.DEFAULT_BASE_DIR))


def test_every_true_assertion_is_accepted():
    assert _RESULT["true"] == {"supported": 2478}


def test_no_false_assertion_is_ever_called_supported():
    assert _RESULT["false_supported"] == []
    assert sum(sum(c.values()) for c in _RESULT["faults"].values()) == 1737


def test_no_exception_escapes_the_verifier():
    assert _RESULT["crashes"] == 0


def test_each_fault_class_gets_the_documented_outcome():
    f = _RESULT["faults"]
    assert set(f["F3"]) == {"contradicted"} and set(f["F4"]) == {"contradicted"} and set(f["F7"]) == {"contradicted"}
    assert set(f["F1"]) == set(f["F2"]) == set(f["F5"]) == set(f["F6"]) == set(f["F8"]) == set(f["F11"]) == {"insufficient_evidence"}
    assert set(f["F12"]) == {"contradicted"}, "look-alike values must never match"
    assert set(f["F10"]) == {"contradicted"}, "one false assertion must poison the whole claim"
    assert "supported" not in f["F9"]
