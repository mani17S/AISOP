"""
The rubric oracle (backend/evaluation_tools/rubric_oracle.py) is a reference implementation of the labelling guide, written only from the guide's text.

Pinned: it agrees with the gate on every judged development case; and it disagrees on the situations the guide is silent about (a delayed copy of the
same observation, records from one vantage, placeholder artefacts), which is exactly the finding recorded in
docs/10_Research/Evaluation/Labelling_Guide_Addendum_PROPOSED.md. If the guide or the gate changes, these tests say so.
"""

from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _ROOT / "backend" / "evaluation_tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


ro = _load("rubric_oracle")
sb = _load("synthetic_benchmark")


def test_the_oracle_agrees_with_the_gate_on_every_judged_development_case():
    cases = ro.load_cases("dev", ro.DEFAULT_BASE_DIR)
    judged = [c for c in cases if c["transform"] != "contradictory"]
    assert len(judged) == 65
    for case in judged:
        gate = ro.evaluate_sufficiency(ro.build_context_from_case(case)).verdict.value.upper()
        assert ro.rubric_label(case) == gate, case["case_id"]


def test_kappa_is_one_for_identical_labels_and_lower_otherwise():
    assert ro.kappa([("SUFFICIENT", "SUFFICIENT"), ("LIMITED", "LIMITED"), ("INSUFFICIENT", "INSUFFICIENT")]) == 1.0
    assert ro.kappa([("SUFFICIENT", "LIMITED"), ("LIMITED", "SUFFICIENT"), ("LIMITED", "LIMITED"), ("SUFFICIENT", "SUFFICIENT")]) < 1.0


def test_the_guide_is_silent_where_the_gate_is_strict():
    rng = random.Random(11)
    counts = {f: 0 for f in ("delayed_copy", "same_vantage", "placeholder_artefact", "weak_link_only", "lone_event")}
    for family in counts:
        for i in range(20):
            case, _ = sb.generate(rng, family, i)
            counts[family] += ro.rubric_label(case) == "SUFFICIENT"
    assert counts["delayed_copy"] == 20 and counts["same_vantage"] == 20 and counts["placeholder_artefact"] > 0
    assert counts["weak_link_only"] == 0 and counts["lone_event"] == 0, "where the guide is explicit, the oracle must not call SUFFICIENT"
