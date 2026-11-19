"""
Stage 3C-R: evaluation metrics (hand-computed) and dataset structure (stratification, opaque ids).

The labelled-evaluation plumbing test writes a TEST-ONLY labels file into a temporary copy of the
dataset; no owner label is ever created in the repository.
"""

from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict
from pathlib import Path

import pytest

from app.modules.evaluation import sufficiency_evaluator as se
from app.modules.evaluation.sufficiency_evaluator import (
    compute_agreement,
    compute_metrics,
    coverage_risk,
    evaluate_split,
    load_cases,
    per_class_metrics,
    weighted_kappa,
    wilson_interval,
)

PAIRS = [  # (owner label, gate prediction): hand-computable example, not real data
    ("SUFFICIENT", "SUFFICIENT"), ("SUFFICIENT", "LIMITED"),
    ("LIMITED", "SUFFICIENT"), ("LIMITED", "LIMITED"),
    ("INSUFFICIENT", "INSUFFICIENT"), ("INSUFFICIENT", "SUFFICIENT"),
    ("LIMITED", "INSUFFICIENT"),
]


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_per_class_precision_recall_f1_and_macro_f1():
    m = per_class_metrics(PAIRS)
    s, l, i = m["per_class"]["SUFFICIENT"], m["per_class"]["LIMITED"], m["per_class"]["INSUFFICIENT"]
    assert (s["precision"], s["recall"], s["f1"]) == (round(1 / 3, 4), 0.5, 0.4)        # TP1 FP2 FN1
    assert (l["precision"], l["recall"], l["f1"]) == (0.5, round(1 / 3, 4), 0.4)        # TP1 FP1 FN2
    assert (i["precision"], i["recall"], i["f1"]) == (0.5, 0.5, 0.5)                    # TP1 FP1 FN1
    assert m["macro_f1"] == round((0.4 + 0.4 + 0.5) / 3, 4)
    assert m["macro_f1_classes_undefined"] == []


def test_undefined_classes_are_reported_not_zeroed():
    m = per_class_metrics([("LIMITED", "LIMITED"), ("LIMITED", "SUFFICIENT")])
    assert m["per_class"]["INSUFFICIENT"]["f1"] is None and m["per_class"]["INSUFFICIENT"]["precision"] is None
    assert "INSUFFICIENT" in m["macro_f1_classes_undefined"]
    assert per_class_metrics([])["macro_f1"] is None


def test_coverage_versus_risk_operating_points():
    cr = coverage_risk(PAIRS)
    assert cr["abstain_only"] == {"coverage": round(5 / 7, 4), "risk": 0.2}             # 1 INSUFFICIENT label among 5 proceeded
    assert cr["strict"] == {"coverage": round(3 / 7, 4), "risk": round(2 / 3, 4)}       # 2 of 3 predicted SUFFICIENT are not
    assert coverage_risk([])["strict"]["risk"] is None


def test_compute_metrics_exposes_every_required_measure():
    m = compute_metrics(PAIRS)
    for key in ("confusion_matrix", "accuracy", "per_class", "macro_f1", "coverage_risk", "false_sufficient_rate",
                "false_insufficient_rate", "predicted_abstention_rate", "label_insufficient_rate", "confidence_intervals_95"):
        assert key in m
    assert m["label_insufficient_rate"] == round(2 / 7, 4)
    lo, hi = m["confidence_intervals_95"]["false_sufficient_rate"]
    assert lo <= 0.4 <= hi


def test_wilson_interval_known_values():
    assert wilson_interval(0, 0) is None
    lo, hi = wilson_interval(5, 10)
    assert round(lo, 2) == 0.24 and round(hi, 2) == 0.76
    assert wilson_interval(0, 10)[0] == 0.0


def test_weighted_kappa_and_agreement():
    a = ["SUFFICIENT", "SUFFICIENT", "LIMITED", "LIMITED", "INSUFFICIENT", "INSUFFICIENT"]
    assert weighted_kappa(a, a) == 1.0
    one_step = ["SUFFICIENT", "LIMITED", "LIMITED", "LIMITED", "INSUFFICIENT", "INSUFFICIENT"]
    two_step = ["INSUFFICIENT", "SUFFICIENT", "LIMITED", "LIMITED", "INSUFFICIENT", "INSUFFICIENT"]
    k1, k2 = weighted_kappa(a, one_step), weighted_kappa(a, two_step)
    assert 0 < k2 < k1 < 1                      # a two-level disagreement costs more than a one-level one
    assert weighted_kappa(["LIMITED"] * 4, ["LIMITED"] * 4) is None   # no variance: undefined, not 1
    ag = compute_agreement({"x": {"label": "LIMITED"}, "y": {"label": "SUFFICIENT"}},
                           {"x": {"label": "LIMITED"}, "y": {"label": "LIMITED"}, "z": {"label": "LIMITED"}})
    assert ag["n_common"] == 2 and ag["raw_agreement"] == 0.5 and ag["disagreements"] == ["y"]


# ── dataset structure ─────────────────────────────────────────────────────────
def test_case_ids_are_opaque():
    for split in ("dev", "heldout"):
        for case in load_cases(split):
            assert re.fullmatch(r"SUFC-[0-9a-f]{10}", case["case_id"]), case["case_id"]
            for name in (case["transform"], case["base_scenario_id"], "SCN-", "empty_scope", "provenance"):
                assert name not in case["case_id"]


def test_split_is_stratified_by_family_and_leak_free():
    fam_split: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    bases: dict[str, set[str]] = defaultdict(set)
    for split in ("dev", "heldout"):
        for case in load_cases(split):
            fam_split[case["family"]][split] += 1
            bases[split].add(case["base_scenario_id"])
    for family in ("multi_stage_chain", "atomic_technique", "benign_baseline", "adversarial_ambiguous"):
        assert fam_split[family]["dev"] > 0 and fam_split[family]["heldout"] > 0, family
    # no base scenario appears in both splits, except the GLOBAL cases that reuse the first scenario id
    global_bases = {c["base_scenario_id"] for c in load_cases("dev") if c["family"] == "global"}
    real_dev = {c["base_scenario_id"] for c in load_cases("dev") if c["family"] != "global"}
    assert not (real_dev & bases["heldout"]) and not (global_bases & bases["heldout"])


def test_new_independence_transforms_are_present():
    transforms = {c["transform"] for s in ("dev", "heldout") for c in load_cases(s)}
    assert {"near_duplicate", "host_user_only_links", "same_record_pair", "independently_corroborated"} <= transforms


# ── labelled-evaluation plumbing (TEST-ONLY labels in a temp copy) ────────────
@pytest.mark.anyio
async def test_labelled_evaluation_reports_all_metrics_from_test_only_labels(tmp_path: Path):
    dst = tmp_path / "ds"
    shutil.copytree(se.DEFAULT_BASE_DIR, dst)
    for f in dst.rglob("*"):
        if f.is_file():
            f.chmod(0o666)
    cases = load_cases("dev", dst)
    cycle = ["SUFFICIENT", "LIMITED", "INSUFFICIENT"]
    labels = {c["case_id"]: {"label": cycle[i % 3], "justification": "TEST-ONLY plumbing label"} for i, c in enumerate(cases)}
    (dst / "dev" / "labels.json").write_text(json.dumps({"labels": labels}), encoding="utf-8")
    (dst / "dev" / "labels.reviewer2.json").write_text(json.dumps({"labels": labels}), encoding="utf-8")
    report = await evaluate_split("dev", dst)
    assert report["labels_available"] is True and report["labelled_cases"] == len(cases)
    assert {"per_class", "macro_f1", "coverage_risk", "confidence_intervals_95"} <= set(report["metrics"])
    assert report["inter_reviewer_agreement"]["weighted_kappa"] == 1.0
    assert report["model_invocation_prevention_rate_label_insufficient"] is not None
    # null labels (ambiguous, needs review) are excluded, not guessed
    first = cases[0]["case_id"]
    labels[first] = {"label": None, "justification": "needs review", "status": "needs_review"}
    (dst / "dev" / "labels.json").write_text(json.dumps({"labels": labels}), encoding="utf-8")
    report2 = await evaluate_split("dev", dst)
    assert report2["labelled_cases"] == len(cases) - 1


@pytest.mark.anyio
async def test_unlabelled_dev_evaluation_reports_metrics_as_unavailable():
    if (se.DEFAULT_BASE_DIR / "dev" / "labels.json").exists():
        pytest.skip("owner labels exist; the unlabelled path is not applicable")
    report = await evaluate_split("dev")
    assert str(report["metrics"]).startswith("UNAVAILABLE") and "accuracy" not in json.dumps(report)
    assert str(report["inter_reviewer_agreement"]).startswith("UNAVAILABLE")
