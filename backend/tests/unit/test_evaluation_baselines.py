"""Baselines B0 and B1: arm definitions, and that they stay out of production code."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from app.modules.evaluation.baselines import ARMS, baseline_verdict, baseline_verdicts
from app.modules.evaluation.sufficiency_evaluator import build_context_from_case, load_cases


def case(events, entities, cid="t1"):
    return {
        "case_id": cid, "base_time_utc": "2026-01-01T00:00:00+00:00", "window": {"start_offset_s": 0, "end_offset_s": 600},
        "events": [{"key": k, "raw_evidence_sha256": sha, "event_id": "1", "event_type": "t", "timestamp_offset_s": i * 10, "action": "a",
                    "outcome": "success", "source_identifier": "s", "summary": "x"} for i, (k, sha) in enumerate(events)],
        "entities": [{"entity_type": "host", "entity_value": "h", "event_keys": ks} for ks in entities],
        "question": {"target_hosts": ["h"]},
    }


def test_b0_counts_any_two_records_sharing_an_entity_even_exact_duplicates():
    c = build_context_from_case(case([("a", "1" * 64), ("b", "1" * 64)], [["a", "b"]]))   # the same raw record twice
    assert baseline_verdict(c, "B0") == "SUFFICIENT"
    assert baseline_verdict(c, "B1") == "INSUFFICIENT"                                       # B1 collapses the duplicate


def test_two_distinct_records_sharing_an_entity_are_sufficient_for_both_arms():
    c = build_context_from_case(case([("a", "1" * 64), ("b", "2" * 64)], [["a", "b"]]))
    assert baseline_verdict(c, "B0") == baseline_verdict(c, "B1") == "SUFFICIENT"


def test_no_shared_entity_or_a_single_record_is_insufficient():
    assert baseline_verdict(build_context_from_case(case([("a", "1" * 64), ("b", "2" * 64)], [["a"], ["b"]])), "B0") == "INSUFFICIENT"
    assert baseline_verdict(build_context_from_case(case([("a", "1" * 64)], [["a"]])), "B1") == "INSUFFICIENT"


def test_unknown_arm_is_refused_and_a_baseline_never_says_limited():
    c = build_context_from_case(case([("a", "1" * 64)], [["a"]]))
    with pytest.raises(ValueError):
        baseline_verdict(c, "B2")
    dev = {c["case_id"]: build_context_from_case(c) for c in load_cases("dev")}              # manifest-verified, read-only
    for arm in ARMS:
        assert set(baseline_verdicts(dev, arm).values()) <= {"SUFFICIENT", "INSUFFICIENT"}
    assert len(baseline_verdicts(dev, "B0")) == len(dev)


def test_baselines_are_not_imported_by_production_code():
    root = Path(__file__).resolve().parents[2] / "app"
    offenders = []
    for p in root.rglob("*.py"):
        if p.name == "baselines.py":
            continue
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if (isinstance(n, ast.ImportFrom) and (n.module or "").endswith("evaluation.baselines")) or (isinstance(n, ast.Import) and any(a.name.endswith("evaluation.baselines") for a in n.names)):
                offenders.append(str(p))
    assert offenders == []
