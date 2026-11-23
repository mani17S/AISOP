"""
The deterministic ATT&CK rules against the 20 hand-authored ground-truth scenarios.

What is asserted: the scorer runs cleanly on every scenario (no record rejected), and benign scenarios never produce a technique.
What is deliberately NOT asserted: recall. On 2026-11-23 the cautious rule table recovered 1 of 20 mandatory expected techniques;
that figure is reported in docs/12_User_Guides/Panel_Criticism_Validation.md, not hidden behind a threshold, and the rules were not
tuned to these scenarios. The scenarios and the rules share an author, so agreement would show consistency, not accuracy.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location("score_attack_mapping", _ROOT / "backend" / "evaluation_tools" / "score_attack_mapping.py")
sc = importlib.util.module_from_spec(_SPEC)
sys.modules["score_attack_mapping"] = sc
_SPEC.loader.exec_module(sc)  # type: ignore[union-attr]

_GT = _ROOT / "datasets" / "ground_truth"


def _scenarios(folder: str) -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((_GT / folder).glob("SCN-*.json"))]


def test_there_are_twenty_scenarios_across_the_four_families():
    counts = {f: len(_scenarios(f)) for f in ("atomic", "chain", "benign", "adversarial")}
    assert counts == {"atomic": 5, "chain": 5, "benign": 5, "adversarial": 5}


@pytest.mark.parametrize("scenario", _scenarios("benign"), ids=lambda s: s["scenario_id"])
def test_a_benign_scenario_produces_no_technique(scenario):
    assert sc.emitted(scenario["raw_telemetry_events"]) == set()


@pytest.mark.parametrize("folder", ["atomic", "chain", "adversarial"])
def test_every_scenario_record_is_accepted_by_the_pipeline(folder):
    for scenario in _scenarios(folder):
        sc.emitted(scenario["raw_telemetry_events"])  # raises SystemExit if any record was rejected


def test_a_technique_is_never_emitted_without_a_rule_and_evidence():
    from app.modules.correlation.mitre import map_techniques
    from app.modules.correlation.normalize import normalize_records

    for scenario in _scenarios("chain"):
        events = normalize_records([{**e, "provider": "microsoft-windows-sysmon"} for e in scenario["raw_telemetry_events"]]).events
        for m in map_techniques(events):
            assert m.rule_id and m.evidence_keys and m.independent_evidence_count >= 1 and m.limitation
