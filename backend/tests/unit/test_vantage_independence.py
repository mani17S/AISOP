"""
ADR-017: vantage-level independence in the sufficiency gate.

Two different raw records are different WITNESSES only if they were seen from different vantage points (a source type at a host, or an
explicit ``attributes["vantage"]``). When the whole chain of specific links around the key event carries a KNOWN vantage and it is one
vantage, the verdict is capped at LIMITED with ``SAME_VANTAGE_ONLY``. Unknown vantage never triggers it; it can only lower a verdict.
The hash-locked development cases carry no vantage, so their verdicts are unchanged (pinned in test_metamorphic and test_ablation).
"""

from __future__ import annotations

import copy

import pytest

from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency
from app.modules.correlation.workflow import analyze
from app.modules.evaluation.sufficiency_evaluator import DEFAULT_BASE_DIR, build_context_from_case, load_cases
from app.modules.evidence_domains import scenarios as S
from app.schemas.sufficiency import ReasonCode

RANK = {"insufficient": 0, "limited": 1, "sufficient": 2}
_CASES = load_cases("dev", DEFAULT_BASE_DIR)


def _verdict(case):
    a = evaluate_sufficiency(build_context_from_case(case))
    return a.verdict.value, {f.code for f in a.findings}


def _annotate(case, mode):
    c = copy.deepcopy(case)
    root = c["question"].get("root_event_key")
    for i, ev in enumerate(c["events"]):
        if mode == "one":
            vantage = "sensor-a"
        elif mode == "root_vs_rest":
            vantage = "sensor-a" if ev["key"] == root else "sensor-b"
        else:  # "each"
            vantage = f"sensor-{i}"
        ev.setdefault("attributes", {})["vantage"] = vantage
    return c


_SUFFICIENT = [c for c in _CASES if _verdict(c)[0] == "sufficient"]


def test_there_are_eleven_sufficient_development_cases_without_any_vantage():
    assert len(_SUFFICIENT) == 11


@pytest.mark.parametrize("case", _SUFFICIENT, ids=lambda c: c["case_id"])
def test_a_corroborated_case_seen_from_one_vantage_falls_to_limited_with_the_reason(case):
    verdict, codes = _verdict(_annotate(case, "one"))
    assert verdict == "limited" and ReasonCode.SAME_VANTAGE_ONLY in codes


@pytest.mark.parametrize("mode", ["root_vs_rest", "each"])
def test_corroboration_from_a_different_vantage_stays_sufficient(mode):
    for case in _SUFFICIENT:
        verdict, codes = _verdict(_annotate(case, mode))
        assert verdict == "sufficient" and ReasonCode.SAME_VANTAGE_ONLY not in codes, case["case_id"]


def test_an_unknown_vantage_never_triggers_the_cap():
    for case in _SUFFICIENT:
        c = _annotate(case, "one")
        del c["events"][-1]["attributes"]["vantage"]  # one record has no vantage: it cannot be called the same
        verdict, codes = _verdict(c)
        assert ReasonCode.SAME_VANTAGE_ONLY not in codes


def test_no_annotation_means_no_change_to_any_development_verdict():
    assert sorted(_verdict(c)[0] for c in _CASES).count("sufficient") == 11
    assert not any(ReasonCode.SAME_VANTAGE_ONLY in _verdict(c)[1] for c in _CASES)


@pytest.mark.parametrize("mode", ["one", "root_vs_rest", "each"])
def test_the_rule_can_only_lower_a_verdict_never_raise_it(mode):
    for case in _CASES:
        before = RANK[_verdict(case)[0]]
        after = RANK[_verdict(_annotate(case, mode))[0]]
        assert after <= before, f"{case['case_id']}: {mode}"


def test_a_chain_carried_by_several_vantage_points_stays_sufficient():
    """Hash links the file to the process artefact; a public IP links those to DNS and firewall records: three vantage points, one story."""
    result = analyze(S.scenario_b_network_endpoint())
    assessment = result.incidents[0].assessment
    assert assessment.verdict.value == "sufficient"
    assert ReasonCode.SAME_VANTAGE_ONLY not in {f.code for f in assessment.findings}


def test_two_records_from_one_collector_sharing_a_hash_are_one_witness():
    records = [
        S.env("forensic.file", "dfir-collector-synthetic", {"host": "ws-fin-07", "path": "C:\\Users\\Public\\svc.exe", "sha256": S.SHA_TOOL},
              t="2026-11-04T09:59:50Z", method="triage_collection"),
        S.env("forensic.process_artifact", "dfir-collector-synthetic", {"host": "ws-fin-07", "image": "C:\\Users\\Public\\svc.exe", "sha256": S.SHA_TOOL,
                                                                       "source_artifact": "process_listing"}, t="2026-11-04T10:00:08Z", method="triage_collection"),
    ]
    assessment = analyze(records).incidents[0].assessment
    codes = {f.code for f in assessment.findings}
    assert assessment.verdict.value == "limited" and ReasonCode.SAME_VANTAGE_ONLY in codes


def test_the_reason_is_explained_in_plain_words_for_the_analyst():
    from app.modules.correlation.report import REASON_EXPLANATIONS as _REASON_TEXT  # noqa: PLC0415

    assert "one vantage point" in _REASON_TEXT["SAME_VANTAGE_ONLY"]
