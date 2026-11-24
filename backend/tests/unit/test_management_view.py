"""
Management view (backend/app/modules/correlation/management_view.py): the one-screen summary for a security leader.

Pinned: the workload figures come from the pipeline's own counts; the telemetry gaps describe only the evidence that was supplied; every next step is a request
for more evidence (never a response action); bad input does not crash it; and the same input always gives the same view.
"""

from __future__ import annotations

import json
import re

from app.modules.correlation import demo_data as dd
from app.modules.correlation.management_view import ALL_DOMAINS, CAVEAT, COLLECT, NEXT_STEP, management_view
from app.modules.correlation.workflow import analyze
from app.modules.evidence_domains import scenarios as S


def test_workload_verdicts_telemetry_and_integrity_for_a_sufficient_multi_source_incident():
    view = management_view(analyze(S.scenario_b_network_endpoint()))
    assert view["workload"] == {"records": 4, "evidence_units": 4, "incidents": 1, "fewer_items_pct": 75.0}
    assert view["verdicts"] == {"sufficient": 1, "limited": 0, "insufficient": 0}
    assert view["telemetry"]["present"] == ["endpoint", "network"]
    assert view["telemetry"]["absent"] == ["identity", "cloud", "email"]
    assert set(view["telemetry"]["collect"]) == {"identity", "cloud", "email"}
    assert view["integrity"] == {"ledger_verified": True} and view["caveat"] == CAVEAT


def test_a_limited_incident_says_what_to_collect_next():
    view = management_view(analyze(dd.SCENARIOS["06_uncorroborated_single_alert"]["build"]()))
    assert view["verdicts"]["limited"] == 1
    steps = {s["reason_code"]: s for s in view["next_steps"]}
    assert "UNCORROBORATED_QUESTION" in steps and steps["UNCORROBORATED_QUESTION"]["incidents"] == 1
    assert "specific artefact" in steps["UNCORROBORATED_QUESTION"]["action"]


def test_disclosure_only_reasons_are_not_presented_as_things_to_fix():
    view = management_view(analyze(dd.SCENARIOS["02_duplicates_near_duplicates"]["build"]()))
    assert "DUPLICATE_EVIDENCE_COLLAPSED" not in {s["reason_code"] for s in view["next_steps"]}


def test_bad_input_does_not_crash_and_is_counted_as_a_data_quality_problem():
    view = management_view(analyze([{"junk": 1}, "not an object"]))
    assert view["workload"]["records"] == 0 and view["workload"]["fewer_items_pct"] is None
    assert view["data_quality"]["records_rejected"] == 2 and sum(view["data_quality"]["rejected_reasons"].values()) == 2
    assert view["telemetry"]["present"] == [] and view["telemetry"]["absent"] == list(ALL_DOMAINS)


def test_records_with_an_assumed_time_are_counted():
    records = [{"source_type": "linux_auth", "program": "sshd", "host": "h", "message": f"sshd[1]: Failed password for root from 203.0.113.5 port {i} ssh2",
                "timestamp": f"2015-12-10T06:55:{i:02d}"} for i in range(5)]
    view = management_view(analyze(records))
    assert view["data_quality"]["records_with_assumed_time"] == 5 and view["telemetry"]["present"] == ["identity"]


def test_no_next_step_or_collection_hint_is_a_response_action():
    banned = re.compile(r"\b(isolate|block|quarantine|contain|disable|delete|kill|reset|revoke|shut ?down|remediate)\b", re.I)
    texts = list(NEXT_STEP.values()) + list(COLLECT.values())
    assert not [t for t in texts if banned.search(t)], "the tool asks for evidence; it never prescribes a response"


def test_the_same_input_always_gives_the_same_view():
    a = json.dumps(management_view(analyze(S.scenario_b_network_endpoint())), sort_keys=True)
    b = json.dumps(management_view(analyze(S.scenario_b_network_endpoint())), sort_keys=True)
    assert a == b
