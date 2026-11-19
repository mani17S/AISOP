"""
Stage 6A: executable SPECIFICATION of the contradiction-aware evidence model (design: docs/Architecture/AISOP_ARCHITECTURE_EVOLUTION_PLAN.md,
section 10). Written BEFORE the implementation, from a probe of the current engine (2026-11-12).

* Plain tests pin behaviour that is already correct and must not regress.
* ``xfail(strict=True)`` tests state the desired behaviour that the current engine does NOT have. They are expected to fail today; when
  the contradiction model is implemented they will start passing, strict mode then fails the run and forces the marker to be removed,
  so the specification cannot be forgotten or silently ignored.

No evaluation ground-truth label is touched. No sufficiency rule is changed by this file.
"""

from __future__ import annotations

import pytest

from app.modules.correlation.workflow import analyze
from app.modules.evidence_domains import scenarios as S

IP = S.ATTACKER_IP
env = S.env


def sole(records):
    res = analyze(records)
    assert len(res.incidents) == 1, "scenario must form exactly one incident"
    return res, res.incidents[0]


# ── already correct: must not regress ────────────────────────────────────────
def test_same_event_reported_by_two_independent_sources_is_corroboration_not_a_contradiction():
    res, a = sole([env("identity.signin", "idp-a", {"user": "u1.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z"),
                   env("identity.signin", "idp-b", {"user": "u1.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:01Z")])
    assert res.correlation.contradictions == [] and a.assessment.corroborating_events == 1


def test_duplicate_raw_record_counts_once_and_is_not_a_contradiction():
    rec = env("identity.signin", "idp-a", {"user": "u2.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z")
    res, a = sole([rec, dict(rec)])
    assert res.correlation.contradictions == [] and a.assessment.corroborating_events == 0 and a.assessment.verdict.value != "sufficient"


def test_failure_then_success_by_retry_forty_seconds_apart_is_a_benign_explanation_not_a_contradiction():
    res, a = sole([env("identity.signin", "idp-a", {"user": "u6.example", "ip": IP, "result": "failure"}, t="2026-11-07T09:00:00Z"),
                   env("identity.signin", "idp-a", {"user": "u6.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:40Z")])
    assert res.correlation.contradictions == []


def test_insufficient_evidence_is_never_sufficient():
    res, a = sole([env("identity.signin", "idp-a", {"user": "u7.example", "ip": "10.2.2.2", "result": "success"}, t="2026-11-07T09:00:00Z")])
    assert a.assessment.verdict.value != "sufficient" and a.assessment.corroborating_events == 0


def test_contradictory_network_observations_are_at_least_visible_today():
    res, a = sole(_network_conflict())
    assert [c.reason for c in res.correlation.contradictions] == ["OUTCOME_CONFLICT_WITHIN_2S"] and a.graph.contradictions
    # Updated 2026-11-12 (ADR-013 implemented): the interim notice added at Stage 6 closure is replaced by the structured block.
    assert "**Contradictions (ADR-013).**" in a.markdown and "Contradiction notice" not in a.markdown


def _network_conflict():
    return [env("network.firewall", "fw-a", {"src_ip": "10.1.1.5", "dst_ip": S.C2_IP, "dst_port": 443, "action": "deny", "host": "h5"}, t="2026-11-07T09:00:00Z"),
            env("network.flow", "flow-b", {"src_ip": "10.1.1.5", "dst_ip": S.C2_IP, "dst_port": 443, "action": "allow", "host": "h5"}, t="2026-11-07T09:00:01Z")]


# ── desired behaviour NOT yet implemented (strict xfail = executable to-do list) ──
def test_unexplained_cross_sensor_network_contradiction_caps_the_verdict_at_limited():
    _res, a = sole(_network_conflict())
    assert a.assessment.verdict.value in ("limited", "insufficient")


def test_conflicting_records_do_not_corroborate_each_other():
    _res, a = sole(S.negative_contradiction())
    assert a.assessment.corroborating_events == 0


def test_cross_sensor_signin_conflict_caps_the_verdict_at_limited():
    _res, a = sole(S.negative_contradiction())
    assert a.assessment.verdict.value in ("limited", "insufficient")


def test_conflicting_identity_attribution_for_one_session_is_reported():
    # Fixture corrected 2026-11-12 (ADR-013 D3): issuer-scoped session + canonical principals; see test_contradiction_matrix_spec.py (S4).
    res, _a = sole([env("identity.signin", "idp-a", {"user": "alice.example", "ip": IP, "session_id": "s-1", "result": "success",
                                                     "canonical_id": "P-100", "canonical_id_issuer": "corp-dir"}, t="2026-11-07T09:00:00Z"),
                    env("cloud.api_call", "cloud-a", {"actor": "bob.example", "action": "ListBuckets", "resource": "bucket/x", "source_ip": IP,
                                                      "session_id": "s-1", "session_issuer": "idp-a",
                                                      "canonical_id": "P-200", "canonical_id_issuer": "corp-dir"}, t="2026-11-07T09:00:30Z")])
    assert any("IDENTITY" in c.reason for c in res.correlation.contradictions)

def test_conflicting_timestamps_for_the_same_native_event_are_reported():
    # Fixture corrected 2026-11-12 (ADR-013 D4): an issuer-scoped correlation id, not a source-native id; see the matrix file (S6).
    corr = {"issuer": "gateway-1", "id": "req-77"}
    res, _a = sole([env("cloud.api_call", "ct-a", {"actor": "u4.example", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T09:00:00Z", correlation=corr),
                    env("cloud.api_call", "ct-b", {"actor": "u4.example", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T13:00:00Z", correlation=corr)])
    assert any("TEMPORAL" in c.reason or "TIMESTAMP" in c.reason for c in res.correlation.contradictions)
