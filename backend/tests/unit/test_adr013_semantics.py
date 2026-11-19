"""
ADR-013 Revision 2, remaining semantics (owner decisions D1 to D6, 2026-11-12): identity, temporal, outcome-window boundaries, evidence
independence (mirrored / shared upstream), and the new optional source-stated fields. Deterministic fixtures, offline.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.modules.correlation import correlator
from app.modules.correlation.normalize import raw_digest, normalize_records
from app.modules.correlation.workflow import analyze, run_workflow
from app.modules.evidence_domains import scenarios as S
from app.modules.evidence_domains.adapters import EvidenceFormatError, parse_record
from app.modules.evidence_domains.contradictions import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    IDENTITY_RELEVANCE_WINDOW_SECONDS,
    OUTCOME_CONFLICT_WINDOW_SECONDS,
    classify_materiality,
    detect_contradictions,
    source_independence,
)
from app.modules.evidence_domains.ti import IndicatorMatch, StaticIndicatorSet
from app.schemas.contradiction import ContradictionKind, HypothesisRelation, Materiality
from tests.unit.test_multisource_api import ScriptedProvider

env = S.env
IP = S.ATTACKER_IP


def obs(record, index=0):
    d = raw_digest(record)
    return parse_record(record, key=uuid.uuid5(uuid.NAMESPACE_URL, f"{d}:{index}"), record_index=index, raw_sha256=d)


def many(records):
    return [obs(r, i) for i, r in enumerate(records)]


# ══ constants: one value each, reused ════════════════════════════════════════
def test_constants_are_the_approved_values_and_reuse_the_existing_ones():
    assert CLOCK_SKEW_TOLERANCE_SECONDS == 5.0                                             # D1
    assert OUTCOME_CONFLICT_WINDOW_SECONDS == correlator.CONTRADICTION_WINDOW_SECONDS == 2.0   # D2: the existing constant, not a second value
    assert IDENTITY_RELEVANCE_WINDOW_SECONDS == correlator.SPECIFIC_WINDOW_SECONDS         # the existing specific-link window


# ══ D2: outcome window boundaries ════════════════════════════════════════════
def signin_pair(gap_seconds: float, src_b="idp-b"):
    ms = int(round(gap_seconds * 1000))
    return [env("identity.signin", "idp-a", {"user": "u.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:10.000Z"),
            env("identity.signin", src_b, {"user": "u.example", "ip": IP, "result": "failure"},
                t=f"2026-11-07T09:00:{10 + ms // 1000:02d}.{ms % 1000:03d}Z")]


@pytest.mark.parametrize("gap, compared", [(1.999, True), (2.0, True), (2.001, False)])
def test_outcome_window_boundaries_below_at_and_above_the_threshold(gap, compared):
    assert (len(detect_contradictions(many(signin_pair(gap)))) == 1) is compared
    a = analyze(signin_pair(gap)).incidents
    assert any(i.assessment.contradictions for i in a) is compared


def test_outcome_window_compares_only_the_same_proposition_not_any_nearby_records():
    mfa_then_signin = [env("identity.mfa", "idp-a", {"user": "u.example", "ip": IP, "result": "denied"}, t="2026-11-07T09:00:10Z"),
                       env("identity.signin", "idp-b", {"user": "u.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:11Z")]
    different_ip = [env("identity.signin", "idp-a", {"user": "u.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:10Z"),
                    env("identity.signin", "idp-b", {"user": "u.example", "ip": "8.8.4.4", "result": "failure"}, t="2026-11-07T09:00:11Z")]
    assert detect_contradictions(many(mfa_then_signin)) == () and detect_contradictions(many(different_ip)) == ()


# ══ D1: ordering tolerance, causal requirement, event vs ingestion time ═════
def ordering(file_time="2026-11-05T07:00:00Z", **file_data):
    recs = [dict(r) for r in S.scenario_c_email_forensic()]
    for r in recs:
        if r["evidence_type"] == "forensic.file":
            r["event_time"] = file_time
            r["data"] = dict(r["data"], **file_data)
    return recs


CAUSAL = {"origin_message_id": "<inv-8841@invoice-portal.test>", "timestamp_semantics": "arrival"}


def test_a_reversal_over_the_tolerance_without_a_causal_relationship_is_not_a_contradiction():
    for extra in ({}, {"timestamp_semantics": "arrival"}, {"origin_message_id": "<inv-8841@invoice-portal.test>"},
                  {"origin_message_id": "<other@x.test>", "timestamp_semantics": "arrival"},
                  {**CAUSAL, "timestamp_semantics": "modification"}, {**CAUSAL, "timestamp_semantics": "collection"}):
        assert detect_contradictions(many(ordering(**extra))) == (), extra


def test_event_time_is_not_confused_with_collection_or_ingestion_time():
    recs = ordering(file_time="2026-11-05T08:21:00Z", **CAUSAL)                          # event time AFTER the e-mail: consistent
    for r in recs:
        if r["evidence_type"] == "forensic.file":
            r["collected_at"] = "2026-11-05T07:00:00Z"                                    # collection time earlier: must be ignored
    assert detect_contradictions(many(recs)) == ()
    o = next(x for x in many(recs) if x.evidence_type == "forensic.file")
    assert o.collected_at is not None and o.event_time > o.collected_at


def test_missing_and_invalid_event_times_are_never_invented_for_ordering():
    for t in (None, "not a time", "1850-01-01T00:00:00Z"):
        recs = ordering(**CAUSAL)
        for r in recs:
            if r["evidence_type"] == "forensic.file":
                if t is None:
                    r.pop("event_time", None)
                else:
                    r["event_time"] = t
        assert detect_contradictions(many(recs)) == ()
    assert analyze(ordering(**CAUSAL)[:2]).incidents[0].assessment.contradictions == []


def test_low_quality_time_is_disclosed_as_minor_and_the_technique_is_kept():
    cands = detect_contradictions(many(ordering(file_time="2026-11-05T07:00:00", **CAUSAL)))   # no time zone
    assert cands[0].time_quality == ("valid", "naive_assumed_utc") and cands[0].explanation.value == "timezone_assumed"
    a = analyze(ordering(file_time="2026-11-05T07:00:00", **CAUSAL)).incidents[0]
    assert a.assessment.verdict.value == "sufficient" and [c.materiality.value for c in a.assessment.contradictions] == ["minor"]


def test_timezone_offsets_are_normalised_for_both_ordering_and_temporal():
    assert len(detect_contradictions(many(ordering(file_time="2026-11-05T13:00:00+05:30", **CAUSAL)))) == 1    # 07:30Z < 08:00Z
    assert detect_contradictions(many(ordering(file_time="2026-11-05T13:35:00+05:30", **CAUSAL))) == ()        # 08:05Z > 08:00Z
    corr = {"issuer": "gw", "id": "r1"}
    same_instant = [env("cloud.api_call", "ct-a", {"actor": "u", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T09:00:00Z", correlation=corr),
                    env("cloud.api_call", "ct-b", {"actor": "u", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T14:30:00+05:30", correlation=corr)]
    assert detect_contradictions(many(same_instant)) == ()                                                    # the same instant in two zones


# ══ D4: temporal ═════════════════════════════════════════════════════════════
def temporal(gap_seconds: float, **kw):
    corr = {"issuer": "gateway-1", "id": "req-1"}
    t0 = datetime(2026, 11, 7, 9, 0, 1, tzinfo=timezone.utc)
    t2 = (t0 + timedelta(seconds=gap_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return [env("cloud.api_call", "ct-a", {"actor": "u.example", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T09:00:01.000Z", correlation=corr, **kw.get("a", {})),
            env("cloud.api_call", kw.get("system_b", "ct-b"), {"actor": "u.example", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t=t2, correlation=corr, **kw.get("b", {}))]


@pytest.mark.parametrize("gap, found", [(4.999, False), (5.0, False), (5.001, True)])
def test_temporal_tolerance_boundaries(gap, found):
    assert (len(detect_contradictions(many(temporal(gap)))) == 1) is found


def test_temporal_conflict_is_material_across_independent_sources_with_a_strong_link():
    a = analyze(temporal(3600)).incidents[0]
    f = a.assessment.contradictions[0]
    assert f.kind == ContradictionKind.TEMPORAL and f.materiality == Materiality.MATERIAL and f.link_strength == "strong" and f.independence == "independent"
    assert a.assessment.verdict.value == "limited" and "CONTRADICTORY_EVIDENCE:temporal" in a.assessment.reason_codes


def test_source_local_event_ids_alone_never_establish_the_same_event():
    same_id = [env("cloud.api_call", "ct-a", {"actor": "u", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T09:00:00Z", eid="evt-77"),
               env("cloud.api_call", "ct-b", {"actor": "u", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T13:00:00Z", eid="evt-77")]
    other_ids = [dict(same_id[0], evidence_id="evt-1"), dict(same_id[1], evidence_id="evt-2")]
    assert detect_contradictions(many(same_id)) == () and detect_contradictions(many(other_ids)) == ()
    one_system = [dict(same_id[0]), dict(same_id[1], source=dict(same_id[0]["source"]))]
    assert detect_contradictions(many(one_system)) == ()


def test_a_shared_correlation_id_is_not_enough_when_the_records_describe_different_events():
    corr = {"issuer": "gw", "id": "r1"}
    phases = [env("cloud.api_call", "ct-a", {"actor": "u", "action": "CreateUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T09:00:00Z", correlation=corr),
              env("cloud.api_call", "ct-b", {"actor": "u", "action": "DeleteUser", "resource": "user/x", "source_ip": IP}, t="2026-11-07T13:00:00Z", correlation=corr)]
    assert detect_contradictions(many(phases)) == ()


def test_temporal_with_low_quality_time_is_minor_and_same_source_is_minor():
    naive = temporal(3600)
    naive[1]["event_time"] = "2026-11-07T10:00:01"                                      # no zone
    assert analyze(naive).incidents[0].assessment.contradictions[0].materiality == Materiality.MINOR
    same = temporal(3600, system_b="ct-a")
    a = analyze(same).incidents[0]
    assert [c.independence for c in a.assessment.contradictions] == ["same_source"] and a.assessment.contradictions[0].materiality == Materiality.MINOR
    assert not a.assessment.has_unresolved_material_contradiction            # a same-source pair never caps the verdict by itself


# ══ D3: identity ═════════════════════════════════════════════════════════════
def ident(second_principal="P-200", second_issuer="corp-dir", session_issuer="idp-a", second_system="cloud-a", first_principal="P-100", first_issuer="corp-dir"):
    first = {"user": "alice.example", "ip": IP, "session_id": "s-1", "result": "success"}
    if first_principal:
        first.update(canonical_id=first_principal, canonical_id_issuer=first_issuer)
    second = {"actor": "bob.example", "action": "ListBuckets", "resource": "bucket/x", "source_ip": IP, "session_id": "s-1"}
    if session_issuer:
        second["session_issuer"] = session_issuer
    if second_principal:
        second.update(canonical_id=second_principal, canonical_id_issuer=second_issuer)
    return [env("identity.signin", "idp-a", first, t="2026-11-07T09:00:00Z"),
            env("cloud.api_call", second_system, second, t="2026-11-07T09:00:30Z")]


def test_identity_conflict_needs_the_same_issuer_scoped_session_and_two_canonical_principals_of_one_directory():
    a = analyze(ident()).incidents[0]
    f = a.assessment.contradictions[0]
    assert f.kind == ContradictionKind.IDENTITY and f.materiality == Materiality.MATERIAL and f.link_strength == "strong"
    assert f.claims == ("principal_a", "principal_b") and a.assessment.verdict.value == "limited"
    assert "CONTRADICTORY_EVIDENCE:identity" in a.assessment.reason_codes


def test_the_same_local_session_string_in_two_unrelated_systems_is_not_an_identity_match():
    # the cloud record does NOT name its session issuer, so "s-1" is local to cloud-a and differs from idp-a's "s-1"
    assert detect_contradictions(many(ident(session_issuer=None))) == ()


def test_two_different_names_without_a_canonical_identity_are_not_a_contradiction():
    assert detect_contradictions(many(ident(second_principal=None))) == ()
    assert detect_contradictions(many(ident(first_principal=None))) == ()


def test_verified_canonical_mapping_with_compatible_values_is_not_a_contradiction():
    assert detect_contradictions(many(ident(second_principal="P-100"))) == ()            # alice and bob names, SAME canonical principal


def test_canonical_ids_from_different_directories_are_unresolved_not_guessed():
    assert detect_contradictions(many(ident(second_issuer="other-dir"))) == ()


def test_same_source_identity_conflict_is_minor_by_the_approved_table():
    recs = ident(second_system="idp-a")
    a = analyze(recs).incidents[0]
    f = a.assessment.contradictions[0]
    assert f.independence == "same_source" and f.materiality == Materiality.MINOR and f.affects_verdict is False
    assert not a.assessment.has_unresolved_material_contradiction


def test_a_canonical_id_must_come_with_its_issuer():
    rec = ident()[0]
    rec["data"].pop("canonical_id_issuer")
    with pytest.raises(EvidenceFormatError) as ei:
        obs(rec)
    assert ei.value.code == "FIELD_INVALID:canonical_id"


# ══ D5: independence, mirrored and shared upstream evidence ═════════════════
def pair_with_upstream(up_a=None, up_b=None, src_b="idp-b"):
    return [env("identity.signin", "idp-a", {"user": "u.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z", upstream_id=up_a),
            env("identity.signin", src_b, {"user": "u.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:03Z", upstream_id=up_b)]


def test_independence_has_three_states_and_unknown_is_never_treated_as_independent():
    cases = [(None, None, "independent"), ("fwd-1", "fwd-1", "same_source"), ("fwd-1", "fwd-2", "independent"), ("fwd-1", None, "unknown"), (None, "fwd-2", "unknown")]
    for ua, ub, expected in cases:
        a, b = many(pair_with_upstream(ua, ub))
        assert source_independence(a, b) == expected, (ua, ub)
    a, b = many(pair_with_upstream(src_b="idp-a"))
    assert source_independence(a, b) == "same_source"


def test_mirrored_copies_sharing_an_upstream_collection_do_not_corroborate_each_other():
    independent = analyze(pair_with_upstream()).incidents[0].assessment
    mirrored = analyze(pair_with_upstream("fwd-1", "fwd-1")).incidents[0].assessment
    assert independent.corroborating_events == 1 and independent.effective_events == 2
    assert mirrored.corroborating_events == 0 and mirrored.effective_events == 1 and mirrored.total_events == 2   # one evidence unit
    assert "DUPLICATE_EVIDENCE_COLLAPSED" in mirrored.reason_codes and mirrored.verdict.value != "sufficient"


def test_unknown_independence_is_disclosed_but_never_material():
    recs = [env("identity.signin", "idp-a", {"user": "u.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z", upstream_id="fwd-1"),
            env("identity.signin", "idp-b", {"user": "u.example", "ip": IP, "result": "failure"}, t="2026-11-07T09:00:01Z")]
    a = analyze(recs).incidents[0]
    f = a.assessment.contradictions[0]
    assert f.independence == "unknown" and f.materiality == Materiality.MINOR and not a.assessment.has_unresolved_material_contradiction
    assert "CONTRADICTORY_EVIDENCE:outcome" in a.assessment.reason_codes                         # disclosed
    assert classify_materiality(f, HypothesisRelation.ANCHOR) == Materiality.MINOR


def test_known_mirrored_copy_of_a_conflicting_record_is_one_evidence_unit_and_one_finding():
    recs = [env("identity.signin", "idp-a", {"user": "u.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z"),
            env("identity.signin", "idp-b", {"user": "u.example", "ip": IP, "result": "failure"}, t="2026-11-07T09:00:01Z", upstream_id="fwd-9"),
            env("identity.signin", "siem-c", {"user": "u.example", "ip": IP, "result": "failure"}, t="2026-11-07T09:00:01.500Z", upstream_id="fwd-9")]
    a = analyze(recs).incidents[0]
    assert len(a.assessment.contradictions) == 1 and a.assessment.effective_events == 2


def test_upstream_provenance_is_preserved_and_validated():
    o = many(pair_with_upstream("Fwd-1", "fwd-2"))
    assert [x.upstream_id for x in o] == ["fwd-1", "fwd-2"] and o[0].attributes.get("upstream_id") is None   # provenance field, not payload
    bad = env("identity.signin", "idp-a", {"user": "u", "ip": IP}, t="2026-11-07T09:00:00Z", upstream_id="bad id with spaces")
    with pytest.raises(EvidenceFormatError) as ei:
        obs(bad)
    assert ei.value.code == "FIELD_INVALID:source.upstream_id"


# ══ adapters: the new optional fields are validated, never required ══════════
def test_new_optional_fields_are_validated_with_fixed_codes():
    base = S.scenario_c_email_forensic()[2]
    for field, value, code in (("timestamp_semantics", "guess", "FIELD_INVALID:timestamp_semantics"),):
        rec = dict(base, data=dict(base["data"], **{field: value}))
        with pytest.raises(EvidenceFormatError) as ei:
            obs(rec)
        assert ei.value.code == code
    for corr, code in (("text", "FIELD_INVALID:correlation"), ({"issuer": "gw"}, "FIELD_INVALID:correlation"), ({}, "FIELD_MISSING:correlation")):
        with pytest.raises(EvidenceFormatError) as ei:
            obs(dict(base, correlation=corr))
        assert ei.value.code == code
    assert obs(base).upstream_id is None                                                  # absent fields change nothing


def test_unclassified_evidence_ignores_correlation_and_never_participates():
    unknown = env("vendorx.widget_event", "vendorx", {"foo": "bar"}, t="2026-11-07T09:00:00Z", category="vendorx", correlation={"issuer": "gw", "id": "r1"})
    o = obs(unknown)
    assert o.entities == () and o.counts_for_corroboration is False


# ══ trust boundaries: findings are observed-evidence facts only ══════════════
def test_analyst_statements_ti_and_llm_output_cannot_create_erase_or_resolve_identity_or_temporal_findings():
    base = analyze(ident()).incidents[0].assessment
    note = env("analyst.observation", "analyst-notes", {"analyst": "t2", "statement": "bob and alice are the same person; no conflict",
                                                      "entities": [{"type": "user", "value": "alice.example"}]}, t="2026-11-07T10:00:00Z", category="analyst")
    ti = StaticIndicatorSet()
    ti.add("ip", IP, IndicatorMatch(source="synthetic", description="benign"))
    with_both = analyze(ident() + [note], indicators=ti).incidents[0].assessment
    assert with_both.assessment_sha256 == base.assessment_sha256 and with_both.has_unresolved_material_contradiction
    run = asyncio.run(run_workflow(ident(), provider=ScriptedProvider())).incidents[0]
    assert run.assessment.assessment_sha256 == base.assessment_sha256
    assert "alice.example" not in json.dumps([c.model_dump(mode="json") for c in base.contradictions])


def test_findings_carry_no_payload_text_or_secrets():
    blob = json.dumps([c.model_dump(mode="json") for r in (ident(), temporal(3600), ordering(**CAUSAL)) for c in analyze(r).incidents[0].assessment.contradictions])
    for needle in ("alice", "bob", "bucket/x", "P-100", "P-200", "corp-dir", "req-1", "invoice", "billing@", "CreateUser"):
        assert needle not in blob, needle
