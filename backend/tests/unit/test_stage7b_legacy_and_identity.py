"""
Stage 7B (owner decisions D3, D4, D5): per-adapter legacy alert coverage, canonical identifier case, and naive timestamps.

Legacy adapters (ADR-007) are exercised through the REAL registry and ``normalize_records`` with one distinct, source-shaped fixture each.
Only behaviour the fixtures prove is asserted; nothing is claimed for a field a fixture does not carry.
"""

from __future__ import annotations

import copy
import hashlib
import json
import uuid

import pytest

from app.modules.alerts.adapter_protocol import get_default_registry
from app.modules.correlation.normalize import normalize_records, raw_digest
from app.modules.correlation.workflow import analyze
from app.modules.evidence_domains import scenarios as S
from app.modules.evidence_domains.adapters import EvidenceFormatError, parse_record
from app.modules.evidence_domains.contradictions import detect_contradictions

T_AWARE, T_NAIVE = "2026-11-07T09:00:00Z", "2026-11-07T09:00:00"

# adapter name -> (native fixture with the placeholder "T" where the SOURCE puts its time, path of that field, native id key or None)
LEGACY = {
    "sysmon": ({"Event": {"System": {"Provider": {"@Name": "Microsoft-Windows-Sysmon"}, "EventID": 1, "Computer": "ws-01",
                                     "TimeCreated": {"@SystemTime": "T"}},
                          "EventData": {"Image": "C:/x/a.exe", "CommandLine": "a.exe", "User": "corp-alice",
                                        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}", "LogonId": "0x1A2B"}}},
               ["Event", "System", "TimeCreated", "@SystemTime"]),
    "windows_security": ({"Event": {"System": {"Provider": {"@Name": "Microsoft-Windows-Security-Auditing"}, "EventID": 4624, "Computer": "ws-01",
                                               "TimeCreated": {"@SystemTime": "T"}},
                                    "EventData": {"TargetUserName": "Alice", "TargetLogonId": "0x3E7", "IpAddress": "203.0.113.5"}}},
                         ["Event", "System", "TimeCreated", "@SystemTime"]),
    "linux_auth": ({"source_type": "linux_auth", "timestamp": "T", "id": "auth-77", "program": "sshd",
                    "message": "Failed password for root from 203.0.113.5 port 22", "hostname": "lx-1"}, ["timestamp"]),
    "edr_malware": ({"source_type": "edr", "timestamp": "T", "detection_id": "det-1", "device_name": "ws-02", "threat_name": "Trojan.X"}, ["timestamp"]),
    "firewall_ids": ({"source_type": "firewall_ids", "timestamp": "T", "signature": "ET TEST", "signature_id": 2001,
                      "src_ip": "203.0.113.5", "dest_ip": "10.0.0.5"}, ["timestamp"]),
    "cloud_audit": ({"source_type": "cloud_audit", "eventTime": "T", "eventName": "ConsoleLogin", "userIdentity": {"userName": "Alice"},
                     "sourceIPAddress": "203.0.113.5"}, ["eventTime"]),
    "email_phishing": ({"source_type": "email_phishing", "timestamp": "T", "sender": "a@x.test", "recipient": "b@y.test", "subject": "hi",
                        "threat_type": "phish"}, ["timestamp"]),
    "generic_siem": ({"source_type": "generic_siem", "timestamp": "T", "rule_id": "R-1", "rule_name": "x", "title": "alert"}, ["timestamp"]),
}
NATIVE_ID = {"sysmon": "1", "linux_auth": "auth-77", "edr_malware": "det-1", "firewall_ids": "2001", "generic_siem": "R-1"}
HOST_SCOPED_SESSION = {"sysmon", "windows_security"}


def build(name: str, t):
    base, path = LEGACY[name]
    d = copy.deepcopy(base)
    cur = d
    for k in path[:-1]:
        cur = cur[k]
    if t is None:
        cur.pop(path[-1], None)
    else:
        cur[path[-1]] = t
    return d


def one(name, t):
    return normalize_records([build(name, t)])


def test_the_fixture_set_covers_every_registered_legacy_adapter():
    assert sorted(LEGACY) == get_default_registry().list_adapters()


@pytest.mark.parametrize("name", sorted(LEGACY))
def test_each_fixture_is_handled_by_its_own_adapter_and_keeps_the_raw_record_digest(name):
    raw = build(name, T_AWARE)
    assert get_default_registry().find_matching_adapter(raw).adapter_name() == name
    res = normalize_records([raw])
    assert len(res.events) == 1 and not res.rejected
    e = res.events[0]
    assert e.source_type == name
    assert e.raw_sha256 == raw_digest(raw)
    assert e.timestamp.isoformat() == "2026-11-07T09:00:00+00:00" and e.time_assumed_utc is False


@pytest.mark.parametrize("name", sorted(LEGACY))
def test_a_missing_event_time_is_rejected_never_replaced_by_now(name):
    res = one(name, None)
    assert not res.events and [r.reason for r in res.rejected] == ["TIMESTAMP_MISSING_OR_INVALID"]


@pytest.mark.parametrize("name", sorted(LEGACY))
def test_legacy_sources_populate_none_of_the_identity_lineage_correlation_or_origin_fields(name):
    e = one(name, T_AWARE).events[0]
    assert e.upstream_id == "" and e.evidence_type == ""
    assert not any(t in ("principal", "event_correlation", "email_message") for t, _v in e.entities)     # nothing global is manufactured
    assert not any(v.startswith(("corp-dir:", "gateway")) for _t, v in e.entities)


ALERT_NATIVE_ID = {"sysmon": "1", "linux_auth": "auth-77", "edr_malware": "det-1", "firewall_ids": "2001", "generic_siem": "R-1"}
EVENT_CARRIES_NATIVE_ID = {"sysmon", "firewall_ids", "generic_siem"}          # the correlation event keeps source_event_id only for these (+ windows_security by event id)
# windows_security / cloud_audit / email_phishing: the adapter derives a synthetic id (winsec-<eid>-<hash>, cloud-<hash>, email-<hash>); no native id is claimed.


@pytest.mark.parametrize("name", sorted(ALERT_NATIVE_ID))
def test_the_adapter_preserves_the_native_id_on_the_canonical_alert(name):
    alert = get_default_registry().get(name).adapt(build(name, T_AWARE), raw_ref="x" * 64)
    assert alert.source_alert_id == ALERT_NATIVE_ID[name] and alert.source_type == name


@pytest.mark.parametrize("name", sorted(ALERT_NATIVE_ID))
def test_native_event_ids_are_source_scoped_and_never_link_entities(name):
    e = one(name, T_AWARE).events[0]
    assert e.source_type == name
    if name in EVENT_CARRIES_NATIVE_ID:
        assert e.source_event_id == ALERT_NATIVE_ID[name]
    else:
        assert e.source_event_id == ""         # DOCUMENTED GAP: edr_malware and linux_auth do not carry the native id onto the correlation event
    assert not any(v == ALERT_NATIVE_ID[name] for _t, v in e.entities)          # the id is not an entity: it cannot link records


def test_the_same_native_id_in_two_sources_does_not_link_them():
    a = one("firewall_ids", T_AWARE).events[0]          # signature id 2001
    b_raw = build("generic_siem", T_AWARE)
    b_raw["rule_id"] = "2001"                            # same string, different source
    b = normalize_records([b_raw]).events[0]
    assert a.source_event_id == b.source_event_id == "2001" and a.source_type != b.source_type
    assert not (set(a.entities) & set(b.entities))


@pytest.mark.parametrize("name", sorted(HOST_SCOPED_SESSION))
def test_logon_sessions_are_scoped_to_the_host_so_equal_ids_on_two_hosts_differ(name):
    r1 = build(name, T_AWARE)
    r2 = copy.deepcopy(r1)
    r2["Event"]["System"]["Computer"] = "ws-99"
    s1 = {v for t, v in one_event(r1).entities if t == "logon_session"}
    s2 = {v for t, v in one_event(r2).entities if t == "logon_session"}
    assert s1 and s2 and s1.isdisjoint(s2) and all(v.startswith("ws-") for v in s1 | s2)


def one_event(raw):
    return normalize_records([raw]).events[0]


# ------------------------------------------------------------------ D5 naive timestamps (legacy)
@pytest.mark.parametrize("name", sorted(set(LEGACY) - HOST_SCOPED_SESSION))
def test_naive_legacy_time_is_flagged_as_an_assumption_and_the_raw_value_is_unchanged(name):
    raw = build(name, T_NAIVE)
    before = json.dumps(raw, sort_keys=True)
    e = normalize_records([raw]).events[0]
    assert e.time_assumed_utc is True                      # UTC was assumed, not stated
    assert json.dumps(raw, sort_keys=True) == before        # the raw string is preserved


@pytest.mark.parametrize("name", sorted(HOST_SCOPED_SESSION))
def test_sysmon_and_windows_event_times_are_utc_by_format_so_a_naive_value_is_not_flagged(name):
    assert one(name, T_NAIVE).events[0].time_assumed_utc is False


def test_sysmon_without_its_format_time_fields_falls_back_to_an_assumption():
    raw = build("sysmon", None)
    raw["timestamp"] = T_NAIVE                             # generic fallback field, no UtcTime / SystemTime
    e = normalize_records([raw]).events[0]
    assert e.time_assumed_utc is True


def test_an_explicit_offset_is_never_flagged():
    for name in sorted(LEGACY):
        assert one(name, "2026-11-07T14:30:00+05:30").events[0].time_assumed_utc is False
    assert one("generic_siem", "2026-11-07T14:30:00+05:30").events[0].timestamp.isoformat() == "2026-11-07T09:00:00+00:00"


def test_incident_context_and_report_disclose_assumed_time_zones():
    recs = [build("firewall_ids", T_NAIVE), build("cloud_audit", T_NAIVE)]
    res = analyze(recs)
    assert res.incidents, "the two records share an IP and must form an incident"
    a = res.incidents[0]
    assert any(f.startswith("NAIVE_TIMESTAMPS_ASSUMED_UTC") for f in a.context.uncertainty_flags)
    md = res.incidents[0].markdown or ""
    from app.modules.correlation.report import render_incident_report
    assert "Time zone assumed" in render_incident_report(res, a)


def test_an_aware_incident_has_no_time_zone_disclosure():
    res = analyze([build("firewall_ids", T_AWARE), build("cloud_audit", T_AWARE)])
    assert res.incidents and not any(f.startswith("NAIVE") for f in res.incidents[0].context.uncertainty_flags)


# ------------------------------------------------------------------ D5 envelope path (already typed): naive stays low confidence
def test_envelope_naive_time_is_marked_assumed_and_never_creates_a_material_ordering_or_temporal_finding():
    corr = {"issuer": "gw-1", "id": "req-1"}
    recs = [S.env("cloud.api_call", "ct-a", {"actor": "u.example", "action": "CreateUser", "resource": "user/x", "source_ip": S.ATTACKER_IP}, t="2026-11-07T09:00:00", correlation=corr),
            S.env("cloud.api_call", "ct-b", {"actor": "u.example", "action": "CreateUser", "resource": "user/x", "source_ip": S.ATTACKER_IP}, t="2026-11-07T13:00:00", correlation=corr)]
    obs = [parse_record(r, key=uuid.uuid4(), record_index=i, raw_sha256=hashlib.sha256(repr(r).encode()).hexdigest()) for i, r in enumerate(recs)]
    assert all(o.time_status.value == "naive_assumed_utc" for o in obs)
    for c in detect_contradictions(obs):
        assert c.explanation is not None and c.explanation.value == "timezone_assumed"       # materiality table rule 3 then makes it minor


# ------------------------------------------------------------------ D4 canonical identifier case
def rec(canonical, issuer="corp-dir", system="idp-a"):
    return S.env("identity.signin", system, {"user": "u.example", "ip": S.ATTACKER_IP, "result": "success", "session_id": "s-1", "session_issuer": "idp-a",
                                              "canonical_id": canonical, "canonical_id_issuer": issuer}, t="2026-11-07T09:00:00Z")


def principal(canonical, issuer="corp-dir"):
    r = rec(canonical, issuer)
    o = parse_record(r, key=uuid.uuid4(), record_index=0, raw_sha256="a" * 64)
    return [v for t, v in o.entities if t == "principal"]


def test_identifiers_differing_only_by_case_stay_distinct_in_a_case_sensitive_namespace():
    assert principal("AbC123") == ["corp-dir:AbC123"] and principal("abc123") == ["corp-dir:abc123"]
    assert principal("AbC123") != principal("abc123")


def test_issuer_scope_is_part_of_the_key_and_is_case_folded_like_the_source_system():
    assert principal("AbC123", "Corp-Dir") == ["corp-dir:AbC123"]
    assert principal("AbC123", "other-dir") != principal("AbC123", "corp-dir")        # matching strings from different issuers are not the same principal


def test_a_uuid_namespace_is_explicitly_case_insensitive():
    u = "3F2504E0-4F89-11D3-9A0C-0305E82C3301"
    assert principal(u) == principal(u.lower()) == [f"corp-dir:{u.lower()}"]


def test_two_principals_differing_only_by_case_are_a_real_identity_conflict_not_a_merge():
    a = rec("AbC123", system="idp-a")
    b = S.env("cloud.api_call", "cloud-a", {"actor": "bob.example", "action": "ListBuckets", "resource": "bucket/x", "source_ip": S.ATTACKER_IP,
                                             "session_id": "s-1", "session_issuer": "idp-a", "canonical_id": "abc123", "canonical_id_issuer": "corp-dir"},
              t="2026-11-07T09:00:30Z")
    obs = [parse_record(r, key=uuid.uuid4(), record_index=i, raw_sha256=hashlib.sha256(repr(r).encode()).hexdigest()) for i, r in enumerate([a, b])]
    assert [c for c in detect_contradictions(obs) if c.kind.value == "identity"], "case-distinct principals of one directory must be reported as different"
    same = [parse_record(rec("AbC123"), key=uuid.uuid4(), record_index=0, raw_sha256="b" * 64),
            parse_record(S.env("cloud.api_call", "cloud-a", {"actor": "bob.example", "action": "ListBuckets", "resource": "bucket/x", "source_ip": S.ATTACKER_IP,
                                                             "session_id": "s-1", "session_issuer": "idp-a", "canonical_id": "AbC123", "canonical_id_issuer": "corp-dir"},
                          t="2026-11-07T09:00:30Z"), key=uuid.uuid4(), record_index=1, raw_sha256="c" * 64)]
    assert not [c for c in detect_contradictions(same) if c.kind.value == "identity"]


def test_the_raw_value_is_preserved_in_the_observation_attributes_and_nothing_is_rewritten():
    r = rec("AbC123")
    before = json.dumps(r, sort_keys=True)
    o = parse_record(r, key=uuid.uuid4(), record_index=0, raw_sha256="a" * 64)
    assert json.dumps(r, sort_keys=True) == before and o.attributes.get("canonical_id") == "AbC123"


def test_correlation_ids_keep_their_case_too():
    def corr(i):
        return parse_record(S.env("cloud.api_call", "ct", {"actor": "u", "action": "CreateUser", "resource": "user/x", "source_ip": S.ATTACKER_IP}, t=T_AWARE,
                                  correlation={"issuer": "GW-1", "id": i}), key=uuid.uuid4(), record_index=0, raw_sha256="d" * 64)
    assert [v for t, v in corr("ReQ-9").entities if t == "event_correlation"] == ["gw-1:ReQ-9"]
    assert [v for t, v in corr("req-9").entities if t == "event_correlation"] == ["gw-1:req-9"]
