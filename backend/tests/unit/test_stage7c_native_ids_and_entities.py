"""
Stage 7C (owner decisions D2 and D3): source-scoped native ids for EDR and Linux auth, and the per-type case rules of entity values.
"""

from __future__ import annotations

import hashlib
import uuid

import pytest

from app.modules.correlation.normalize import normalize_records
from app.modules.correlation.workflow import analyze
from app.modules.evidence.independence import canonical_entity_value, fold_mailbox
from app.modules.evidence_domains import scenarios as S
from app.modules.evidence_domains.adapters import parse_record
from tests.unit.test_stage7b_legacy_and_identity import T_AWARE, build

IP = S.ATTACKER_IP


def ev(name, **over):
    raw = build(name, T_AWARE)
    raw.update(over)
    return normalize_records([raw]).events[0]


# ------------------------------------------------------------------------------------------------ D2
@pytest.mark.parametrize("name, native", [("edr_malware", "det-1"), ("linux_auth", "auth-77")])
def test_the_native_id_is_kept_on_the_event_as_source_scoped_provenance(name, native):
    e = ev(name)
    assert e.native_event_id == native and e.source_type == name                      # the scope (source_type) travels with it
    assert e.source_event_id == ""                                                    # NOT placed in the identity / observation-class field
    assert not any(native in v for _t, v in e.entities)                                # not an entity, so no canonical identity or link
    assert e.upstream_id == "" and e.evidence_type == ""


@pytest.mark.parametrize("name", ["edr_malware", "linux_auth"])
def test_a_generated_fallback_id_is_never_presented_as_native(name):
    raw = build(name, T_AWARE)
    for k in ("detection_id", "id"):
        raw.pop(k, None)
    e = normalize_records([raw]).events[0]
    assert e.native_event_id == ""                                                    # the adapter generated an id; the source supplied none


def test_other_adapters_do_not_gain_a_native_id_field():
    for name in ("sysmon", "windows_security", "firewall_ids", "cloud_audit", "email_phishing", "generic_siem"):
        assert ev(name).native_event_id == ""


def test_equal_native_id_strings_from_different_sources_do_not_link_or_corroborate():
    edr = build("edr_malware", T_AWARE)
    lin = build("linux_auth", T_AWARE)
    edr["detection_id"], lin["id"] = "SHARED-1", "SHARED-1"
    lin["hostname"], edr["device_name"] = "lx-9", "ws-9"                              # no shared host or entity
    lin["message"] = "Failed password for root from 198.51.100.7 port 22"
    res = analyze([edr, lin])
    assert {e.native_event_id for e in res.normalization.events} == {"SHARED-1"} and len(res.normalization.events) == 2
    assert res.correlation.links == []                                                # the equal id string created no link
    assert not res.incidents or all(len(i.incident.event_keys) == 1 for i in res.incidents)


def test_native_ids_do_not_change_duplicate_collapsing():
    def pair(with_ids):
        a, b = build("edr_malware", T_AWARE), build("edr_malware", "2026-11-07T09:00:01Z")
        if with_ids:
            a["detection_id"], b["detection_id"] = "det-A", "det-B"
        else:
            a.pop("detection_id"), b.pop("detection_id")
        return analyze([a, b]).correlation.clusters
    assert len(pair(True)) == len(pair(False))


def test_the_native_id_is_available_next_to_its_source_scope_on_the_event():
    res = analyze([build("edr_malware", T_AWARE), build("firewall_ids", T_AWARE)])
    by_source = {e.source_type: e.native_event_id for e in res.normalization.events}
    assert by_source["edr_malware"] == "det-1" and by_source["firewall_ids"] == ""


# ------------------------------------------------------------------------------------------------ D3
def obs(record):
    return parse_record(record, key=uuid.uuid4(), record_index=0, raw_sha256=hashlib.sha256(repr(record).encode()).hexdigest())


def ents(o, kind):
    return sorted(v for t, v in o.entities if t == kind)


def test_email_domain_is_folded_and_the_local_part_is_preserved():
    assert canonical_entity_value("email", "Alice@Example.COM") == "Alice@example.com"
    assert canonical_entity_value("email", "alice@EXAMPLE.com") == "alice@example.com"
    assert canonical_entity_value("email", "Alice@Example.COM") != canonical_entity_value("email", "alice@example.com")
    assert fold_mailbox("no-at-sign") == "no-at-sign" and fold_mailbox("<AbC@Example.TEST>") == "<AbC@example.test>"


def test_email_adapter_applies_the_component_rules_and_keeps_the_raw_value():
    rec = S.env("email.message", "mail-a", {"message_id": "<AbC@Mail.Example.TEST>", "from": "Alice@Example.COM", "to": ["Bob@Corp.Test"]}, t=T_AWARE)
    o = obs(rec)
    assert ents(o, "email") == ["Alice@example.com", "Bob@corp.test"]
    assert ents(o, "email_message") == ["<AbC@mail.example.test>"]
    assert rec["data"]["from"] == "Alice@Example.COM"                                  # the submitted record is untouched
    other = obs(S.env("email.message", "mail-a", {"message_id": "<abc@mail.example.test>", "from": "alice@example.com", "to": ["bob@corp.test"]}, t=T_AWARE))
    assert set(ents(o, "email")).isdisjoint(ents(other, "email")) and ents(o, "email_message") != ents(other, "email_message")


def test_opaque_session_ids_keep_their_case_and_only_the_issuer_is_folded():
    def sess(sid, issuer="IdP-X"):
        o = obs(S.env("identity.signin", "idp-a", {"user": "u.example", "ip": IP, "result": "success", "session_id": sid, "session_issuer": issuer}, t=T_AWARE))
        return ents(o, "logon_session")
    assert sess("AbC-1") == ["idp-x:AbC-1"] and sess("abc-1") == ["idp-x:abc-1"] and sess("AbC-1") != sess("abc-1")


def test_cloud_resources_and_accounts_keep_their_case():
    def res(r):
        return obs(S.env("cloud.api_call", "ct", {"actor": "u", "action": "GetObject", "resource": r, "source_ip": IP, "account": "Prod-A"}, t=T_AWARE))
    a, b = res("Bucket/ObjectKey"), res("bucket/objectkey")
    assert ents(a, "cloud_resource") == ["Bucket/ObjectKey"] and ents(a, "cloud_resource") != ents(b, "cloud_resource")
    assert ents(a, "cloud_account") == ["Prod-A"]


@pytest.mark.parametrize("etype, raw, expected", [
    ("domain", "Mail.EXAMPLE.test.", "mail.example.test"),                               # DNS names: case-insensitive (RFC 4343), trailing dot dropped
    ("file_hash", "ABCDEF0123456789" * 4, ("abcdef0123456789" * 4)),                      # hexadecimal digits
    ("ip", "2001:DB8::1", "2001:db8::1"),                                                # IPv6 text
    ("process_guid", "{ABCDEF01-2345-6789-ABCD-EF0123456789}", "{abcdef01-2345-6789-abcd-ef0123456789}"),
    ("user", "Alice", "Alice"),                                                          # canonical form keeps case (adapters decide; see below)
    ("cloud_resource", "Bucket/Key", "Bucket/Key"),
    ("logon_session", "idp:AbC", "idp:AbC"),
    ("principal", "Dir:AbC", "Dir:AbC"),
    ("event_correlation", "gw:ReQ-1", "gw:ReQ-1"),
])
def test_canonical_entity_value_rule_per_type(etype, raw, expected):
    assert canonical_entity_value(etype, raw) == expected


def test_url_host_is_folded_and_path_and_query_keep_their_case():
    o = obs(S.env("email.message", "mail-a", {"message_id": "<m@x.test>", "from": "a@x.test", "urls": ["HTTPS://Evil.EXAMPLE/Path/AbC?Q=1"]}, t=T_AWARE))
    assert ents(o, "url") == ["https://evil.example/Path/AbC?Q=1"]


def test_pinned_unchanged_rules_that_remain_an_open_owner_decision():
    """
    NOT changed in Stage 7C, pinned so a future change is deliberate: user names, file paths, registry keys and process names are still
    folded by their adapters because their case rules depend on the directory or operating system, which the record does not state.
    """
    o = obs(S.env("identity.signin", "idp-a", {"user": "Alice.Example", "ip": IP, "result": "success"}, t=T_AWARE))
    assert ents(o, "user") == ["alice.example"]
    f = obs(S.env("forensic.file", "edr-x", {"host": "WS-1", "path": "C:/Users/Alice/A.EXE", "sha256": "ab" * 32}, t=T_AWARE))
    assert ents(f, "file") == ["ws-1:c:/users/alice/a.exe"]
