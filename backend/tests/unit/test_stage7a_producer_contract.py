"""
Stage 7A (owner decision D3): fixture-based proof of the source-to-canonical field contract.

The contract document (docs/Architecture/PRODUCER_FIELD_CONTRACT.md) states, per evidence type, which source-stated fields become which
canonical field. Every row is proven here by parsing a fixture through the REAL adapter (no mock) and by the negative: when the source does
not state a field, the canonical field is ABSENT (nothing is manufactured from matching strings).

Scope: the AISOP evidence envelope (``aisop.evidence/1``) adapters. The legacy alert adapters are covered at the end only for what they
guarantee about event time (no invented time).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

import pytest

from app.modules.evidence_domains.adapters import EvidenceFormatError, parse_record
from app.modules.evidence_domains.model import Predicate, TimeStatus
from app.modules.evidence_domains import scenarios as S

SHA = hashlib.sha256(b"fixture").hexdigest()
IP = "91.240.118.172"
T = "2026-11-07T09:00:00Z"

MINIMAL = {
    "identity.signin": {"user": "u.example", "ip": IP, "result": "success", "session_id": "s-1"},
    "identity.mfa": {"user": "u.example", "ip": IP, "result": "success", "session_id": "s-1"},
    "identity.privilege_change": {"actor": "a.example", "target_user": "t.example", "role": "admin", "ip": IP},
    "identity.account_change": {"actor": "a.example", "target_user": "t.example", "change": "password reset", "ip": IP},
    "cloud.api_call": {"actor": "a.example", "action": "ListBuckets", "resource": "bucket/x", "source_ip": IP, "session_id": "s-1"},
    "cloud.config_change": {"actor": "a.example", "action": "PutPolicy", "resource": "bucket/x", "source_ip": IP, "session_id": "s-1"},
    "cloud.object_access": {"actor": "a.example", "action": "GetObject", "resource": "bucket/x", "source_ip": IP, "session_id": "s-1"},
    "network.dns": {"src_ip": "10.0.0.5", "query": "x.example.test", "host": "ws-1"},
    "network.flow": {"src_ip": "10.0.0.5", "dst_ip": IP, "action": "allow", "dst_port": "443"},
    "network.firewall": {"src_ip": "10.0.0.5", "dst_ip": IP, "action": "deny"},
    "network.ids": {"src_ip": "10.0.0.5", "dst_ip": IP, "signature": "ET TEST"},
    "email.message": {"message_id": "<m1@x.test>", "from": "a@x.test", "to": ["b@y.test"], "attachments": [{"sha256": SHA}]},
    "forensic.file": {"host": "ws-1", "path": "C:/x/a.exe", "sha256": SHA},
    "forensic.registry": {"host": "ws-1", "key": "HKLM/Run/x"},
    "forensic.memory_finding": {"tool": "vol", "finding_type": "injection", "host": "ws-1"},
    "forensic.process_artifact": {"host": "ws-1", "image": "C:/x/a.exe", "sha256": SHA},
    "analyst.observation": {"analyst": "t1.example", "statement": "note"},
}
EXTRA = {"canonical_id": "P-1", "canonical_id_issuer": "corp-dir", "session_issuer": "idp-x", "origin_message_id": "<m1@x.test>", "timestamp_semantics": "arrival"}


def rec(etype, *, data=None, correlation=None, upstream=None, t=T, system="sys-a", extra=False):
    d = dict(MINIMAL[etype], **(EXTRA if extra else {}), **(data or {}))
    r = {"schema": "aisop.evidence/1", "evidence_type": etype, "source": {"system": system, "category": etype.split(".")[0], "collection_method": "api_export"}, "data": d}
    if upstream:
        r["source"]["upstream_id"] = upstream
    if correlation:
        r["correlation"] = correlation
    if t is not None:
        r["event_time"] = t
    return r


def parse(r):
    return parse_record(r, key=uuid.uuid4(), record_index=0, raw_sha256=hashlib.sha256(repr(r).encode()).hexdigest())


def ents(o, kind):
    return sorted(v for t, v in o.entities if t == kind)


# --------------------------------------------------------------- capability matrix, computed from the real adapters
SESSION_TYPES = {"identity.signin", "identity.mfa", "cloud.api_call", "cloud.config_change", "cloud.object_access"}
ALL_TYPES = sorted(MINIMAL)


@pytest.mark.parametrize("etype", ALL_TYPES)
def test_every_type_parses_and_time_is_the_source_event_time_never_invented(etype):
    o = parse(rec(etype))
    assert o.event_time == datetime(2026, 11, 7, 9, 0, tzinfo=timezone.utc) and o.time_status == TimeStatus.VALID
    assert o.source_system == "sys-a" and o.raw_sha256 and o.adapter and o.adapter_version
    # event time absent -> unknown, collected_at never promoted to event time
    u = parse(dict(rec(etype, t=None), collected_at="2026-11-09T00:00:00Z"))
    assert u.event_time is None and u.time_status == TimeStatus.MISSING and u.collected_at is not None


@pytest.mark.parametrize("etype", ALL_TYPES)
def test_session_issuer_and_canonical_principal_only_where_the_adapter_supports_them(etype):
    o = parse(rec(etype, extra=True))
    if etype in SESSION_TYPES:
        assert ents(o, "logon_session") == ["idp-x:s-1"]            # issuer-scoped
        assert ents(o, "principal") == ["corp-dir:P-1"]             # canonical, issuer-scoped; identifier case PRESERVED (Stage 7B, D4); only the issuer is lower-cased
    else:
        assert ents(o, "logon_session") == [] and ents(o, "principal") == []   # stated by the source but NOT mapped: left unknown, not guessed


@pytest.mark.parametrize("etype", sorted(SESSION_TYPES))
def test_without_session_issuer_the_session_is_scoped_to_the_record_system_and_there_is_no_principal(etype):
    o = parse(rec(etype))
    assert ents(o, "logon_session") == ["sys-a:s-1"] and ents(o, "principal") == []
    # the same local id from a different system is a DIFFERENT entity (never globally equal)
    assert ents(parse(rec(etype, system="sys-b")), "logon_session") == ["sys-b:s-1"]


@pytest.mark.parametrize("bad", [{"canonical_id": "P-1"}, {"canonical_id_issuer": "corp-dir"}])
def test_canonical_id_requires_both_value_and_issuer(bad):
    with pytest.raises(EvidenceFormatError):
        parse(rec("identity.signin", data=bad))


@pytest.mark.parametrize("etype", [t for t in ALL_TYPES])
def test_correlation_and_upstream_are_envelope_level_for_every_corroborating_adapter(etype):
    o = parse(rec(etype, correlation={"issuer": "gw-1", "id": "req-9"}, upstream="Collector-7"))
    assert ents(o, "event_correlation") == ["gw-1:req-9"]
    assert o.upstream_id == "collector-7"
    plain = parse(rec(etype))
    assert ents(plain, "event_correlation") == [] and plain.upstream_id is None


def test_native_event_ids_are_never_a_correlation_key():
    o = parse(dict(rec("cloud.api_call"), evidence_id="native-123"))
    assert ents(o, "event_correlation") == [] and o.evidence_id == "native-123"


def test_correlation_without_issuer_is_rejected_not_guessed():
    with pytest.raises(EvidenceFormatError):
        parse(rec("cloud.api_call", correlation={"id": "req-9"}))


def test_unclassified_records_keep_upstream_but_never_map_correlation_or_entities():
    r = {"schema": "aisop.evidence/1", "evidence_type": "vendorx.thing", "source": {"system": "vx", "upstream_id": "u-1"}, "data": {"a": 1},
         "correlation": {"issuer": "g", "id": "1"}, "event_time": T}
    o = parse(r)
    assert o.upstream_id == "u-1" and o.entities == () and not o.counts_for_corroboration


def test_origin_message_is_mapped_only_for_forensic_file_and_only_when_stated():
    o = parse(rec("forensic.file", extra=True))
    assert any(r.predicate == Predicate.DERIVED_FROM and r.obj == ("email_message", "<m1@x.test>") for r in o.relations)
    none = parse(rec("forensic.file"))
    assert not any(r.predicate == Predicate.DERIVED_FROM for r in none.relations)
    # the same field on another type is not mapped (the contract states this as UNAVAILABLE)
    other = parse(rec("forensic.process_artifact", extra=True))
    assert not any(r.predicate == Predicate.DERIVED_FROM for r in other.relations)


def test_timestamp_semantics_is_validated_and_a_bad_value_is_rejected():
    for ok in ("arrival", "creation", "modification", "collection"):
        parse(rec("forensic.file", data={"timestamp_semantics": ok}))
    with pytest.raises(EvidenceFormatError):
        parse(rec("forensic.file", data={"timestamp_semantics": "whenever"}))


@pytest.mark.parametrize("value, status", [
    ("2026-11-07T09:00:00Z", TimeStatus.VALID),
    ("2026-11-07T14:30:00+05:30", TimeStatus.VALID),            # offset normalised to UTC
    ("2026-11-07T09:00:00", TimeStatus.NAIVE_ASSUMED_UTC),       # time zone assumed and disclosed
    ("yesterday", TimeStatus.INVALID),
    ("1850-01-01T00:00:00Z", TimeStatus.OUT_OF_RANGE),
    (None, TimeStatus.MISSING),
    ("", TimeStatus.MISSING),
])
def test_timestamp_quality_and_timezone_contract(value, status):
    o = parse(rec("identity.signin", t=value))
    assert o.time_status == status
    if status in (TimeStatus.VALID, TimeStatus.NAIVE_ASSUMED_UTC):
        assert o.event_time.tzinfo is not None and o.event_time.utcoffset().total_seconds() == 0
        assert o.event_time == datetime(2026, 11, 7, 9, 0, tzinfo=timezone.utc)
    else:
        assert o.event_time is None


def test_local_user_name_is_never_promoted_to_a_canonical_principal():
    # two systems, the same user string: two user entities with the same value, but NO principal on either
    a, b = parse(rec("identity.signin", system="idp-a")), parse(rec("cloud.api_call", data={"actor": "u.example"}, system="cloud-a"))
    assert ents(a, "principal") == [] and ents(b, "principal") == []


def test_scenarios_in_the_repository_still_parse_through_the_contract():
    for build in (S.scenario_a_identity_cloud, S.scenario_b_network_endpoint, S.scenario_c_email_forensic):
        for r in build():
            parse(r)


# --------------------------------------------------------------- legacy alert adapters: event time is never invented
def test_legacy_normalizer_rejects_records_whose_time_the_adapter_would_have_invented():
    from app.modules.correlation.normalize import normalize_records
    siem = {"title": "alert", "severity": "high", "source": "generic", "description": "x"}       # no timestamp at all
    res = normalize_records([siem])
    assert not res.events and [r.reason for r in res.rejected] and all(r.reason in ("TIMESTAMP_MISSING_OR_INVALID", "NO_ADAPTER") or r.reason.startswith("ADAPTER_ERROR") for r in res.rejected)
