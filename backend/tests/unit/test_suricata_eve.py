"""Suricata EVE translator: mapping, no invented facts, flow-level independence, hostile text, bounds."""
from __future__ import annotations

import json
import uuid

import pytest

import app.modules.correlation  # noqa: F401  (import order: correlation first avoids a pre-existing circular import with evidence_domains.bridge)
from app.modules.evidence_domains.adapters import EvidenceFormatError, parse_record
from app.modules.evidence_domains.bridge import is_projectable, observation_to_event
from app.modules.evidence_domains.model import EvidenceFamily, TimeStatus, TrustClass
from app.modules.evidence_domains.suricata_eve import eve_file_to_envelopes, eve_to_envelope

ALERT = {"timestamp": "2026-11-07T09:00:00.123456+0000", "flow_id": 1234567890, "event_type": "alert", "src_ip": "203.0.113.7", "src_port": 51000,
         "dest_ip": "10.0.0.5", "dest_port": 445, "proto": "TCP", "app_proto": "smb",
         "alert": {"action": "allowed", "signature_id": 2024897, "signature": "ET EXPLOIT SMB test", "category": "Attempted Administrator Privilege Gain", "severity": 1}}
FLOW = {"timestamp": "2026-11-07T09:00:05.000000+0000", "flow_id": 1234567890, "event_type": "flow", "src_ip": "203.0.113.7", "dest_ip": "10.0.0.5", "dest_port": 445, "proto": "TCP"}
DNS = {"timestamp": "2026-11-07T09:00:01.000000+0000", "flow_id": 99, "event_type": "dns", "src_ip": "10.0.0.5",
       "dns": {"type": "answer", "rrname": "Bad.Example.test", "rcode": "NOERROR", "answers": [{"rrtype": "A", "rdata": "198.51.100.9"}, {"rrtype": "CNAME", "rdata": "x.test"}]}}


def obs(env, i=0):
    return parse_record(env, key=uuid.uuid5(uuid.NAMESPACE_URL, f"t{i}"), record_index=i, raw_sha256=("%064x" % (i + 1)))


def test_alert_becomes_a_network_ids_observation_and_severity_is_only_an_attribute():
    o = obs(eve_to_envelope(ALERT, sensor="sensor-1"))
    assert o.evidence_type == "network.ids" and o.family == EvidenceFamily.NETWORK and o.source_system == "suricata"
    assert o.trust_class == TrustClass.RAW_OBSERVED and o.time_status == TimeStatus.VALID and o.event_time is not None
    assert ("ip", "203.0.113.7") in o.entities and ("ip", "10.0.0.5") in o.entities
    assert o.attributes["signature_id"] == 2024897 and o.attributes["suricata_severity"] == 1
    assert "mitre" not in json.dumps(o.attributes).lower()                      # no ATT&CK claim comes from a signature category


def test_dns_query_answers_keep_only_ip_addresses():
    o = obs(eve_to_envelope(DNS, sensor="sensor-1"))
    assert o.evidence_type == "network.dns" and ("domain", "bad.example.test") in o.entities
    assert ("ip", "198.51.100.9") in o.entities and not any(v == "x.test" and t == "ip" for t, v in o.entities)


def test_flow_is_observed_traffic_and_asserts_no_connection_relationship():
    o = obs(eve_to_envelope(FLOW, sensor="sensor-1"))
    assert o.evidence_type == "network.flow" and o.outcome == "unknown"
    assert not any(r.predicate.value == "CONNECTED_TO" for r in o.relations)


def test_missing_or_bad_time_is_never_invented():
    no_time = {k: v for k, v in ALERT.items() if k != "timestamp"}
    o = obs(eve_to_envelope(no_time, sensor="s"))
    assert o.event_time is None and o.time_status == TimeStatus.MISSING and not is_projectable(o)
    bad = obs(eve_to_envelope({**ALERT, "timestamp": "yesterday"}, sensor="s"))
    assert bad.event_time is None and bad.time_status == TimeStatus.INVALID


def test_same_sensor_same_flow_is_one_unit_of_evidence_but_another_sensor_is_independent():
    a = obs(eve_to_envelope(ALERT, sensor="sensor-1"), 1)
    f = obs(eve_to_envelope(FLOW, sensor="sensor-1"), 2)
    other = obs(eve_to_envelope(FLOW, sensor="sensor-2"), 3)
    assert a.upstream_id == f.upstream_id == "suricata:sensor-1:1234567890"
    assert other.upstream_id != a.upstream_id
    assert observation_to_event(a).upstream_id == observation_to_event(f).upstream_id          # carried into the independence rules
    assert obs(eve_to_envelope({k: v for k, v in ALERT.items() if k != "flow_id"}, sensor="s")).upstream_id is None   # none is invented


def test_unsupported_types_are_skipped_not_interpreted_and_bad_records_are_rejected_with_fixed_codes():
    assert eve_to_envelope({"event_type": "http", "src_ip": "1.2.3.4"}, sensor="s") is None
    cases = (({**ALERT, "src_ip": "not-an-ip"}, "FIELD_INVALID:src_ip"), ({**ALERT, "dest_ip": None}, "FIELD_INVALID:dest_ip"),
             ({**ALERT, "alert": {}}, "FIELD_MISSING:alert.signature"), ({**DNS, "dns": {}}, "FIELD_MISSING:dns.rrname"), ("text", "RECORD_MALFORMED"))
    for bad, code in cases:
        with pytest.raises(EvidenceFormatError) as e:
            eve_to_envelope(bad, sensor="s")
        assert str(e.value) == code
    for sensor in ("", "bad sensor", "x" * 65, "a/b"):
        with pytest.raises(EvidenceFormatError):
            eve_to_envelope(ALERT, sensor=sensor)


def test_hostile_signature_text_is_preserved_as_data_and_never_executed():
    evil = "<script>alert(1)</script> | [x](javascript:alert(1))"
    o = obs(eve_to_envelope({**ALERT, "alert": {**ALERT["alert"], "signature": evil}}, sensor="s"))
    assert o.title.startswith("IDS signature <script>")                            # kept verbatim here; escaping happens where reports are rendered


def test_file_import_counts_and_bounds(tmp_path):
    p = tmp_path / "eve.json"
    lines = [json.dumps(ALERT), json.dumps(FLOW), json.dumps({"event_type": "stats"}), "{not json", json.dumps({**ALERT, "src_ip": "x"}), ""]
    p.write_text("\n".join(lines), encoding="utf-8")
    envs, counts = eve_file_to_envelopes(p, sensor="s1")
    assert len(envs) == 2 and counts == {"read": 5, "converted": 2, "skipped_unsupported": 1, "rejected": 2}
    with pytest.raises(EvidenceFormatError):
        eve_file_to_envelopes(p, sensor="s1", max_records=3)
    with pytest.raises(EvidenceFormatError):
        eve_file_to_envelopes(tmp_path / "missing.json", sensor="s1")
    with pytest.raises(EvidenceFormatError):
        eve_file_to_envelopes(p, sensor="bad sensor")
