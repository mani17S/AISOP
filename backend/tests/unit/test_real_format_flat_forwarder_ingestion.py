"""
Flat Windows-forwarder exports (Winlogbeat/NXLog style) from a public dataset the project did not write.

Before 2026-11-23 none of the 377 records in the two source files was accepted (Sysmon records had no adapter, Security records failed
on the timestamp). The excerpt in datasets/samples/public holds one record per event type, copied unmodified (OTRF Security-Datasets, MIT).
"""

from __future__ import annotations

import json
from pathlib import Path

from app.modules.alerts.adapters.sysmon_adapter import SysmonAlertAdapter
from app.modules.alerts.adapters.windows_security_adapter import WindowsSecurityAdapter
from app.modules.correlation.normalize import normalize_records

_FIXTURE = Path(__file__).resolve().parents[3] / "datasets" / "samples" / "public" / "otrf_flat_forwarder_excerpt.jsonl"
_RECORDS = [json.loads(line) for line in _FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_the_fixture_has_the_ten_real_records():
    assert len(_RECORDS) == 10
    assert {r["Channel"].split("/")[0].lower() for r in _RECORDS} == {"microsoft-windows-sysmon", "security"}


def test_every_real_record_is_accepted_with_a_real_host_and_time():
    result = normalize_records(_RECORDS)
    assert result.rejected == [] or len(result.rejected) == 0
    assert len(result.events) == 10
    assert {e.source_type for e in result.events} == {"sysmon", "windows_security"}
    for e in result.events:
        assert e.host and e.host.upper() not in {"UNKNOWN-HOST", "WINDOWS-ENDPOINT"}, "the forwarder's Hostname must be used"
        assert e.timestamp.tzinfo is not None and e.timestamp.year == 2020


def test_the_raw_records_are_kept_with_a_digest_each():
    result = normalize_records(_RECORDS)
    assert len({e.raw_sha256 for e in result.events}) == 10


def test_a_flat_record_without_a_sysmon_or_security_marker_is_still_not_claimed():
    stranger = {"EventID": 1, "UtcTime": "2020-10-29 08:23:20.000", "Image": "C:\\x.exe", "Hostname": "h1"}
    assert SysmonAlertAdapter().can_adapt(stranger) is False
    assert WindowsSecurityAdapter().can_adapt({"Channel": "Application", "EventID": 99}) is False


def test_flat_forwarder_records_expose_their_process_guid_and_dns_name_to_the_correlator():
    """Before 2026-11-23 the correlator read an empty event for flat records, so these were missing."""
    result = normalize_records(_RECORDS)
    by_event_id = {str(r["EventID"]): e for r, e in zip(_RECORDS, result.events) if "Sysmon" in r["Channel"]}
    assert any(kind == "process_guid" for kind, _ in by_event_id["1"].entities) or any(
        kind == "process_guid" for e in result.events for kind, _ in e.entities
    ), "a Sysmon record with a ProcessGuid must produce a process_guid entity"
    dns = by_event_id["22"]
    assert any(kind == "domain" for kind, _ in dns.entities), "the DNS query name must become a domain entity"
