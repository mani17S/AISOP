"""
The report points, under the ATT&CK table, to the records each technique rule matched (time, source, host, process name, record number, hash prefix), bounded
and escaped. It must NOT copy command lines or other evidence text into the stored result (test_multisource_api pins that for the API payload).
"""

from __future__ import annotations

from app.modules.correlation.workflow import analyze

SECRET = "SECRETPAYLOAD9f3a"


def _rec(i: int, cmd: str, image: str = "C:\\Windows\\System32\\schtasks.exe"):
    return {"SourceName": "Microsoft-Windows-Sysmon", "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "ws1", "EventID": "1",
            "UtcTime": f"2026-01-02 03:{i * 5:02d}:00.000", "ProcessGuid": "{00000000-0000-0000-0000-0000000000%02d}" % i,
            "Image": image, "CommandLine": cmd, "ParentImage": "C:\\Windows\\explorer.exe", "ProcessId": str(100 + i), "User": "LAB\\u", "LogonId": "0x1a2b3"}


def _result(records):
    result = analyze(records)
    assert result.incidents and result.incidents[0].mitre
    return result


def _line(md: str) -> str:
    return next(l for l in md.splitlines() if l.startswith("- T1053.005"))


def test_each_technique_points_to_its_matching_record_without_copying_the_command():
    result = _result([_rec(1, f"schtasks /create /tn Updater /tr C:\\a.exe /sc daily {SECRET}")])
    md = result.incidents[0].markdown
    line = _line(md)
    event = result.normalization.events[0]
    assert "Records behind each technique" in md and "EP-T1053.005-SCHTASKS-CREATE" in line
    assert "sysmon/1" in line and "host=ws1" in line and "process=schtasks.exe" in line
    assert f"record #{event.record_index}" in line and event.raw_sha256[:12] in line
    assert SECRET not in md and "/create" not in line                       # no evidence text in the stored report


def test_a_hostile_host_name_cannot_form_markup():
    record = _rec(1, "schtasks /create /tn x")
    record["Hostname"] = "<img src=x onerror=alert(1)>[a](http://evil.test)`rm`"
    result = _result([record])
    line = _line(result.incidents[0].markdown)
    assert "<img" not in line and "](http" not in line and line.count("`") == 2     # only the fixed rule-id span


def test_at_most_three_records_are_listed_per_technique():
    result = _result([_rec(i, "schtasks /create /tn T%d /tr C:\\a.exe" % i) for i in range(1, 8)])
    assert _line(result.incidents[0].markdown).count("sysmon/1") == 3
