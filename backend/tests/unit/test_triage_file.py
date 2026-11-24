"""Offline triage tool (backend/scripts/triage_file.py): one export file in, reports out, with stated bounds and no evidence text in the summary."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location("triage_file", _ROOT / "backend" / "scripts" / "triage_file.py")
tf = importlib.util.module_from_spec(_SPEC)
sys.modules["triage_file"] = tf
_SPEC.loader.exec_module(tf)  # type: ignore[union-attr]

SECRET = "SECRETPAYLOAD7c1d"


def _rec(i: int, cmd: str, host: str = "ws1"):
    return {"SourceName": "Microsoft-Windows-Sysmon", "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": host, "EventID": "1",
            "UtcTime": f"2026-01-02 03:{i * 5:02d}:00.000", "ProcessGuid": "{00000000-0000-0000-0000-0000000000%02d}" % i,
            "Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": cmd, "ParentImage": "C:\\Windows\\explorer.exe", "ProcessId": str(100 + i),
            "User": "LAB\\u", "LogonId": "0x1a2b3"}


def _write_jsonl(path: Path, records, extra_lines=()):
    path.write_text("\n".join([json.dumps(r) for r in records] + list(extra_lines)) + "\n", encoding="utf-8")


def test_a_jsonl_export_produces_a_summary_and_incident_reports(tmp_path, capsys):
    src = tmp_path / "export.jsonl"
    _write_jsonl(src, [_rec(i, f"schtasks /create /tn T{i} /tr C:\\a.exe {SECRET}") for i in range(1, 4)], extra_lines=["this line is not json"])
    out = tmp_path / "out"
    assert tf.main([str(src), "--out", str(out)]) == 0
    summary = (out / "summary.md").read_text(encoding="utf-8")
    assert "Records read: 3 (lines that were not valid JSON: 1)" in summary
    assert "T1053.005" in summary and "EP-T1053.005-SCHTASKS-CREATE" in summary
    assert "Ledger hash chain verified: yes" in summary and "Input SHA-256:" in summary
    assert "endpoint-attack-v1" in summary and "suff-v5" in summary
    assert SECRET not in summary                                            # counts, names and pointers only
    reports = sorted(p.name for p in out.glob("incident_*.md"))
    assert reports and all(name.endswith(("_limited.md", "_sufficient.md", "_insufficient.md")) for name in reports)
    assert "Records behind each technique" in (out / reports[0]).read_text(encoding="utf-8")
    assert "records 3" in capsys.readouterr().out


def test_a_json_array_is_read_too(tmp_path):
    src = tmp_path / "export.json"
    src.write_text(json.dumps([_rec(1, "schtasks /create /tn x /tr C:\\a.exe")]), encoding="utf-8")
    assert tf.main([str(src), "--out", str(tmp_path / "o")]) == 0
    assert "Records read: 1" in (tmp_path / "o" / "summary.md").read_text(encoding="utf-8")


def test_more_records_than_the_bound_is_refused_and_writes_nothing(tmp_path, capsys):
    src = tmp_path / "big.jsonl"
    _write_jsonl(src, [_rec(i % 9 + 1, "schtasks /create /tn x /tr C:\\a.exe") for i in range(30)])
    out = tmp_path / "out"
    assert tf.main([str(src), "--out", str(out), "--max-records", "10"]) == 2
    assert not out.exists() and "exceeds --max-records 10" in capsys.readouterr().err


def test_missing_and_empty_inputs_are_refused(tmp_path, capsys):
    assert tf.main([str(tmp_path / "nope.jsonl"), "--out", str(tmp_path / "o")]) == 2
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n\nnot json\n", encoding="utf-8")
    assert tf.main([str(empty), "--out", str(tmp_path / "o2")]) == 2
    assert "no records found" in capsys.readouterr().err


def test_no_technique_is_reported_as_no_evidence_of_absence(tmp_path):
    src = tmp_path / "quiet.jsonl"
    _write_jsonl(src, [_rec(1, "notepad.exe readme.txt")])
    assert tf.main([str(src), "--out", str(tmp_path / "o")]) == 0
    summary = (tmp_path / "o" / "summary.md").read_text(encoding="utf-8")
    assert "No technique rule fired" in summary and "not evidence of absence" in summary


def test_the_report_cap_is_applied_and_disclosed(tmp_path):
    src = tmp_path / "many.jsonl"
    _write_jsonl(src, [_rec(i, "schtasks /create /tn x /tr C:\\a.exe", host=f"ws{i}") for i in range(1, 6)])
    out = tmp_path / "out"
    assert tf.main([str(src), "--out", str(out), "--max-reports", "2"]) == 0
    assert len(list(out.glob("incident_*.md"))) == 2
    assert "Incident reports written: 2 of 5" in (out / "summary.md").read_text(encoding="utf-8")
