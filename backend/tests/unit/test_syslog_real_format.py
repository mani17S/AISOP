"""
Raw sshd syslog (RFC 3164) as a second real source format (backend/scripts/syslog_to_records.py and the linux_auth adapter).

Lines below are written in the same format as a public real SSH log that was measured outside the repository (2,000 lines: 2,000 accepted); the hosts, users
and addresses are invented (documentation ranges). A syslog line has no year, so the pipeline must not invent one: a raw line is rejected, and the converter
needs an explicit year that it records as an assumption on every record.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from app.modules.alerts.adapters.linux_auth_adapter import _first_ip, _user_from
from app.modules.correlation.normalize import normalize_records
from app.modules.correlation.workflow import analyze

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location("syslog_to_records", _ROOT / "backend" / "scripts" / "syslog_to_records.py")
conv = importlib.util.module_from_spec(_SPEC)
sys.modules["syslog_to_records"] = conv
_SPEC.loader.exec_module(conv)  # type: ignore[union-attr]

H = "Dec 10 06:55:{s:02d} labhost sshd[2{n}]: "
SHAPES = [  # (message after the header, expected ip, expected user)
    ("Failed password for root from 203.0.113.5 port 54321 ssh2", "203.0.113.5", "root"),
    ("Failed password for invalid user admin from 203.0.113.6 port 40022 ssh2", "203.0.113.6", "admin"),
    ("Invalid user webmaster from 203.0.113.7", "203.0.113.7", "webmaster"),
    ("input_userauth_request: invalid user guest [preauth]", "", "guest"),
    ("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.8  user=root", "203.0.113.8", "root"),
    ("Received disconnect from 203.0.113.9: 11: Bye Bye [preauth]", "203.0.113.9", ""),
    ("Connection closed by 203.0.113.10 [preauth]", "203.0.113.10", ""),
    ("reverse mapping checking getaddrinfo for host.example [203.0.113.11] failed - POSSIBLE BREAK-IN ATTEMPT!", "203.0.113.11", ""),
]


def _records(messages, year=2015):
    lines = [H.format(s=i, n=i) + m for i, m in enumerate(messages)]
    records, counts = conv.convert(lines, year)
    assert counts["converted"] == len(lines)
    return records


def test_a_raw_syslog_line_is_rejected_because_it_has_no_year_and_none_is_invented():
    line = H.format(s=1, n=1) + "Failed password for root from 203.0.113.5 port 1 ssh2"
    bare = analyze([line])
    assert len(bare.normalization.events) == 0 and [r.reason for r in bare.normalization.rejected] == ["NOT_AN_OBJECT"]
    no_time = analyze([{"source_type": "linux_auth", "program": "sshd", "host": "labhost", "message": line}])
    assert len(no_time.normalization.events) == 0 and [r.reason for r in no_time.normalization.rejected] == ["TIMESTAMP_MISSING_OR_INVALID"]


def test_the_converter_needs_an_explicit_year_and_records_it_as_an_assumption():
    with pytest.raises(SystemExit):
        conv.main(["--in", "x", "--out", "y"])
    rec = _records([SHAPES[0][0]], year=2015)[0]
    assert rec["timestamp"] == "2015-12-10T06:55:00" and rec["year_assumed"] is True and rec["source_type"] == "linux_auth"
    assert rec["message"].endswith("Failed password for root from 203.0.113.5 port 54321 ssh2"), "the original line is kept verbatim"


def test_non_syslog_lines_are_skipped_and_counted_and_a_new_year_is_flagged():
    records, counts = conv.convert(["not a syslog line", "Dec 31 23:59:59 h sshd[1]: x", "Jan  1 00:00:05 h sshd[1]: y"], 2015)
    assert counts == {"converted": 2, "skipped_not_syslog": 1, "year_rollovers": 1}
    assert records[0]["timestamp"].startswith("2015-12-31") and records[1]["timestamp"].startswith("2016-01-01")


@pytest.mark.parametrize("message,ip,user", SHAPES)
def test_each_real_line_shape_yields_the_address_and_user_it_names(message, ip, user):
    event = normalize_records(_records([message])).events[0]
    assert (event.src_ip or "") == ip and (event.user or "") == user
    assert event.time_assumed_utc is True, "a time with an assumed year and no zone must be flagged"


def test_an_address_with_a_trailing_colon_is_cleaned_and_a_word_is_never_taken_as_an_address():
    assert _first_ip("Received disconnect from 203.0.113.9: 11: Bye") == "203.0.113.9"
    assert _first_ip("Failed password for root from nobody port 22") == ""
    assert _user_from("check pass; user unknown") == ""


def test_a_flood_of_failed_logins_from_one_address_seen_by_one_sensor_is_not_called_sufficient():
    messages = [f"Failed password for root from 203.0.113.5 port {40000 + i} ssh2" for i in range(12)]
    result = analyze(_records(messages))
    assert len(result.normalization.events) == 12 and result.normalization.rejected == []
    assert result.incidents and all(i.assessment.verdict.value != "sufficient" for i in result.incidents)
