#!/usr/bin/env python3
"""
Convert raw RFC 3164 syslog lines (for example /var/log/auth.log) into the JSON records the ``linux_auth`` adapter accepts.

Why a converter and not a looser adapter. A classic syslog line carries month, day and time but NO YEAR ("Dec 10 06:55:46 host sshd[24200]: ..."). AISOP never
invents a timestamp, so the year is an explicit, recorded assumption supplied by the operator: ``--year`` is required, every record is marked
``year_assumed: true`` and the time stays naive (the pipeline then also flags it as assumed UTC, Stage 7B). When the month goes backwards by more than six
months the year is advanced by one (a log that crosses New Year); that is also an assumption and is counted and reported.

Lines that are not syslog (no header) are not converted and are counted. The original line is kept verbatim in ``message`` so nothing is lost.

    .venv\\Scripts\\python.exe backend\\scripts\\syslog_to_records.py --year 2015 --in D:\\path\\auth.log --out D:\\path\\records.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator, Optional

_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_HEADER = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)


def convert(lines: Iterable[str], year: int) -> tuple[list[dict], dict[str, int]]:
    """Return (records, counts). ``counts`` has converted, skipped_not_syslog, year_rollovers."""
    records: list[dict] = []
    counts = {"converted": 0, "skipped_not_syslog": 0, "year_rollovers": 0}
    current_year, previous_month = year, None
    for number, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        m = _HEADER.match(line)
        month = _MONTHS.get(m.group("mon")) if m else None
        if not m or month is None:
            counts["skipped_not_syslog"] += 1
            continue
        if previous_month is not None and month < previous_month - 6:
            current_year += 1
            counts["year_rollovers"] += 1
        previous_month = month
        hh, mm, ss = m.group("time").split(":")
        records.append({
            "id": f"line-{number}",
            "source_type": "linux_auth",
            "program": m.group("prog"),
            "host": m.group("host"),
            "message": line,
            "timestamp": f"{current_year:04d}-{month:02d}-{int(m.group('day')):02d}T{hh}:{mm}:{ss}",
            "year_assumed": True,
        })
        counts["converted"] += 1
    return records, counts


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--year", type=int, required=True, help="the year the log was written (a syslog line has none); recorded as an assumption")
    ap.add_argument("--in", dest="src", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    for p in (args.src, args.out):
        if p.resolve().drive.upper() != "D:":
            print(f"REFUSING: {p} is not on drive D:")
            return 2
    records, counts = convert(args.src.read_text(encoding="utf-8", errors="replace").splitlines(), args.year)
    args.out.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    print(f"converted {counts['converted']} lines, skipped {counts['skipped_not_syslog']} that are not syslog, "
          f"{counts['year_rollovers']} year rollover(s); year ASSUMED as {args.year}; wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
