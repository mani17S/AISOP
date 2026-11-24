#!/usr/bin/env python3
"""
Offline triage of one evidence export: the investigation reports an analyst would get from AISOP, from a single file, with no database, no model and no network.

Reads a JSON-lines file (one record per line) or a JSON array, runs the same deterministic workflow the product runs (normalise, correlate, sufficiency gate,
ATT&CK rules, hash-chained ledger) and writes a folder of Markdown: ``summary.md`` for the SOC lead and one report per incident for the analyst.

Bounds (stated, not hidden): at most 5,000 records unless ``--max-records`` is raised, because correlation time grows faster than linearly with the batch
(1,500 records take about 15 seconds on a laptop); at most 256 MB of input; at most 50 incident reports unless ``--max-reports`` is raised. Evidence text is
untrusted: the reports are the product's own escaped Markdown, and ``summary.md`` carries counts, names and record pointers, never evidence text.

    .venv\\Scripts\\python.exe backend\\scripts\\triage_file.py D:\\exports\\hosts.jsonl --out D:\\triage_run_1
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.modules.correlation.management_view import CAVEAT, management_view  # noqa: E402
from app.modules.correlation.mitre import MAPPING_VERSION  # noqa: E402
from app.modules.correlation.mitre_endpoint import ENDPOINT_MAPPING_VERSION  # noqa: E402
from app.modules.correlation.report import _cell  # noqa: E402
from app.modules.correlation.workflow import analyze  # noqa: E402
from app.modules.evidence_domains.domain_attack import DOMAIN_MAPPING_VERSION  # noqa: E402
from app.schemas.sufficiency import SUFFICIENCY_RULE_VERSION  # noqa: E402

MAX_BYTES = 256 * 1024 * 1024
VERDICT_RANK = {"sufficient": 0, "limited": 1, "insufficient": 2}


def load_records(path: Path) -> tuple[list[Any], int]:
    """(records, unparsed_lines). A JSON array is read whole; otherwise one JSON value per non-empty line, counting lines that are not valid JSON."""
    text = path.read_bytes().decode("utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
            if isinstance(data, list):
                return data, 0
        except ValueError:
            pass
    records: list[Any] = []
    bad = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except ValueError:
            bad += 1
    return records, bad


def build_summary(path: Path, digest: str, records_read: int, unparsed: int, result: Any, shown: int) -> str:
    view = management_view(result)
    norm = result.normalization
    verdicts = view["verdicts"]
    techniques: dict[str, dict[str, Any]] = {}
    for index, analysis in enumerate(result.incidents, start=1):
        for m in analysis.mitre:
            row = techniques.setdefault(m.technique_id, {"name": m.technique_name, "rules": set(), "incidents": []})
            row["rules"].add(m.rule_id)
            row["incidents"].append(index)
    lines = [
        f"# Triage summary: {_cell(path.name)}",
        "",
        f"- Input SHA-256: `{digest}`",
        f"- Records read: {records_read} (lines that were not valid JSON: {unparsed})",
        f"- Accepted by an adapter: {len(norm.events)}; rejected: {len(norm.rejected)} {dict(Counter(r.reason for r in norm.rejected)) or ''}",
        f"- Distinct evidence units after collapsing duplicates: {view['workload']['evidence_units']}; incidents: {view['workload']['incidents']}",
        f"- Verdicts: sufficient {verdicts['sufficient']}, limited {verdicts['limited']}, insufficient {verdicts['insufficient']}",
        f"- Ledger hash chain verified: {'yes' if view['integrity']['ledger_verified'] else 'NO'}",
        f"- Rule versions: sufficiency `{SUFFICIENCY_RULE_VERSION}`, ATT&CK `{MAPPING_VERSION}` + `{ENDPOINT_MAPPING_VERSION}` + `{DOMAIN_MAPPING_VERSION}`",
        f"- Incident reports written: {shown} of {len(result.incidents)}",
        "",
        "## Techniques the rules derived",
    ]
    if techniques:
        lines += ["| Technique | Rules | Incidents (report numbers) |", "|---|---|---|"]
        for tid, row in sorted(techniques.items()):
            lines.append(f"| {tid} {_cell(row['name'])} | {', '.join(f'`{r}`' for r in sorted(row['rules']))} | {', '.join(str(i) for i in row['incidents'][:12])} |")
        lines += ["", "Each incident report lists the records behind its techniques by record number and hash prefix. A rule matching is not proof of intent or success."]
    else:
        lines.append("No technique rule fired on this evidence. That is not evidence of absence: the rules cover a limited set of techniques.")
    lines += ["", "## What is missing from this evidence"]
    tele = view["telemetry"]
    lines.append(f"- Telemetry kinds present: {', '.join(tele['present']) or 'none'}")
    for kind, what in tele["collect"].items():
        lines.append(f"- Not present: {kind}. To raise confidence, collect {what}.")
    if view["next_steps"]:
        lines += ["", "## What would raise confidence on incidents held at LIMITED"]
        for step in view["next_steps"]:
            lines.append(f"- {step['incidents']} incident(s) ({step['reason_code']}): {step['action']}")
    dq = view["data_quality"]
    lines += ["", "## Data quality", f"- Records with an assumed (not source-documented) time zone: {dq['records_with_assumed_time']}", "", f"> {CAVEAT}", ""]
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("input", type=Path)
    ap.add_argument("--out", type=Path, required=True, help="folder for the reports (created)")
    ap.add_argument("--max-records", type=int, default=5000)
    ap.add_argument("--max-reports", type=int, default=50)
    args = ap.parse_args(argv)

    if not args.input.is_file():
        print(f"not a file: {args.input}", file=sys.stderr)
        return 2
    if args.input.stat().st_size > MAX_BYTES:
        print(f"input is larger than {MAX_BYTES // (1024 * 1024)} MB; split it first", file=sys.stderr)
        return 2
    digest = hashlib.sha256(args.input.read_bytes()).hexdigest()
    records, unparsed = load_records(args.input)
    if len(records) > args.max_records:
        print(f"{len(records)} records exceeds --max-records {args.max_records}: correlation time grows faster than linearly, so split the export by host or "
              f"time window, or raise the limit knowingly", file=sys.stderr)
        return 2
    if not records:
        print("no records found (expected a JSON array or one JSON object per line)", file=sys.stderr)
        return 2

    result = analyze(records)
    ordered = sorted(enumerate(result.incidents, start=1), key=lambda p: (-len(p[1].mitre), VERDICT_RANK.get(p[1].assessment.verdict.value, 3), p[0]))
    args.out.mkdir(parents=True, exist_ok=True)
    written = 0
    for number, analysis in ordered[: args.max_reports]:
        name = f"incident_{number:03d}_{analysis.assessment.verdict.value}.md"
        (args.out / name).write_text(analysis.markdown or "", encoding="utf-8", newline="\n")
        written += 1
    (args.out / "summary.md").write_text(build_summary(args.input, digest, len(records), unparsed, result, written), encoding="utf-8", newline="\n")

    view = management_view(result)
    print(f"records {len(records)}  accepted {len(result.normalization.events)}  rejected {len(result.normalization.rejected)}  incidents {len(result.incidents)}  "
          f"verdicts {view['verdicts']}  reports written {written}")
    print(f"wrote {args.out / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
