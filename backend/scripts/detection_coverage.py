#!/usr/bin/env python3
"""
Generate docs/10_Research/Detection_Coverage_and_Telemetry.md from the endpoint rule table.

For a detection engineer or a SOC lead planning a pilot: which logging must be switched on for each rule to be able to see anything, and what each rule does and
does not prove. The table is generated from ``ENDPOINT_RULES`` so it cannot drift from the code (a test regenerates it and compares).

    .venv\\Scripts\\python.exe backend\\scripts\\detection_coverage.py --out docs\\10_Research\\Detection_Coverage_and_Telemetry.md
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.modules.correlation.mitre_endpoint import ENDPOINT_MAPPING_VERSION, ENDPOINT_RULES  # noqa: E402

PROC_CMD = "Process creation with command line (Sysmon event 1, or Windows Security 4688 with command-line auditing on)"
PROC = "Process creation (Sysmon event 1 or Windows Security 4688); the command line is not needed"
SYSMON_1 = "Sysmon event 1 with ParentImage"
SYSMON_8 = "Sysmon event 8 (CreateRemoteThread)"
SYSMON_10 = "Sysmon event 10 (process access) with lsass.exe not excluded by the Sysmon configuration"
SYSMON_13 = "Sysmon event 13 (registry value set)"
SYSMON_11 = "Sysmon event 11 (file create)"
SEC_4719 = "Windows Security event 4719 (audit policy change; subcategory Audit Policy Change)"
SEC_1102 = "Windows Security event 1102 (audit log cleared; logged by default)"

#: Rules that do not simply need process creation with a command line. Everything else is a command-line rule (PROC_CMD).
TELEMETRY: dict[str, tuple[str, ...]] = {
    "EP-T1003.001-LSASS-MEMORY-READ": (SYSMON_10,),
    "EP-T1055-REMOTE-THREAD": (SYSMON_8,),
    "EP-T1547.001-RUN-KEY-OR-STARTUP": (SYSMON_13, SYSMON_11, PROC_CMD),
    "EP-T1037.001-LOGON-SCRIPT": (SYSMON_13, PROC_CMD),
    "EP-T1548.002-UAC-BYPASS-REGISTRY": (SYSMON_13, PROC_CMD),
    "EP-T1562.002-AUDIT-POLICY-CHANGED": (SEC_4719,),
    "EP-T1070.001-LOG-CLEARED": (SEC_1102, PROC_CMD),
    "EP-T1047-WMI-PROVIDER-SPAWN": (SYSMON_1,),
    "EP-T1021.006-WINRM-HOST-PROCESS": (PROC,),
    "EP-T1220-XSL-SCRIPT": (PROC_CMD,),
}


def telemetry_for(rule_id: str) -> tuple[str, ...]:
    return TELEMETRY.get(rule_id, (PROC_CMD,))


def build_markdown() -> str:
    by_source: dict[str, list[str]] = defaultdict(list)
    for r in ENDPOINT_RULES:
        for t in telemetry_for(r.rule_id):
            by_source[t].append(r.rule_id)
    techniques = sorted({r.technique_id for r in ENDPOINT_RULES})
    lines = [
        "# Detection coverage and telemetry requirements (endpoint rule table)",
        "",
        f"Generated from `backend/app/modules/correlation/mitre_endpoint.py` (table `{ENDPOINT_MAPPING_VERSION}`) by `backend/scripts/detection_coverage.py`; "
        "a test regenerates it and fails if this file differs. Do not edit by hand.",
        "",
        "## What this is for",
        "A rule can only fire if the telemetry it reads exists. Before a pilot, a detection engineer checks that each source below is collected and forwarded in the "
        "form the rules read. This document lists the rules that exist and the logging they depend on; it is **not** a claim that a technique is detected.",
        "",
        "Measured result, for context (`docs/10_Research/Detection_Engineering_Evaluation.md`): on the held-out half of public attack captures labelled by their own "
        "authors, the rules recovered 11 of 34 documented techniques (32%; interval about 19% to 49%). Lateral movement, Kerberos and in-memory techniques are mostly "
        "not covered, and several captures lacked the telemetry altogether.",
        "",
        f"The table has {len(ENDPOINT_RULES)} rules covering {len(techniques)} techniques: " + ", ".join(techniques) + ".",
        "",
        "## Logging to enable, and how many rules depend on it",
        "| Telemetry | Rules |",
        "|---|---|",
    ]
    for source, ids in sorted(by_source.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines.append(f"| {source} | {len(ids)} |")
    lines += [
        "",
        "Notes a detection engineer should act on:",
        "- Most rules read **process creation with the command line**. On Windows that means Sysmon event 1, or Security event 4688 with the policy "
        "\"Include command line in process creation events\" enabled. One public capture shows an attacker turning that policy off, and the table has a rule for it "
        "(`EP-T1562.002-LOGGING-DISABLE-COMMAND`), but the change is only visible if it was logged before it took effect.",
        "- Sysmon event 10 against lsass.exe is excluded by many default configurations to reduce volume. If it is excluded, the LSASS memory rule cannot fire.",
        "- Command-line rules show that a command was run. They do not show who ran it, whether it succeeded, or why; each rule's limitation is stated below.",
        "- Normalised records keep a fixed whitelist of typed source fields (`source_fields`, 300 characters each). Fields outside that list are not visible to any rule.",
        "",
        "## Rules",
        "| Rule | Technique | Tactics | Telemetry it reads | What it does not prove |",
        "|---|---|---|---|---|",
    ]
    for r in ENDPOINT_RULES:
        lines.append(f"| `{r.rule_id}` | {r.technique_id} {r.technique_name} | {', '.join(r.tactics)} | {' or '.join(telemetry_for(r.rule_id))} | {r.limitation.replace('|', '/')} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.write_text(build_markdown(), encoding="utf-8", newline="\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
