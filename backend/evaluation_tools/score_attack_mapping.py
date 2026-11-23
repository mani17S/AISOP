#!/usr/bin/env python3
"""
Score the deterministic ATT&CK mapping against the 20 hand-authored ground-truth scenarios.

No model, no network, no database: it runs the same normalisation and rule engines the product uses
(``correlation.normalize``, ``correlation.mitre.map_techniques``, ``evidence_domains.domain_attack``)
over each scenario's raw telemetry and compares the techniques it emits with ``expected_mitre_techniques``.

What this is NOT: independent validation. The scenarios and their expected techniques were written by the
project author, and the rules were written by the same author, so agreement shows consistency, and each
miss shows a real gap in rule coverage. Nothing here is real telemetry.

    .venv\\Scripts\\python.exe backend\\evaluation_tools\\score_attack_mapping.py --out D:\\AISOP-Backups\\AISOP_Dev_Logs\\attack_run
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.modules.correlation.mitre import map_techniques  # noqa: E402
from app.modules.correlation.workflow import analyze  # noqa: E402
from app.modules.evidence_domains.domain_attack import map_domain_techniques  # noqa: E402


def parent(technique_id: str) -> str:
    return technique_id.split(".")[0]


def emitted(events: list[dict]) -> set[str]:
    # The scenario records are bare Sysmon fields. A real sensor labels its source, so add the provider marker the
    # Sysmon adapter looks for. No field value is changed.
    result = analyze([{**e, "provider": "microsoft-windows-sysmon"} for e in events])
    if result.normalization.rejected:
        raise SystemExit(f"{len(result.normalization.rejected)} record(s) were rejected, so the score would be wrong: {result.normalization.rejected[0]}")
    found = {m.technique_id for m in map_techniques(result.normalization.events)}
    found |= {m.technique_id for m in map_domain_techniques(result.observations)}
    return found


def covered(expected_id: str, found: set[str]) -> bool:
    """Exact match, or the emitted technique is the parent or a sub-technique of the expected one."""
    return any(f == expected_id or parent(f) == parent(expected_id) for f in found)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="folder for the per-scenario CSV and JSON")
    args = ap.parse_args()

    rows = []
    for path in sorted(p for d in ("atomic", "chain", "benign", "adversarial") for p in (ROOT / "datasets" / "ground_truth" / d).glob("SCN-*.json")):
        sc = json.loads(path.read_text(encoding="utf-8"))
        expected = sc["expected_mitre_techniques"]
        mandatory = [e["technique_id"] for e in expected if e["is_mandatory"]]
        acceptable = {e["technique_id"] for e in expected}
        found = emitted(sc["raw_telemetry_events"])
        hit = [m for m in mandatory if covered(m, found)]
        missed = [m for m in mandatory if m not in hit]
        extra = sorted(f for f in found if not any(f == a or parent(f) == parent(a) for a in acceptable))
        rows.append({
            "scenario": sc["scenario_id"], "category": sc["category"], "interpretation": sc["expected_interpretation"],
            "mandatory": mandatory, "hit": hit, "missed": missed, "emitted": sorted(found), "unexpected": extra,
        })

    print(f"{'scenario':12} {'category':20} {'mandatory':>9} {'hit':>4} {'emitted':>8} {'unexpected':>10}")
    for r in rows:
        print(f"{r['scenario']:12} {r['category']:20} {len(r['mandatory']):9d} {len(r['hit']):4d} {len(r['emitted']):8d} {len(r['unexpected']):10d}")

    m_total = sum(len(r["mandatory"]) for r in rows)
    m_hit = sum(len(r["hit"]) for r in rows)
    e_total = sum(len(r["emitted"]) for r in rows)
    e_unexp = sum(len(r["unexpected"]) for r in rows)
    benign = [r for r in rows if r["category"] == "benign_baseline"]
    benign_fp = [r["scenario"] for r in benign if r["emitted"]]
    print()
    print(f"scenarios: {len(rows)}   mandatory expected techniques: {m_total}   recovered: {m_hit}  (recall {m_hit / m_total:.2f})")
    print(f"emitted techniques: {e_total}   not in the expected list: {e_unexp}  (precision {(e_total - e_unexp) / e_total:.2f})" if e_total else "emitted techniques: 0")
    print(f"benign scenarios: {len(benign)}   with any technique emitted: {len(benign_fp)} {benign_fp}")
    print("missed:", {r["scenario"]: r["missed"] for r in rows if r["missed"]})
    print("unexpected:", {r["scenario"]: r["unexpected"] for r in rows if r["unexpected"]})

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "attack_mapping_scores.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"wrote {out / 'attack_mapping_scores.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
