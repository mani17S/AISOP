#!/usr/bin/env python3
"""
Ablation of the sufficiency gate on the 67 development cases. No labels, no model, no network, no database; the held-out split is never used.

The arms add AISOP's rules to the naive baseline one at a time (definitions in app/modules/evaluation/baselines.py):
  B0 any shared entity corroborates | B1 + identical raw records count once | B2 + only specific or strong artefacts corroborate
  B3 + AISOP's duplicate clustering | B4 + the records must be different observations | AISOP the full gate (LIMITED tier,
  provenance, contradictions, truncation, root event).

For each arm it prints: how often it says SUFFICIENT, whether those cases are the same cases as AISOP's, how many metamorphic
relations it breaks (backend/evaluation_tools/metamorphic_sufficiency.py), and what the full gate adds on top of the last ablation arm.
It measures behaviour, not correctness: no labels exist, and B4 is an approximation of one gate rule, not the gate.

    .venv\\Scripts\\python.exe backend\\evaluation_tools\\ablation_sufficiency.py --out D:\\AISOP-Backups\\AISOP_Dev_Logs\\ablation_run
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import metamorphic_sufficiency as mm  # noqa: E402
from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency  # noqa: E402
from app.modules.evaluation.baselines import ABLATION_ARMS, baseline_verdict, ablation_verdict  # noqa: E402
from app.modules.evaluation.sufficiency_evaluator import DEFAULT_BASE_DIR, build_context_from_case, load_cases, verify_manifest  # noqa: E402

ARMS = ("B0", "B1", "B2", "B3", "B4", "AISOP")
DESCRIPTION = {
    "B0": "any shared entity corroborates", "B1": "+ identical raw records count once", "B2": "+ only specific or strong artefacts",
    "B3": "+ AISOP duplicate clustering", "B4": "+ different observations required", "AISOP": "full gate (LIMITED, provenance, contradictions)",
}


def verdicts_for(case: dict[str, Any]) -> dict[str, str]:
    ctx = build_context_from_case(case)
    out = {a: baseline_verdict(ctx, a) for a in ("B0", "B1")}
    out.update({a: ablation_verdict(ctx, a) for a in ABLATION_ARMS})
    out["AISOP"] = evaluate_sufficiency(ctx).verdict.value.upper()
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--out", required=True, help="output directory on drive D:")
    args = ap.parse_args(argv)
    out_dir = Path(args.out).resolve()
    if out_dir.drive.upper() != "D:":
        print(f"REFUSING: --out must be on drive D: (got {out_dir})")
        return 2

    verify_manifest(DEFAULT_BASE_DIR)
    cases = load_cases("dev", DEFAULT_BASE_DIR)
    base = {c["case_id"]: verdicts_for(c) for c in cases}
    sufficient = {a: {cid for cid, v in base.items() if v[a] == "SUFFICIENT"} for a in ARMS}

    violations: dict[str, dict[str, int]] = {a: {} for a in ARMS}
    for name, mutate, kind in mm.RELATIONS:
        for c in cases:
            m = mutate(c)
            if m is None:
                continue
            after = verdicts_for(m)
            for a in ARMS:
                if mm.violated(kind, base[c["case_id"]][a], after[a]):
                    violations[a][name] = violations[a].get(name, 0) + 1

    print(f"development cases: {len(cases)} (manifest verified)\n")
    print(f"{'arm':6} {'rule added':50} {'SUFFICIENT':>10} {'same as AISOP':>13} {'also in AISOP':>13} {'metamorphic breaks':>19}")
    rows = {}
    for a in ARMS:
        s = sufficient[a]
        inter = len(s & sufficient["AISOP"])
        total_breaks = sum(violations[a].values())
        rows[a] = {"sufficient": len(s), "in_aisop": inter, "metamorphic_breaks": total_breaks, "breaks_by_relation": violations[a]}
        print(f"{a:6} {DESCRIPTION[a]:50} {len(s):10d} {('identical set' if s == sufficient['AISOP'] else '-'):>13} {inter:>13d} {total_breaks:>19d}")
    only_aisop = sorted(sufficient["AISOP"] - sufficient["B4"])
    only_b4 = sorted(sufficient["B4"] - sufficient["AISOP"])
    print(f"\nSUFFICIENT for AISOP but not B4: {len(only_aisop)}   SUFFICIENT for B4 but not AISOP: {len(only_b4)}")
    dist = Counter(v["AISOP"] for v in base.values())
    non_suff_b4 = [cid for cid, v in base.items() if v["B4"] == "INSUFFICIENT"]
    split = Counter(base[cid]["AISOP"] for cid in non_suff_b4)
    print(f"AISOP overall: {dict(dist)}")
    print(f"where B4 says INSUFFICIENT ({len(non_suff_b4)} cases) the full gate says: {dict(split)}  <- the LIMITED tier is what the extra rules add")

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "ablation_results.json").write_text(json.dumps({"arms": rows, "only_aisop": only_aisop, "only_b4": only_b4, "aisop_split_where_b4_insufficient": dict(split)}, indent=2), encoding="utf-8")
    print(f"\nwrote {out_dir / 'ablation_results.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
