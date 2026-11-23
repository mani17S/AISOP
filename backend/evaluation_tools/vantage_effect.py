#!/usr/bin/env python3
"""
Measured effect of vantage-level independence (ADR-017) on the 67 development cases. No labels, no model, no network, no database; the
held-out split is never used.

The hash-locked cases carry no vantage, so the rule changes nothing for them as they are. To measure what the rule does, each case is
re-annotated in four controlled ways (an explicit ``attributes["vantage"]`` on every record) and the verdicts are compared with the
unannotated ones:
  none           no annotation (the dataset as locked)
  one vantage    every record seen from one vantage        -> corroboration is one witness
  root vs rest   the key event from vantage A, the rest from B  -> corroboration crosses vantages
  each distinct  every record from its own vantage           -> corroboration crosses vantages
The rule may only LOWER a verdict. The script counts raises (there must be none) and reports how many SUFFICIENT cases fall.

    .venv\\Scripts\\python.exe backend\\evaluation_tools\\vantage_effect.py
"""

from __future__ import annotations

import copy
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency  # noqa: E402
from app.modules.evaluation.sufficiency_evaluator import DEFAULT_BASE_DIR, build_context_from_case, load_cases, verify_manifest  # noqa: E402
from app.schemas.sufficiency import ReasonCode  # noqa: E402

RANK = {"insufficient": 0, "limited": 1, "sufficient": 2}


def verdict(case):
    a = evaluate_sufficiency(build_context_from_case(case))
    return a.verdict.value, ReasonCode.SAME_VANTAGE_ONLY in {f.code for f in a.findings}


def annotate(case, mode):
    c = copy.deepcopy(case)
    root = c["question"].get("root_event_key")
    for i, ev in enumerate(c["events"]):
        vantage = "sensor-a" if mode == "one" else ("sensor-a" if ev["key"] == root else "sensor-b") if mode == "root_vs_rest" else f"sensor-{i}"
        ev.setdefault("attributes", {})["vantage"] = vantage
    return c


def main() -> int:
    verify_manifest(DEFAULT_BASE_DIR)
    cases = load_cases("dev", DEFAULT_BASE_DIR)
    base = {c["case_id"]: verdict(c)[0] for c in cases}
    print(f"development cases: {len(cases)} (manifest verified)\n")
    print(f"{'annotation':16} {'SUFFICIENT':>10} {'LIMITED':>8} {'INSUFFICIENT':>13} {'fell':>5} {'raised':>7} {'capped by the rule':>19}")
    for label, mode in (("none (as locked)", None), ("one vantage", "one"), ("root vs rest", "root_vs_rest"), ("each distinct", "each")):
        dist, fell, raised, capped = Counter(), 0, 0, 0
        for c in cases:
            v, capped_here = verdict(annotate(c, mode) if mode else c)
            dist[v] += 1
            fell += RANK[v] < RANK[base[c["case_id"]]]
            raised += RANK[v] > RANK[base[c["case_id"]]]
            capped += capped_here
        print(f"{label:16} {dist['sufficient']:10d} {dist['limited']:8d} {dist['insufficient']:13d} {fell:5d} {raised:7d} {capped:19d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
