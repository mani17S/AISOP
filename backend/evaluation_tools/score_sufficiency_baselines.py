"""
Score baselines B0, B1 and the AISOP sufficiency gate on the derived sufficiency cases
(docs/10_Research/Evaluation.md). Read-only on the hash-locked dataset: the manifest is verified first.

Usage (from the repository root):
    .venv\\Scripts\\python.exe backend\\evaluation_tools\\score_sufficiency_baselines.py --out D:\\AISOP-Backups\\AISOP_Dev_Logs\\eval_run1
    ... --held-out   (explicit flag; run ONCE, after the rule and baselines are frozen)
    ... --write-labels-template   (writes datasets/sufficiency_eval/labels_template.csv for the development split; never overwrites)

Always written to --out (a directory on drive D:): ``verdicts_<split>.csv`` with columns
case_id, B0, B1, AISOP. Printed without labels: how often each arm says SUFFICIENT / LIMITED / INSUFFICIENT,
and label-independent agreement counts (B0 or B1 SUFFICIENT where AISOP is not, and the reverse). These say
how the arms behave, NOT which is right.

Labels (owner-authored; this script never creates or fills them). If ``datasets/sufficiency_eval/labels.json``
exists (override with --labels) it is used; the evaluator's per-split ``<split>/labels.json`` is the fallback.
Schema (the same as ``labelling_guide.md``):

    {"labeller": "<name>", "second_reviewer": "<name or null>", "date": "YYYY-MM-DD",
     "labels": {"<case_id>": {"label": "SUFFICIENT|LIMITED|INSUFFICIENT", "justification": "one line"}}}

Label case is ignored. Cases without a label are skipped. With labels, per arm over the labelled cases of
the chosen split: false-sufficient rate = share of cases labelled LIMITED or INSUFFICIENT that the arm calls
SUFFICIENT (95% Wilson interval), and abstention rate = share of labelled cases the arm calls INSUFFICIENT.
B0 and B1 cannot say LIMITED; that is part of what is being measured, not a defect.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency  # noqa: E402
from app.modules.evaluation.baselines import baseline_verdict  # noqa: E402
from app.modules.evaluation.sufficiency_evaluator import (  # noqa: E402
    DEFAULT_BASE_DIR,
    LABELS,
    build_context_from_case,
    load_cases,
    load_labels,
    verify_manifest,
    wilson_interval,
)

ARM_NAMES = ("B0", "B1", "AISOP")
HELDOUT_WARNING = (
    "WARNING: the held-out split is for ONE final run after the rules and baselines are frozen. "
    "Do not iterate on it or tune anything against these results."
)


def run_case(case: dict[str, Any]) -> dict[str, str]:
    ctx = build_context_from_case(case)
    return {
        "case_id": case["case_id"],
        "B0": baseline_verdict(ctx, "B0"),
        "B1": baseline_verdict(ctx, "B1"),
        "AISOP": evaluate_sufficiency(ctx).verdict.value.upper(),
    }


def distribution(rows: list[dict[str, str]], arm: str) -> dict[str, int]:
    c = Counter(r[arm] for r in rows)
    return {lab: c.get(lab, 0) for lab in LABELS}


def agreement_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    """Label-independent counts of how the arms differ."""
    return {
        "cases": len(rows),
        "B0_sufficient_AISOP_not": sum(1 for r in rows if r["B0"] == "SUFFICIENT" and r["AISOP"] != "SUFFICIENT"),
        "B1_sufficient_AISOP_not": sum(1 for r in rows if r["B1"] == "SUFFICIENT" and r["AISOP"] != "SUFFICIENT"),
        "AISOP_sufficient_B0_not": sum(1 for r in rows if r["AISOP"] == "SUFFICIENT" and r["B0"] != "SUFFICIENT"),
        "AISOP_sufficient_B1_not": sum(1 for r in rows if r["AISOP"] == "SUFFICIENT" and r["B1"] != "SUFFICIENT"),
        "B0_equals_AISOP": sum(1 for r in rows if r["B0"] == r["AISOP"]),
        "B1_equals_AISOP": sum(1 for r in rows if r["B1"] == r["AISOP"]),
        "B0_equals_B1": sum(1 for r in rows if r["B0"] == r["B1"]),
    }


def labelled_metrics(rows: list[dict[str, str]], labels: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Per arm: false-sufficient rate (labelled LIMITED/INSUFFICIENT called SUFFICIENT) with a Wilson 95% interval; abstention rate."""
    scored = [r for r in rows if r["case_id"] in labels]
    not_sufficient = [r for r in scored if labels[r["case_id"]]["label"] in ("LIMITED", "INSUFFICIENT")]
    out: dict[str, Any] = {"labelled_cases": len(scored), "labelled_not_sufficient": len(not_sufficient)}
    for arm in ARM_NAMES:
        k = sum(1 for r in not_sufficient if r[arm] == "SUFFICIENT")
        n = len(not_sufficient)
        a = sum(1 for r in scored if r[arm] == "INSUFFICIENT")
        out[arm] = {
            "false_sufficient": k,
            "false_sufficient_rate": None if n == 0 else round(k / n, 4),
            "false_sufficient_ci95": wilson_interval(k, n),
            "abstained": a,
            "abstention_rate": None if not scored else round(a / len(scored), 4),
        }
    return out


def describe_case(case: dict[str, Any]) -> str:
    """One neutral line from the case content only (no generator metadata, no gate output)."""
    events = case.get("events", [])
    types = Counter(e["event_type"] for e in events)
    kinds = ", ".join(f"{t} x{n}" for t, n in sorted(types.items())) or "no events"
    digests = {e["raw_evidence_sha256"] for e in events}
    keys = {e["key"] for e in events}
    root = case.get("question", {}).get("root_event_key")
    root_txt = "root event present" if root in keys else ("root event absent" if root else "no root event")
    shared = sum(1 for x in case.get("entities", []) if len(set(x["event_keys"])) >= 2)
    omitted = int(case.get("omitted_events", 0))
    parts = [
        f"{len(events)} events ({kinds})",
        f"{len(digests)} distinct raw digests",
        f"{len(case.get('entities', []))} entities, {shared} shared by 2+ events",
        root_txt,
        f"{omitted} omitted" if omitted else "not truncated",
    ]
    return "; ".join(parts)


def write_labels_template(path: Path, base_dir: Path) -> int:
    if path.exists():
        print(f"REFUSING: {path} already exists (never overwritten)")
        return 2
    cases = load_cases("dev", base_dir)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "description", "label", "notes"])
        for c in cases:
            w.writerow([c["case_id"], describe_case(c), "", ""])
    print(f"wrote {path} ({len(cases)} rows; label column empty; allowed: sufficient / limited / insufficient)")
    return 0


def _load_labels(path: Optional[Path], split: str, base_dir: Path) -> Optional[dict[str, dict[str, Any]]]:
    if path is None:
        path = base_dir / "labels.json"
    if path.is_file():
        raw = json.loads(path.read_text(encoding="utf-8"))
        out: dict[str, dict[str, Any]] = {}
        for cid, entry in raw.get("labels", raw).items():
            if entry is None or entry.get("label") is None:
                continue
            lab = str(entry["label"]).upper()
            if lab not in LABELS:
                raise ValueError(f"invalid label {entry['label']!r} for {cid}")
            out[cid] = {"label": lab}
        return out
    return load_labels(split, base_dir)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--out", help="output directory on drive D: (required unless --write-labels-template)")
    ap.add_argument("--held-out", action="store_true", help="score the held-out split instead of development (run once)")
    ap.add_argument("--labels", type=Path, default=None, help="labels file (default datasets/sufficiency_eval/labels.json)")
    ap.add_argument("--base-dir", type=Path, default=DEFAULT_BASE_DIR, help=argparse.SUPPRESS)
    ap.add_argument("--write-labels-template", action="store_true")
    args = ap.parse_args(argv)

    if args.write_labels_template:
        return write_labels_template(args.base_dir / "labels_template.csv", args.base_dir)
    if args.held_out:
        print(HELDOUT_WARNING)
    if not args.out:
        print("REFUSING: --out is required")
        return 2
    out_dir = Path(args.out).resolve()
    if out_dir.drive.upper() != "D:":
        print(f"REFUSING: --out must be on drive D: (got {out_dir})")
        return 2

    split = "heldout" if args.held_out else "dev"
    verify_manifest(args.base_dir)
    rows = [run_case(c) for c in load_cases(split, args.base_dir)]
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / f"verdicts_{split}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["case_id", *ARM_NAMES])
        w.writeheader()
        w.writerows(rows)

    print(f"split: {split}; cases: {len(rows)}; wrote {csv_path}")
    for arm in ARM_NAMES:
        print(f"{arm:6s} {distribution(rows, arm)}")
    print("agreement (label-independent; says nothing about who is right):")
    for k, v in agreement_counts(rows).items():
        print(f"  {k}: {v}")
    labels = _load_labels(args.labels, split, args.base_dir)
    if labels is None:
        print("labels: none found; accuracy, false-sufficient rate and abstention against labels are NOT computed")
    else:
        m = labelled_metrics(rows, labels)
        print("against owner labels:", json.dumps(m, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
