#!/usr/bin/env python3
"""
Score the deterministic ATT&CK rules against PUBLIC attack datasets whose technique labels were written by someone else.

Truth: the OTRF Security-Datasets metadata (MIT licence) documents, for each captured simulation, the ATT&CK technique(s) the dataset author
says it demonstrates (``attack_mappings``). The author of those labels is not the author of AISOP's rules, which is the point: the earlier
20-scenario score used scenarios and rules written by the same person.

What is measured, per dataset: did any rule emit the documented technique (exactly, or at the parent technique)? What else did the rules emit
(reported, NOT counted as false positives automatically: an attack capture also holds real activity the author did not label)?

What this is NOT: precision against labelled benign data (none is used here), event-level truth (labels are per dataset), or a claim about
real incidents. Datasets the host cannot open (for example attack-tool text blocked by endpoint protection) are listed as unreadable and are
excluded the same way on every split.

    .venv\\Scripts\\python.exe backend\\evaluation_tools\\score_attack_datasets.py --side dev --out D:\\AISOP-Backups\\AISOP_Dev_Logs\\attack_datasets_dev.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.modules.correlation.mitre import MAPPING_VERSION, RULES, map_techniques  # noqa: E402
from app.modules.correlation.mitre_endpoint import ENDPOINT_MAPPING_VERSION, ENDPOINT_RULES, map_endpoint_techniques  # noqa: E402
from app.modules.correlation.normalize import normalize_records  # noqa: E402

DATA = Path("D:/AISOP-Reference-Data")
SPLIT = DATA / "otrf_metadata_20261124" / "split.json"
_TECH = __import__("re").compile(r"^T(?!0000)\d{4}(?:\.\d{3})?$")  # T0000 is the dataset authors' placeholder, not a technique


def parent(t: str) -> str:
    return t.split(".")[0]


def load_records(folder: Path) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    unreadable: list[str] = []
    for f in sorted(folder.rglob("*.json")):
        try:
            fh = open(f, encoding="utf-8", errors="replace")
        except OSError:
            unreadable.append(f.name)
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict):
                    records.append(r)
    return records, unreadable


def score_one(dataset: dict[str, Any], folder: Path) -> dict[str, Any]:
    documented = [t for t in dataset["techniques"] if _TECH.match(t)]
    records, unreadable = load_records(folder)
    base = {"id": dataset["id"], "title": dataset["title"], "documented": documented}
    if not records:
        return {**base, "status": "unreadable" if unreadable else "empty", "unreadable_files": unreadable}
    started = time.perf_counter()
    norm = normalize_records(records)
    mappings = map_techniques(norm.events) + map_endpoint_techniques(norm.events)
    emitted = sorted({m.technique_id for m in mappings})
    per_rule = Counter(m.rule_id for m in mappings)
    exact = [t for t in documented if t in emitted]
    at_parent = [t for t in documented if any(parent(e) == parent(t) for e in emitted)]
    extra = sorted(e for e in emitted if not any(parent(e) == parent(t) for t in documented))
    return {**base, "status": "scored", "records": len(records), "accepted": len(norm.events), "rejected": len(norm.rejected),
            "emitted": emitted, "exact": exact, "parent_level": at_parent, "missed": [t for t in documented if t not in at_parent],
            "other_techniques": extra, "rules_fired": dict(per_rule), "seconds": round(time.perf_counter() - started, 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--side", choices=("dev", "heldout"), required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    folder_root = DATA / f"otrf_{args.side}_20261124"
    datasets = [d for d in json.loads(SPLIT.read_text(encoding="utf-8")) if d["side"] == args.side and (folder_root / d["id"]).is_dir()]
    results = []
    for d in datasets:
        r = score_one(d, folder_root / d["id"])
        results.append(r)
        if r["status"] == "scored":
            print(f"{r['id']} {','.join(r['documented']):22s} acc={r['accepted']:6d}/{r['records']:<6d} parent_hit={len(r['parent_level'])}/{len(r['documented'])} "
                  f"emitted={','.join(r['emitted']) or '-'}", flush=True)
        else:
            print(f"{r['id']} {r['status']}", flush=True)
    scored = [r for r in results if r["status"] == "scored"]
    pairs = [(r["id"], t) for r in scored for t in r["documented"]]
    hit_parent = sum(len(r["parent_level"]) for r in scored)
    hit_exact = sum(len(r["exact"]) for r in scored)
    ds_any = sum(1 for r in scored if r["parent_level"])
    summary = {
        "mapping_version": MAPPING_VERSION, "endpoint_mapping_version": ENDPOINT_MAPPING_VERSION, "rules": len(RULES) + len(ENDPOINT_RULES), "side": args.side,
        "datasets_total": len(results), "datasets_scored": len(scored), "datasets_unreadable_or_empty": len(results) - len(scored),
        "documented_techniques": len(pairs), "recovered_at_parent": hit_parent, "recovered_exact": hit_exact,
        "datasets_with_any_recovery": ds_any,
        "records_total": sum(r["records"] for r in scored), "records_accepted": sum(r["accepted"] for r in scored),
    }
    print(json.dumps(summary, indent=1))
    args.out.write_text(json.dumps({"summary": summary, "datasets": results}, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
