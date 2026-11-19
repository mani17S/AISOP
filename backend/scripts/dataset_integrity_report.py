"""
Stage 5 dataset integrity check for ``datasets/sufficiency_eval`` (read-only).

Checks, without reading labels and without running the gate on the held-out split:
manifest hash lock, unique opaque case ids, no case-id/metadata leakage, base-scenario disjointness
between splits, content-level leakage (identical event/entity payload in both splits), within-split
duplicates, family/transform distribution, label-file availability.

Usage: python backend/scripts/dataset_integrity_report.py [--out report.json]
Exit code 0 when every integrity check passes (label availability is reported, not a failure).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "datasets" / "sufficiency_eval"
# Deliberately independent of the evaluation/ablation module: production scripts must not import it.


def verify_manifest() -> None:
    """Every line of MANIFEST.sha256 must match the file; every case file must be listed."""
    listed: dict[str, str] = {}
    for line in (BASE / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, rel = line.split(None, 1)
            listed[rel.strip()] = digest
    for rel, digest in listed.items():
        if hashlib.sha256((BASE / rel).read_bytes()).hexdigest() != digest:
            raise ValueError(f"hash mismatch: {rel}")
    on_disk = {p.relative_to(BASE).as_posix() for p in BASE.glob("*/cases/*.json")}
    if on_disk != {r for r in listed if "/cases/" in r}:
        raise ValueError("case files and manifest differ")


def load_cases(split: str) -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((BASE / split / "cases").glob("*.json"))]


def _content_key(case: dict) -> str:
    """Hash of the evidence content, independent of ids, base time and generator metadata."""
    payload = {"events": case.get("events"), "entities": case.get("entities"), "question": case.get("question")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def build_report() -> dict:
    checks: dict[str, dict] = {}
    try:
        verify_manifest()
        checks["manifest_hash_lock"] = {"ok": True}
    except (ValueError, OSError) as exc:
        checks["manifest_hash_lock"] = {"ok": False, "detail": str(exc)[:200]}
    cases = {s: load_cases(s) for s in ("dev", "heldout")}
    ids = [c["case_id"] for s in cases for c in cases[s]]
    checks["unique_case_ids"] = {"ok": len(ids) == len(set(ids)), "total": len(ids)}
    checks["opaque_ids"] = {"ok": all(i.startswith("SUFC-") and len(i) == 15 for i in ids)}
    bases = {s: {c["base_scenario_id"] for c in cases[s]} for s in cases}
    overlap = sorted(bases["dev"] & bases["heldout"])
    checks["base_scenario_disjoint"] = {"ok": not overlap, "overlap": overlap}
    keys = {s: {_content_key(c) for c in cases[s]} for s in cases}
    leak = keys["dev"] & keys["heldout"]
    checks["content_leakage_between_splits"] = {"ok": not leak, "identical_content_pairs": len(leak)}
    dup = {s: len(cases[s]) - len(keys[s]) for s in cases}
    checks["within_split_identical_content"] = {"ok": True, "duplicates": dup, "note": "informational: degradations can coincide"}
    fam = {s: dict(Counter(c["family"] for c in cases[s])) for s in cases}
    scoped = lambda s: {f for f in fam[s] if f != "global"}  # noqa: E731 - "global" = scope-free degradations
    checks["scenario_family_present_in_both_splits"] = {"ok": scoped("dev") == scoped("heldout")}
    tr = {s: dict(Counter(c["transform"] for c in cases[s])) for s in cases}
    missing = sorted(set(tr["dev"]) - set(tr["heldout"]))
    synthetic_only = all(str(c["base_scenario_id"]).startswith("SCN-") for s in cases for c in cases[s])
    labels = {s: (BASE / s / "labels.json").is_file() for s in cases}
    return {
        "dataset": "datasets/sufficiency_eval",
        "counts": {s: len(cases[s]) for s in cases},
        "checks": checks,
        "all_integrity_checks_pass": all(v["ok"] for v in checks.values()),
        "families": fam,
        "transforms": tr,
        "coverage_gaps": {
            "transforms_in_dev_but_absent_from_heldout": missing,
            "note": "Held-out has no probe of host/user-only links, same-record pairs, empty scope or out-of-window "
                    "evidence; the independence rules fixed in Stage 3C-R are therefore only exercised on dev. "
                    "Reported, not corrected: the held-out split is hash-locked and unseen.",
        },
        "base_scenarios": {s: len(bases[s]) for s in cases},
        "provenance": "synthetic: every base scenario is a hand-authored SCN-* scenario" if synthetic_only else "mixed",
        "labels_available": labels,
        "metrics_status": "AVAILABLE" if all(labels.values()) else "BLOCKED: owner labels absent",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    a = ap.parse_args()
    rep = build_report()
    text = json.dumps(rep, indent=2, sort_keys=True)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)
    return 0 if rep["all_integrity_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
