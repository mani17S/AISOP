#!/usr/bin/env python3
"""
Synthetic benchmark with ground truth BY CONSTRUCTION, for the sufficiency gate and the baselines. No labels, no model, no network, no database.

Why. The 67 locked cases are hand-built and few. This benchmark generates thousands of randomised cases from a written specification (the
corroboration definition in datasets/sufficiency_eval/labelling_guide.md, not the gate's code) and scores every arm against what each case was
BUILT to be. Truth is binary: SUFFICIENT only when another record, from a different vantage point, a different raw record and a different
observation, shares a specific artefact with the key event; every other family is built so that the evidence is NOT independently corroborated.

Families (250 cases each by default). Positive: corroborated_cross_vantage (1 to 3 corroborators). Negative: lone_event, exact_duplicate (same digest),
near_duplicate (new digest, same content, within 1.5 s), delayed_copy (new digest, same content, 3 to 60 s later), weak_link_only (other vantage, shares
only host, user, internal IP or process name), same_vantage (a second observation sharing a specific artefact, but from the same vantage),
placeholder_artefact (the shared artefact is empty, a placeholder or not public), out_of_window (the corroborator is dated far outside the window).
Noise on every case: shuffled record order, random timestamps, 0 to 3 unrelated records on other hosts, random extra attributes, upper-case or trailing-dot
variants of hashes and domains, extra weak entities.

Two runs per seed: with the vantage written on every record, and with it removed (the rule cannot know), to show what the vantage rule needs.

What this is NOT. Truth comes from the same idea of independence the gate implements, so a high score shows the implementation honours its specification
under noise at scale, not that the specification is right for real analysts. Procedure: run on development seeds to look at failures; after any change,
run once on a fresh seed for the numbers that are reported.

    .venv\\Scripts\\python.exe backend\\evaluation_tools\\synthetic_benchmark.py --seed 1001 --per-family 100 --out D:\\AISOP-Backups\\AISOP_Dev_Logs\\synth_dev
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency  # noqa: E402
from app.modules.evaluation.baselines import ablation_verdict, baseline_verdict  # noqa: E402
from app.modules.evaluation.sufficiency_evaluator import build_context_from_case, wilson_interval  # noqa: E402

FAMILIES = ["corroborated_cross_vantage", "lone_event", "exact_duplicate", "near_duplicate", "delayed_copy", "weak_link_only", "same_vantage",
            "placeholder_artefact", "out_of_window"]
POSITIVE = {"corroborated_cross_vantage"}
ARMS = ("B0", "B1", "B2", "B3", "B4", "AISOP")
OBS = {"process_creation": ("1", "started"), "network_connection": ("3", "connect"), "dns_query": ("22", "queried"),
       "file_create": ("11", "created"), "registry_set": ("13", "set")}
WORDS = ["update", "cdn", "sync", "mail", "static", "login", "files", "api", "node", "edge"]
PUBLIC_PREFIXES = ["45.77", "91.240", "185.220", "104.21", "195.123", "212.102"]


def digest(rng: random.Random) -> str:
    return hashlib.sha256(rng.randbytes(16)).hexdigest()


def artefact(rng: random.Random, kind: Optional[str] = None) -> tuple[str, str]:
    kind = kind or rng.choice(["file_hash", "domain", "ip", "file", "url"])
    if kind == "file_hash":
        return kind, digest(rng)
    if kind == "domain":
        return kind, f"{rng.choice(WORDS)}-{digest(rng)[:8]}.example"
    if kind == "ip":
        return kind, f"{rng.choice(PUBLIC_PREFIXES)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}"
    if kind == "file":
        return kind, f"C:\\Users\\Public\\{rng.choice(WORDS)}{rng.randint(1, 999)}.exe"
    return "url", f"http://{rng.choice(WORDS)}-{digest(rng)[:6]}.example/{rng.choice(WORDS)}"


def variant(kind: str, value: str, rng: random.Random) -> str:
    if kind == "file_hash" and rng.random() < 0.5:
        return value.upper()
    if kind == "domain" and rng.random() < 0.5:
        return value.upper() + "."
    return value


def placeholder(rng: random.Random) -> tuple[str, str]:
    return rng.choice([("file_hash", "0" * 64), ("file_hash", "a" * 64), ("domain", "localhost"), ("domain", "x"), ("ip", "10.1.2.3"),
                       ("ip", "192.168.0.5"), ("ip", "127.0.0.1"), ("file_hash", "deadbeef")])


class Builder:
    def __init__(self, rng: random.Random, family: str, index: int) -> None:
        self.rng, self.family = rng, family
        self.case_id = f"SYN-{family}-{index:04d}"
        self.host = f"HOST-{rng.randint(1, 99):02d}"
        self.user = f"corp\\user{rng.randint(1, 50)}"
        self.events: list[dict[str, Any]] = []
        self.links: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.n = 0

    def event(self, etype: str, offset: float, vantage: str, host: Optional[str] = None, dig: Optional[str] = None, content: Optional[dict] = None) -> str:
        key = f"e{self.n}"
        self.n += 1
        eid, action = OBS[etype]
        attrs = {"EventID": eid, "note": f"{etype} {self.rng.randint(1, 10**6)}", "vantage": vantage} if content is None else {**content, "vantage": vantage}
        if self.rng.random() < 0.5:
            attrs[f"extra{self.rng.randint(1, 9)}"] = self.rng.choice(["a", "b", "c", 1, 2])
        self.events.append({
            "key": key, "event_id": eid, "event_type": etype, "action": action, "outcome": "success", "severity": "informational",
            "source_identifier": host or self.host, "summary": f"{etype} {action}", "attributes": attrs,
            "raw_evidence_sha256": dig or digest(self.rng), "timestamp_offset_s": round(offset, 3),
        })
        return key

    def link(self, etype: str, value: str, *keys: str) -> None:
        self.links[(etype, value)].extend(keys)

    def case(self, root: str, window_end: float) -> dict[str, Any]:
        self.rng.shuffle(self.events)
        entities = [{"entity_type": t, "entity_value": v, "event_keys": sorted(set(ks))} for (t, v), ks in self.links.items()]
        self.rng.shuffle(entities)
        return {"case_id": self.case_id, "base_time_utc": "2026-11-24T09:00:00+00:00", "split": "synthetic", "family": self.family,
                "events": self.events, "entities": entities, "omitted_events": 0,
                "question": {"root_event_key": root, "target_hosts": [self.host]},
                "window": {"start_offset_s": -1.0, "end_offset_s": window_end}}


def generate(rng: random.Random, family: str, index: int) -> tuple[dict[str, Any], bool]:
    b = Builder(rng, family, index)
    root_type = rng.choice(list(OBS))
    root_vantage = f"sensor-{rng.choice('abc')}-{b.host.lower()}"
    root = b.event(root_type, 0.0, root_vantage)
    b.link("host", b.host, root)
    b.link("user", b.user, root)
    b.link("process", rng.choice(["powershell.exe", "cmd.exe", "svchost.exe"]), root)
    kind, value = artefact(rng)
    b.link(kind, variant(kind, value, rng), root)
    if root_type == "network_connection" and kind != "ip":
        # A network connection is incomplete without its address (the labelling guide: required details of the anchor must be present).
        b.link("ip", artefact(rng, "ip")[1], root)
    root_ev = next(e for e in b.events if e["key"] == root)
    window_end = 1.0
    other_type = lambda: rng.choice([t for t in OBS if t != root_type])  # noqa: E731
    other_vantage = lambda: f"sensor-{rng.choice('xyz')}-{digest(rng)[:4]}"  # noqa: E731

    if family == "corroborated_cross_vantage":
        for _ in range(rng.randint(1, 3)):
            off = rng.uniform(0.5, 120)
            k = b.event(other_type(), off, other_vantage())
            b.link(kind, variant(kind, value, rng), k)
            window_end = max(window_end, off + 1)
    elif family == "exact_duplicate":
        for _ in range(rng.randint(1, 4)):
            k = b.event(root_type, rng.uniform(0, 1.0), root_vantage, dig=root_ev["raw_evidence_sha256"], content=dict(root_ev["attributes"]))
            for ent in list(b.links):
                if root in b.links[ent]:
                    b.links[ent].append(k)
    elif family in ("near_duplicate", "delayed_copy"):
        lo, hi = (0.0, 1.5) if family == "near_duplicate" else (3.0, 60.0)
        for _ in range(rng.randint(1, 3)):
            off = rng.uniform(lo, hi)
            k = b.event(root_type, off, root_vantage, content={k2: v for k2, v in root_ev["attributes"].items() if k2 != "vantage"})
            for ent in list(b.links):
                if root in b.links[ent]:
                    b.links[ent].append(k)
            window_end = max(window_end, off + 1)
    elif family == "weak_link_only":
        for _ in range(rng.randint(1, 3)):
            off = rng.uniform(0.5, 60)
            k = b.event(other_type(), off, other_vantage())
            b.link(rng.choice(["host", "user"]), b.host if rng.random() < 0.5 else b.user, k)
            if rng.random() < 0.5:  # an internal address shared by both is still only context
                shared_internal = f"10.{rng.randint(0, 9)}.{rng.randint(0, 9)}.{rng.randint(1, 9)}"
                b.link("ip", shared_internal, root, k)
            window_end = max(window_end, off + 1)
    elif family == "same_vantage":
        for _ in range(rng.randint(1, 3)):
            off = rng.uniform(0.5, 60)
            k = b.event(other_type(), off, root_vantage)
            b.link(kind, variant(kind, value, rng), k)
            window_end = max(window_end, off + 1)
    elif family == "placeholder_artefact":
        pk, pv = placeholder(rng)
        b.links.pop((kind, variant(kind, value, rng)), None)
        b.links.pop((kind, value), None)
        b.link(pk, pv, root)
        for _ in range(rng.randint(1, 3)):
            off = rng.uniform(0.5, 60)
            k = b.event(other_type(), off, other_vantage())
            b.link(pk, pv, k)
            window_end = max(window_end, off + 1)
    elif family == "out_of_window":
        k = b.event(other_type(), rng.uniform(10_000, 50_000), other_vantage())
        b.link(kind, variant(kind, value, rng), k)
    # lone_event: nothing more

    for _ in range(rng.randint(0, 3)):  # unrelated noise on other hosts, no shared artefact
        other_host = f"OTHER-{rng.randint(1, 99):02d}"
        k = b.event(rng.choice(list(OBS)), rng.uniform(0.2, 50), other_vantage(), host=other_host)
        b.link("host", other_host, k)
        window_end = max(window_end, 50.0)
    return b.case(root, window_end), family in POSITIVE


def strip_vantage(case: dict[str, Any]) -> dict[str, Any]:
    c = copy.deepcopy(case)
    for e in c["events"]:
        e["attributes"].pop("vantage", None)
    return c


def predict(case: dict[str, Any]) -> dict[str, str]:
    ctx = build_context_from_case(case)
    out = {a: baseline_verdict(ctx, a) for a in ("B0", "B1")}
    out.update({a: ablation_verdict(ctx, a) for a in ("B2", "B3", "B4")})
    out["AISOP"] = evaluate_sufficiency(ctx).verdict.value.upper()
    return out


def rate(k: int, n: int) -> dict[str, Any]:
    lo, hi = wilson_interval(k, n) if n else (None, None)
    return {"k": k, "n": n, "rate": None if n == 0 else round(k / n, 4), "ci95": [lo, hi]}


def run(seed: int, per_family: int, annotated: bool) -> dict[str, Any]:
    rng = random.Random(seed)
    cells: dict[str, dict[str, Counter]] = {a: defaultdict(Counter) for a in ARMS}
    wrong: list[dict[str, Any]] = []
    total = 0
    for family in FAMILIES:
        for i in range(per_family):
            case, positive = generate(rng, family, i)
            verdicts = predict(case if annotated else strip_vantage(case))
            total += 1
            for a in ARMS:
                called = verdicts[a] == "SUFFICIENT"
                cells[a][family]["called"] += called
                cells[a][family]["n"] += 1
                if called != positive and a == "AISOP" and len(wrong) < 12:
                    wrong.append({"case": case["case_id"], "family": family, "aisop": verdicts[a], "truth": "SUFFICIENT" if positive else "not sufficient"})
    result: dict[str, Any] = {"seed": seed, "per_family": per_family, "annotated": annotated, "total": total, "arms": {}, "aisop_errors_sample": wrong}
    for a in ARMS:
        pos_n = sum(cells[a][f]["n"] for f in POSITIVE)
        pos_called = sum(cells[a][f]["called"] for f in POSITIVE)
        neg_fams = [f for f in FAMILIES if f not in POSITIVE]
        neg_n = sum(cells[a][f]["n"] for f in neg_fams)
        neg_called = sum(cells[a][f]["called"] for f in neg_fams)
        correct = pos_called + (neg_n - neg_called)
        result["arms"][a] = {
            "accuracy": rate(correct, pos_n + neg_n),
            "false_sufficient": rate(neg_called, neg_n),
            "missed_sufficient": rate(pos_n - pos_called, pos_n),
            "false_sufficient_by_family": {f: rate(cells[a][f]["called"], cells[a][f]["n"]) for f in neg_fams},
        }
    return result


def show(r: dict[str, Any]) -> None:
    tag = "vantage written on every record" if r["annotated"] else "vantage removed (unknown)"
    print(f"\nseed {r['seed']}, {r['total']} cases ({r['per_family']} per family), {tag}")
    print(f"{'arm':6} {'accuracy':>9} {'false-sufficient':>17} {'95% CI':>17} {'missed sufficient':>18}")
    for a in ARMS:
        m = r["arms"][a]
        fs = m["false_sufficient"]
        print(f"{a:6} {m['accuracy']['rate']:9.3f} {fs['rate']:17.3f} [{fs['ci95'][0]:.3f}, {fs['ci95'][1]:.3f}] {m['missed_sufficient']['rate']:18.3f}")
    print("false-sufficient rate by family (the share of that family each arm wrongly calls SUFFICIENT):")
    fams = [f for f in FAMILIES if f not in POSITIVE]
    print(f"{'family':22} " + " ".join(f"{a:>6}" for a in ARMS))
    for f in fams:
        print(f"{f:22} " + " ".join(f"{r['arms'][a]['false_sufficient_by_family'][f]['rate']:6.2f}" for a in ARMS))
    if r["aisop_errors_sample"]:
        print("AISOP disagreements with construction (sample):", r["aisop_errors_sample"][:5])


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--per-family", type=int, default=250)
    ap.add_argument("--out", required=True, help="output directory on drive D:")
    args = ap.parse_args(argv)
    out_dir = Path(args.out).resolve()
    if out_dir.drive.upper() != "D:":
        print(f"REFUSING: --out must be on drive D: (got {out_dir})")
        return 2
    results = [run(args.seed, args.per_family, True), run(args.seed, args.per_family, False)]
    for r in results:
        show(r)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"synthetic_benchmark_seed{args.seed}.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nwrote {out_dir / f'synthetic_benchmark_seed{args.seed}.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
