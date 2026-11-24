#!/usr/bin/env python3
"""
Fingerprint of the full deterministic pipeline output over fixed inputs, to prove that a performance change alters nothing.

For each input set it runs ``analyze`` and hashes a canonical form of the result: normalised events (key, time, host, entities), evidence clusters (members),
typed links (pair, strength, shared entities), incidents (id, core and context clusters, event keys, severity, stages, link counts, hosts, users) and each
incident's sufficiency verdict, reason codes and assessment hash. Inputs: the built-in demo scenarios, the envelope scenarios, an SSH-format log built
from a fixed seed, and any real public data present on this machine (reported as "absent" otherwise, never faked).

    .venv\\Scripts\\python.exe backend\\evaluation_tools\\pipeline_fingerprint.py --out D:\\AISOP-Backups\\AISOP_Dev_Logs\\fingerprint_before.json
    (change the code)
    .venv\\Scripts\\python.exe backend\\evaluation_tools\\pipeline_fingerprint.py --out D:\\AISOP-Backups\\AISOP_Dev_Logs\\fingerprint_after.json --compare D:\\AISOP-Backups\\AISOP_Dev_Logs\\fingerprint_before.json
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import random
import sys
import time
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
sys.path.insert(0, str(PROJECT_ROOT / "backend" / "scripts"))

from app.modules.correlation import demo_data as dd  # noqa: E402
from app.modules.correlation.workflow import analyze  # noqa: E402
from app.modules.evidence_domains import scenarios as S  # noqa: E402
import syslog_to_records  # noqa: E402


def canonical(result: Any) -> dict[str, Any]:
    events = sorted(
        [(str(e.event_key), e.timestamp.isoformat(), e.host, e.source_type, sorted(e.entities)) for e in result.normalization.events],
        key=lambda x: x[0])
    clusters = [(c.cluster_id, [str(k) for k in c.members]) for c in result.correlation.clusters]
    links = [(l.cluster_a, l.cluster_b, l.strength, [list(s) for s in l.shared_entities]) for l in result.correlation.links]
    incidents = []
    for ia in result.incidents:
        i = ia.incident
        incidents.append({
            "id": str(i.incident_id), "core": list(i.core_clusters), "ctx": list(i.weak_context_clusters), "keys": [str(k) for k in i.event_keys],
            "severity": i.severity, "stages": list(i.stages), "escalated": i.escalated, "link_counts": i.link_counts, "hosts": list(i.hosts),
            "users": list(i.users), "weakly_related": sorted(str(w) for w in i.weakly_related),
            "verdict": ia.assessment.verdict.value, "reasons": sorted(str(r) for r in ia.assessment.reason_codes),
            "assessment_sha256": ia.assessment.assessment_sha256,
        })
    return {"events": events, "clusters": clusters, "links": links, "incidents": incidents,
            "rejected": sorted([(r.record_index, r.reason) for r in result.normalization.rejected])}


def fingerprint(result: Any) -> str:
    return hashlib.sha256(json.dumps(canonical(result), sort_keys=True, default=str).encode()).hexdigest()


def synthetic_ssh(n: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    hosts = ["labhost", "gate1", "gate2"]
    lines = []
    for i in range(n):
        ip = f"203.0.113.{rng.randint(1, 40)}"
        kind = rng.choice(["fail", "invalid", "disc", "ok"])
        msg = {"fail": f"Failed password for {rng.choice(['root', 'admin', 'guest'])} from {ip} port {rng.randint(1000, 65000)} ssh2",
               "invalid": f"Invalid user {rng.choice(['test', 'oracle', 'git'])} from {ip}", "disc": f"Received disconnect from {ip}: 11: Bye Bye [preauth]",
               "ok": f"Accepted password for deploy from {ip} port {rng.randint(1000, 65000)} ssh2"}[kind]
        lines.append(f"Dec 10 {6 + i // 3600:02d}:{(i // 60) % 60:02d}:{i % 60:02d} {rng.choice(hosts)} sshd[{1000 + i}]: {msg}")
    return syslog_to_records.convert(lines, 2015)[0]


def inputs() -> dict[str, Optional[list[Any]]]:
    out: dict[str, Optional[list[Any]]] = {}
    for name, s in dd.SCENARIOS.items():
        out[f"demo:{name}"] = s["build"]()
    for builder in (S.scenario_a_identity_cloud, S.scenario_b_network_endpoint, S.scenario_c_email_forensic):
        out[f"envelope:{builder.__name__}"] = builder()
    out["synthetic_ssh_600"] = synthetic_ssh(600, 7)
    out["synthetic_ssh_1500"] = synthetic_ssh(1500, 11)
    real = Path("D:/AISOP-Reference-Data/loghub_openssh_20261124/records.jsonl")
    out["real_ssh_2000"] = [json.loads(l) for l in real.read_text(encoding="utf-8").splitlines() if l.strip()] if real.exists() else None
    for f in sorted(glob.glob("D:/AISOP-Reference-Data/otrf_samples_20261123/extracted/*/*.json")):
        out[f"real_otrf:{Path(f).stem[:24]}"] = [json.loads(l) for l in Path(f).read_text(encoding="utf-8").splitlines() if l.strip()]
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--compare", type=Path, default=None)
    args = ap.parse_args(argv)
    result: dict[str, Any] = {}
    for name, recs in inputs().items():
        if recs is None:
            result[name] = {"status": "absent"}
            print(f"{name:44} absent")
            continue
        assets = dd.SCENARIOS[name.split(':', 1)[1]].get("assets") if name.startswith("demo:") else None
        t = time.perf_counter()
        r = analyze(recs, assets=assets)
        dt = time.perf_counter() - t
        result[name] = {"records": len(recs), "incidents": len(r.incidents), "seconds": round(dt, 3), "sha256": fingerprint(r)}
        print(f"{name:44} records={len(recs):5d} incidents={len(r.incidents):3d} {dt:7.2f}s {result[name]['sha256'][:12]}")
    args.out.write_text(json.dumps(result, indent=1), encoding="utf-8")
    if args.compare:
        before = json.loads(args.compare.read_text(encoding="utf-8"))
        diffs = [k for k in result if result[k].get("sha256") != before.get(k, {}).get("sha256")]
        total_b = sum(v.get("seconds", 0) for v in before.values())
        total_a = sum(v.get("seconds", 0) for v in result.values())
        print(f"\nidentical output for {len(result) - len(diffs)} of {len(result)} inputs; differing: {diffs or 'none'}")
        print(f"total time {total_b:.2f}s -> {total_a:.2f}s")
        return 1 if diffs else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
