"""
Stage 5 bounded local benchmark of the deterministic multi-source investigation (no LLM, no database, no network).

Synthetic data only. Two shapes per size:
  * ``separate``: N/10 independent 10-event intrusion chains (many small incidents)
  * ``single``  : the same chains all sharing one C2 domain and one attacker IP (worst case: one very large incident)

Stage timings are measured by wrapping the engine functions the workflow actually calls (the workflow is run once
per repetition; the figures are the best and median of ``--reps`` repetitions). Peak Python memory is measured in a
separate tracemalloc run because tracemalloc slows execution. Result size is the JSON size of the document the
integration stores (``MultiSourceInvestigationService.build_payload``).

Usage: python backend/scripts/benchmark_investigation.py [--sizes 10 100 500 1000] [--reps 3] [--out file.json]
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.modules.correlation import demo_data as dd  # noqa: E402
from app.modules.correlation import report as report_mod  # noqa: E402
from app.modules.correlation import workflow as wf  # noqa: E402
from app.services.multisource_investigation_service import MultiSourceInvestigationService  # noqa: E402

STAGES = {
    "normalize": (wf, "normalize_records"),
    "correlate": (wf, "correlate"),
    "context_build": (wf, "build_incident_context"),
    "sufficiency": (wf, "evaluate_sufficiency"),
    "timeline": (wf, "build_timeline"),
    "attack_map": (wf, "map_techniques"),
    "report": (report_mod, "render_incident_report"),
}


def chain(i: int, shared_c2: bool) -> list[dict[str, Any]]:
    host, user = f"WS-{i:04d}", f"user{i:04d}"
    ip = f"10.{(i // 250) % 250}.{i % 250}.7"
    att = dd.ATTACKER_IP if shared_c2 else f"185.220.{(i // 250) % 250}.{i % 250 + 1}"
    c2_ip = dd.C2_IP if shared_c2 else f"91.240.{(i // 250) % 250}.{i % 250 + 1}"
    dom = dd.C2_DOMAIN if shared_c2 else f"c2-{i:04d}.badcdn.example"
    g0, g1 = f"{{A1B2C3D4-0000-0000-0000-{i:012d}}}", f"{{A1B2C3D4-1111-0000-0000-{i:012d}}}"
    sha = f"{i:064x}"
    m, base = (i * 7) % 3600, "2026-11-10T"
    t = lambda s: f"{base}{9 + (m + s) // 3600:02d}:{((m + s) // 60) % 60:02d}:{(m + s) % 60:02d}Z"  # noqa: E731
    rid = 10_000 + i * 20
    return [
        dd._win(4625, rid, t(5), ip=att, user=user, host=host, sub_status="0xC000006A"),
        dd._win(4625, rid + 1, t(12), ip=att, user=user, host=host, sub_status="0xC000006A"),
        dd._win(4625, rid + 2, t(20), ip=att, user=user, host=host, sub_status="0xC000006A"),
        dd._siem(t(30), "Multiple failed logons followed by success", techniques=["T1110"], host=host, user=user, src_ip=att, rule_id=f"R-{i}"),
        dd._win(4624, rid + 3, t(70), ip=att, user=user, host=host, logon_id=f"0x{0x5a1b + i:x}"),
        dd._sysmon(1, t(120), host=host, user=f"CORP\\{user}", guid=g1, CommandLine=dd.ENC_PS, Hashes=f"SHA256={sha}",
                   ParentImage=r"C:\Windows\explorer.exe", ParentProcessGuid=g0, ParentProcessId="1200", LogonId=f"0x{0x5a1b + i:x}"),
        dd._sysmon(22, t(148), host=host, user=f"CORP\\{user}", guid=g1, QueryName=dom, QueryResults=f"{c2_ip};", QueryStatus="0"),
        dd._dns(t(149), dom, src=ip),
        dd._sysmon(3, t(150), host=host, user=f"CORP\\{user}", guid=g1, Protocol="tcp", Initiated="true", SourceIp=ip, SourcePort="50123",
                   DestinationIp=c2_ip, DestinationPort="443", DestinationHostname=dom),
        dd._fw(t(160), "ET MALWARE C2 beacon", 2001, src=ip, dst=c2_ip),
    ]


def build(n_events: int, shared_c2: bool) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    i = 0
    while len(out) < n_events:
        out.extend(chain(i, shared_c2))
        i += 1
    return out[:n_events]


def run_once(records: list[Any]) -> tuple[dict[str, float], float, Any]:
    timings = {k: 0.0 for k in STAGES}
    originals = {}
    for key, (mod, name) in STAGES.items():
        fn = getattr(mod, name)
        originals[key] = fn

        def wrapped(*a: Any, _fn: Any = fn, _k: str = key, **kw: Any) -> Any:
            t0 = time.perf_counter()
            try:
                return _fn(*a, **kw)
            finally:
                timings[_k] += time.perf_counter() - t0

        setattr(mod, name, wrapped)
    try:
        t0 = time.perf_counter()
        result = wf.analyze(records, assets=dd.ASSETS)
        total = time.perf_counter() - t0
    finally:
        for key, (mod, name) in STAGES.items():
            setattr(mod, name, originals[key])
    return timings, total, result


def measure(n: int, shape: str, reps: int) -> dict[str, Any]:
    records = build(n, shared_c2=(shape == "single"))
    runs = [run_once(records) for _ in range(reps)]
    totals = [r[1] for r in runs]
    stage_median = {k: round(statistics.median(r[0][k] for r in runs) * 1000, 2) for k in STAGES}
    result = runs[-1][2]
    payload = MultiSourceInvestigationService.build_payload(MultiSourceInvestigationService(), result, "0" * 64, False)
    size = len(json.dumps(payload))
    tracemalloc.start()
    wf.analyze(records, assets=dd.ASSETS)
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "events_in": n,
        "shape": shape,
        "events_normalized": len(result.normalization.events),
        "evidence_clusters": len(result.correlation.clusters),
        "incidents": len(result.incidents),
        "links": len(result.correlation.links),
        "total_ms_best": round(min(totals) * 1000, 2),
        "total_ms_median": round(statistics.median(totals) * 1000, 2),
        "stage_ms_median": stage_median,
        "stored_result_bytes": size,
        "peak_python_memory_mb": round(peak / 1_048_576, 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[10, 100, 500, 1000])
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out")
    a = ap.parse_args()
    rows = [measure(n, shape, a.reps) for n in a.sizes for shape in ("separate", "single")]
    doc = {"python": sys.version.split()[0], "reps": a.reps, "note": "synthetic data; single process; no database; no LLM", "rows": rows}
    text = json.dumps(doc, indent=2)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    for r in rows:
        print(f"{r['events_in']:>5} {r['shape']:8s} total_med={r['total_ms_median']:>9.1f}ms  incidents={r['incidents']:>3} "
              f"clusters={r['evidence_clusters']:>4} links={r['links']:>6} size={r['stored_result_bytes']:>8}B peak={r['peak_python_memory_mb']}MB "
              f"| " + " ".join(f"{k}={v}" for k, v in r["stage_ms_median"].items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
