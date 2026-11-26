r"""
Measurement only: where does `AlertIngestionService.ingest_batch` spend its time? In-process (no HTTP), against a SCRATCH database (name must start with aisop_load).

    .venv\Scripts\python.exe backend\scripts\profile_ingest_batch.py --dbpw <app role password file> --db aisop_loadtest --out <json> [--alerts 1000] [--repeats 3]

It adds synthetic alert rows to the scratch database (it deletes nothing) and times, with application functions wrapped but not changed:
  total wall time and process CPU time (CPU versus waiting for the database), per-stage time and call counts (hash, adapter selection, adapt, to_canonical_event,
  entity extraction, session.add, each flush, the commit), SQL statements counted and timed through SQLAlchemy engine events, and event-loop lag (a 5 ms ticker).
Conditions: source_type "generic_siem" (adapter named by the request) and "auto" (the registry tries adapters in order for every alert); then one cProfile run
on a smaller batch to see the call tree. Timer overhead is small but not zero; compare only timed runs with timed runs.
"""
from __future__ import annotations

import argparse
import asyncio
import cProfile
import io
import json
import os
import pstats
import sys
import time
import uuid
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
os.chdir(ROOT)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
PROTECTED = {"aisop_demo", "aisop_dev", "aisop", "aisop_test", "postgres"}

ACC: dict[str, list] = defaultdict(lambda: [0, 0.0])      # stage -> [calls, seconds]


def wrap(obj, name: str, label: str, is_async: bool = False):
    orig = getattr(obj, name)
    if is_async:
        async def w(*a, **k):
            t = time.perf_counter()
            try:
                return await orig(*a, **k)
            finally:
                ACC[label][0] += 1; ACC[label][1] += time.perf_counter() - t
    else:
        def w(*a, **k):
            t = time.perf_counter()
            try:
                return orig(*a, **k)
            finally:
                ACC[label][0] += 1; ACC[label][1] += time.perf_counter() - t
    setattr(obj, name, w)


def make_alerts(n: int, nonce: str, offset: int = 0) -> list[dict]:
    return [{"source_type": "generic_siem", "rule_id": f"R-IB-{nonce}-{offset + i}", "rule_name": f"ingest rule {i % 40}", "severity": ["low", "medium", "high"][i % 3],
             "timestamp": f"2026-11-07T{(i // 60) % 24:02d}:{i % 60:02d}:00Z", "host": f"ib-host-{i % 20}", "user": f"ib-user-{i % 7}",
             "src_ip": f"203.0.113.{i % 50 + 1}", "dest_ip": f"198.51.100.{i % 30 + 1}"} for i in range(n)]


async def main_async(a) -> dict:
    from sqlalchemy import event
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    import app.services.alert_ingestion_service as S
    from app.schemas.alert import CanonicalAlert
    from app.schemas.alert_ingest import AlertIngestRequest
    from app.modules.alerts.adapters.generic_siem_adapter import GenericSiemAdapter

    if os.environ.get("AISOP_GC") == "freeze":                # diagnosis: move the long-lived startup objects out of the collector (what a server can do once after start-up)
        import gc
        gc.collect()
        gc.freeze()
    if os.environ.get("AISOP_GC") == "off":                   # diagnosis: is the loop lag caused by garbage-collection pauses?
        import gc
        gc.disable()
    if os.environ.get("AISOP_SLOW_CB"):                       # diagnosis: asyncio logs any single loop step slower than this many seconds, with its location
        asyncio.get_running_loop().slow_callback_duration = float(os.environ["AISOP_SLOW_CB"])
    pw = Path(a.dbpw).read_text(encoding="utf-8").strip()
    eng = create_async_engine(f"postgresql+psycopg://aisop_app:{pw}@127.0.0.1:5433/{a.db}")
    Session = async_sessionmaker(eng, expire_on_commit=False)

    sql = {"n": 0, "s": 0.0}

    @event.listens_for(eng.sync_engine, "before_cursor_execute")
    def _b(conn, cur, stmt, params, ctx, many):
        ctx._t0 = time.perf_counter()

    @event.listens_for(eng.sync_engine, "after_cursor_execute")
    def _a(conn, cur, stmt, params, ctx, many):
        sql["n"] += 1; sql["s"] += time.perf_counter() - getattr(ctx, "_t0", time.perf_counter())

    # wrap application functions (module-level names used by the service) and methods
    S.compute_sha256 = _timed("hash", S.compute_sha256)
    S.extract_entities = _timed("extract_entities", S.extract_entities)
    wrap(GenericSiemAdapter, "adapt", "adapter.adapt")
    wrap(GenericSiemAdapter, "can_adapt", "adapter.can_adapt(generic)")
    wrap(CanonicalAlert, "to_canonical_event", "to_canonical_event")
    wrap(AsyncSession, "flush", "session.flush", is_async=True)
    wrap(AsyncSession, "commit", "session.commit", is_async=True)
    wrap(AsyncSession, "begin_nested", "session.begin_nested(create)")
    wrap(AsyncSession, "add", "session.add")
    from app.modules.alerts.adapter_protocol import AlertAdapterRegistry
    wrap(AlertAdapterRegistry, "find_matching_adapter", "registry.find_matching_adapter")

    res: dict = {"db": a.db, "alerts_per_batch": a.alerts, "runs": []}
    nonce = uuid.uuid4().hex[:8]
    seq = 0

    async def lag_ticker(out: dict):
        loop = asyncio.get_running_loop()
        while True:
            t0 = loop.time(); await asyncio.sleep(0.005)
            lag = loop.time() - t0 - 0.005
            out["max"] = max(out.get("max", 0.0), lag); out["ticks"] = out.get("ticks", 0) + 1; out["o50"] = out.get("o50", 0) + (lag > 0.05)

    async def one(label: str, source_type: str, n: int, profile: bool = False):
        nonlocal seq
        ACC.clear(); sql["n"] = 0; sql["s"] = 0.0
        alerts = make_alerts(n, nonce, seq); seq += n
        req = AlertIngestRequest(source_type=source_type, source_identifier="profile-ingest", alerts=alerts)
        if a.chunk_size:
            S.AlertIngestionService.FAST_CHUNK_SIZE = a.chunk_size
        svc = S.AlertIngestionService(chunked=not a.per_alert)
        lag: dict = {}
        task = asyncio.get_running_loop().create_task(lag_ticker(lag))
        await asyncio.sleep(0.05)
        pr = cProfile.Profile() if profile else None
        async with Session() as s:
            c0, t0 = time.process_time(), time.perf_counter()
            if pr: pr.enable()
            r = await svc.ingest_batch(s, req)
            if pr: pr.disable()
            wall, cpu = time.perf_counter() - t0, time.process_time() - c0
        task.cancel()
        row = {"label": label, "source_type": source_type, "alerts": n, "stored": r.total_normalized, "errors": len(r.errors), "wall_s": round(wall, 2), "cpu_s": round(cpu, 2),
               "cpu_share_of_wall": round(cpu / wall, 2), "ms_per_alert_wall": round(1000 * wall / n, 2), "ms_per_alert_cpu": round(1000 * cpu / n, 2),
               "sql_statements": sql["n"], "sql_statements_per_alert": round(sql["n"] / n, 2), "sql_seconds_as_seen_by_app": round(sql["s"], 2),
               "loop_lag_max_ms": round(lag.get("max", 0) * 1000), "loop_ticks_over_50ms": lag.get("o50", 0), "loop_ticks": lag.get("ticks", 0),
               "stages_ms_per_alert": {k: {"calls": v[0], "ms_per_alert": round(1000 * v[1] / n, 3)} for k, v in sorted(ACC.items(), key=lambda kv: -kv[1][1])}}
        if pr:
            buf = io.StringIO(); pstats.Stats(pr, stream=buf).sort_stats("tottime").print_stats(30)
            row["cprofile_top_by_own_time"] = "\n".join(l[:150] for l in buf.getvalue().splitlines()[:48])
        res["runs"].append(row)
        print(f"== {label}: wall {row['wall_s']} s, cpu {row['cpu_s']} s ({int(row['cpu_share_of_wall']*100)}% of wall), {row['sql_statements_per_alert']} SQL/alert, "
              f"loop lag max {row['loop_lag_max_ms']} ms, stored {row['stored']}", flush=True)

    for r in range(a.repeats):
        await one(f"generic_siem r{r}", "generic_siem", a.alerts)
    for r in range(a.repeats):
        await one(f"auto r{r}", "auto", a.alerts)
    await one("cprofile generic_siem (300 alerts)", "generic_siem", 300, profile=True)
    await eng.dispose()
    return res


def _timed(label: str, fn):
    def w(*a, **k):
        t = time.perf_counter()
        try:
            return fn(*a, **k)
        finally:
            ACC[label][0] += 1; ACC[label][1] += time.perf_counter() - t
    return w


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dbpw", required=True); ap.add_argument("--db", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--alerts", type=int, default=1000); ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--chunk-size", type=int, default=0, help="override AlertIngestionService.FAST_CHUNK_SIZE for this run (0 = the class default)")
    ap.add_argument("--per-alert", action="store_true", help="force the old one-savepoint-per-alert path (chunked=False) for a same-session comparison")
    a = ap.parse_args()
    if a.db in PROTECTED or not a.db.startswith("aisop_load"):
        print("Refusing: database name must start with aisop_load and not be protected.", file=sys.stderr); return 2
    if not a.out.upper().startswith("D:"):
        print("--out must be on drive D:", file=sys.stderr); return 2
    res = asyncio.run(main_async(a))
    Path(a.out).write_text(json.dumps(res, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
