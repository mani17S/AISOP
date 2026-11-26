r"""
Standalone verification of the ingest concurrency scenario SQLite cannot show: another writer inserting the same hashes while a batch is in its database phase.
Runs against a SCRATCH PostgreSQL database only (name must start with aisop_load, not protected). Adds synthetic rows (nonce-tagged), deletes nothing.

    .venv\Scripts\python.exe backend\scripts\verify_ingest_race_pg.py --dbpw <app role password file> --db aisop_loadtest --out D:\AISOP-Control\Reports\ingest_race_pg.json

Session A is held open (uncommitted) by running the service's own ingest_batch on it with commit replaced by a no-op on that session instance only;
its row locks stay until the script commits A for real (AsyncSession.commit). Session B runs the service unchanged as an asyncio task.
Scenarios: S1 overlap race (chunked and per-alert), S2 partial overlap, S3 reversed order (deadlock risk, both paths), S4 chunk boundary, S5 integrity.
A FAIL is recorded in the JSON, never raised; exit code is 0 unless arguments are refused (2).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
os.chdir(ROOT)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
PROTECTED = {"aisop_demo", "aisop_dev", "aisop", "aisop_test", "postgres"}
TIMEOUT = 20.0
NONCE = uuid.uuid4().hex[:8]
RUN_HASHES: set[str] = set()
WARN = [0]                      # count of 'Chunk savepoint failed' log messages
Session = None                  # set in main_async


async def _noop() -> None:
    return None


def make_alerts(n: int, tag: str) -> list[dict]:
    return [{"source_type": "generic_siem", "rule_id": f"R-RACE-{NONCE}-{tag}-{i}", "rule_name": f"race rule {i % 10}", "severity": ["low", "medium", "high"][i % 3],
             "timestamp": f"2026-11-20T{(i // 60) % 24:02d}:{i % 60:02d}:00Z", "host": f"race-host-{i % 20}", "user": f"race-user-{i % 7}",
             "src_ip": f"203.0.113.{i % 50 + 1}", "dest_ip": f"198.51.100.{i % 30 + 1}"} for i in range(n)]


def make_req(alerts: list[dict]):
    """Returns (request, hashes) with the hashes computed by the same function the service uses."""
    import app.services.alert_ingestion_service as S
    from app.schemas.alert_ingest import AlertIngestRequest
    req = AlertIngestRequest(source_type="generic_siem", source_identifier="verify-race", alerts=alerts)
    hs = [S.compute_sha256(x) for x in req.alerts]
    RUN_HASHES.update(hs)
    return req, hs


def svc(chunked: bool):
    from app.services.alert_ingestion_service import AlertIngestionService
    return AlertIngestionService(chunked=chunked)


def summ(r) -> dict:
    return {"normalized": r.total_normalized, "skipped": r.total_skipped_duplicates, "errors": len(r.errors), "existing_ids": len(r.existing_evidence_ids),
            "alert_ids": len(r.alert_ids)}


async def real_commit(s) -> None:
    from sqlalchemy.ext.asyncio import AsyncSession
    await AsyncSession.commit(s)


# ---- read-only database helpers (fresh session each) ----
async def per_hash_counts(hs: list[str]) -> dict[str, int]:
    from sqlalchemy import func, select
    from app.models.evidence import RawEvidence
    async with Session() as s:
        rows = await s.execute(select(RawEvidence.sha256_hash, func.count(RawEvidence.id)).where(RawEvidence.sha256_hash.in_(hs)).group_by(RawEvidence.sha256_hash))
        return {h: c for h, c in rows}


async def server_counts(hs: list[str]) -> tuple[int, int]:
    from sqlalchemy import func, select
    from app.models.evidence import RawEvidence
    async with Session() as s:
        r = (await s.execute(select(func.count(RawEvidence.id), func.count(func.distinct(RawEvidence.sha256_hash))).where(RawEvidence.sha256_hash.in_(hs)))).one()
        return r[0], r[1]


async def raw_ids(hs: list[str]) -> set:
    from sqlalchemy import select
    from app.models.evidence import RawEvidence
    async with Session() as s:
        return {r[0] for r in await s.execute(select(RawEvidence.id).where(RawEvidence.sha256_hash.in_(hs)))}


async def hashes_for_events(ev_ids: list) -> list:
    from sqlalchemy import select
    from app.models.evidence import NormalizedEventModel, RawEvidence
    async with Session() as s:
        rows = await s.execute(select(NormalizedEventModel.id, RawEvidence.sha256_hash).join(RawEvidence, RawEvidence.id == NormalizedEventModel.raw_evidence_id)
                               .where(NormalizedEventModel.id.in_(ev_ids)))
        m = dict(rows.all())
    return [m.get(e) for e in ev_ids]


async def orphans(hs: list[str], nonce_wide: bool = False) -> dict:
    from sqlalchemy import Text, cast, exists, func, select
    from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
    hs = list(hs)
    ids = select(RawEvidence.id).where(RawEvidence.sha256_hash.in_(hs))
    async with Session() as s:
        raw_no_ev = (await s.execute(select(func.count(RawEvidence.id)).where(RawEvidence.sha256_hash.in_(hs), ~exists().where(NormalizedEventModel.raw_evidence_id == RawEvidence.id)))).scalar_one()
        ent_no_ev = (await s.execute(select(func.count(ExtractedEntityModel.id)).where(ExtractedEntityModel.raw_evidence_id.in_(ids), ~exists().where(NormalizedEventModel.id == ExtractedEntityModel.event_id)))).scalar_one()
        multi_ev = (await s.execute(select(func.count()).select_from(select(NormalizedEventModel.raw_evidence_id).where(NormalizedEventModel.raw_evidence_id.in_(ids))
                                                                    .group_by(NormalizedEventModel.raw_evidence_id).having(func.count() > 1).subquery()))).scalar_one()
        out = {"raw_without_event": raw_no_ev, "entities_without_event": ent_no_ev, "raws_with_more_than_one_event": multi_ev}
        if nonce_wide:
            q = select(func.count(NormalizedEventModel.id)).outerjoin(RawEvidence, RawEvidence.id == NormalizedEventModel.raw_evidence_id).where(
                cast(NormalizedEventModel.normalized_payload, Text).like(f"%{NONCE}%"), RawEvidence.id.is_(None))
            out["events_without_raw"] = (await s.execute(q)).scalar_one()
            out["events_with_run_nonce"] = (await s.execute(select(func.count(NormalizedEventModel.id)).where(cast(NormalizedEventModel.normalized_payload, Text).like(f"%{NONCE}%")))).scalar_one()
    return out


class Ctx:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, dict]] = []
        self.sessions: list = []
        self.tasks: list = []
        self.info: dict = {}

    def check(self, name: str, ok: bool, **kw) -> None:
        self.checks.append((name, bool(ok), kw))

    def session(self, hold: bool = False):
        s = Session()
        if hold:
            s.commit = _noop            # this instance only: the service's final commit becomes a no-op, locks stay held
        self.sessions.append((s, hold))
        return s

    def task(self, coro):
        t = asyncio.get_running_loop().create_task(coro)
        self.tasks.append(t)
        return t

    async def cleanup(self) -> None:
        async def quiet(aw, t=5.0):
            try:
                await asyncio.wait_for(aw, t)
            except BaseException:       # noqa: BLE001 - cleanup must never raise
                pass
        for s, hold in self.sessions:   # held session first: releases the locks a blocked task waits for
            if hold:
                await quiet(s.rollback())
        for t in self.tasks:
            if not t.done():
                t.cancel()
        if self.tasks:
            await quiet(asyncio.gather(*self.tasks, return_exceptions=True))
        for s, _ in self.sessions:
            await quiet(s.rollback())
            await quiet(s.close())


RESULTS: list[dict] = []


async def run_scenario(name: str, fn, *args) -> Ctx:
    ctx = Ctx()
    w0, t0 = WARN[0], time.perf_counter()
    try:
        await asyncio.wait_for(fn(ctx, *args), TIMEOUT)
    except asyncio.TimeoutError:
        ctx.check("completed within timeout", False, timeout_s=TIMEOUT)
    except Exception as exc:            # noqa: BLE001 - a scenario error is a recorded FAIL
        ctx.check("no unexpected exception", False, error=f"{type(exc).__name__}: {str(exc)[:150]}")
    finally:
        await ctx.cleanup()
    ok = all(c[1] for c in ctx.checks) and bool(ctx.checks)
    RESULTS.append({"scenario": name, "verdict": "PASS" if ok else "FAIL", "seconds": round(time.perf_counter() - t0, 2), "chunk_fallback_warnings": WARN[0] - w0,
                    "info": ctx.info, "checks": [{"check": n, "ok": o, **d} for n, o, d in ctx.checks]})
    print(f"{name:<34} {RESULTS[-1]['verdict']:<5} {json.dumps(ctx.info, default=str)[:160]}  fallback_warnings={WARN[0] - w0}", flush=True)
    for n, o, d in ctx.checks:
        if not o:
            print(f"    FAILED check: {n} {json.dumps(d, default=str)[:200]}", flush=True)
    return ctx


# ---- scenarios ----
async def s1(ctx: Ctx, chunked: bool) -> None:
    alerts = make_alerts(50, f"s1{int(chunked)}")
    req_a, hs = make_req(alerts)
    req_b, _ = make_req(alerts)
    sA = ctx.session(hold=True)
    ra = await svc(False).ingest_batch(sA, req_a)             # A stores 50 rows, uncommitted
    ctx.check("A stored 50 uncommitted", ra.total_normalized == 50, a=summ(ra))
    sB = ctx.session()
    tb = ctx.task(svc(chunked).ingest_batch(sB, req_b))
    await asyncio.sleep(0.5)
    ctx.check("B blocked while A uncommitted", not tb.done())
    await real_commit(sA)
    rb = await tb
    ids = await raw_ids(hs)
    total, distinct = await server_counts(hs)
    ctx.info.update(b=summ(rb), rows=total, distinct=distinct)
    ctx.check("B normalized == 0", rb.total_normalized == 0, got=rb.total_normalized)
    ctx.check("B skipped_duplicates == 50", rb.total_skipped_duplicates == 50, got=rb.total_skipped_duplicates)
    ctx.check("B errors empty", not rb.errors, got=len(rb.errors))
    ctx.check("one raw row per hash", total == 50 and distinct == 50, rows=total, distinct=distinct)
    ctx.check("B existing_evidence_ids == A raw ids", set(rb.existing_evidence_ids) == ids and len(rb.existing_evidence_ids) == 50, ids=len(ids))
    ctx.check("B did not store alert_ids", len(rb.alert_ids) == 0, got=len(rb.alert_ids))


async def s2(ctx: Ctx) -> None:
    alerts = make_alerts(50, "s2")
    req_a, hs = make_req(alerts[:25])
    req_b, _ = make_req(alerts)
    sA = ctx.session(hold=True)
    await svc(False).ingest_batch(sA, req_a)
    sB = ctx.session()
    tb = ctx.task(svc(True).ingest_batch(sB, req_b))
    await asyncio.sleep(0.5)
    ctx.check("B blocked while A uncommitted", not tb.done())
    await real_commit(sA)
    rb = await tb
    all_h = [h for h in (make_req(alerts)[1])]
    counts = await per_hash_counts(all_h)
    order = await hashes_for_events(list(rb.alert_ids))
    ctx.info.update(b=summ(rb), hashes_with_one_row=sum(1 for h in all_h if counts.get(h) == 1))
    ctx.check("B stored 25", rb.total_normalized == 25, got=rb.total_normalized)
    ctx.check("B skipped 25", rb.total_skipped_duplicates == 25, got=rb.total_skipped_duplicates)
    ctx.check("B errors empty", not rb.errors, got=len(rb.errors))
    ctx.check("one row per hash for all 50", all(counts.get(h) == 1 for h in all_h) and len(counts) == 50)
    ctx.check("alert_ids order == input order of stored", order == all_h[25:], first=str(order[:1]))


async def s3(ctx: Ctx, chunked: bool) -> None:
    from sqlalchemy.exc import DBAPIError
    alerts = make_alerts(2, f"s3{int(chunked)}")
    x, y = alerts
    (rx, hx), (ry, hy) = make_req([x]), make_req([y])
    rb_req, _ = make_req([y, x])
    sA = ctx.session(hold=True)
    await svc(False).ingest_batch(sA, rx)                      # A holds x
    sB = ctx.session()
    tb = ctx.task(svc(chunked).ingest_batch(sB, rb_req))       # B takes y, then wants x (blocked on A)
    await asyncio.sleep(0.5)
    async def a_batch_then_commit():                            # a real ingest batch commits as soon as it ends: A must release its locks then,
        r = await svc(False).ingest_batch(sA, ry)               # otherwise B (retrying after the deadlock) would wait for a commit the script itself delays
        await real_commit(sA)
        return r
    ta = ctx.task(a_batch_then_commit())                       # A now wants y (held by B): lock cycle, PostgreSQL must break it
    res = await asyncio.gather(ta, tb, return_exceptions=True)
    outcome = {}
    for nm, r in zip(("A", "B"), res):
        outcome[nm] = {"exception": type(r).__name__} if isinstance(r, BaseException) else summ(r)
    outcome["A_commit"] = "committed by its own batch" if not isinstance(res[0], BaseException) else "batch failed"
    if isinstance(res[0], BaseException):
        await sA.rollback()
    counts = await per_hash_counts(hx + hy)
    orph = await orphans(hx + hy)
    ctx.info.update(outcome=outcome, rows={"x": counts.get(hx[0], 0), "y": counts.get(hy[0], 0)})
    ctx.check("each batch completed or controlled DB failure", all(not isinstance(r, BaseException) or isinstance(r, DBAPIError) for r in res), outcome=outcome)
    ctx.check("exactly one row per hash", counts.get(hx[0]) == 1 and counts.get(hy[0]) == 1, x=counts.get(hx[0], 0), y=counts.get(hy[0], 0))
    ctx.check("no orphans", not any(orph.values()), **orph)


async def s4(ctx: Ctx, chunked: bool) -> None:
    alerts = make_alerts(120, f"s4{int(chunked)}")
    pre, _ = make_req([alerts[70]])
    sP = ctx.session()
    await svc(False).ingest_batch(sP, pre)                     # committed by the service before the batch starts
    req, hs = make_req(alerts)
    sB = ctx.session()
    rb = await svc(chunked).ingest_batch(sB, req)
    order = await hashes_for_events(list(rb.alert_ids))
    counts = await per_hash_counts(hs)
    ctx.info.update(b=summ(rb))
    ctx.check("119 stored, 1 skipped, no errors", (rb.total_normalized, rb.total_skipped_duplicates, len(rb.errors)) == (119, 1, 0), b=summ(rb))
    ctx.check("existing ids == 1", len(rb.existing_evidence_ids) == 1)
    ctx.check("alert_ids order == input order (minus index 70)", order == hs[:70] + hs[71:])
    ctx.check("one row per hash", all(counts.get(h) == 1 for h in hs))


def compare(name: str, a: Ctx, b: Ctx, key: str) -> None:
    ca, cb = a.info.get(key), b.info.get(key)
    ok = ca is not None and ca == cb
    RESULTS.append({"scenario": name, "verdict": "PASS" if ok else "FAIL", "seconds": 0, "chunk_fallback_warnings": 0, "info": {"chunked": ca, "per_alert": cb},
                    "checks": [{"check": "outcome equal across paths", "ok": ok}]})
    print(f"{name:<34} {'PASS' if ok else 'FAIL':<5} chunked={ca} per_alert={cb}", flush=True)


async def s5(ctx: Ctx) -> None:
    hs = sorted(RUN_HASHES)
    counts = {}
    for i in range(0, len(hs), 400):
        counts.update(await per_hash_counts(hs[i:i + 400]))
    orph = {"raw_without_event": 0, "entities_without_event": 0, "raws_with_more_than_one_event": 0}
    for i in range(0, len(hs), 400):
        o = await orphans(hs[i:i + 400], nonce_wide=(i == 0))
        for k, v in o.items():
            orph[k] = orph.get(k, 0) + v if k not in ("events_without_raw", "events_with_run_nonce") else v
    ctx.info.update(hashes_known=len(hs), raw_rows_found=sum(counts.values()), **orph)
    ctx.check("no raw without event", orph["raw_without_event"] == 0, got=orph["raw_without_event"])
    ctx.check("no entity without event", orph["entities_without_event"] == 0, got=orph["entities_without_event"])
    ctx.check("no event without raw (nonce match)", orph.get("events_without_raw", 0) == 0, got=orph.get("events_without_raw"), seen=orph.get("events_with_run_nonce"))
    ctx.check("no raw with more than one event", orph["raws_with_more_than_one_event"] == 0, got=orph["raws_with_more_than_one_event"])
    ctx.check("no hash stored more than once", all(c == 1 for c in counts.values()), max=max(counts.values(), default=0))


async def main_async(a) -> dict:
    global Session
    from loguru import logger
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    pw = Path(a.dbpw).read_text(encoding="utf-8").strip()
    eng = create_async_engine(f"postgresql+psycopg://aisop_app:{pw}@127.0.0.1:5433/{a.db}")
    Session = async_sessionmaker(eng, expire_on_commit=False)

    def sink(msg) -> None:
        if "Chunk savepoint failed" in msg.record["message"]:
            WARN[0] += 1
    sink_id = logger.add(sink, level="WARNING", format="{message}")
    started = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        c1 = await run_scenario("S1 overlap race (chunked)", s1, True)
        p1 = await run_scenario("S1 overlap race (per-alert)", s1, False)
        compare("S1 compare chunked vs per-alert", c1, p1, "b")
        await run_scenario("S2 partial overlap (chunked)", s2)
        await run_scenario("S3 reversed order (per-alert)", s3, False)
        await run_scenario("S3 reversed order (chunked)", s3, True)
        c4 = await run_scenario("S4 chunk boundary (chunked)", s4, True)
        p4 = await run_scenario("S4 chunk boundary (per-alert)", s4, False)
        compare("S4 compare chunked vs per-alert", c4, p4, "b")
        await run_scenario("S5 integrity", s5)
    finally:
        logger.remove(sink_id)
        try:
            await asyncio.wait_for(eng.dispose(), 10)
        except BaseException:           # noqa: BLE001
            pass
    fails = [r["scenario"] for r in RESULTS if r["verdict"] != "PASS"]
    return {"db": a.db, "nonce": NONCE, "started": started, "chunk_fallback_warnings_total": WARN[0], "overall": "PASS" if not fails else "FAIL",
            "failed_scenarios": fails, "scenarios": RESULTS}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dbpw", required=True, help="file holding the aisop_app role password")
    ap.add_argument("--db", required=True, help="scratch database, name starting with aisop_load")
    ap.add_argument("--out", required=True, help="JSON result path on D:")
    a = ap.parse_args()
    if a.db in PROTECTED or not a.db.startswith("aisop_load"):
        print("Refusing: database name must start with aisop_load and not be protected.", file=sys.stderr)
        return 2
    if not a.out.upper().startswith("D:"):
        print("--out must be on drive D:", file=sys.stderr)
        return 2
    res = asyncio.run(main_async(a))
    Path(a.out).write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(f"\nOVERALL {res['overall']}  failed={res['failed_scenarios']}  fallback_warnings={res['chunk_fallback_warnings_total']}  json={a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
