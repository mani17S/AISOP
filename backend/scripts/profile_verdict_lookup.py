r"""
Where does the case-verdict lookup spend its time? Read-only measurement against a SCRATCH database (name must start with aisop_load).

    .venv\Scripts\python.exe backend\scripts\profile_verdict_lookup.py --dbpw <app role password file> --db aisop_loadtest --out <json> [--pages 20] [--repeats 5]

It reads the audit rows that the application's case_sufficiency_summaries() reads and times the stages separately, on this machine, with the server idle:
  1 database execution   PostgreSQL's own time for the window query and for the details fetch (EXPLAIN (ANALYZE, BUFFERS) execution time, no network involved)
  2 transfer             fetching the same rows as raw TEXT with psycopg, no JSON parsing (network + libpq + Python string creation)
  3 JSON decoding        json.loads of that text (what SQLAlchemy's JSON type does for each row)
  4 ORM materialisation  select(CaseAuditEventModel.case_id, details, created_at) through SQLAlchemy, versus select of only a tiny JSON path value
  5 reduction            the application's own reducer on the decoded dict
It also reports the bytes transferred per page and pg_column_size of the stored values. It writes nothing to the database and never prints credentials.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
os.chdir(ROOT)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
PROTECTED = {"aisop_demo", "aisop_dev", "aisop", "aisop_test", "postgres"}
ACTION = "case_multisource_investigation"


def med(v):
    s = sorted(v)
    return round(s[len(s) // 2] * 1000, 2) if s else None


async def main_async(a) -> dict:
    only_new = "and details ? 'verdict_summary' " if a.require_summary else ""
    import psycopg
    from sqlalchemy import select
    from app.models.case import CaseAuditEventModel
    from app.services.multisource_investigation_service import _case_sufficiency_from_row
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

    pw_app = Path(a.dbpw).read_text(encoding="utf-8").strip()
    su = os.environ.get("POSTGRES_PASSWORD", "aisop")
    res: dict = {"db": a.db, "page_cases": a.pages, "repeats": a.repeats, "rows_selected": "only rows with verdict_summary (new code)" if a.require_summary else "largest latest rows of any age"}
    with psycopg.connect(f"postgresql://aisop:{su}@127.0.0.1:5433/{a.db}", autocommit=True) as c:
        # the latest investigation row per case, biggest first: the worst page the list endpoint could build
        rows = c.execute(
            "select distinct on (case_id) id, case_id, pg_column_size(details), octet_length(details::text) from case_audit_events "
            "where action=%s " + only_new + "order by case_id, created_at desc, id desc", (ACTION,)).fetchall()
        rows.sort(key=lambda r: -r[3])
        page = rows[: a.pages]
        ids = [str(r[0]) for r in page]
        cases = [r[1] for r in page]
        res["cases_with_investigation"] = len(rows)
        res["page_rows"] = len(page)
        res["page_stored_bytes_pg_column_size"] = sum(r[2] for r in page)
        res["page_text_bytes"] = sum(r[3] for r in page)
        res["largest_row_text_bytes"] = page[0][3] if page else 0
        # 1 database execution time, server side
        plan = c.execute("explain (analyze, buffers, format json) select id, case_id, details, created_at from case_audit_events where id = any(%s::uuid[])", (ids,)).fetchone()[0][0]
        res["pg_execution_ms_details_fetch"] = round(plan["Execution Time"], 2)
        plan2 = c.execute(
            "explain (analyze, format json) select a.id from (select id, row_number() over (partition by case_id order by created_at desc, id desc) rn "
            "from case_audit_events where case_id = any(%s::uuid[]) and action=%s) a where a.rn=1", (cases, ACTION)).fetchone()[0][0]
        res["pg_execution_ms_window_query"] = round(plan2["Execution Time"], 2)
        # 2 transfer as raw text, no parsing
        t2 = []
        for _ in range(a.repeats):
            t = time.perf_counter()
            raw = c.execute("select details::text from case_audit_events where id = any(%s::uuid[])", (ids,)).fetchall()
            t2.append(time.perf_counter() - t)
        res["transfer_raw_text_ms_median"] = med(t2)
        # 3 JSON decoding of exactly that text
        t3 = []
        for _ in range(a.repeats):
            t = time.perf_counter()
            decoded = [json.loads(r[0]) for r in raw]
            t3.append(time.perf_counter() - t)
        res["json_decode_ms_median"] = med(t3)
        # transfer of only a small value, for comparison (what a compact summary key would cost)
        t2b = []
        for _ in range(a.repeats):
            t = time.perf_counter()
            small = c.execute("select details->'batch_sufficiency' from case_audit_events where id = any(%s::uuid[])", (ids,)).fetchall()
            t2b.append(time.perf_counter() - t)
        res["transfer_small_jsonb_path_ms_median"] = med(t2b)
        res["small_value_bytes"] = sum(len(json.dumps(r[0])) for r in small if r[0] is not None)

    # 4 through SQLAlchemy (the application's own path), full details versus a tiny JSON path value
    eng = create_async_engine(f"postgresql+psycopg://aisop_app:{pw_app}@127.0.0.1:5433/{a.db}")
    Session = async_sessionmaker(eng, expire_on_commit=False)
    import uuid as _uuid
    uid = [_uuid.UUID(i) for i in ids]
    t4, t4s, t5 = [], [], []
    async with Session() as s:
        for _ in range(a.repeats):
            t = time.perf_counter()
            r = (await s.execute(select(CaseAuditEventModel.case_id, CaseAuditEventModel.details, CaseAuditEventModel.created_at).where(CaseAuditEventModel.id.in_(uid)))).all()
            t4.append(time.perf_counter() - t)
        for _ in range(a.repeats):
            t = time.perf_counter()
            await s.execute(select(CaseAuditEventModel.case_id, CaseAuditEventModel.details["batch_sufficiency"], CaseAuditEventModel.created_at).where(CaseAuditEventModel.id.in_(uid)))
            t4s.append(time.perf_counter() - t)
        for _ in range(a.repeats):
            t = time.perf_counter()
            for _, d, ca in r:
                _case_sufficiency_from_row(d, ca)
            t5.append(time.perf_counter() - t)
        # whole function as the application runs it
        from app.services.multisource_investigation_service import case_sufficiency_summaries
        t6 = []
        for _ in range(a.repeats):
            t = time.perf_counter()
            await case_sufficiency_summaries(s, cases)
            t6.append(time.perf_counter() - t)
    await eng.dispose()
    res["sqlalchemy_full_details_ms_median"] = med(t4)
    res["sqlalchemy_json_path_value_ms_median"] = med(t4s)
    res["reduction_ms_median"] = med(t5)
    res["case_sufficiency_summaries_total_ms_median"] = med(t6)
    res["case_sufficiency_summaries_first_call_ms"] = round(t6[0] * 1000, 2)      # before the in-process memo is warm
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dbpw", required=True); ap.add_argument("--db", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--pages", type=int, default=20); ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--require-summary", action="store_true", help="only rows written with details.verdict_summary (new code); default measures the largest rows of any age")
    a = ap.parse_args()
    if a.db in PROTECTED or not a.db.startswith("aisop_load"):
        print("Refusing: database name must start with aisop_load and not be protected.", file=sys.stderr); return 2
    if not a.out.upper().startswith("D:"):
        print("--out must be on drive D:", file=sys.stderr); return 2
    res = asyncio.run(main_async(a))
    Path(a.out).write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
