"""
Stage 5 end-to-end API benchmark (in-process FastAPI app, in-memory SQLite, no network, no LLM, synthetic data).

Measures, per event count and shape (see benchmark_investigation.py): ingestion through POST /alerts/ingest (batches of 100),
the first POST .../multisource (load + engine + audit write), the idempotent repeat, and GET .../status.
SQLite timings say nothing about PostgreSQL. Usage:  python backend/scripts/benchmark_investigation_api.py [--out file.json]
"""
import sys, json, time, asyncio, statistics, importlib.util
import argparse, pathlib
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
spec=importlib.util.spec_from_file_location('demo',str(HERE/'run_integrated_demo.py')); demo=importlib.util.module_from_spec(spec); spec.loader.exec_module(demo)
spec2=importlib.util.spec_from_file_location('bench',str(HERE/'benchmark_investigation.py')); bench=importlib.util.module_from_spec(spec2); spec2.loader.exec_module(bench)
import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db.base import Base
from app.models.analyst import Analyst
from tests.conftest import AsyncSessionAdapter
async def run(n, shape):
    engine=create_engine("sqlite:///:memory:", connect_args={"check_same_thread":False}, poolclass=StaticPool); Base.metadata.create_all(engine)
    session=AsyncSessionAdapter(sessionmaker(bind=engine.connect())()); prov=demo.ScriptedProvider(); app=demo.build_app(session,prov)
    token,case=await demo.seed_case(session); aid=(await session.execute(select(Analyst.id))).scalars().first()
    H={"Authorization":f"Bearer {token}"}; base=f"/api/v1/cases/{case.id}/investigations/multisource"
    recs=bench.build(n, shape=="single")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://b", timeout=120) as c:
        t0=time.perf_counter(); norm=0
        for i in range(0,len(recs),100):
            r=await c.post("/api/v1/alerts/ingest", json={"source_type":"auto","source_identifier":"bench","alerts":recs[i:i+100]}, headers=demo.MACHINE)
            assert r.status_code==200, (r.status_code, r.text[:200]); norm+=r.json()["total_normalized"]
        t_ing=time.perf_counter()-t0
        await demo.link_new_events(session, case, aid)
        t0=time.perf_counter(); r=await c.post(base, json={}, headers=H); t_start=time.perf_counter()-t0
        assert r.status_code==201, (r.status_code, r.text[:200]); size=len(r.content)
        t0=time.perf_counter(); r2=await c.post(base, json={}, headers=H); t_reuse=time.perf_counter()-t0
        t0=time.perf_counter(); r3=await c.get(base+"/status", headers=H); t_status=time.perf_counter()-t0
    return dict(events=n, shape=shape, ingested=norm, ingest_s=round(t_ing,2), start_s=round(t_start,3), reuse_s=round(t_reuse,3), status_get_s=round(t_status,3), response_bytes=size, incidents=r.json()["counts"]["incidents"], reuse_code=r2.status_code)
rows=[]
for n in (10,100,500,1000):
    for shape in ("separate","single"):
        rows.append(asyncio.run(run(n,shape))); print(rows[-1], flush=True)
ap=argparse.ArgumentParser(); ap.add_argument('--out'); a=ap.parse_args()
if a.out: pathlib.Path(a.out).write_text(json.dumps(rows, indent=1), encoding='utf-8')
