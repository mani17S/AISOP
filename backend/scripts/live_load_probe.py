r"""
Load probe for criticism 5 (multiple-alert reliability): loopback only, synthetic data only, a SCRATCH database only.

    .venv\Scripts\python.exe backend\scripts\live_load_probe.py --tokens <tokens file> --dbpw <app role password file> --db aisop_loadtest --out <json>

It starts its own throwaway backend on 127.0.0.1:8021 (rate limiter off, LLM off) against the scratch database and stops it at the end.
It refuses to run against the demo or development databases. While heavy work runs, two pollers measure what other users would see:
  liveness  GET /api/v1/health              (no database)
  cases     GET /api/v1/cases?limit=1        (analyst key, touches the database)
Scenarios: idle baseline; one 1,000-alert batch; 8 concurrent clients with 100 alerts each; investigation over 500 and 1,000 linked
records; two investigations at the same time. Each reports duration, errors and the worst poll latency during the work.
Tokens and the DB password are never printed. Results describe this one laptop and this synthetic data only.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
PORT = 8021
BASE = f"http://127.0.0.1:{PORT}"
PROTECTED = {"aisop_demo", "aisop_dev", "aisop", "aisop_test", "postgres"}
RESULTS: list[dict] = []


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p * (len(s) - 1))))]


class Poller:
    """Polls one URL every 100 ms from its own thread and keeps every latency and failure."""

    def __init__(self, name: str, path: str, headers: dict | None = None):
        self.name, self.path, self.headers = name, path, headers or {}
        self.lat: list[float] = []
        self.fail = 0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        with httpx.Client(base_url=BASE, timeout=60) as c:
            while not self._stop.is_set():
                t = time.perf_counter()
                try:
                    r = c.get(self.path, headers=self.headers)
                    if r.status_code != 200:
                        self.fail += 1
                    self.lat.append(time.perf_counter() - t)
                except Exception:
                    self.fail += 1
                    self.lat.append(time.perf_counter() - t)
                self._stop.wait(0.1)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *a):
        self._stop.set()
        self._t.join(timeout=70)

    def summary(self) -> dict:
        return {"polls": len(self.lat), "failed": self.fail, "p50_ms": round(pct(self.lat, 0.5) * 1000), "p95_ms": round(pct(self.lat, 0.95) * 1000),
                "max_ms": round(max(self.lat or [0]) * 1000)}


def alert(i: int, nonce: str) -> dict:
    return {"source_type": "generic_siem", "rule_id": f"R-LD-{nonce}-{i}", "rule_name": f"load rule {i % 40}", "severity": ["low", "medium", "high"][i % 3],
            "timestamp": f"2026-11-07T{(i // 60) % 24:02d}:{i % 60:02d}:00Z", "host": f"ld-host-{i % 20}", "user": f"ld-user-{i % 7}",
            "src_ip": f"203.0.113.{i % 50 + 1}", "dest_ip": f"198.51.100.{i % 30 + 1}"}


def rss_mb(pid: int) -> float | None:
    """Working-set memory of the backend process in MB, read with Windows tasklist (no extra dependency)."""
    try:
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=10).stdout
        mem = out.strip().split('","')[-1].strip('"')                   # e.g. 155,432 K
        return round(int(mem.replace(" K", "").replace(",", "").replace(".", "")) / 1024)
    except Exception:
        return None


def record(name: str, **kw) -> None:
    RESULTS.append({"scenario": name, **kw})
    print(f"== {name}: " + json.dumps(kw, default=str))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--dbpw", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.db in PROTECTED or not a.db.startswith("aisop_load"):
        print("Refusing: the database name must start with aisop_load and not be a protected database.", file=sys.stderr)
        return 2
    if not a.out.upper().startswith("D:"):
        print("--out must be on drive D:", file=sys.stderr)
        return 2
    tokens = dict(l.split("=", 1) for l in Path(a.tokens).read_text(encoding="utf-8").splitlines() if "=" in l)
    dbpw = Path(a.dbpw).read_text(encoding="utf-8").strip()
    analyst = {"X-API-Key": tokens["analyst"]}
    sensor = {"X-API-Key": tokens["sensor"]}
    outdir = Path(a.out).parent
    outdir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({"DATABASE_URL": f"postgresql+psycopg://aisop_app:{dbpw}@127.0.0.1:5433/{a.db}", "API_AUTH_ENABLED": "true", "API_AUTH_ALLOW_LEGACY_KEYS": "false",
                "ENVIRONMENT": "development", "AISOP_PORT": str(PORT), "RATE_LIMIT_ENABLED": "false", "LLM_ENABLED": "false",
                "ATTACK_REFERENCE_PATH": "D:\\AISOP-Reference-Data\\MITRE-ATT&CK\\Enterprise\\v20.1\\enterprise-attack-20.1.json"})
    log = open(outdir / "load_backend_8021.log", "w")
    proc = subprocess.Popen([sys.executable, str(ROOT / "backend" / "run_local.py")], cwd=str(ROOT), env=env, stdout=log, stderr=log)
    try:
        for _ in range(60):
            try:
                if httpx.get(f"{BASE}/api/v1/health", timeout=2).status_code == 200:
                    break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("backend did not start")
        run(proc.pid, analyst, sensor)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except Exception:
            proc.kill()
    Path(a.out).write_text(json.dumps(RESULTS, indent=2, default=str), encoding="utf-8")
    return 0


def run(pid: int, analyst: dict, sensor: dict) -> None:
    c = httpx.Client(base_url=BASE, timeout=600)
    nonce = uuid.uuid4().hex[:8]

    def pollers():
        return Poller("liveness", "/api/v1/health"), Poller("cases", "/api/v1/cases?limit=1", analyst)

    def ingest(alerts, client=c):
        return client.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "load", "alerts": alerts}, headers=sensor)

    def new_case(title: str) -> str:
        return c.post("/api/v1/cases", json={"title": title, "description": "synthetic load probe"}, headers=analyst).json()["id"]

    def link(cid: str, ids: list[str]) -> int:
        def one(i):
            with httpx.Client(base_url=BASE, timeout=120) as cl:
                return cl.post(f"/api/v1/cases/{cid}/evidence", json={"evidence_id": i}, headers=analyst).status_code == 201
        with ThreadPoolExecutor(8) as ex:
            return sum(ex.map(one, ids))

    # 1 idle baseline
    p1, p2 = pollers()
    with p1, p2:
        time.sleep(8)
    record("idle_baseline", liveness=p1.summary(), cases=p2.summary(), rss_mb=rss_mb(pid))

    # 2 one batch of 1,000 alerts (the API cap) while polling
    batch = [alert(i, nonce) for i in range(1000)]
    p1, p2 = pollers()
    with p1, p2:
        t = time.perf_counter()
        r = ingest(batch)
        dur = time.perf_counter() - t
    b = r.json() if r.status_code == 200 else {}
    record("ingest_1000_one_batch", status=r.status_code, seconds=round(dur, 2), normalized=b.get("total_normalized"), skipped=b.get("total_skipped"),
           errors=len(b.get("errors", [])) if b else None, liveness=p1.summary(), cases=p2.summary(), rss_mb=rss_mb(pid))
    ids_1000 = b.get("alert_ids", [])

    # 3 eight concurrent clients, 100 alerts each
    chunks = [[alert(10_000 + k * 100 + j, nonce) for j in range(100)] for k in range(8)]
    p1, p2 = pollers()
    codes: list[int] = []
    normalized = 0
    with p1, p2:
        t = time.perf_counter()

        def worker(chunk):
            with httpx.Client(base_url=BASE, timeout=600) as cl:
                rr = ingest(chunk, cl)
                return rr.status_code, (rr.json().get("total_normalized", 0) if rr.status_code == 200 else 0)
        with ThreadPoolExecutor(8) as ex:
            for sc, n in ex.map(worker, chunks):
                codes.append(sc)
                normalized += n
        dur = time.perf_counter() - t
    record("ingest_8_clients_x_100", statuses=sorted(set(codes)), seconds=round(dur, 2), normalized=normalized, expected=800, liveness=p1.summary(), cases=p2.summary(),
           rss_mb=rss_mb(pid))

    # 4 duplicate storm: the same 100 alerts from 8 clients at once must create each record once
    dup = [alert(50_000 + j, nonce) for j in range(100)]
    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(lambda _: ingest(dup, httpx.Client(base_url=BASE, timeout=600)), range(8)))
    tot = sum(x.json().get("total_normalized", 0) for x in res if x.status_code == 200)
    record("duplicate_storm_8x100", statuses=sorted({x.status_code for x in res}), normalized_total=tot, expected=100)

    # 5 investigations over 500 and 1,000 linked records, with polling
    for n in (500, 1000):
        cid = new_case(f"Load probe {n} records")
        linked = link(cid, ids_1000[:n])
        p1, p2 = pollers()
        with p1, p2:
            t = time.perf_counter()
            r = c.post(f"/api/v1/cases/{cid}/investigations/multisource", json={}, headers=analyst)
            dur = time.perf_counter() - t
        record(f"investigation_{n}_records", linked=linked, status=r.status_code, seconds=round(dur, 2), liveness=p1.summary(), cases=p2.summary(), rss_mb=rss_mb(pid))
        if n == 1000:
            case_1000 = cid

    # 6 two investigations at once on separate cases
    cids = []
    for k in range(2):
        cid = new_case(f"Load probe parallel {k}")
        link(cid, ids_1000[:500])
        cids.append(cid)
    p1, p2 = pollers()
    with p1, p2:
        t = time.perf_counter()
        with ThreadPoolExecutor(2) as ex:
            rr = list(ex.map(lambda x: httpx.Client(base_url=BASE, timeout=600).post(f"/api/v1/cases/{x}/investigations/multisource", json={}, headers=analyst), cids))
        dur = time.perf_counter() - t
    record("two_parallel_investigations_500", statuses=[x.status_code for x in rr], seconds=round(dur, 2), liveness=p1.summary(), cases=p2.summary(), rss_mb=rss_mb(pid))


if __name__ == "__main__":
    raise SystemExit(main())
