r"""
Repeatable benchmark: is AISOP responsive while large investigations and ingestion run? Loopback only, synthetic data, a SCRATCH database only.

    .venv\Scripts\python.exe backend\scripts\bench_investigation.py --tokens <file> --dbpw <file> --db aisop_loadtest --out D:\...\run_name
        [--sizes 500,1000] [--repeats 3] [--parallel 2,4] [--instrument] [--scaling 1000,2000,4000] [--label before-change]

It starts its own backend on 127.0.0.1:8022 (rate limiter off, LLM off), plain or instrumented (--instrument uses profile_investigation_server.py and
writes phases.jsonl beside the results). It never touches aisop_demo, aisop_dev or any database whose name does not start with aisop_load, and it only
adds rows (it deletes nothing). For every scenario and repeat it records:
  responsiveness   a no-database poll (/api/v1/health) and a database poll (/api/v1/cases?limit=1) every 100 ms: poll count, p50/p95/max, failures
  server process   the REAL server process (found by its listening port, not the launcher): working-set memory, peak, CPU seconds and mean CPU % of one core
  database side    PostgreSQL pg_stat_activity sampled every 150 ms: peak active sessions, sessions waiting on locks, idle-in-transaction age, longest running query
  correctness      alerts stored versus sent (none lost, none duplicated), and a digest of the investigation result that must be identical across repeats
  scaling          (--scaling) in-process timing of analyze() alone at larger sizes than the API allows (the API caps one investigation at 1,000 records)
Tokens and passwords are never printed. Output: results.json and summary.md in --out. Results describe this laptop and this synthetic data only.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
PORT = 8022
BASE = f"http://127.0.0.1:{PORT}"
PROTECTED = {"aisop_demo", "aisop_dev", "aisop", "aisop_test", "postgres"}


def pct(v: list[float], p: float) -> float:
    s = sorted(v)
    return s[min(len(s) - 1, int(round(p * (len(s) - 1))))] if s else 0.0


# ── real server process: memory and CPU through the Windows API (no extra dependency) ─────────────────────────────
class _PMC(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


def listening_pid(port: int) -> int | None:
    out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = re.search(rf"127\.0\.0\.1:{port}\s+0\.0\.0\.0:0\s+LISTENING\s+(\d+)", line)
        if m:
            return int(m.group(1))
    return None


def descendants(pid: int) -> list[int]:
    """All descendant processes of pid (worker processes are grandchildren behind the venv launcher stub on Windows)."""
    ps = next((c for c in ("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "pwsh", "powershell") if c in ("pwsh", "powershell") or os.path.exists(c)), "powershell")
    out = subprocess.run([ps, "-NoProfile", "-Command", "Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId),$($_.ParentProcessId)\" }"],
                         capture_output=True, text=True, timeout=30).stdout
    kids: dict[int, list[int]] = {}
    for line in out.splitlines():
        try:
            c, par = (int(x) for x in line.strip().split(","))
        except ValueError:
            continue
        kids.setdefault(par, []).append(c)
    found, stack = [], [pid]
    while stack:
        for c in kids.get(stack.pop(), []):
            found.append(c); stack.append(c)
    return found


class ProcSampler:
    def __init__(self, pid: int):
        k32, self.psapi = ctypes.WinDLL("kernel32", use_last_error=True), ctypes.WinDLL("psapi", use_last_error=True)
        k32.OpenProcess.restype = wt.HANDLE
        self.k32, self.h = k32, k32.OpenProcess(0x0400 | 0x0010, False, pid)
        self.samples: list[tuple[float, float, float]] = []   # (t, rss_mb, cpu_s)
        self.peak_mb = 0.0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _read(self) -> tuple[float, float, float]:
        pmc = _PMC(); pmc.cb = ctypes.sizeof(_PMC)
        self.psapi.GetProcessMemoryInfo(self.h, ctypes.byref(pmc), pmc.cb)
        c, e, kt, ut = (wt.FILETIME() for _ in range(4))
        self.k32.GetProcessTimes(self.h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut))
        ft = lambda f: ((f.dwHighDateTime << 32) | f.dwLowDateTime) / 1e7
        self.peak_mb = max(self.peak_mb, pmc.PeakWorkingSetSize / 1048576)
        return time.time(), pmc.WorkingSetSize / 1048576, ft(kt) + ft(ut)

    def _run(self) -> None:
        while not self._stop.is_set():
            self.samples.append(self._read())
            self._stop.wait(0.25)

    def __enter__(self):
        self.samples.append(self._read()); self._t.start(); return self

    def __exit__(self, *a):
        self._stop.set(); self._t.join(5); self.samples.append(self._read())

    def summary(self) -> dict:
        (t0, m0, c0), (t1, m1, c1) = self.samples[0], self.samples[-1]
        return {"rss_start_mb": round(m0), "rss_end_mb": round(m1), "rss_max_in_window_mb": round(max(s[1] for s in self.samples)),
                "rss_peak_process_lifetime_mb": round(self.peak_mb), "cpu_seconds": round(c1 - c0, 2),
                "cpu_pct_of_one_core": round(100 * (c1 - c0) / max(t1 - t0, 1e-6))}


# ── PostgreSQL side ────────────────────────────────────────────────────────────────────────────────────────────────
class PgSampler:
    def __init__(self, db: str):
        self.db, self.rows = db, []
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)
        self.error: str | None = None

    def _run(self) -> None:
        try:
            import psycopg
            pw = os.environ.get("POSTGRES_PASSWORD", "aisop")
            with psycopg.connect(f"postgresql://aisop:{pw}@127.0.0.1:5433/postgres", autocommit=True, connect_timeout=5) as c:
                while not self._stop.is_set():
                    cur = c.execute(
                        "select state, wait_event_type, extract(epoch from now()-xact_start), extract(epoch from now()-query_start) "
                        "from pg_stat_activity where datname=%s and pid<>pg_backend_pid()", (self.db,))
                    rows = cur.fetchall()
                    locks = c.execute("select count(*) from pg_locks l join pg_database d on d.oid=l.database where d.datname=%s and not l.granted", (self.db,)).fetchone()[0]
                    self.rows.append((time.time(), rows, locks))
                    self._stop.wait(0.15)
        except Exception as exc:  # noqa: BLE001
            self.error = type(exc).__name__

    def __enter__(self):
        self._t.start(); return self

    def __exit__(self, *a):
        self._stop.set(); self._t.join(5)

    def summary(self) -> dict:
        if self.error or not self.rows:
            return {"unavailable": self.error or "no samples"}
        active = [sum(1 for r in rows if r[0] == "active") for _, rows, _ in self.rows]
        lockwait = [sum(1 for r in rows if r[1] == "Lock") for _, rows, _ in self.rows]
        idle_tx = [max([r[2] or 0 for r in rows if r[0] == "idle in transaction"] or [0]) for _, rows, _ in self.rows]
        qage = [max([r[3] or 0 for r in rows if r[0] == "active"] or [0]) for _, rows, _ in self.rows]
        return {"samples": len(self.rows), "sessions_max": max(len(r) for _, r, _ in self.rows), "active_max": max(active), "lock_waiters_max": max(lockwait),
                "ungranted_locks_max": max(l for _, _, l in self.rows), "idle_in_transaction_max_s": round(max(idle_tx), 2), "longest_active_query_s": round(max(qage), 2)}


class Poller:
    def __init__(self, path: str, headers: dict | None = None):
        self.path, self.headers, self.lat, self.fail = path, headers or {}, [], 0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        with httpx.Client(base_url=BASE, timeout=60) as c:
            while not self._stop.is_set():
                t = time.perf_counter()
                try:
                    self.fail += c.get(self.path, headers=self.headers).status_code != 200
                except Exception:
                    self.fail += 1
                self.lat.append(time.perf_counter() - t)
                self._stop.wait(0.1)

    def __enter__(self):
        self._t.start(); return self

    def __exit__(self, *a):
        self._stop.set(); self._t.join(70)

    def summary(self, seconds: float) -> dict:
        return {"polls": len(self.lat), "expected_polls": int(seconds / 0.1), "failed": self.fail, "p50_ms": round(pct(self.lat, 0.5) * 1000),
                "p95_ms": round(pct(self.lat, 0.95) * 1000), "max_ms": round(max(self.lat or [0]) * 1000)}


def alert(i: int, nonce: str) -> dict:
    return {"source_type": "generic_siem", "rule_id": f"R-BN-{nonce}-{i}", "rule_name": f"bench rule {i % 40}", "severity": ["low", "medium", "high"][i % 3],
            "timestamp": f"2026-11-07T{(i // 60) % 24:02d}:{i % 60:02d}:00Z", "host": f"bn-host-{i % 20}", "user": f"bn-user-{i % 7}",
            "src_ip": f"203.0.113.{i % 50 + 1}", "dest_ip": f"198.51.100.{i % 30 + 1}"}


def result_digest(payload: dict) -> str:
    """Stable digest of what the analysis concluded (volatile fields such as times and ids of the run itself are excluded)."""
    inc = payload.get("incidents", [])
    key = [{"ctx": i.get("context_sha256"), "verdict": (i.get("sufficiency") or {}).get("verdict"), "n": i.get("event_count", i.get("events"))} for i in inc]
    return hashlib.sha256(json.dumps({"fp": payload.get("evidence_fingerprint"), "incidents": key, "summary": payload.get("summary")}, sort_keys=True, default=str).encode()).hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tokens", required=True); ap.add_argument("--dbpw", required=True); ap.add_argument("--db", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--sizes", default="500,1000"); ap.add_argument("--repeats", type=int, default=3); ap.add_argument("--parallel", default="2,4")
    ap.add_argument("--instrument", action="store_true"); ap.add_argument("--scaling", default=""); ap.add_argument("--label", default="run")
    a = ap.parse_args()
    if a.db in PROTECTED or not a.db.startswith("aisop_load"):
        print("Refusing: database name must start with aisop_load and not be protected.", file=sys.stderr); return 2
    if not a.out.upper().startswith("D:"):
        print("--out must be on drive D:", file=sys.stderr); return 2
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    tokens = dict(l.split("=", 1) for l in Path(a.tokens).read_text(encoding="utf-8").splitlines() if "=" in l)
    dbpw = Path(a.dbpw).read_text(encoding="utf-8").strip()
    results: dict = {"label": a.label, "started": time.strftime("%Y-%m-%d %H:%M:%S"), "cpu_count": os.cpu_count(), "python": sys.version.split()[0],
                     "git_head": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip(),
                     "instrumented": a.instrument, "out_dir": str(out), "analysis_worker_processes": os.environ.get("ANALYSIS_WORKER_PROCESSES", "0"), "scenarios": []}
    if a.scaling:
        results["scaling"] = scaling([int(x) for x in a.scaling.split(",")])
        print("SCALING", json.dumps(results["scaling"]))
    env = os.environ.copy()
    env.update({"DATABASE_URL": f"postgresql+psycopg://aisop_app:{dbpw}@127.0.0.1:5433/{a.db}", "API_AUTH_ENABLED": "true", "API_AUTH_ALLOW_LEGACY_KEYS": "false",
                "ENVIRONMENT": "development", "AISOP_PORT": str(PORT), "RATE_LIMIT_ENABLED": "false", "LLM_ENABLED": "false", "AISOP_PROFILE_OUT": str(out),
                "CASE_CREATE_MAX_PER_HOUR": "1000",        # benchmark server only (the setting allows at most 1000): the per-analyst creation cap would otherwise stop repeated runs (HTTP 429)
                "ATTACK_REFERENCE_PATH": "D:\\AISOP-Reference-Data\\MITRE-ATT&CK\\Enterprise\\v20.1\\enterprise-attack-20.1.json"})
    script = "profile_investigation_server.py" if a.instrument else None
    cmd = [sys.executable, str(ROOT / "backend" / (f"scripts/{script}" if script else "run_local.py"))]
    log = open(out / "server.log", "w")
    proc = subprocess.Popen(cmd, cwd=str(ROOT), env=env, stdout=log, stderr=log)
    try:
        for _ in range(90):
            try:
                if httpx.get(f"{BASE}/api/v1/health", timeout=2).status_code == 200:
                    break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("server did not start")
        if int(env.get("ANALYSIS_WORKER_PROCESSES", "0") or 0) > 0:
            time.sleep(8)                                              # let the pool pre-warm (2 to 3 s) before measuring
        pid = listening_pid(PORT)
        results["server_pid"], results["launcher_pid"] = pid, proc.pid
        run(results, tokens, pid, a.db, [int(x) for x in a.sizes.split(",")], a.repeats, [int(x) for x in a.parallel.split(",") if x])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except Exception:
            proc.kill()
    (out / "results.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    (out / "summary.md").write_text(summarize(results), encoding="utf-8")
    print(summarize(results))
    return 0


def scaling(sizes: list[int]) -> list[dict]:
    """analyze() alone, in this process, at sizes above the API cap. Shows how CPU time grows with n (complexity), not request behaviour."""
    sys.path.insert(0, str(ROOT / "backend"))
    os.chdir(ROOT)
    from app.modules.correlation.workflow import analyze
    rows = []
    for n in sizes:
        recs = [alert(i, "scale") for i in range(n)]
        c0, t0 = time.process_time(), time.perf_counter()
        res = analyze(recs, None, None, None, None)
        rows.append({"records": n, "wall_s": round(time.perf_counter() - t0, 2), "cpu_s": round(time.process_time() - c0, 2), "incidents": len(res.incidents)})
    return rows


def run(results: dict, tokens: dict, server_pid: int, db: str, sizes: list[int], repeats: int, parallels: list[int]) -> None:
    analyst, sensor = {"X-API-Key": tokens["analyst"]}, {"X-API-Key": tokens["sensor"]}
    c = httpx.Client(base_url=BASE, timeout=900)
    nonce = uuid.uuid4().hex[:8]
    seq = {"n": 0}

    def ingest(alerts, cl=c):
        return cl.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "bench", "alerts": alerts}, headers=sensor)

    def new_case(title):
        return c.post("/api/v1/cases", json={"title": title, "description": "synthetic benchmark"}, headers=analyst).json()["id"]

    def link(cid, ids):
        def one(i):
            with httpx.Client(base_url=BASE, timeout=120) as cl:
                return cl.post(f"/api/v1/cases/{cid}/evidence", json={"evidence_id": i}, headers=analyst).status_code == 201
        with ThreadPoolExecutor(8) as ex:
            return sum(ex.map(one, ids))

    def fresh_alerts(n):
        base = seq["n"]; seq["n"] += n
        return [alert(base + i, nonce) for i in range(n)]

    def measure(name: str, work, **extra) -> dict:
        lv, cs, au = Poller("/api/v1/health"), Poller("/api/v1/cases?limit=1", analyst), Poller("/api/v1/auth/me", analyst)
        kids = [ProcSampler(k) for k in descendants(server_pid)]          # worker processes (empty when ANALYSIS_WORKER_PROCESSES is 0)
        for k in kids:
            k.__enter__()
        with ProcSampler(server_pid) as ps, PgSampler(db) as pg, lv, cs, au:
            time.sleep(0.5)
            t = time.perf_counter()
            out = work()
            dur = time.perf_counter() - t
            time.sleep(0.3)
        for k in kids:
            k.__exit__(None, None, None)
        wk = [k.summary() for k in kids]
        workers = {"processes": len(wk), "cpu_seconds_total": round(sum(w["cpu_seconds"] for w in wk), 2),
                   "rss_end_mb_total": sum(w["rss_end_mb"] for w in wk), "rss_peak_mb_total": sum(w["rss_peak_process_lifetime_mb"] for w in wk)}
        row = {"scenario": name, "seconds": round(dur, 2), "liveness": lv.summary(dur), "db_poll": cs.summary(dur), "auth_poll": au.summary(dur),
               "server": ps.summary(), "workers": workers, "postgres": pg.summary(), **extra, **(out or {})}
        results["scenarios"].append(row)
        Path(results["out_dir"], "results.partial.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")   # survives a later failure
        print("==", name, json.dumps(row, default=str)[:700], flush=True)
        return row

    measure("idle", lambda: time.sleep(6))
    # seed once: a pool of stored alerts, then link subsets to fresh cases
    pool_n = max(max(sizes), 1000)
    pool = ingest(fresh_alerts(pool_n)).json()
    pool_ids = pool.get("alert_ids", [])
    results["seed"] = {"sent": pool_n, "stored": pool.get("total_normalized"), "errors": len(pool.get("errors", []))}
    digests: dict[int, set] = {}

    for n in sizes:
        for r in range(repeats):
            cid = new_case(f"bench {n} r{r}")
            linked = link(cid, pool_ids[:n])

            def work():
                resp = c.post(f"/api/v1/cases/{cid}/investigations/multisource", json={"force": True}, headers=analyst)
                body = resp.json() if resp.status_code in (200, 201) else {}
                return {"status": resp.status_code, "digest": result_digest(body) if body else None, "incidents": len(body.get("incidents", []))}
            row = measure(f"investigation_{n}", work, repeat=r, linked=linked)
            digests.setdefault(n, set()).add(row.get("digest"))
    results["result_digests_identical_across_repeats"] = {str(n): len(s) == 1 for n, s in digests.items()}

    for k in parallels:                                      # k investigations of 500 records at once
        cids = []
        for j in range(k):
            cid = new_case(f"bench parallel {k}/{j}"); link(cid, pool_ids[:500]); cids.append(cid)

        def work_par():
            def one(cid):
                with httpx.Client(base_url=BASE, timeout=900) as cl:
                    return cl.post(f"/api/v1/cases/{cid}/investigations/multisource", json={"force": True}, headers=analyst).status_code
            with ThreadPoolExecutor(k) as ex:
                return {"statuses": list(ex.map(one, cids))}
        measure(f"parallel_investigations_x{k}_500", work_par)

    # ingestion while an investigation of the largest size runs: nothing may be lost or duplicated
    biggest = max(sizes)
    cid = new_case("bench ingest-during-investigation"); link(cid, pool_ids[:biggest])
    batches = [fresh_alerts(100) for _ in range(4)]

    def work_mixed():
        def inv():
            with httpx.Client(base_url=BASE, timeout=900) as cl:
                return cl.post(f"/api/v1/cases/{cid}/investigations/multisource", json={"force": True}, headers=analyst).status_code
        def ing(b):
            with httpx.Client(base_url=BASE, timeout=900) as cl:
                t = time.perf_counter(); r = ingest(b, cl); return r.status_code, (r.json().get("total_normalized") if r.status_code == 200 else None), time.perf_counter() - t
        with ThreadPoolExecutor(5) as ex:
            fi = ex.submit(inv); fs = [ex.submit(ing, b) for b in batches]
            ing_res = [f.result() for f in fs]; inv_status = fi.result()
        return {"investigation_status": inv_status, "ingest_statuses": [x[0] for x in ing_res], "ingest_stored": sum(x[1] or 0 for x in ing_res), "ingest_expected": 400,
                "ingest_max_s": round(max(x[2] for x in ing_res), 2)}
    measure(f"ingest_during_investigation_{biggest}", work_mixed)

    dup = fresh_alerts(100)               # duplicate storm: 8 clients, identical 100 alerts, each stored exactly once

    def work_dup():
        with ThreadPoolExecutor(8) as ex:
            res = list(ex.map(lambda _: ingest(dup, httpx.Client(base_url=BASE, timeout=900)), range(8)))
        return {"statuses": sorted({x.status_code for x in res}), "stored_total": sum(x.json().get("total_normalized", 0) for x in res if x.status_code == 200), "expected": 100}
    measure("duplicate_storm_8x100", work_dup)


def summarize(r: dict) -> str:
    # Poll rate is compared with the same run's idle poll rate (idle window 0.5 + 6 + 0.3 s = 6.8 s) over each scenario's measured window
    # (work + 0.5 s before + 0.3 s after). The older "got/expected" count was biased: expected ignored the extra 0.8 s and the poll cycle is longer than 0.1 s.
    idle = next((x for x in r["scenarios"] if x["scenario"] == "idle"), None)
    idle_rate = (idle["liveness"]["polls"] / 6.8) if idle else None
    rel = lambda x: f"{100 * (x['liveness']['polls'] / (x['seconds'] + 0.8)) / idle_rate:.0f}%" if idle_rate else "n/a"
    lines = [f"# Benchmark {r['label']} ({r['started']}, git {r['git_head']}, instrumented={r['instrumented']}, ANALYSIS_WORKER_PROCESSES={r.get('analysis_worker_processes')}, cpus={r['cpu_count']})", "",
             f"Server process pid {r.get('server_pid')} (launcher {r.get('launcher_pid')}). Seed: {r.get('seed')}", "",
             "| Scenario | s | Poll rate vs idle | Liveness max ms | Auth-only DB poll max ms | Cases DB poll max ms | Server CPU s | Server CPU % of 1 core | Server RSS end MB | Server RSS peak MB | Worker CPU s | Worker RSS end MB (total) | PG active max | PG lock waiters |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in r["scenarios"]:
        lv, db, sv, pg = s["liveness"], s["db_poll"], s["server"], s["postgres"]
        lines.append(f"| {s['scenario']} r{s.get('repeat', '-')} | {s['seconds']} | {rel(s)} | {lv['max_ms']} | {s['auth_poll']['max_ms']} | {db['max_ms']} | {sv['cpu_seconds']} | {sv['cpu_pct_of_one_core']} | "
                     f"{sv['rss_end_mb']} | {sv['rss_peak_process_lifetime_mb']} | {s['workers']['cpu_seconds_total']} | {s['workers']['rss_end_mb_total']} | {pg.get('active_max', '?')} | {pg.get('lock_waiters_max', '?')} |")
    if "scaling" in r:
        lines += ["", "## analyze() scaling (in-process, no server)", "", "| records | wall s | cpu s | incidents |", "|---|---|---|---|"]
        lines += [f"| {x['records']} | {x['wall_s']} | {x['cpu_s']} | {x['incidents']} |" for x in r["scaling"]]
    lines += ["", f"Result digests identical across repeats: {r.get('result_digests_identical_across_repeats')}"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
