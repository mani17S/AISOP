r"""
Spike (measurement only, not used by the application): does running the deterministic analysis in a separate PROCESS keep the event loop
responsive without the throughput penalty that a smaller thread-switch interval caused?

    .venv\Scripts\python.exe backend\scripts\spike_process_worker.py --out D:\...\spike.json [--sizes 500,1000,2000] [--repeats 3]

It reuses the application's own functions (correlation.workflow.analyze and MultiSourceInvestigationService.build_payload), unchanged, on the same
synthetic records, and compares three execution models inside a bare asyncio loop with a 5 ms lag ticker:
  thread    await asyncio.to_thread(analyze, ...), then build_payload on the loop thread   (what the application does today)
  process   one worker process (spawn), analyze + build_payload run in the worker, only the JSON-safe payload dict returns
  process2  two worker processes, two jobs at once (concurrency test)
For each it records: wall time, event-loop lag (max, ticks over 50/250/1000 ms, ticks received versus expected), parent and worker memory and CPU seconds
(Windows API, no extra dependency), pickled bytes in and out and their pickling time, and process start-up time to first result.
Correctness: the payload from the process path must equal the payload from the thread path byte for byte (canonical JSON hash).
Loopback only, no database, no network, synthetic data.
"""
from __future__ import annotations

import argparse
import asyncio
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import pickle
import sys
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
os.chdir(ROOT)
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("LLM_ENABLED", "false")
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def make_inputs(n: int):
    recs = [{"source_type": "generic_siem", "rule_id": f"R-SP-{i}", "rule_name": f"spike rule {i % 40}", "severity": ["low", "medium", "high"][i % 3],
             "timestamp": f"2026-11-07T{(i // 60) % 24:02d}:{i % 60:02d}:00Z", "host": f"sp-host-{i % 20}", "user": f"sp-user-{i % 7}",
             "src_ip": f"203.0.113.{i % 50 + 1}", "dest_ip": f"198.51.100.{i % 30 + 1}"} for i in range(n)]
    digests = [hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest() for r in recs]
    keys = [uuid.UUID(int=(0x5EED << 96) + i) for i in range(n)]              # fixed keys: results are comparable across execution models
    return recs, digests, keys


# ── the worker side (runs in the child process) ─────────────────────────────────────────────────────────────────
def _warm() -> int:
    """Pool initializer: import what the job needs once per worker so the first real job does not pay for imports."""
    import app.modules.correlation.workflow  # noqa: F401
    import app.services.multisource_investigation_service  # noqa: F401
    return os.getpid()


def worker_job(records, digests, keys):
    from app.modules.correlation.workflow import analyze
    from app.services.multisource_investigation_service import MultiSourceInvestigationService
    t = time.perf_counter()
    result = analyze(records, None, digests, keys, None)
    payload = MultiSourceInvestigationService().build_payload(result, "spike-fingerprint", False)
    return payload, time.perf_counter() - t, os.getpid()


def canonical(payload) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:16]


# ── process memory and CPU (Windows API) ───────────────────────────────────────────────────────────────────────
class _PMC(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


def proc_stats(pid: int) -> tuple[float, float, float]:
    """(working set MB, peak working set MB, CPU seconds) of a process."""
    k32, psapi = ctypes.WinDLL("kernel32", use_last_error=True), ctypes.WinDLL("psapi", use_last_error=True)
    k32.OpenProcess.restype = wt.HANDLE
    h = k32.OpenProcess(0x0400 | 0x0010, False, pid)
    pmc = _PMC(); pmc.cb = ctypes.sizeof(_PMC)
    psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb)
    c, e, kt, ut = (wt.FILETIME() for _ in range(4))
    k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut))
    k32.CloseHandle(h)
    ft = lambda f: ((f.dwHighDateTime << 32) | f.dwLowDateTime) / 1e7
    return pmc.WorkingSetSize / 1048576, pmc.PeakWorkingSetSize / 1048576, ft(kt) + ft(ut)


class Lag:
    """5 ms ticker on the running loop: how late does the loop wake up while heavy work is going on?"""

    def __init__(self):
        self.max = 0.0; self.o50 = self.o250 = self.o1000 = self.ticks = 0
        self._task = None

    async def _run(self):
        loop = asyncio.get_running_loop()
        while True:
            t0 = loop.time()
            await asyncio.sleep(0.005)
            lag = loop.time() - t0 - 0.005
            self.ticks += 1; self.max = max(self.max, lag)
            self.o50 += lag > 0.05; self.o250 += lag > 0.25; self.o1000 += lag > 1.0

    def start(self):
        self._task = asyncio.get_running_loop().create_task(self._run())

    def stop(self, seconds: float) -> dict:
        self._task.cancel()
        return {"max_lag_ms": round(self.max * 1000), "ticks_over_50ms": self.o50, "ticks_over_250ms": self.o250, "ticks_over_1s": self.o1000,
                "ticks_received": self.ticks, "ticks_expected": int(seconds / 0.005)}


async def timed(label: str, coro_factory, parent_pid: int, worker_pids=None) -> tuple[dict, list]:
    lag = Lag(); lag.start()
    await asyncio.sleep(0.05)
    m0, _, c0 = proc_stats(parent_pid)
    w0 = {p: proc_stats(p)[2] for p in (worker_pids or [])}
    t = time.perf_counter()
    out = await coro_factory()
    wall = time.perf_counter() - t
    m1, peak, c1 = proc_stats(parent_pid)
    wcpu = sum(proc_stats(p)[2] - w0[p] for p in w0)
    wmem = [round(proc_stats(p)[0]) for p in (worker_pids or [])]
    row = {"mode": label, "wall_s": round(wall, 2), "parent_cpu_s": round(c1 - c0, 2), "worker_cpu_s": round(wcpu, 2), "parent_rss_mb": round(m1),
           "parent_peak_mb": round(peak), "worker_rss_mb": wmem, **lag.stop(wall)}
    return row, out


async def main_async(a) -> dict:
    from app.modules.correlation.workflow import analyze
    from app.services.multisource_investigation_service import MultiSourceInvestigationService
    import multiprocessing as mp

    me = os.getpid()
    res: dict = {"python": sys.version.split()[0], "cpus": os.cpu_count(), "rows": [], "equality": [], "pickle": []}
    loop = asyncio.get_running_loop()
    svc = MultiSourceInvestigationService()

    async def thread_job(recs, digests, keys):
        result = await asyncio.to_thread(analyze, recs, None, digests, keys, None)
        return svc.build_payload(result, "spike-fingerprint", False), None, me

    # process start-up cost: create the pool, run the initializer, time to the first (tiny) result
    t = time.perf_counter()
    pool = ProcessPoolExecutor(max_workers=1, mp_context=mp.get_context("spawn"), initializer=_warm)
    pid1 = await loop.run_in_executor(pool, os.getpid)
    res["startup_one_worker_s"] = round(time.perf_counter() - t, 2)
    res["worker_pid"] = pid1
    res["worker_idle_rss_mb"] = round(proc_stats(pid1)[0])
    await asyncio.sleep(0.5)

    for n in [int(x) for x in a.sizes.split(",")]:
        recs, digests, keys = make_inputs(n)
        t = time.perf_counter(); b_in = pickle.dumps((recs, digests, keys)); t_in = time.perf_counter() - t
        for r in range(a.repeats):
            row_t, out_t = await timed("thread", lambda: thread_job(recs, digests, keys), me)
            row_p, out_p = await timed("process", lambda: loop.run_in_executor(pool, worker_job, recs, digests, keys), me, [pid1])
            payload_t, payload_p = out_t[0], out_p[0]
            row_t.update(records=n, repeat=r); row_p.update(records=n, repeat=r, worker_compute_s=round(out_p[1], 2))
            res["rows"] += [row_t, row_p]
            res["equality"].append({"records": n, "repeat": r, "payload_hash_thread": canonical(payload_t), "payload_hash_process": canonical(payload_p),
                                    "identical": canonical(payload_t) == canonical(payload_p)})
            print(f"n={n} r={r} thread wall {row_t['wall_s']} s lag max {row_t['max_lag_ms']} ms ticks {row_t['ticks_received']}/{row_t['ticks_expected']} | "
                  f"process wall {row_p['wall_s']} s lag max {row_p['max_lag_ms']} ms ticks {row_p['ticks_received']}/{row_p['ticks_expected']} "
                  f"identical={res['equality'][-1]['identical']}", flush=True)
        t = time.perf_counter(); b_out = pickle.dumps(payload_p); t_out = time.perf_counter() - t
        t = time.perf_counter(); pickle.loads(b_out); t_un = time.perf_counter() - t
        res["pickle"].append({"records": n, "input_bytes": len(b_in), "input_pickle_ms": round(t_in * 1000, 1), "output_bytes": len(b_out),
                              "output_pickle_ms": round(t_out * 1000, 1), "output_unpickle_ms": round(t_un * 1000, 1)})

    # two jobs at once: thread mode versus two worker processes
    recs, digests, keys = make_inputs(500)
    row_t, _ = await timed("thread x2", lambda: asyncio.gather(thread_job(recs, digests, keys), thread_job(recs, digests, keys)), me)
    pool2 = ProcessPoolExecutor(max_workers=2, mp_context=mp.get_context("spawn"), initializer=_warm)
    pids = await asyncio.gather(loop.run_in_executor(pool2, os.getpid), loop.run_in_executor(pool2, os.getpid))
    await asyncio.sleep(0.3)
    wp = list(getattr(pool2, "_processes", {}).keys()) or list(set(pids))
    row_p, _ = await timed("process x2", lambda: asyncio.gather(loop.run_in_executor(pool2, worker_job, recs, digests, keys),
                                                                 loop.run_in_executor(pool2, worker_job, recs, digests, keys)), me, wp)
    row_t.update(records=500, repeat=0); row_p.update(records=500, repeat=0)
    res["rows"] += [row_t, row_p]
    print(f"2 x 500: thread wall {row_t['wall_s']} s lag max {row_t['max_lag_ms']} ms | process wall {row_p['wall_s']} s lag max {row_p['max_lag_ms']} ms", flush=True)
    pool.shutdown(); pool2.shutdown()
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True); ap.add_argument("--sizes", default="500,1000,2000"); ap.add_argument("--repeats", type=int, default=3)
    a = ap.parse_args()
    if not a.out.upper().startswith("D:"):
        print("--out must be on drive D:", file=sys.stderr); return 2
    res = asyncio.run(main_async(a))
    Path(a.out).write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k not in ("rows", "equality")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
