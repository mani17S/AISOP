r"""
Instrumented launcher for measuring where a large multi-source investigation spends its time. Measurement only: never used to serve real users.

    set AISOP_PROFILE_OUT=D:\some\folder   (required, must be on D:)  then the usual backend environment (DATABASE_URL, AISOP_PORT, ...)
    .venv\Scripts\python.exe backend\scripts\profile_investigation_server.py

It imports the unmodified application, wraps a few functions with timers (no application file is changed) and appends one JSON line per event to
<AISOP_PROFILE_OUT>\phases.jsonl:
  phase       wall time of: row loading, input building, fingerprint, analyze (also cProfile -> analyze_<n>.txt/.prof), build_payload, commit,
              FastAPI response serialization, JSON rendering (with byte size)
  lag         event-loop lag (a 5 ms ticker measuring how late it wakes); a summary line every second
  sql         SQL statements that took 20 ms or more as seen from the application (this includes time spent waiting for the event loop, so compare
              with the database-side view that bench_investigation.py samples), and a per-second statement count
The timers add small overhead; compare instrumented runs only with other instrumented runs.
"""
from __future__ import annotations

import asyncio
import cProfile
import io
import json
import os
import pstats
import sys
import threading
import time
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
ROOT = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))
os.chdir(ROOT)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

OUT = Path(os.environ.get("AISOP_PROFILE_OUT", ""))
if not str(OUT).upper().startswith("D:"):
    raise SystemExit("AISOP_PROFILE_OUT must be set to a folder on drive D:")
OUT.mkdir(parents=True, exist_ok=True)
_LOCK = threading.Lock()
_FH = open(OUT / "phases.jsonl", "a", buffering=1, encoding="utf-8")


def emit(kind: str, **kw) -> None:
    kw.update(kind=kind, t=round(time.time(), 4), thread=threading.current_thread().name)
    with _LOCK:
        _FH.write(json.dumps(kw, default=str) + "\n")


def timed(name):
    def deco(fn):
        def wrapper(*a, **k):
            t = time.perf_counter()
            try:
                return fn(*a, **k)
            finally:
                emit("phase", name=name, ms=round((time.perf_counter() - t) * 1000, 1))
        return wrapper
    return deco


def atimed(name):
    def deco(fn):
        async def wrapper(*a, **k):
            t = time.perf_counter()
            try:
                return await fn(*a, **k)
            finally:
                emit("phase", name=name, ms=round((time.perf_counter() - t) * 1000, 1))
        return wrapper
    return deco


def install_wrappers() -> None:
    import app.modules.correlation.workflow as W
    import app.services.multisource_investigation_service as M
    from fastapi import routing as fastapi_routing
    from sqlalchemy.ext.asyncio import AsyncSession
    from starlette.responses import JSONResponse

    cls = M.MultiSourceInvestigationService
    cls._load_rows = atimed("load_rows")(cls._load_rows)
    cls._inputs = staticmethod(timed("inputs")(cls.__dict__["_inputs"].__func__))
    cls.fingerprint = staticmethod(timed("fingerprint")(cls.__dict__["fingerprint"].__func__))
    cls.build_payload = timed("build_payload")(cls.build_payload)
    AsyncSession.commit = atimed("commit")(AsyncSession.commit)
    fastapi_routing.serialize_response = atimed("serialize_response")(fastapi_routing.serialize_response)

    orig_render = JSONResponse.render

    def render(self, content):
        t = time.perf_counter()
        body = orig_render(self, content)
        emit("phase", name="json_render", ms=round((time.perf_counter() - t) * 1000, 1), bytes=len(body))
        return body
    JSONResponse.render = render

    orig_analyze = W.analyze

    def analyze(records, *a, **k):
        n = len(records)
        t = time.perf_counter()
        # cProfile roughly doubles the analysis time (and in Python 3.12 profiles every thread), so it is opt-in: AISOP_PROFILE_CPROFILE=1.
        # Use profiled runs only to attribute CPU time, never to compare timings.
        prof = cProfile.Profile() if (n >= 200 and os.environ.get("AISOP_PROFILE_CPROFILE") == "1") else None
        if prof:
            prof.enable()
        try:
            return orig_analyze(records, *a, **k)
        finally:
            if prof:
                prof.disable()
                prof.dump_stats(str(OUT / f"analyze_{n}.prof"))
                s = io.StringIO()
                pstats.Stats(prof, stream=s).sort_stats("cumulative").print_stats(40)
                (OUT / f"analyze_{n}.txt").write_text(s.getvalue(), encoding="utf-8")
            emit("phase", name="analyze", ms=round((time.perf_counter() - t) * 1000, 1), records=n)
    W.analyze = analyze


def install_sql_events() -> None:
    from sqlalchemy import event
    from app.db.session import get_engine

    eng = get_engine().sync_engine
    counter = {"n": 0}

    @event.listens_for(eng, "before_cursor_execute")
    def _before(conn, cursor, statement, parameters, context, executemany):
        context._t0 = time.perf_counter()

    @event.listens_for(eng, "after_cursor_execute")
    def _after(conn, cursor, statement, parameters, context, executemany):
        counter["n"] += 1
        ms = (time.perf_counter() - getattr(context, "_t0", time.perf_counter())) * 1000
        if ms >= 20:
            emit("sql", ms=round(ms, 1), stmt=" ".join(statement.split())[:90])

    async def counter_task():
        last = 0
        while True:
            await asyncio.sleep(1.0)
            if counter["n"] != last:
                emit("sql_count", per_s=counter["n"] - last)
                last = counter["n"]
    return counter_task


async def lag_monitor() -> None:
    loop = asyncio.get_running_loop()
    win_start, mx, over50, over250, over1000, ticks = loop.time(), 0.0, 0, 0, 0, 0
    while True:
        t0 = loop.time()
        await asyncio.sleep(0.005)
        lag = loop.time() - t0 - 0.005
        ticks += 1
        mx = max(mx, lag)
        over50 += lag > 0.05
        over250 += lag > 0.25
        over1000 += lag > 1.0
        if loop.time() - win_start >= 1.0:
            if mx > 0.02:
                emit("lag", max_ms=round(mx * 1000), over50=over50, over250=over250, over1000=over1000, ticks=ticks)
            win_start, mx, over50, over250, over1000, ticks = loop.time(), 0.0, 0, 0, 0, 0


def install_gc_timer() -> None:
    """Logs garbage-collection pauses (every full collection, and any pause of 20 ms or more)."""
    import gc

    state: dict = {}

    def cb(phase, info):
        if phase == "start":
            state["t"] = time.perf_counter()
        else:
            ms = (time.perf_counter() - state.get("t", time.perf_counter())) * 1000
            if info.get("generation") == 2 or ms >= 20:
                emit("gc", gen=info.get("generation"), ms=round(ms, 1), collected=info.get("collected"))
    gc.callbacks.append(cb)


def main() -> None:
    import uvicorn
    from app.main import app

    interval = os.environ.get("AISOP_SWITCH_INTERVAL")          # experiment: Python's thread switch interval (default 0.005 s)
    if interval:
        sys.setswitchinterval(float(interval))
    emit("config", switch_interval=sys.getswitchinterval())
    install_gc_timer()
    install_wrappers()
    counter_task = install_sql_events()

    started = {"v": False}

    async def asgi(scope, receive, send):
        """Pass-through ASGI wrapper: starts the lag and SQL-count monitors on the server's own event loop at the first event."""
        if not started["v"]:
            started["v"] = True
            loop = asyncio.get_running_loop()
            loop.create_task(lag_monitor())
            loop.create_task(counter_task())
        await app(scope, receive, send)

    emit("start", pid=os.getpid())
    uvicorn.run(asgi, host=os.environ.get("AISOP_HOST", "127.0.0.1"), port=int(os.environ.get("AISOP_PORT", "8000")), loop="none")


if __name__ == "__main__":
    main()
