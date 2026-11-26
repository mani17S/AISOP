"""
Hardening of the worker-process option (``app.services.analysis_executor``): a deadline per job, a cool-down after a pool failure, and the
documented cancellation behaviour (docs/05_Backend/Investigation_Responsiveness_Profiling_2026-11-25.md, section 19, findings 2, 3 and 4).

Offline. Only the timeout and the cancellation tests spawn a real one-worker pool (each about 2 to 3 s) and both shut it down. The hung job is a
sleeping stand-in for ``worker_job`` (a top-level function of this module, picklable by reference under spawn): it is deterministic, whereas the
real analysis of a few hundred records can finish faster than the smallest legal deadline (1 s).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from types import SimpleNamespace
from typing import Any

import pytest
from concurrent.futures.process import BrokenProcessPool
from loguru import logger

from app.core.config import Settings
from app.modules.correlation import workflow
from app.services import analysis_executor as ex
from app.services.multisource_investigation_service import MultiSourceInvestigationService
from tests.unit.test_analysis_lookup_reuse_equivalence import _dataset

FP = "f" * 64
_real_worker_job = ex.worker_job   # captured at import, before any test patches it


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _sleep_job(records: Any, digests: Any, keys: Any, fingerprint: str) -> tuple[Any, ...]:
    """Stand-in for ``worker_job`` that runs for ``records`` seconds (runs inside the spawned worker)."""
    time.sleep(records)
    return ("ok", {"slept": records})


def _settings(monkeypatch, *, processes=1, timeout=300, cooldown=30) -> None:
    monkeypatch.setattr(ex, "get_settings", lambda: SimpleNamespace(
        ANALYSIS_WORKER_PROCESSES=processes, ANALYSIS_WORKER_TIMEOUT_SECONDS=timeout, ANALYSIS_WORKER_COOLDOWN_SECONDS=cooldown))


def _clean_state(monkeypatch) -> None:
    monkeypatch.setattr(ex, "_pool", None)
    monkeypatch.setattr(ex, "_unavailable_until", 0.0)


def _inputs(name: str = "mixed") -> tuple[list[Any], Any, Any]:
    ds = _dataset(name)
    return ds["records"], ds.get("digests"), ds.get("event_keys")


def _in_process(records, digests, keys) -> dict[str, Any]:
    result = workflow.analyze(records, None, digests, keys, None)
    return MultiSourceInvestigationService().build_payload(result, FP, False)


def _canon(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _capture_warnings() -> tuple[list[str], int]:
    messages: list[str] = []
    return messages, logger.add(lambda m: messages.append(str(m)), level="WARNING", format="{message}")


class _Clock:
    """A fake ``time`` for the executor module only (the event loop keeps the real clock)."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


class _BrokenPoolStub:
    """Replaces ``ProcessPoolExecutor``: counts constructions; every submit fails as a broken pool does."""
    constructed = 0

    def __init__(self, *a, **k) -> None:
        type(self).constructed += 1
        self._processes: dict = {}

    def submit(self, *a, **k):
        raise BrokenProcessPool("stub")

    def shutdown(self, *a, **k) -> None:
        pass


@pytest.fixture
def stub_pool(monkeypatch):
    _BrokenPoolStub.constructed = 0
    monkeypatch.setattr(ex, "ProcessPoolExecutor", _BrokenPoolStub)
    clock = _Clock()
    monkeypatch.setattr(ex, "time", clock)
    return clock


# ── (1) a hung job is stopped at the deadline ────────────────────────────────
@pytest.mark.anyio
async def test_a_job_that_overruns_the_deadline_is_stopped_the_pool_discarded_and_the_next_request_works(monkeypatch):
    _clean_state(monkeypatch)
    _settings(monkeypatch, timeout=1, cooldown=30)
    await ex.start_pool()                                                       # warm: the deadline then measures the job, not the spawn
    try:
        first_pool = ex._pool
        assert first_pool is not None
        procs = list(first_pool._processes.values())
        assert procs and all(p.is_alive() for p in procs)

        monkeypatch.setattr(ex, "worker_job", _sleep_job)                       # looked up at call time; the worker imports it by reference
        messages, sink = _capture_warnings()
        started = time.monotonic()
        try:
            with pytest.raises(ex.AnalysisWorkerError) as err:
                await ex.run_deterministic(60, None, None, FP)                  # type: ignore[arg-type]
        finally:
            logger.remove(sink)
        assert time.monotonic() - started < 15                                  # the job would have run for 60 s
        assert str(err.value) == "analysis timed out"
        assert sum("time limit" in m for m in messages) == 1 and all("slept" not in m for m in messages)

        for p in procs:
            p.join(10)
        assert not any(p.is_alive() for p in procs)                             # the worker process was killed
        assert ex._pool is None                                                 # the pool was discarded
        assert ex._unavailable_until > time.monotonic()                         # and the cool-down started
        assert ex._gate is not None and ex._gate._value == 1                    # the slot is free again

        # inside the cool-down: correct in-process result, no pool is built
        monkeypatch.setattr(ex, "worker_job", _real_worker_job)
        records, digests, keys = _inputs()
        expected = _canon(_in_process(records, digests, keys))
        assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == expected
        assert ex._pool is None

        # after the cool-down: one fresh pool, a correct payload
        monkeypatch.setattr(ex, "_unavailable_until", 0.0)
        _settings(monkeypatch, timeout=60, cooldown=30)                         # a cold pool spawns inside the call; 1 s would be too short
        assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == expected
        assert ex._pool is not None and ex._pool is not first_pool
    finally:
        await ex.shutdown_pool()


# ── (2) the cool-down ────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_cooldown_sends_requests_in_process_without_touching_a_pool_then_rebuilds_once(monkeypatch, stub_pool):
    _clean_state(monkeypatch)
    _settings(monkeypatch, cooldown=30)
    records, digests, keys = _inputs()
    expected = _canon(_in_process(records, digests, keys))

    messages, sink = _capture_warnings()
    try:
        for _ in range(6):
            assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == expected   # always the correct payload
    finally:
        logger.remove(sink)
    assert _BrokenPoolStub.constructed == 1                                     # one attempt, then the cool-down
    assert sum("worker pool unavailable" in m for m in messages) == 1           # logged once, nothing per request
    assert ex._pool is None
    assert ex._unavailable_until == pytest.approx(stub_pool.now + 30)

    stub_pool.now += 29                                                         # still inside
    assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == expected
    assert _BrokenPoolStub.constructed == 1

    stub_pool.now += 2                                                          # expired: exactly one more attempt, and a new cool-down
    for _ in range(4):
        assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == expected
    assert _BrokenPoolStub.constructed == 2


@pytest.mark.anyio
async def test_cooldown_zero_rebuilds_the_pool_on_every_request_as_before(monkeypatch, stub_pool):
    _clean_state(monkeypatch)
    _settings(monkeypatch, cooldown=0)
    records, digests, keys = _inputs()
    expected = _canon(_in_process(records, digests, keys))
    for _ in range(3):
        assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == expected
    assert _BrokenPoolStub.constructed == 3 and ex._unavailable_until == 0.0


@pytest.mark.anyio
async def test_a_spawn_error_also_starts_the_cooldown(monkeypatch, stub_pool):
    _clean_state(monkeypatch)
    _settings(monkeypatch, cooldown=30)
    calls: list[int] = []

    def refuse():
        calls.append(1)
        raise OSError("cannot start")

    monkeypatch.setattr(ex, "_get_pool", refuse)
    records, digests, keys = _inputs()
    expected = _canon(_in_process(records, digests, keys))
    for _ in range(4):
        assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == expected
    assert calls == [1]


# ── (3) a failed pre-warm starts the cool-down ───────────────────────────────
@pytest.mark.anyio
async def test_a_failed_prewarm_starts_the_cooldown(monkeypatch, stub_pool):
    _clean_state(monkeypatch)
    _settings(monkeypatch, cooldown=30)
    await ex.start_pool()                                                       # the stub's submit raises BrokenProcessPool: logged, never raised
    assert _BrokenPoolStub.constructed == 1 and ex._pool is None
    assert ex._unavailable_until == pytest.approx(stub_pool.now + 30)
    records, digests, keys = _inputs()
    assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == _canon(_in_process(records, digests, keys))
    assert _BrokenPoolStub.constructed == 1                                     # the request did not build a pool


# ── (4) settings ─────────────────────────────────────────────────────────────
def test_new_settings_defaults_and_bounds():
    s = Settings(_env_file=None)
    assert s.ANALYSIS_WORKER_TIMEOUT_SECONDS == 300 and s.ANALYSIS_WORKER_COOLDOWN_SECONDS == 30
    for field, good, bad in (("ANALYSIS_WORKER_TIMEOUT_SECONDS", (1, 3600), (0, 3601)),
                             ("ANALYSIS_WORKER_COOLDOWN_SECONDS", (0, 3600), (-1, 3601))):
        for value in good:
            assert getattr(Settings(_env_file=None, **{field: value}), field) == value
        for value in bad:
            with pytest.raises(Exception):
                Settings(_env_file=None, **{field: value})


# ── (5) setting 0 is untouched ───────────────────────────────────────────────
@pytest.mark.anyio
async def test_setting_zero_builds_no_pool_and_starts_no_timer(monkeypatch, stub_pool):
    _clean_state(monkeypatch)
    _settings(monkeypatch, processes=0)
    assert ex.enabled() is False
    await ex.start_pool()
    await ex.shutdown_pool()
    assert _BrokenPoolStub.constructed == 0 and ex._pool is None and ex._unavailable_until == 0.0


# ── (6) cancellation ─────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_cancelling_a_request_releases_the_slot_and_the_next_call_succeeds(monkeypatch):
    _clean_state(monkeypatch)
    _settings(monkeypatch, timeout=60, cooldown=30)
    await ex.start_pool()
    try:
        monkeypatch.setattr(ex, "worker_job", _sleep_job)
        task = asyncio.ensure_future(ex.run_deterministic(2, None, None, FP))   # type: ignore[arg-type]
        await asyncio.sleep(0.5)                                                # the job is running in the worker
        assert ex._gate is not None and ex._gate._value == 0
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert ex._gate._value == 1                                             # the slot was released; the worker still runs the orphan job
        assert ex._pool is not None and ex._unavailable_until == 0.0            # a cancellation is not a pool failure

        monkeypatch.setattr(ex, "worker_job", _real_worker_job)
        records, digests, keys = _inputs()
        # with one worker the retry queues behind the orphan job (at most about 1.5 s more), then succeeds
        assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == _canon(_in_process(records, digests, keys))
        assert ex._gate._value == 1
    finally:
        await ex.shutdown_pool()
