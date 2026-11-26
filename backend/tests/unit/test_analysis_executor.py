"""
Optional worker-process pool for the deterministic investigation (``app.services.analysis_executor``).

Offline, no network, no database. The process-spawning tests share ONE pool (module-scoped fixture, one worker) and each worker start-up is
about 2 to 3 s, so only a few tests spawn. The pool is shut down at the end of the module.

What is proved: the payload from a worker process equals, byte for byte (canonical JSON hash), the payload the in-process path produces with the
same inputs; the parent never runs ``analyze`` for a job that went to a worker; a worker crash, a worker exception and a pool that cannot
start never lose or distort an investigation; shutdown is idempotent; concurrency is bounded.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from types import SimpleNamespace
from typing import Any

import pytest
from loguru import logger

from app.core.config import Settings
from app.modules.correlation import workflow
from app.services import analysis_executor as ex
from app.services.multisource_investigation_service import MultiSourceInvestigationService
from tests.unit.test_analysis_lookup_reuse_equivalence import _dataset

FP = "f" * 64


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
def pool():
    """One shared single-worker pool for the module: the setting is 1, the pool is warmed once and always shut down."""
    patch = pytest.MonkeyPatch()
    patch.setattr(ex, "get_settings", lambda: SimpleNamespace(ANALYSIS_WORKER_PROCESSES=1))
    asyncio.run(ex.start_pool())
    try:
        yield
    finally:
        asyncio.run(ex.shutdown_pool())
        patch.undo()


def _inputs(name: str) -> tuple[list[Any], Any, Any]:
    ds = _dataset(name)
    return ds["records"], ds.get("digests"), ds.get("event_keys")


def _rejected_only() -> tuple[list[Any], Any, Any]:
    return [{"foo": "bar"}, "not json", 5, None], None, None


def _in_process(records, digests, keys) -> dict[str, Any]:
    """The reference: exactly what the in-process path does (``analyze`` then ``build_payload``)."""
    result = workflow.analyze(records, None, digests, keys, None)
    return MultiSourceInvestigationService().build_payload(result, FP, False)


def _canon(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _capture_warnings() -> tuple[list[str], int]:
    messages: list[str] = []
    return messages, logger.add(lambda m: messages.append(str(m)), level="WARNING", format="{message}")


# ── (a) equivalence, (i) the parent does not run the analysis ────────────────
@pytest.mark.anyio
async def test_worker_payload_equals_the_in_process_payload_and_the_parent_does_not_analyse(pool, monkeypatch):
    cases = {name: _inputs(name) for name in ("keyed_duplicates_bad_digest", "big_incident_260", "mixed", "demo:03_contradictory_evidence")}
    cases["rejected_only"] = _rejected_only()
    expected = {name: _canon(_in_process(*args)) for name, args in cases.items()}   # reference first, with the real analyze

    calls: list[int] = []
    real_analyze = workflow.analyze
    monkeypatch.setattr(workflow, "analyze", lambda *a, **k: (calls.append(1), real_analyze(*a, **k))[1])
    monkeypatch.setattr(ex, "_compute", lambda *a, **k: calls.append(1))             # the in-process fallback must not be taken either

    payloads = {}
    for name, (records, digests, keys) in cases.items():
        payloads[name] = await ex.run_deterministic(records, digests, keys, FP)
        assert _canon(payloads[name]) == expected[name], f"{name}: worker payload differs from the in-process payload"
    assert calls == []                                                               # every analysis ran in the worker

    assert payloads["rejected_only"]["counts"]["records_rejected"] == 4 and payloads["rejected_only"]["counts"]["incidents"] == 0
    assert payloads["big_incident_260"]["counts"]["incidents"] >= 1


# ── (e) an exception inside the worker ───────────────────────────────────────
@pytest.mark.anyio
async def test_exception_in_the_worker_has_the_same_type_and_does_not_break_the_pool(pool):
    with pytest.raises(TypeError):
        _in_process(None, None, None)                                               # what the in-process path does with this input
    with pytest.raises(TypeError) as err:
        await ex.run_deterministic(None, None, None, FP)                            # type: ignore[arg-type]
    assert "Traceback" not in str(err.value) and "\\" not in str(err.value)         # a short message, no paths

    first_pool = ex._pool
    records, digests, keys = _inputs("mixed")
    assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == _canon(_in_process(records, digests, keys))
    assert ex._pool is first_pool                                                    # the same pool is still in use: nothing was discarded


def test_error_envelope_is_picklable_and_maps_builtins_to_the_same_type_and_others_to_a_generic_error():
    import pickle

    class Custom(Exception):
        def __init__(self, lock, extra):
            super().__init__("never recreated in the parent")
            self.unpicklable = lambda: None

    decode_error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")                 # a builtin whose constructor needs five arguments
    for exc, expected in ((ValueError("bad value"), ValueError), (KeyError("k"), KeyError), (Custom(1, 2), ex.AnalysisWorkerError),
                          (decode_error, ex.AnalysisWorkerError)):
        envelope = ex._envelope(exc)
        assert pickle.loads(pickle.dumps(envelope)) == envelope and envelope[0] == "err"
        with pytest.raises(Exception) as raised:
            ex._raise_from_envelope(envelope)
        assert type(raised.value) is expected
    assert len(ex._envelope(ValueError("x" * 5000))[2]) <= 200


# ── (h) bounded concurrency ──────────────────────────────────────────────────
@pytest.mark.anyio
async def test_two_simultaneous_calls_with_one_worker_both_succeed(pool):
    records, digests, keys = _inputs("mixed")
    expected = _canon(_in_process(records, digests, keys))
    a, b = await asyncio.gather(ex.run_deterministic(records, digests, keys, FP), ex.run_deterministic(records, digests, keys, FP))
    assert _canon(a) == expected and _canon(b) == expected
    assert ex._gate is not None and ex._gate._value == 1                             # one slot, both released


# ── (d) a worker crash ───────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_worker_crash_falls_back_to_the_server_process_and_the_pool_is_rebuilt(pool, monkeypatch):
    records, digests, keys = _inputs("mixed")
    expected = _canon(_in_process(records, digests, keys))
    assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == expected            # make sure a worker exists
    broken = ex._pool
    procs = list(broken._processes.values())
    assert procs
    for p in procs:
        p.terminate()
    for p in procs:
        p.join(10)

    fallback_calls: list[int] = []
    real_compute = ex._compute
    monkeypatch.setattr(ex, "_compute", lambda *a, **k: (fallback_calls.append(1), real_compute(*a, **k))[1])
    messages, sink = _capture_warnings()
    try:
        payload = await ex.run_deterministic(records, digests, keys, FP)
    finally:
        logger.remove(sink)
    assert _canon(payload) == expected                                                            # no investigation is lost
    assert fallback_calls == [1]                                                                  # this request ran in the server process
    assert any("worker pool unavailable" in m for m in messages)
    assert ex._pool is None                                                                       # the broken pool was discarded, not retried

    monkeypatch.setattr(ex, "_compute", real_compute)
    assert _canon(await ex.run_deterministic(records, digests, keys, FP)) == expected             # the next call works on a rebuilt pool
    assert ex._pool is not None and ex._pool is not broken
    assert all(p.is_alive() for p in ex._pool._processes.values())


# ── pool cannot start ────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_pool_that_cannot_start_falls_back_once_and_is_not_kept(monkeypatch):
    monkeypatch.setattr(ex, "get_settings", lambda: SimpleNamespace(ANALYSIS_WORKER_PROCESSES=1))
    monkeypatch.setattr(ex, "_pool", None)

    def refuse():
        raise OSError("cannot start")

    monkeypatch.setattr(ex, "_get_pool", refuse)
    records, digests, keys = _inputs("mixed")
    messages, sink = _capture_warnings()
    try:
        payload = await ex.run_deterministic(records, digests, keys, FP)
    finally:
        logger.remove(sink)
    assert _canon(payload) == _canon(_in_process(records, digests, keys))
    assert sum("worker pool unavailable" in m for m in messages) == 1                            # one warning, no retry loop
    assert ex._pool is None


@pytest.mark.anyio
async def test_prewarm_failure_is_logged_and_never_raised(monkeypatch):
    monkeypatch.setattr(ex, "get_settings", lambda: SimpleNamespace(ANALYSIS_WORKER_PROCESSES=1))
    monkeypatch.setattr(ex, "_pool", None)
    monkeypatch.setattr(ex, "_get_pool", lambda: (_ for _ in ()).throw(OSError("cannot start")))
    messages, sink = _capture_warnings()
    try:
        await ex.start_pool()
    finally:
        logger.remove(sink)
    assert any("could not be pre-warmed" in m for m in messages)


# ── (f) setting 0 and (g) shutdown ───────────────────────────────────────────
@pytest.mark.anyio
async def test_setting_zero_creates_no_pool_and_is_disabled(monkeypatch):
    monkeypatch.setattr(ex, "get_settings", lambda: SimpleNamespace(ANALYSIS_WORKER_PROCESSES=0))
    monkeypatch.setattr(ex, "_pool", None)
    assert ex.enabled() is False
    await ex.start_pool()
    await ex.shutdown_pool()
    assert ex._pool is None


def test_default_setting_is_zero_and_bounded():
    s = Settings(_env_file=None)
    assert s.ANALYSIS_WORKER_PROCESSES == 0
    assert Settings(_env_file=None, ANALYSIS_WORKER_PROCESSES=4).ANALYSIS_WORKER_PROCESSES == 4
    for bad in (-1, 5):
        with pytest.raises(Exception):
            Settings(_env_file=None, ANALYSIS_WORKER_PROCESSES=bad)


@pytest.mark.anyio
async def test_shutdown_is_idempotent_and_leaves_no_worker(monkeypatch):
    monkeypatch.setattr(ex, "get_settings", lambda: SimpleNamespace(ANALYSIS_WORKER_PROCESSES=1))
    monkeypatch.setattr(ex, "_pool", None)
    await ex.start_pool()                                                                         # its own small pool, to be shut down here
    assert ex._pool is not None
    procs = list(ex._pool._processes.values())
    assert procs
    await ex.shutdown_pool()
    await ex.shutdown_pool()
    assert ex._pool is None and not any(p.is_alive() for p in procs)
    assert os.getpid() not in [p.pid for p in procs]
