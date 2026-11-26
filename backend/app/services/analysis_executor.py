"""
Optional process pool for the deterministic multi-source investigation (docs/05_Backend/Investigation_Responsiveness_Profiling_2026-11-25.md,
sections 10 and 11).

The analysis is CPU-bound pure Python. Run in a thread of the server process it competes with the event loop for the GIL, so health checks
and other requests stall for the duration. With ``ANALYSIS_WORKER_PROCESSES`` above 0 the SAME functions (``analyze`` then
``MultiSourceInvestigationService.build_payload``) run in a bounded pool of spawned worker processes and only the JSON-safe payload dict
returns. With 0 (the default) nothing here is used and behaviour is exactly as before.

Invariants: only the deterministic path (no model call) comes here; ``analyze`` already contains the single evidence-sufficiency gate and
the worker never receives a provider, so no model is ever invoked from a worker. The result is the same function output, byte for byte.
If the pool cannot start or breaks (a worker crash), the request that hit it is run in the server process (a thread) so no investigation
is lost, the pool is discarded and rebuilt after a short cool-down (``ANALYSIS_WORKER_COOLDOWN_SECONDS``). No retry loop: one attempt per request.

Deadline: one job may run at most ``ANALYSIS_WORKER_TIMEOUT_SECONDS``. On expiry the worker processes of the pool are killed (a running job
cannot be cancelled), the pool is discarded, the cool-down starts and ``AnalysisWorkerError`` is raised. A timeout is NOT retried in a thread:
a hung analysis would hang that thread forever and a thread cannot be stopped. During the cool-down (after a timeout, a broken pool, a spawn
failure or a failed pre-warm) every request goes straight to the in-process path without touching a pool; when it ends, the next request
builds one fresh pool. A cool-down of 0 disables this (every request after a failure rebuilds the pool).

Cancellation: when the awaiting request is cancelled (a client disconnect) the semaphore slot is released at once but the worker keeps
running the job; its result is discarded and no audit row is written. With a pool of one worker a retry therefore queues behind that orphan
job (its wait counts against the retry's deadline). Queued work is not bounded by the semaphore. The same cancellation point exists on the
thread path (``asyncio.to_thread``): a cancelled request leaves its thread running to the end.

Windows uses spawn: a worker re-imports the launcher module as ``__mp_main__``, so every entry point must guard its server start with
``if __name__ == "__main__":`` (``backend/run_local.py`` does). Importing the application modules makes no database connection (the engine
is created lazily).
"""

from __future__ import annotations

import asyncio
import builtins
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from typing import Any, Optional

from loguru import logger

from app.core.config import get_settings

svc_logger = logger.bind(component="analysis_executor")

_MAX_MESSAGE_CHARS = 200
_DEFAULT_TIMEOUT_SECONDS = 300      # both fallbacks apply only if the settings object has no such field (a stub); the real Settings always has them
_DEFAULT_COOLDOWN_SECONDS = 0       # 0 = no cool-down = behaviour from before the cool-down existed (the real setting defaults to 30)


class AnalysisWorkerError(Exception):
    """An exception raised inside a worker whose type is not a plain builtin (it cannot be recreated safely in the parent)."""


# ── the worker side (runs in the child process) ─────────────────────────────────────────────────────────────────
def _warm() -> None:
    """Pool initializer: import what the job needs once per worker so the first real job does not pay for imports."""
    import app.modules.correlation.workflow  # noqa: F401
    import app.services.multisource_investigation_service  # noqa: F401


def _noop() -> bool:
    return True


def _compute(records: list[Any], digests: list[Any], keys: list[Any], fingerprint: str) -> dict[str, Any]:
    """Exactly what the in-process path does for a deterministic run: ``analyze`` then ``build_payload`` (no assets, no indicators, no model)."""
    from app.modules.correlation.workflow import analyze
    from app.services.multisource_investigation_service import MultiSourceInvestigationService

    result = analyze(records, None, digests, keys, None)
    return MultiSourceInvestigationService().build_payload(result, fingerprint, False)


def _envelope(exc: BaseException) -> tuple[str, str, str]:
    """A small picklable description of a failure: class name and a short message, never a traceback (it would carry file paths)."""
    return ("err", type(exc).__name__, str(exc)[:_MAX_MESSAGE_CHARS])


def worker_job(records: list[Any], digests: list[Any], keys: list[Any], fingerprint: str) -> tuple[Any, ...]:
    """Top-level (picklable under spawn). Returns ``("ok", payload)`` or an error envelope; an exception never crosses the pool boundary."""
    try:
        return ("ok", _compute(records, digests, keys, fingerprint))
    except Exception as exc:  # noqa: BLE001 - converted to an envelope so an unpicklable exception cannot break the pool
        return _envelope(exc)


def _raise_from_envelope(envelope: tuple[Any, ...]) -> None:
    """Re-raise a worker failure in the parent: the same type when it is a plain builtin exception, otherwise ``AnalysisWorkerError``."""
    _tag, name, message = envelope
    cls = getattr(builtins, name, None)
    error: Exception = AnalysisWorkerError(f"{name}: {message}")
    if isinstance(cls, type) and issubclass(cls, Exception):
        try:
            error = cls(message)
        except TypeError:  # a builtin whose constructor needs other arguments
            pass
    raise error


# ── the parent side ─────────────────────────────────────────────────────────────────────────────────────────────
_pool: Optional[ProcessPoolExecutor] = None
_pool_size = 0
_gate: Optional[asyncio.Semaphore] = None
_gate_key: Optional[tuple[asyncio.AbstractEventLoop, int]] = None   # (loop, size) the semaphore was made for
_unavailable_until = 0.0   # time.monotonic() until which the pool is not used (cool-down after a failure); 0 = no cool-down


def _setting(name: str, default: int) -> int:
    return int(getattr(get_settings(), name, default))


def _start_cooldown() -> None:
    """After a pool failure, route requests to the in-process path for ``ANALYSIS_WORKER_COOLDOWN_SECONDS``. 0 = today's behaviour (no cool-down)."""
    global _unavailable_until
    cooldown = _setting("ANALYSIS_WORKER_COOLDOWN_SECONDS", _DEFAULT_COOLDOWN_SECONDS)
    if cooldown > 0:
        _unavailable_until = time.monotonic() + cooldown


def _kill_workers(pool: ProcessPoolExecutor) -> None:
    """Stop the worker processes of a pool whose job overran. ``_processes`` is a private CPython attribute of ``ProcessPoolExecutor`` (no public
    API can stop a running job), so it is read defensively: if it is missing, nothing is killed and the pool is still discarded."""
    try:
        for process in list((getattr(pool, "_processes", None) or {}).values()):
            try:
                process.kill()
            except Exception:  # noqa: BLE001 - already gone
                pass
    except Exception:  # noqa: BLE001 - the attribute changed shape in another Python version
        pass


def enabled() -> bool:
    """Read at call time. 0 = today's behaviour (thread inside ``run_workflow``)."""
    return get_settings().ANALYSIS_WORKER_PROCESSES > 0


def _get_pool() -> ProcessPoolExecutor:
    """Create the pool on first use. No ``await`` between the check and the assignment, so no lock is needed on one event loop."""
    global _pool, _pool_size
    if _pool is None:
        _pool_size = get_settings().ANALYSIS_WORKER_PROCESSES
        _pool = ProcessPoolExecutor(max_workers=_pool_size, mp_context=multiprocessing.get_context("spawn"), initializer=_warm)
    return _pool


def _get_gate() -> asyncio.Semaphore:
    """Bounds concurrency to the pool size: extra investigations wait here, in the parent. Rebuilt if the running loop or the size changed."""
    global _gate, _gate_key
    key = (asyncio.get_running_loop(), get_settings().ANALYSIS_WORKER_PROCESSES)
    if _gate is None or _gate_key != key:
        _gate, _gate_key = asyncio.Semaphore(key[1]), key
    return _gate


def _discard(pool: ProcessPoolExecutor) -> None:
    """Forget a broken pool (only if it is still the current one) so the next request builds a fresh one. Never blocks."""
    global _pool
    if _pool is pool:
        _pool = None
    try:
        pool.shutdown(wait=False, cancel_futures=True)
    except Exception:  # noqa: BLE001 - a broken pool may refuse; it is already unusable
        pass


async def run_deterministic(records: list[Any], digests: list[Any], keys: list[Any], fingerprint: str) -> dict[str, Any]:
    """Run the deterministic investigation in a worker process and return the JSON-safe payload (same value as the in-process path)."""
    loop = asyncio.get_running_loop()
    async with _get_gate():
        if time.monotonic() < _unavailable_until:   # cool-down: no pool is created or touched, nothing is logged per request
            return await asyncio.to_thread(_compute, records, digests, keys, fingerprint)
        pool: Optional[ProcessPoolExecutor] = None
        try:
            pool = _get_pool()
            submitted = loop.run_in_executor(pool, worker_job, records, digests, keys, fingerprint)
            try:
                outcome = await asyncio.wait_for(submitted, _setting("ANALYSIS_WORKER_TIMEOUT_SECONDS", _DEFAULT_TIMEOUT_SECONDS))
            except asyncio.TimeoutError:   # only the wait can raise it here; inside this inner try it is not mistaken for an OSError
                _kill_workers(pool)
                _discard(pool)
                _start_cooldown()
                svc_logger.warning("Analysis worker exceeded its time limit; workers stopped, pool discarded")
                raise AnalysisWorkerError("analysis timed out") from None
        except (BrokenProcessPool, OSError) as exc:
            if pool is not None:
                _discard(pool)
            _start_cooldown()
            svc_logger.warning("Analysis worker pool unavailable; running this investigation in the server process",
                               error_type=type(exc).__name__)
            return await asyncio.to_thread(_compute, records, digests, keys, fingerprint)
    if outcome[0] == "ok":
        return outcome[1]
    _raise_from_envelope(outcome)
    raise AssertionError("unreachable")  # pragma: no cover - _raise_from_envelope always raises


async def start_pool() -> None:
    """Pre-warm: create the pool and run a no-op so the first real request does not pay the 2 to 3 s start-up. Never raises."""
    if not enabled():
        return
    pool: Optional[ProcessPoolExecutor] = None
    try:
        pool = _get_pool()
        await asyncio.get_running_loop().run_in_executor(pool, _noop)
        svc_logger.info("Analysis worker pool ready", workers=_pool_size)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - the server must start without the pool; the first request retries or falls back
        if pool is not None:
            _discard(pool)
        _start_cooldown()
        svc_logger.warning("Analysis worker pool could not be pre-warmed", error_type=type(exc).__name__)


async def shutdown_pool() -> None:
    """Idempotent. Waits for running jobs, cancels queued ones, and does not block the event loop."""
    global _pool
    while _pool is not None:   # loop: a request that built a new pool while this shutdown was waiting must not leave it running
        pool, _pool = _pool, None
        await asyncio.to_thread(pool.shutdown, wait=True, cancel_futures=True)


__all__ = ["AnalysisWorkerError", "enabled", "run_deterministic", "shutdown_pool", "start_pool", "worker_job"]
