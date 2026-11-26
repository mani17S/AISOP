"""
Opt-in garbage-collector freeze after start-up (``GC_FREEZE_AT_STARTUP``, ``app.main._freeze_gc_after_startup``).

Offline, no network, no database, no real server. The lifespan is entered directly with its heavy parts replaced by stubs. gc.collect and gc.freeze
are replaced by recorders, so the real collector is never frozen by these tests.

What is proved: the setting defaults to False and is read from the environment as a bool; when true the lifespan runs gc.collect and then gc.freeze
once and logs one info line; when false neither is called; a failure inside the helper never prevents start-up.
"""

from __future__ import annotations

import asyncio
import gc

import pytest
from fastapi import FastAPI
from loguru import logger

from app import main as app_main
from app.core.config import Settings


@pytest.fixture
def calls(monkeypatch):
    recorded: list[str] = []
    monkeypatch.setattr(gc, "collect", lambda *a, **k: recorded.append("collect") or 0)
    monkeypatch.setattr(gc, "freeze", lambda: recorded.append("freeze"))
    return recorded


@pytest.fixture
def logs():
    records: list[tuple[str, str]] = []
    sink_id = logger.add(lambda m: records.append((m.record["level"].name, m.record["message"])), level="INFO")
    try:
        yield records
    finally:
        logger.remove(sink_id)


def _run_lifespan(monkeypatch, *, freeze: bool) -> bool:
    """Enter and leave the real lifespan with its other start-up work stubbed; return True when the body ran."""
    settings = Settings(_env_file=None, GC_FREEZE_AT_STARTUP=freeze)

    async def _noop(*a, **k):
        return None

    async def _forever(*a, **k):
        await asyncio.sleep(3600)

    class _Feeds:
        def load_feeds_from_directory(self, **k):
            return None

    monkeypatch.setattr(app_main, "get_settings", lambda: settings)
    monkeypatch.setattr(app_main, "validate_production_settings", lambda s: None)
    monkeypatch.setattr(app_main, "setup_logging", lambda s: None)
    monkeypatch.setattr(app_main, "LocalFeedManager", _Feeds)
    monkeypatch.setattr(app_main, "LocalThreatIntelEngine", lambda feed_manager: object())
    monkeypatch.setattr(app_main, "KnowledgeRetriever", lambda: object())
    monkeypatch.setattr(app_main, "_security_events_loop", _forever)
    monkeypatch.setattr(app_main, "_flush_security_events_once", _noop)
    monkeypatch.setattr(app_main.analysis_executor, "start_pool", _noop)
    monkeypatch.setattr(app_main.analysis_executor, "shutdown_pool", _noop)

    entered = False

    async def _go() -> None:
        nonlocal entered
        async with app_main.lifespan(FastAPI()):
            entered = True

    asyncio.run(_go())
    return entered


def test_setting_defaults_to_false_and_reads_environment_as_bool(monkeypatch):
    monkeypatch.delenv("GC_FREEZE_AT_STARTUP", raising=False)
    assert Settings(_env_file=None).GC_FREEZE_AT_STARTUP is False
    monkeypatch.setenv("GC_FREEZE_AT_STARTUP", "true")
    assert Settings(_env_file=None).GC_FREEZE_AT_STARTUP is True
    monkeypatch.setenv("GC_FREEZE_AT_STARTUP", "0")
    assert Settings(_env_file=None).GC_FREEZE_AT_STARTUP is False


def test_helper_collects_then_freezes_and_logs_once(calls, logs):
    app_main._freeze_gc_after_startup()
    assert calls == ["collect", "freeze"]
    info = [m for level, m in logs if level == "INFO" and "frozen" in m.lower()]
    assert len(info) == 1


def test_lifespan_with_setting_true_freezes_once(monkeypatch, calls, logs):
    assert _run_lifespan(monkeypatch, freeze=True) is True
    assert calls == ["collect", "freeze"]
    assert len([1 for level, m in logs if level == "INFO" and "Garbage collector frozen" in m]) == 1


def test_lifespan_with_setting_false_never_touches_the_collector(monkeypatch, calls, logs):
    assert _run_lifespan(monkeypatch, freeze=False) is True
    assert calls == []
    assert not [1 for _, m in logs if "Garbage collector" in m]


def test_helper_failure_never_prevents_startup(monkeypatch, logs):
    def boom():
        raise RuntimeError("freeze unavailable")

    monkeypatch.setattr(gc, "freeze", boom)
    assert _run_lifespan(monkeypatch, freeze=True) is True
    assert [1 for level, m in logs if level == "WARNING" and "freeze failed" in m]
