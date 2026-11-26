"""
The worker-process option through the real service and API path (``MultiSourceInvestigationService.start``), SQLite harness, offline.

The stored result, the status codes, review and export, and the evidence-changed protection must be the same whether the deterministic
analysis runs in the server process (``ANALYSIS_WORKER_PROCESSES`` = 0) or in a worker process (1). ``use_llm`` always stays in the server
process. One worker is started for the module (about 2 to 3 s) and shut down at the end.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

import app.services.multisource_investigation_service as svc
from app.modules.correlation.demo_data import intrusion_chain
from app.services import analysis_executor as ex
from tests.unit.test_multisource_api import (  # noqa: F401  (fixtures and helpers)
    START,
    Keep,
    ScriptedProvider,
    anyio_backend,
    app_instance,
    audit_rows,
    auth_settings,
    bearer,
    ingest,
    link_all_events,
    seed_analyst_with_token,
    setup,
)

EXPORT = "/api/v1/cases/{cid}/investigations/multisource/export"
REVIEW = "/api/v1/cases/{cid}/investigations/multisource/review"


def _workers(monkeypatch, n: int) -> None:
    monkeypatch.setattr(ex, "get_settings", lambda: SimpleNamespace(ANALYSIS_WORKER_PROCESSES=n))


@pytest.fixture(scope="module")
def pool():
    """Warm one worker for the module (the setting is only switched on inside each test) and always shut it down."""
    patch = pytest.MonkeyPatch()
    patch.setattr(ex, "get_settings", lambda: SimpleNamespace(ANALYSIS_WORKER_PROCESSES=1))
    asyncio.run(ex.start_pool())
    try:
        yield
    finally:
        asyncio.run(ex.shutdown_pool())
        patch.undo()


def _spy_run_deterministic(monkeypatch) -> list[int]:
    calls: list[int] = []
    real = ex.run_deterministic

    async def spy(*a, **k):
        calls.append(1)
        return await real(*a, **k)

    monkeypatch.setattr(ex, "run_deterministic", spy)
    return calls


def _without_time(payload: dict) -> dict:
    return {k: v for k, v in payload.items() if k != "created_at"}


# ── (b) the same case with the setting 0 and 1 ───────────────────────────────
@pytest.mark.anyio
async def test_stored_result_status_review_and_export_are_the_same_with_workers_on_and_off(pool, db_session, app_instance, monkeypatch):
    calls = _spy_run_deterministic(monkeypatch)
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="wk")
    async with Keep(client):
        _workers(monkeypatch, 0)
        off = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert off.status_code == 201 and calls == []                                    # setting 0: the executor is never used

        _workers(monkeypatch, 1)
        on = await client.post(START.format(cid=case.id), json={"force": True}, headers=bearer(token))
        assert on.status_code == 201 and calls == [1]                                    # setting 1: the worker path was taken
        reused = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert reused.status_code == 200 and reused.json()["reused"] is True and calls == [1]   # an idempotent repeat never reaches the executor

        assert _without_time(on.json()) == _without_time(off.json())
        assert on.json()["started_by"] == lead.username and on.json()["use_llm"] is False
        rows = sorted(await audit_rows(db_session, case.id), key=lambda r: r.created_at)
        assert len(rows) == 2 and rows[0].id != rows[1].id
        assert _without_time(rows[1].details) == _without_time(rows[0].details)           # the stored documents are equal
        assert rows[1].context_sha256 == rows[0].context_sha256

        # review and export behave as for any stored result: refused until approved, then released
        fp = on.json()["evidence_fingerprint"]
        assert (await client.get(EXPORT.format(cid=case.id), headers=bearer(token))).status_code == 409
        review = await client.post(REVIEW.format(cid=case.id), json={"decision": "approved", "evidence_fingerprint": fp}, headers=bearer(token))
        assert review.status_code == 200 and review.json()["state"] == "approved"
        export = await client.get(EXPORT.format(cid=case.id), headers=bearer(token))
        assert export.status_code == 200
        assert on.json()["incidents"][0]["report_markdown"] in export.json()["markdown"]
        for section in ("status", "report", "timeline", "sufficiency"):
            assert (await client.get(START.format(cid=case.id) + "/" + section, headers=bearer(token))).status_code == 200


@pytest.mark.anyio
async def test_evidence_changing_while_a_worker_runs_still_discards_the_result(pool, db_session, app_instance, monkeypatch):
    _workers(monkeypatch, 1)
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain()[:5], prefix="wkrace")
    real = ex.run_deterministic

    async def racing(*a, **k):
        payload = await real(*a, **k)
        await ingest(client, intrusion_chain()[5:7])
        await link_all_events(db_session, case, lead)                                    # evidence added while the analysis ran
        return payload

    monkeypatch.setattr(ex, "run_deterministic", racing)
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert r.status_code == 409 and "changed" in r.json()["detail"] and len(await audit_rows(db_session, case.id)) == 0


@pytest.mark.anyio
async def test_a_failing_analysis_surfaces_exactly_as_it_does_in_process(pool, db_session, app_instance, monkeypatch):
    """An unexpected exception is not a MultiSourceError: in both modes it propagates out of ``start`` as the same exception type."""
    client, token, lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="wkfail")
    async def bad_inputs(self, session, case_id):
        return None, [], [], []                                                                                  # records None: makes analyze raise TypeError (data-driven, so also in the worker)

    monkeypatch.setattr(svc.MultiSourceInvestigationService, "_load_inputs", bad_inputs)
    async with Keep(client):
        for n in (0, 1):
            _workers(monkeypatch, n)
            with pytest.raises(TypeError):
                await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert len(await audit_rows(db_session, case.id)) == 0


# ── (c) use_llm stays in the server process ──────────────────────────────────
@pytest.mark.anyio
async def test_model_assisted_investigation_never_uses_the_worker(db_session, app_instance, monkeypatch):
    _workers(monkeypatch, 1)
    calls = _spy_run_deterministic(monkeypatch)
    provider = ScriptedProvider()
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix="wkllm")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
        assert r.status_code == 201 and r.json()["use_llm"] is True
        assert provider.calls >= 1 and calls == []                                       # the model ran in the server process; no worker job


# ── (f) setting 0 ────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_setting_zero_never_touches_the_executor_or_creates_a_pool(db_session, app_instance, monkeypatch):
    _workers(monkeypatch, 0)
    monkeypatch.setattr(ex, "_pool", None)
    calls = _spy_run_deterministic(monkeypatch)
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="wkzero")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert r.status_code == 201 and r.json()["counts"]["incidents"] == 1
    assert calls == [] and ex._pool is None
