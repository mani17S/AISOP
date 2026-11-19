"""
Stage 7C: the PROPOSED PostgreSQL verification scenarios, executed OFFLINE on SQLite.

The scenario coroutines live in ``tests/integration/test_postgres_stage7b_verification.py`` (marked ``postgres``, never run here). Running the
very same coroutines over SQLite proves that their assertions about stored values, reuse, staleness, isolation and rollback are correct and are
not typos waiting for the first authorized run. PostgreSQL-only parts (real concurrency, octet_length, the append-only trigger) are NOT covered here.
"""

from __future__ import annotations

import pytest

from tests.integration import test_postgres_stage7b_verification as V


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_s1_scenario_offline(db_session):
    stored = await V.scenario_findings_round_trip(db_session, V.new_run())
    assert stored["incidents"][0]["sufficiency"]["rule_version"] == "suff-v4"


@pytest.mark.anyio
async def test_s2_scenario_offline(db_session):
    assert await V.scenario_large_audit_row(db_session, V.new_run()) > 1_000_000


@pytest.mark.anyio
async def test_s4_scenario_offline(db_session, monkeypatch):
    await V.scenario_rollback(db_session, V.new_run(), monkeypatch)


@pytest.mark.anyio
async def test_s5_scenario_offline(db_session):
    await V.scenario_case_isolation(db_session, V.new_run())


@pytest.mark.anyio
async def test_s6_scenario_offline(db_session):
    await V.scenario_sufficiency_persistence_and_stale(db_session, V.new_run())


def test_the_race_test_is_postgres_only_and_uses_a_barrier_not_sleeps():
    import ast
    import inspect
    fn = ast.parse(inspect.getsource(V.test_s3_concurrent_import_of_one_record_yields_one_raw_row))
    fn.body[0].body = fn.body[0].body[1:]                      # drop the docstring: inspect code only
    code = ast.unparse(fn)
    assert "asyncio.Barrier" in code and "sleep" not in code
    assert V.pytestmark.mark.name == "postgres"
