"""
Controlled multi-alert RELIABILITY MATRIX (R01-R12), tests only, real application/API path.

This is NOT a reconstruction of the historical panel failure (its input, endpoint, ordering, concurrency and traceback were never recovered). It is a
labelled diagnostic matrix: alerts go through ``POST /api/v1/alerts/ingest`` and investigations through
``POST /api/v1/cases/{id}/investigations/multisource`` using the repository's SQLite test fixtures, scripted providers and injected failures.

Harness limitation that applies to every concurrency case (stated, not hidden): the SQLite fixtures give all requests ONE synchronous session whose
async methods never suspend, so handlers interleave only at genuine awaits (for example a provider ``asyncio.sleep``). R03 therefore shows
request-level interleaving through the application and shared-state safety, NOT true multi-connection database concurrency; that belongs to the
PostgreSQL-marked tests, which are not run here.

No production code is changed or monkeypatched except to INJECT a failure at a seam. No PostgreSQL, no live Ollama, no external network.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select

from app.api.v1.endpoints.cases import get_case_llm_provider
from app.models.case import CaseAuditEventModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.ai.llm.exceptions import LLMConnectionError, LLMTimeoutError
from app.modules.ai.providers.ollama.provider import OllamaProvider
from app.modules.correlation.demo_data import SCENARIOS, intrusion_chain
from app.schemas.ai import LLMResponse, TokenUsage
from tests.unit.test_case_synthesis_api import app_instance, auth_settings  # noqa: F401  (fixtures)
from tests.unit.test_local_first_controls import Garbage, REQ, _provider, fast_sleep  # noqa: F401
from tests.unit.test_multisource_api import MACHINE, START, Keep, ScriptedProvider, audit_rows, bearer, link_all_events, setup

INGEST = "/api/v1/alerts/ingest"
SAMPLE = json.loads((Path(__file__).resolve().parents[3] / "datasets" / "samples" / "alerts" / "generic_siem_correlation_alert.json").read_text(encoding="utf-8"))
BASE_TIME = datetime(2026, 10, 31, 9, 0, 0, tzinfo=timezone.utc)
OBS: list[dict[str, Any]] = []                                            # observations, optionally written to AISOP_RELIABILITY_REPORT


@pytest.fixture(scope="module", autouse=True)
def _write_observations():
    yield
    target = os.environ.get("AISOP_RELIABILITY_REPORT")
    if target:
        Path(target).write_text(json.dumps(OBS, indent=1, sort_keys=True, default=str), encoding="utf-8")


@pytest.fixture
def anyio_backend():
    return "asyncio"


def mk(i: int, **over: Any) -> dict[str, Any]:
    d = copy.deepcopy(SAMPLE)
    d["rule_id"] = f"rel-rule-{i}"
    d["timestamp"] = (BASE_TIME + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    d["description"] = f"Reliability matrix alert number {i}"
    d.update(over)
    return d


def body(alerts: list[Any], source_type: str = "generic_siem") -> dict[str, Any]:
    return {"source_type": source_type, "source_identifier": "reliability-matrix", "alerts": alerts}


async def row_counts(db) -> tuple[int, int]:
    raw = (await db.execute(select(func.count()).select_from(RawEvidence))).scalar_one()
    ev = (await db.execute(select(func.count()).select_from(NormalizedEventModel))).scalar_one()
    return int(raw), int(ev)


def contract_client(app) -> httpx.AsyncClient:
    """Client that returns the HTTP response an unhandled server error produces (the default test transport re-raises the exception instead)."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test")


def note(case: str, **kw: Any) -> None:
    OBS.append({"case": case, **kw})


def stable(inc: dict[str, Any]) -> dict[str, Any]:
    s = json.loads(json.dumps(inc["sufficiency"]))
    s.get("rationale", {}).get("status", {}).pop("llm_status", None)
    return {"timeline": [{k: v for k, v in t.items() if k != "event_id"} for t in inc["timeline"]], "mitre": inc["mitre"], "sufficiency": s,
            "severity": inc["severity"], "event_count": inc["event_count"]}


# ── R01 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_r01_single_alert_baseline(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, [], prefix="r01")
    async with Keep(client):
        r = await client.post(INGEST, json=body([mk(1)]), headers=MACHINE)
        assert r.status_code == 200, r.text
        b = r.json()
        assert (b["total_received"], b["total_normalized"], b["total_skipped_duplicates"], b["errors"]) == (1, 1, 0, [])
        await link_all_events(db_session, case, lead)
        t0 = time.perf_counter()
        r2 = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        latency = time.perf_counter() - t0
        assert r2.status_code == 201, r2.text
        inc = r2.json()["incidents"][0]
        assert inc["event_count"] == 1 and len(inc["timeline"]) == 1
        stored = {str(e.id): e for e in (await db_session.execute(select(NormalizedEventModel))).scalars().all()}
        raws = {x.id: x for x in (await db_session.execute(select(RawEvidence))).scalars().all()}
        t = inc["timeline"][0]
        assert raws[stored[t["event_id"]].raw_evidence_id].sha256_hash.startswith(t["raw_sha256_prefix"])      # timeline row maps to preserved raw evidence
        assert await row_counts(db_session) == (1, 1)
        note("R01", latency_seconds=round(latency, 4), verdict=inc["sufficiency"]["verdict"])


# ── R02 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_r02_multiple_sequential_alerts_multi_source_without_cross_case_contamination(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, [], prefix="r02a")
    async with Keep(client):
        for rec in intrusion_chain():                                           # four source types, one request per alert
            r = await client.post(INGEST, json={"source_type": "auto", "source_identifier": "seq", "alerts": [rec]}, headers=MACHINE)
            assert r.status_code == 200 and r.json()["total_normalized"] == 1 and r.json()["errors"] == [], r.text
        assert await row_counts(db_session) == (10, 10)
        await link_all_events(db_session, case, lead)
        a = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
        # same shape as the single-batch end-to-end test: ingestion granularity must not change the investigation
        inc_a = a["incidents"][0]
        assert len(inc_a["timeline"]) == 10 and len(a["sources"]) == 4 and inc_a["sufficiency"]["verdict"] == "sufficient"
        assert sorted(m["technique_id"] for m in inc_a["mitre"]) == ["T1027", "T1059.001", "T1071", "T1078", "T1110", "T1564.003"]
        ids_a = {t["event_id"] for t in inc_a["timeline"]}

    client2, token2, lead2, case2 = await setup(db_session, app_instance, [], prefix="r02b")
    async with Keep(client2):
        for i in (11, 12, 13):
            assert (await client2.post(INGEST, json=body([mk(i)]), headers=MACHINE)).json()["total_normalized"] == 1
        assert await link_all_events(db_session, case2, lead2) == 3
        b = (await client2.post(START.format(cid=case2.id), json={}, headers=bearer(token2))).json()
        ids_b = {t["event_id"] for inc in b["incidents"] for t in inc["timeline"]}
        assert len(ids_b) == 3 and ids_a.isdisjoint(ids_b)                      # no cross-investigation contamination
        assert sum(i["event_count"] for i in b["incidents"]) == 3
    note("R02", sequential_requests=13, case_a_events=10, case_b_events=3)


# ── R03 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
@pytest.mark.parametrize("n", [2, 5, 10])
async def test_r03_concurrent_ingest_of_distinct_alerts(db_session, app_instance, n):
    client, _token, _lead, _case = await setup(db_session, app_instance, [], prefix=f"r03i{n}")
    async with Keep(client):
        base = n * 100
        rs = await asyncio.wait_for(asyncio.gather(*[client.post(INGEST, json=body([mk(base + i)]), headers=MACHINE) for i in range(n)]), timeout=60)
    assert [r.status_code for r in rs] == [200] * n
    bodies = [r.json() for r in rs]
    assert sum(b["total_normalized"] for b in bodies) == n and all(b["errors"] == [] for b in bodies)
    ids = [a for b in bodies for a in b["alert_ids"]]
    assert len(ids) == n and len(set(ids)) == n                                    # no duplicate or shared identifiers across requests
    assert len({b["batch_id"] for b in bodies}) == n
    assert await row_counts(db_session) == (n, n)
    note("R03-ingest", concurrency=n, harness="shared synchronous session (cooperative interleaving)")


@pytest.mark.anyio
async def test_r03_concurrent_identical_submissions_are_deduplicated(db_session, app_instance):
    client, _t, _l, _c = await setup(db_session, app_instance, [], prefix="r03d")
    async with Keep(client):
        rs = await asyncio.gather(*[client.post(INGEST, json=body([mk(900)]), headers=MACHINE) for _ in range(5)])
    assert [r.status_code for r in rs] == [200] * 5
    b = [r.json() for r in rs]
    assert sum(x["total_normalized"] for x in b) == 1 and sum(x["total_skipped_duplicates"] for x in b) == 4
    assert await row_counts(db_session) == (1, 1)
    note("R03-duplicates", concurrency=5, normalized=1, skipped=4)


class SlowProvider(ScriptedProvider):
    """Scripted provider that really suspends, forcing request interleaving inside the investigation path."""

    async def generate(self, request):
        await asyncio.sleep(0.02)
        return await super().generate(request)


@pytest.mark.anyio
@pytest.mark.parametrize("n", [2, 5])
async def test_r03_concurrent_investigations_on_separate_cases_do_not_cross_contaminate(db_session, app_instance, n):
    provider = SlowProvider()
    clients = []
    for i in range(n):
        client, token, lead, case = await setup(db_session, app_instance, [], prefix=f"r03v{n}{i}", provider=provider)
        r = await client.post(INGEST, json=body([mk(2000 + n * 10 + i)]), headers=MACHINE)
        assert r.json()["total_normalized"] == 1
        await link_all_events(db_session, case, lead)
        clients.append((client, token, case))
    try:
        rs = await asyncio.wait_for(asyncio.gather(*[c.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(tok)) for c, tok, case in clients]), timeout=60)
    finally:
        for c, _t, _case in clients:
            await c.aclose()
    assert [r.status_code for r in rs] == [201] * n, [r.text[:200] for r in rs if r.status_code != 201]
    seen: set[str] = set()
    for (_c, _t, case), r in zip(clients, rs):
        payload = r.json()
        ids = {t["event_id"] for inc in payload["incidents"] for t in inc["timeline"]}
        assert len(ids) == 1 and seen.isdisjoint(ids)                              # each result contains only its own case's evidence
        seen |= ids
        assert payload["incidents"][0]["llm_status"] == "validated"
        assert len(await audit_rows(db_session, case.id)) == 1                     # exactly one audit record per case
    assert provider.calls == n
    note("R03-investigations", concurrency=n, provider_calls=provider.calls)


# ── R04 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_r04_duplicate_submissions_are_deduplicated_and_never_corroborate(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, [], prefix="r04")
    async with Keep(client):
        first = (await client.post(INGEST, json=body([mk(40)]), headers=MACHINE)).json()
        again = (await client.post(INGEST, json=body([mk(40)]), headers=MACHINE)).json()
        intra = (await client.post(INGEST, json=body([mk(41), mk(41)]), headers=MACHINE)).json()
        assert first["total_normalized"] == 1 and again["total_normalized"] == 0 and again["total_skipped_duplicates"] == 1
        assert again["existing_evidence_ids"] and again["alert_ids"] == []         # points at the existing evidence, creates nothing new
        assert intra["total_normalized"] == 1 and intra["total_skipped_duplicates"] == 1
        assert await row_counts(db_session) == (2, 2)
        await link_all_events(db_session, case, lead)
        inc = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
        assert sum(i["event_count"] for i in inc["incidents"]) == 2                # two distinct alerts, not four
        single = SCENARIOS["06_uncorroborated_single_alert"]["build"]()[0]
    client2, token2, lead2, case2 = await setup(db_session, app_instance, [], prefix="r04b")
    async with Keep(client2):
        for _ in range(3):
            await client2.post(INGEST, json=body([single]), headers=MACHINE)
        await link_all_events(db_session, case2, lead2)
        one = (await client2.post(START.format(cid=case2.id), json={}, headers=bearer(token2))).json()["incidents"][0]
        assert one["event_count"] == 1 and one["sufficiency"]["verdict"] == "limited" and "UNCORROBORATED_QUESTION" in one["sufficiency"]["reason_codes"]
    note("R04", duplicate_requests=3, evidence_rows_created=1)


# ── R05 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
@pytest.mark.parametrize("payload", [
    {"source_type": "generic_siem", "alerts": "not-a-list"},
    {"source_type": "generic_siem", "alerts": ["a string, not an object"]},
    {"source_type": "generic_siem", "alerts": [[1, 2, 3]]},
    {"source_type": "bad type!", "alerts": []},
    {"source_type": "generic_siem", "alerts": None},
])
async def test_r05_malformed_requests_are_rejected_with_422_and_persist_nothing(db_session, app_instance, payload):
    client, _t, _l, _c = await setup(db_session, app_instance, [], prefix="r05a")
    async with Keep(client):
        r = await client.post(INGEST, json=payload, headers=MACHINE)
        assert r.status_code in (200, 422), r.text                                 # never a 5xx
        if r.status_code == 200:
            assert r.json()["total_normalized"] == 0
    assert await row_counts(db_session) == (0, 0)


@pytest.mark.anyio
async def test_r05_invalid_json_body_and_wrong_content_are_controlled(db_session, app_instance):
    client, _t, _l, _c = await setup(db_session, app_instance, [], prefix="r05b")
    async with Keep(client):
        r = await client.post(INGEST, content=b"{not json", headers={**MACHINE, "Content-Type": "application/json"})
        assert r.status_code == 422
        r2 = await client.post(INGEST, content=b"", headers={**MACHINE, "Content-Type": "application/json"})
        assert r2.status_code == 422
    assert await row_counts(db_session) == (0, 0)


@pytest.mark.anyio
@pytest.mark.parametrize("label,alert", [
    ("wrong_type_severity", mk(53, severity=["critical"])),
    ("deeply_nested_content", mk(54, extra={"n": json.loads('{"a":' * 60 + "1" + "}" * 60)})),
])
async def test_r05_wrongly_typed_or_nested_alert_content_is_controlled(db_session, app_instance, label, alert):
    client, _t, _l, _c = await setup(db_session, app_instance, [], prefix="r05c")
    async with Keep(client):
        r = await client.post(INGEST, json=body([alert]), headers=MACHINE)
        assert r.status_code in (200, 422), f"{label}: {r.status_code} {r.text[:200]}"      # controlled, never a 5xx
        if r.status_code == 200:
            b = r.json()
            assert b["total_received"] == 1 and b["total_normalized"] + len(b["errors"]) + b["total_skipped_duplicates"] == 1
            raw, ev = await row_counts(db_session)
            assert ev == b["total_normalized"]                                      # a rejected alert leaves no normalized event
            note("R05", label=label, status=200, normalized=b["total_normalized"], errors=len(b["errors"]), raw_rows=raw)
        else:
            assert await row_counts(db_session) == (0, 0)
            note("R05", label=label, status=422)


def _fabricated_now(ev: NormalizedEventModel, t0: datetime, t1: datetime) -> bool:
    """True when the stored event time equals the ingestion moment, i.e. the pipeline substituted 'now' for a missing or unusable timestamp."""
    ts = ev.event_timestamp
    ts = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)
    return t0 - timedelta(seconds=2) <= ts <= t1 + timedelta(seconds=2)


@pytest.mark.anyio
@pytest.mark.parametrize("label,alert", [
    ("wrong_type_timestamp", mk(50, timestamp=12345)),
    ("invalid_timestamp_string", mk(51, timestamp="not-a-date")),
    ("nested_object_timestamp", mk(52, timestamp={"a": {"b": 1}})),
])
async def test_r05_unusable_timestamp_must_not_be_replaced_by_the_ingestion_time(db_session, app_instance, label, alert):
    """STRICT INVARIANT (project rule: never invent a missing timestamp). Preserved as written; see 02_FAILURE_EVIDENCE.md for the observed failure."""
    client, _t, _l, _c = await setup(db_session, app_instance, [], prefix="r05t")
    async with Keep(client):
        t0 = datetime.now(timezone.utc)
        r = await client.post(INGEST, json=body([alert]), headers=MACHINE)
        t1 = datetime.now(timezone.utc)
        assert r.status_code in (200, 422)
        for ev in (await db_session.execute(select(NormalizedEventModel))).scalars().all():
            assert not _fabricated_now(ev, t0, t1), f"{label}: stored event time equals the ingestion time (invented timestamp): {ev.event_timestamp}"


@pytest.mark.anyio
async def test_r06_content_free_alert_must_not_become_a_normalized_event_with_invented_fields(db_session, app_instance):
    """STRICT INVARIANT (never invent source identity, timestamp or outcome). Preserved as written; see 02_FAILURE_EVIDENCE.md."""
    client, _t, _l, _c = await setup(db_session, app_instance, [], prefix="r06e")
    async with Keep(client):
        r = await client.post(INGEST, json=body([{}]), headers=MACHINE)
        assert r.status_code in (200, 422)
        b = r.json() if r.status_code == 200 else {"total_normalized": 0}
        evs = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
        assert b["total_normalized"] == 0 and evs == [], (
            f"an alert with no content was normalized into {[(e.provider, e.action, e.outcome, e.severity) for e in evs]} with an invented timestamp"
        )


# ── R06 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
@pytest.mark.parametrize("label,drop", [
    ("timestamp_absent", ["timestamp"]), ("host_and_user_absent", ["host", "user"]), ("rule_identity_absent", ["rule_id", "rule_name"]),
    ("all_optional_absent", ["src_ip", "dest_ip", "sha256", "category", "urgency"]), ("severity_absent", ["severity"]),
])
async def test_r06_missing_fields_stay_unknown_and_are_never_fabricated(db_session, app_instance, label, drop):
    client, token, lead, case = await setup(db_session, app_instance, [], prefix="r06")
    async with Keep(client):
        alert = mk(60)
        for k in drop:
            alert.pop(k, None)
        t0 = datetime.now(timezone.utc)
        r = await client.post(INGEST, json=body([alert]), headers=MACHINE)
        t1 = datetime.now(timezone.utc)
        assert r.status_code in (200, 422), f"{label}: {r.status_code} {r.text[:200]}"
        if r.status_code != 200:
            note("R06", label=label, status=r.status_code)
            return
        b = r.json()
        assert b["total_normalized"] + len(b["errors"]) == 1
        note("R06", label=label, normalized=b["total_normalized"], errors=[e["error"][:80] for e in b["errors"]])
        if b["total_normalized"]:
            ev = (await db_session.execute(select(NormalizedEventModel))).scalars().one()
            if "timestamp" in drop:
                assert not _fabricated_now(ev, t0, t1), f"{label}: missing timestamp was replaced by the ingestion time {ev.event_timestamp}"
            await link_all_events(db_session, case, lead)
            inv = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
            assert inv.status_code == 201, inv.text[:200]                           # incomplete evidence never breaks the investigation


def _without_time_fields(o: Any) -> Any:
    if isinstance(o, dict):
        return {k: _without_time_fields(v) for k, v in o.items() if not any(w in k.lower() for w in ("time", "date", "created", "ts"))}
    if isinstance(o, list):
        return [_without_time_fields(x) for x in o]
    return o


_SAMPLE_FILES = sorted((Path(__file__).resolve().parents[3] / "datasets" / "samples" / "alerts").glob("*.json"))


@pytest.mark.anyio
@pytest.mark.parametrize("path", _SAMPLE_FILES, ids=[f.stem for f in _SAMPLE_FILES])
async def test_r06_each_sample_adapter_keeps_a_missing_timestamp_unknown(db_session, app_instance, path):
    """STRICT INVARIANT across the eight shipped sample alert types. Exploratory evidence for the shared fallback pattern; see 02_FAILURE_EVIDENCE.md."""
    original = json.loads(path.read_text(encoding="utf-8"))
    client, _t, _l, _c = await setup(db_session, app_instance, [], prefix="r06s")
    async with Keep(client):
        t0 = datetime.now(timezone.utc)
        r = await client.post(INGEST, json={"source_type": original.get("source_type", "auto"), "source_identifier": "matrix",
                                              "alerts": [_without_time_fields(original)]}, headers=MACHINE)
        t1 = datetime.now(timezone.utc)
        assert r.status_code in (200, 422), r.text[:200]
        evs = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
        assert [e for e in evs if _fabricated_now(e, t0, t1)] == [], f"{path.stem}: event stored with the ingestion time instead of an unknown timestamp"


# ── R07 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_r07_large_payloads_are_bounded(db_session, app_instance):
    from app.schemas.alert_ingest import MAX_ALERT_BATCH_SIZE, MAX_ALERT_PAYLOAD_BYTES

    client, _t, _l, _c = await setup(db_session, app_instance, [], prefix="r07")
    async with Keep(client):
        big_ok = mk(70, description="x" * (MAX_ALERT_PAYLOAD_BYTES - 4000))
        r = await client.post(INGEST, json=body([big_ok]), headers=MACHINE)
        assert r.status_code == 200 and r.json()["total_normalized"] == 1, r.text[:200]
        raw = (await db_session.execute(select(RawEvidence))).scalars().one()
        assert len(json.dumps(raw.raw_payload, ensure_ascii=False)) > MAX_ALERT_PAYLOAD_BYTES - 6000     # preserved, not truncated
        too_big = mk(71, description="y" * (MAX_ALERT_PAYLOAD_BYTES + 10))
        r2 = await client.post(INGEST, json=body([too_big]), headers=MACHINE)
        assert r2.status_code == 422
        r3 = await client.post(INGEST, json=body([{"i": i} for i in range(MAX_ALERT_BATCH_SIZE + 1)]), headers=MACHINE)
        assert r3.status_code == 422
        nested = mk(72, blob={"k" + str(i): "z" * 500 for i in range(150)})                          # large nested content, under the limit
        r4 = await client.post(INGEST, json=body([nested]), headers=MACHINE)
        assert r4.status_code == 200 and r4.json()["total_normalized"] == 1
        batch = [mk(1000 + i) for i in range(200)]                                                   # bounded batch, well under the 1000 limit
        t0 = time.perf_counter()
        r5 = await asyncio.wait_for(client.post(INGEST, json=body(batch), headers=MACHINE), timeout=120)
        elapsed = time.perf_counter() - t0
        assert r5.status_code == 200 and r5.json()["total_normalized"] == 200 and r5.json()["errors"] == []
    assert await row_counts(db_session) == (202, 202)                                                # rejected payloads left nothing behind
    note("R07", max_payload_bytes=MAX_ALERT_PAYLOAD_BYTES, batch_limit=MAX_ALERT_BATCH_SIZE, batch_of_200_seconds=round(elapsed, 3))


# ── R08 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_r08_commit_failure_during_ingest_returns_a_generic_500(db_session, app_instance, monkeypatch):
    client, _t, _l, _c = await setup(db_session, app_instance, [], prefix="r08a")
    real_commit = db_session.commit

    async def failing_commit():
        raise RuntimeError("injected commit failure SECRET-DETAIL")

    async with Keep(client), contract_client(app_instance) as strict:
        monkeypatch.setattr(db_session, "commit", failing_commit)
        r = await strict.post(INGEST, json=body([mk(80)]), headers=MACHINE)
        monkeypatch.setattr(db_session, "commit", real_commit)
        note("R08-commit", status=r.status_code, body=r.text[:80])
        assert r.status_code == 500 and "SECRET-DETAIL" not in r.text and "injected" not in r.text      # not reported as success, no internal detail
        await db_session.rollback()


@pytest.mark.skip(reason=(
    "BLOCKED on the SQLite test harness (not a production finding): with pysqlite a SAVEPOINT that is the first write of a transaction is released "
    "as an outer COMMIT, so a later rollback cannot undo it (demonstrated in the report: 1 row survives rollback). The ingest service opens "
    "begin_nested() at its first write, so atomicity-on-commit-failure and retry-creates-one-record can only be validated on PostgreSQL "
    "(test_postgres_* nodes, owner-controlled launcher). Assertions preserved below for that run."))
@pytest.mark.anyio
async def test_r08_commit_failure_leaves_nothing_persisted_and_the_retry_creates_exactly_one_record(db_session, app_instance, monkeypatch):
    client, _t, _l, _c = await setup(db_session, app_instance, [], prefix="r08c")
    real_commit = db_session.commit

    async def failing_commit():
        raise RuntimeError("injected commit failure")

    async with Keep(client), contract_client(app_instance) as strict:
        monkeypatch.setattr(db_session, "commit", failing_commit)
        await strict.post(INGEST, json=body([mk(81)]), headers=MACHINE)
        monkeypatch.setattr(db_session, "commit", real_commit)
        await db_session.rollback()
        assert await row_counts(db_session) == (0, 0)
        ok = await client.post(INGEST, json=body([mk(81)]), headers=MACHINE)
        assert ok.status_code == 200 and ok.json()["total_normalized"] == 1
    assert await row_counts(db_session) == (1, 1)


@pytest.mark.anyio
async def test_r08_read_failure_during_investigation_is_a_controlled_error_with_no_audit_row(db_session, app_instance, monkeypatch):
    client, token, lead, case = await setup(db_session, app_instance, SCENARIOS["06_uncorroborated_single_alert"]["build"](), prefix="r08b")
    from app.services.multisource_investigation_service import MultiSourceInvestigationService

    async def broken(self, session, case_id):
        raise RuntimeError("injected read failure SECRET-DETAIL")

    async with Keep(client), contract_client(app_instance) as strict:
        monkeypatch.setattr(MultiSourceInvestigationService, "_load_inputs", broken)
        r = await strict.post(START.format(cid=case.id), json={}, headers=bearer(token))
        status, text = r.status_code, r.text
        note("R08-read", status=status, body=text[:80])
        assert status == 500 and "SECRET-DETAIL" not in text and "injected" not in text
        monkeypatch.undo()
        assert audit_rows and len(await audit_rows(db_session, case.id)) == 0
        ok = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        assert ok.status_code == 201                                               # the next independent request still works


# ── R09 ─────────────────────────────────────────────────────────────────────────────────────────────
class Raising(ScriptedProvider):
    def __init__(self, exc: Exception) -> None:
        super().__init__(raise_exc=exc)


@pytest.mark.anyio
@pytest.mark.parametrize("exc,expected", [(LLMTimeoutError("timed out"), "fallback:LLMTimeoutError"), (LLMConnectionError("down"), "fallback:LLMConnectionError")])
async def test_r09_llm_timeout_or_failure_keeps_deterministic_results(db_session, app_instance, exc, expected):
    provider = Raising(exc)
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=provider, prefix="r09")
    async with Keep(client):
        off = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()["incidents"][0]
        r = await client.post(START.format(cid=case.id), json={"use_llm": True, "force": True}, headers=bearer(token))
        assert r.status_code == 201
        inc = r.json()["incidents"][0]
    assert inc["llm_status"] == expected and provider.calls == 1                      # one bounded attempt at the service level, no fallback provider
    assert not (inc["llm"] or {}).get("claims")                                       # no unsupported AI claim emitted
    assert stable(inc) == stable(off)                                                 # deterministic fields identical to AI-off
    note("R09", llm_status=inc["llm_status"], provider_calls=provider.calls)


@pytest.mark.anyio
async def test_r09_real_ollama_adapter_with_a_timing_out_transport_through_the_api(db_session, app_instance, fast_sleep):
    seen: list[str] = []

    def slow(request):
        raise httpx.ReadTimeout("slow")

    provider, seen = _provider(slow, retries=3)
    client, token, _lead, case = await setup(db_session, app_instance, SCENARIOS["06_uncorroborated_single_alert"]["build"](), provider=provider, prefix="r09b")
    async with Keep(client):
        r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
        assert r.status_code == 201
        assert r.json()["incidents"][0]["llm_status"] == "fallback:LLMTimeoutError"
    assert 1 <= len(seen) <= 3 and all(s.split()[1].startswith("localhost") for s in seen)    # bounded, local only
    note("R09-adapter", transport_requests=len(seen))


# ── R10 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_r10_threat_intelligence_is_not_called_and_missing_ti_is_not_fabricated(db_session, app_instance, monkeypatch):
    import socket

    seen: list[str] = []

    async def no_send(self, request, *a, **k):
        if not isinstance(self._transport_for_url(request.url), httpx.ASGITransport):
            seen.append(request.url.host)
            raise httpx.ConnectError("blocked")
        return await real_send(self, request, *a, **k)

    real_send = httpx.AsyncClient.send
    monkeypatch.setattr(httpx.AsyncClient, "send", no_send)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(OSError("blocked")))
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="r10")
    async with Keep(client):
        inc = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()["incidents"][0]
    assert seen == []                                                                  # no outbound request on the investigation path
    assert inc["enrichments"] == []                                                    # missing TI is absent, never invented
    note("R10", outbound_requests=0, enrichments=len(inc["enrichments"]), path="multisource investigation does not invoke TI")


# ── R11 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_r11_explanation_failure_does_not_break_the_investigation(db_session, app_instance, monkeypatch):
    import app.services.multisource_investigation_service as svc

    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="r11a")
    async with Keep(client):
        ref = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()["incidents"][0]
        monkeypatch.setattr(svc, "build_rationale", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("injected explanation failure")))
        r = await client.post(START.format(cid=case.id), json={"force": True}, headers=bearer(token))
        assert r.status_code == 201, r.text[:200]
        inc = r.json()["incidents"][0]
    assert stable({**inc, "sufficiency": {**inc["sufficiency"]}})["timeline"] == stable(ref)["timeline"] and inc["sufficiency"]["verdict"] == ref["sufficiency"]["verdict"]
    note("R11-explanation", rationale_present="rationale" in inc["sufficiency"])


@pytest.mark.anyio
async def test_r11_report_rendering_failure_fails_the_whole_run_without_a_partial_audit_row(db_session, app_instance, monkeypatch):
    import app.modules.correlation.report as report_mod

    client, token, _lead, case = await setup(db_session, app_instance, SCENARIOS["06_uncorroborated_single_alert"]["build"](), prefix="r11b")
    async with Keep(client), contract_client(app_instance) as strict:
        monkeypatch.setattr(report_mod, "render_incident_report", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("injected render failure SECRET-DETAIL")))
        r = await strict.post(START.format(cid=case.id), json={}, headers=bearer(token))
        status, text = r.status_code, r.text
        note("R11-report-render", status=status, body=text[:80])
        assert status == 500 and "SECRET-DETAIL" not in text and "injected" not in text
        monkeypatch.undo()
        assert len(await audit_rows(db_session, case.id)) == 0                       # a failed run is never recorded as completed
        assert (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).status_code == 201


@pytest.mark.anyio
async def test_r11_malformed_ai_output_is_a_fallback_not_a_validated_result(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=Garbage(), prefix="r11c")
    async with Keep(client):
        inc = (await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))).json()["incidents"][0]
    assert inc["llm_status"].startswith("fallback:") and inc["llm_status"] != "validated" and inc["sufficiency"]["verdict"] == "sufficient"


# ── R12 ─────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_r12_retry_policy_is_bounded_and_does_not_retry_validation_errors(fast_sleep):
    refuse_seen: list[str] = []

    def refuse(request):
        raise httpx.ConnectError("refused")

    p, refuse_seen = _provider(refuse, retries=3)
    with pytest.raises(Exception):
        await p.generate(REQ)
    assert len(refuse_seen) == 3                                                       # exactly the configured bound: no retry storm
    p400, seen400 = _provider(lambda r: httpx.Response(400, json={"error": "bad request"}))
    with pytest.raises(Exception):
        await p400.generate(REQ)
    assert len(seen400) == 1                                                           # a non-retryable error is not retried
    p503, seen503 = _provider(lambda r: httpx.Response(503, json={}), retries=3)
    with pytest.raises(Exception):
        await p503.generate(REQ)
    assert len(seen503) <= 3
    note("R12-provider", connect_error_attempts=len(refuse_seen), http_400_attempts=len(seen400), http_503_attempts=len(seen503))


@pytest.mark.anyio
async def test_r12_failed_run_then_retry_creates_exactly_one_result_and_later_requests_work(db_session, app_instance, monkeypatch):
    client, token, _lead, case = await setup(db_session, app_instance, SCENARIOS["06_uncorroborated_single_alert"]["build"](), prefix="r12")
    real_commit = db_session.commit

    async def failing_commit():
        raise RuntimeError("injected commit failure")

    async with Keep(client), contract_client(app_instance) as strict:
        monkeypatch.setattr(db_session, "commit", failing_commit)
        first_status = (await strict.post(START.format(cid=case.id), json={}, headers=bearer(token))).status_code
        monkeypatch.setattr(db_session, "commit", real_commit)
        await db_session.rollback()
        assert first_status != 201 and len(await audit_rows(db_session, case.id)) == 0
        second = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        third = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))   # identical retry after success is idempotent
        assert second.status_code == 201 and third.status_code in (200, 201)
        assert len(await audit_rows(db_session, case.id)) == 1                          # no duplicate result or audit record from retries
    assert await row_counts(db_session) == (1, 1)
    note("R12-run", first_status=first_status, second=second.status_code, third=third.status_code, audit_rows=1)
