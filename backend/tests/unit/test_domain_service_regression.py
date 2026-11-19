"""
Post-implementation verification of ``DomainEvidenceService`` (Master Prompt 25). SQLite only; nothing here validates PostgreSQL.

Adds only the properties that the earlier tests did not cover: both retry attempts losing, mid-batch failure atomicity, multi-byte size
accounting, and SHA-256 consistency for non-ASCII payloads.
"""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from app.models.case import CaseAuditEventModel, CaseEvidenceModel
from app.models.evidence import RawEvidence
from app.modules.correlation.normalize import raw_digest
from app.modules.evidence.hasher import compute_sha256
from app.modules.evidence_domains import scenarios as S
from app.services import domain_evidence_service as svc
from tests.unit.test_case_synthesis_api import app_instance, auth_settings  # noqa: F401  (fixtures)
from tests.unit.test_domain_evidence_api import IMPORT, count
from tests.unit.test_multisource_api import START, Keep, bearer, setup


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_when_both_attempts_lose_the_race_the_request_fails_safe_with_nothing_stored(db_session, app_instance, monkeypatch):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="lose2")
    calls = {"n": 0}

    async def always_conflicts(session, record, digest, obs, now):
        calls["n"] += 1
        raise IntegrityError("INSERT", {}, Exception("unique sha256_hash (detail that must not leak)"))

    monkeypatch.setattr(svc.DomainEvidenceService, "_create", staticmethod(always_conflicts))
    async with Keep(client):
        r = await client.post(IMPORT.format(cid=case.id), json={"records": S.negative_unknown_type()}, headers=bearer(token))
    assert calls["n"] == 2                                                # exactly one retry, no loop
    assert r.status_code == 500 and "detail that must not leak" not in r.text and "nothing was imported" in r.json()["detail"]
    assert await count(db_session, RawEvidence) == 0 and await count(db_session, CaseEvidenceModel) == 0
    assert await count(db_session, CaseAuditEventModel, CaseAuditEventModel.action == svc.IMPORT_ACTION) == 0


@pytest.mark.anyio
async def test_a_failure_in_the_middle_of_a_batch_rolls_back_the_records_stored_before_it(db_session, app_instance, monkeypatch):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="mid")
    real = svc.DomainEvidenceService._create
    calls = {"n": 0}

    async def fail_on_second(session, record, digest, obs, now):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("storage failure detail that must not leak")
        return await real(session, record, digest, obs, now)

    monkeypatch.setattr(svc.DomainEvidenceService, "_create", staticmethod(fail_on_second))
    async with Keep(client):
        r = await client.post(IMPORT.format(cid=case.id), json={"records": S.scenario_b_network_endpoint()}, headers=bearer(token))
    assert calls["n"] == 2 and r.status_code == 500 and "must not leak" not in r.text
    assert await count(db_session, RawEvidence) == 0 and await count(db_session, CaseEvidenceModel) == 0     # the first record was rolled back too


@pytest.mark.anyio
async def test_multibyte_records_are_sized_in_bytes_not_characters(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="bytes")
    # 300,000 characters of a 4-byte emoji = ~1.2 MB: under 1 MiB by character count, over it by bytes.
    wide = S.env("identity.signin", "idp", {"user": "u.example", "ip": S.ATTACKER_IP, "note": "\U0001F600" * 300_000}, t="2026-11-01T00:00:00Z")
    narrow = S.env("identity.signin", "idp", {"user": "u.example", "ip": S.ATTACKER_IP, "note": "x" * 300_000}, t="2026-11-01T00:00:00Z")
    async with Keep(client):
        r = await client.post(IMPORT.format(cid=case.id), json={"records": [wide, narrow]}, headers=bearer(token))
    body = r.json()
    assert r.status_code == 201
    assert [q["reason"] for q in body["quarantined_records"]] == ["RECORD_TOO_LARGE"] and body["accepted"] == 1


@pytest.mark.anyio
async def test_sha256_is_consistent_end_to_end_for_non_ascii_payloads(db_session, app_instance):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="utf")
    rec = S.env("identity.signin", "idp", {"user": "josé.example", "ip": S.ATTACKER_IP, "result": "success"}, t="2026-11-01T00:00:00Z")
    async with Keep(client):
        imp = (await client.post(IMPORT.format(cid=case.id), json={"records": [rec]}, headers=bearer(token))).json()
        await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
        ev = (await client.get(START.format(cid=case.id) + "/evidence", headers=bearer(token))).json()
    stored = imp["evidence"][0]["sha256"]
    assert stored == compute_sha256(rec)                                   # import digest = the documented canonical hasher
    assert ev["observations"][0]["raw_sha256"] == stored                   # the investigation uses the STORED digest, not a recomputation
    # Documented discrepancy (not a defect in the application path): the correlation library's own ``raw_digest`` escapes non-ASCII
    # (ensure_ascii default) and therefore differs from ``compute_sha256`` for such records. It matters only for a caller that omits the
    # stored digests; the application always supplies them.
    assert raw_digest(rec) != compute_sha256(rec)
    ascii_rec = S.scenario_a_identity_cloud()[0]
    assert raw_digest(ascii_rec) == compute_sha256(ascii_rec)              # identical for ASCII payloads
