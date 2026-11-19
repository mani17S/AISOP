"""
Stage 6A (closing outstanding Stage 6 gaps): offline tests for
 * the request-body limit on POST /api/v1/alerts/ingest (was absent),
 * concurrent / racing import of the same evidence record (was UNVERIFIED),
 * the existing case-synthesis endpoint with domain evidence in the case (was UNVERIFIED).
SQLite only; nothing here validates PostgreSQL behaviour.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from sqlalchemy import func, select

from app.api.v1.endpoints.cases import get_case_llm_provider
from app.models.case import CaseEvidenceModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.correlation.demo_data import intrusion_chain
from app.modules.evidence_domains import scenarios as S
from tests.unit.test_case_synthesis_api import (  # noqa: F401  (fixtures and seeding helpers)
    MockCaseLLMProvider,
    app_instance,
    auth_settings,
    build_valid_llm_json,
    seed_analyst_with_token,
    seed_case_with_lead,
)
from tests.unit.test_domain_evidence_api import IMPORT, count
from tests.unit.test_multisource_api import MACHINE, Keep, bearer, ingest, setup


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_alert_ingest_rejects_an_oversized_body_with_413_and_still_accepts_normal_batches(db_session, app_instance):
    client, _token, _lead, _case = await setup(db_session, app_instance, [], prefix="ing")
    huge = [{"source_type": "generic_siem", "timestamp": "2026-11-01T00:00:00Z", "title": "t", "blob": "x" * 900_000} for _ in range(19)]
    async with Keep(client):
        r = await client.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "f", "alerts": huge}, headers=MACHINE)
        assert r.status_code == 413 and r.json()["detail"] == "Request body too large." and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
        ok = await ingest(client, intrusion_chain()[:3])
        assert ok["total_received"] == 3
    assert await count(db_session, RawEvidence) == 3                                   # nothing from the rejected request was stored


@pytest.mark.anyio
async def test_a_lost_insert_race_is_an_ordinary_duplicate_not_a_500(db_session, app_instance, monkeypatch):
    """Simulates two requests importing the same NEW record: the second one's existence check misses (the first had not committed),
    then its insert hits the unique sha256 constraint. Expected: duplicate=True, linked to the second case, one raw row, 201."""
    client, token, lead, case_a = await setup(db_session, app_instance, [], prefix="race")
    case_b = await seed_case_with_lead(db_session, lead=lead, title="Race B")
    rec = S.negative_unknown_type()
    async with Keep(client):
        assert (await client.post(IMPORT.format(cid=case_a.id), json={"records": rec}, headers=bearer(token))).status_code == 201
        real_execute = db_session.execute
        state = {"missed": False}

        async def execute(stmt, *a, **k):
            if not state["missed"] and "FROM raw_evidence" in str(stmt) and "sha256_hash" in str(stmt):
                state["missed"] = True

                class _Empty:
                    def scalars(self):
                        return self

                    def first(self):
                        return None

                return _Empty()
            return await real_execute(stmt, *a, **k)

        monkeypatch.setattr(db_session, "execute", execute)
        r = await client.post(IMPORT.format(cid=case_b.id), json={"records": rec}, headers=bearer(token))
        monkeypatch.setattr(db_session, "execute", real_execute)
    assert state["missed"] is True
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["accepted"] == 1 and body["evidence"][0]["duplicate"] is True and body["quarantined"] == 0
    assert await count(db_session, RawEvidence) == 1 and await count(db_session, NormalizedEventModel) == 1
    assert await count(db_session, CaseEvidenceModel, CaseEvidenceModel.case_id == case_b.id) == 1


@pytest.mark.anyio
async def test_one_record_racing_inside_a_batch_does_not_lose_the_other_records(db_session, app_instance, monkeypatch):
    client, token, lead, case_a = await setup(db_session, app_instance, [], prefix="race2")
    case_b = await seed_case_with_lead(db_session, lead=lead, title="Race B2")
    first = S.negative_unknown_type()
    batch = first + S.scenario_b_network_endpoint()[:2]
    async with Keep(client):
        await client.post(IMPORT.format(cid=case_a.id), json={"records": first}, headers=bearer(token))
        real_execute = db_session.execute
        state = {"missed": False}

        async def execute(stmt, *a, **k):
            if not state["missed"] and "FROM raw_evidence" in str(stmt) and "sha256_hash" in str(stmt):
                state["missed"] = True

                class _Empty:
                    def scalars(self):
                        return self

                    def first(self):
                        return None

                return _Empty()
            return await real_execute(stmt, *a, **k)

        monkeypatch.setattr(db_session, "execute", execute)
        r = await client.post(IMPORT.format(cid=case_b.id), json={"records": batch}, headers=bearer(token))
        monkeypatch.setattr(db_session, "execute", real_execute)
    assert r.status_code == 201 and r.json()["accepted"] == 3
    assert await count(db_session, RawEvidence) == 3
    assert await count(db_session, CaseEvidenceModel, CaseEvidenceModel.case_id == case_b.id) == 3


@pytest.mark.anyio
async def test_existing_case_synthesis_endpoint_works_with_domain_evidence_in_the_case(db_session, app_instance):
    client, token, lead, case = await setup(db_session, app_instance, [], prefix="syn")
    async with Keep(client):
        imp = await client.post(IMPORT.format(cid=case.id), json={"records": S.scenario_a_identity_cloud()}, headers=bearer(token))
        evidence_id = uuid.UUID(imp.json()["evidence"][0]["evidence_id"])
        app_instance.dependency_overrides[get_case_llm_provider] = lambda: MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=evidence_id))
        r = await client.post(f"/api/v1/cases/{case.id}/investigations/synthesize", json={}, headers=bearer(token))
    assert r.status_code == 200, r.text
    body = r.json()
    # The mock model asserts PowerShell activity that identity/cloud evidence cannot support. The existing validator must not accept it:
    # the endpoint works with domain rows (200) and the unsupported claim is demoted, never presented as validated.
    assert body["decision"] == "remediated"
    assert body["output"]["claims"] and all(c["grounding_status"] != "validated_reference" for c in body["output"]["claims"])
    # Known limitation observed here (existing validator behaviour, not Stage 6): the unsupported ATT&CK *hypothesis* is kept in the AI
    # section, labelled as a hypothesis. It is not a derived mapping. Tightening this is a Stage 8 grounding item.
    assert [h["technique_id"] for h in body["output"]["mitre_attack_hypotheses"]] == ["T1059.001"]
