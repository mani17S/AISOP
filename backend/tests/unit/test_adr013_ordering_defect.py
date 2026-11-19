"""
ADR-013 Revision 2, first slice: the event-ordering defect (owner-approved implementation, 2026-11-12).

Defect (reproduced BEFORE any production change): a ``forensic.file`` artefact whose event time is EARLIER than the e-mail that supposedly
delivered it (same SHA-256) still produced ATT&CK T1566.001 and a SUFFICIENT verdict, because (a) ``domain_attack._attachment_on_host``
matched on the shared hash only and never compared times, and (b) neither the correlator nor the gate has any notion of ordering.

These tests exercise the REAL path (HTTP import -> stored raw evidence -> investigation -> persisted result), not only a fixture.
"""

from __future__ import annotations

import pytest

from app.modules.evidence_domains import scenarios as S
from tests.unit.test_case_synthesis_api import app_instance, auth_settings  # noqa: F401  (fixtures)
from tests.unit.test_domain_evidence_api import IMPORT
from tests.unit.test_multisource_api import START, Keep, bearer, setup


@pytest.fixture
def anyio_backend():
    return "asyncio"


def scenario_c(file_time: str | None = None, causal: bool = True):
    """``causal=True``: the artefact record STATES its origin e-mail and that its time is an arrival time (verified causal relationship).
    ``causal=False``: the ORIGINAL first-slice fixture (earlier timestamp + shared hash only), which D6 says is NOT a causal-ordering violation."""
    recs = [dict(r) for r in S.scenario_c_email_forensic()]
    for r in recs:
        if r["evidence_type"] == "forensic.file":
            if file_time is not None:
                r["event_time"] = file_time
            if causal:
                r["data"] = dict(r["data"], origin_message_id="<inv-8841@invoice-portal.test>", timestamp_semantics="arrival")
    return recs


@pytest.mark.anyio
async def test_defect_reproduction_file_older_than_the_email_must_not_support_attachment_delivery_or_a_sufficient_verdict(db_session, app_instance):
    """E-mail 2026-11-05T08:00:00Z contains hash H; the file artefact with hash H is timestamped 07:00:00Z (one hour EARLIER)."""
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="ordering")
    async with Keep(client):
        imp = await client.post(IMPORT.format(cid=case.id), json={"records": scenario_c("2026-11-05T07:00:00Z")}, headers=bearer(token))
        assert imp.status_code == 201 and imp.json()["accepted"] == 6
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
    assert r.status_code == 201, r.text
    inc = max(r.json()["incidents"], key=lambda i: i["event_count"])
    techniques = {m["technique_id"] for m in inc["mitre"]}
    assert "T1566.001" not in techniques, "attachment delivery derived although the artefact predates the e-mail"
    assert inc["sufficiency"]["verdict"] != "sufficient", "the contradictory pair still supports a SUFFICIENT verdict"
    assert any(c.startswith("CONTRADICTORY_EVIDENCE:ordering") for c in inc["sufficiency"]["reason_codes"])


@pytest.mark.anyio
async def test_a_file_that_merely_predates_the_email_is_not_a_contradiction_through_the_real_path(db_session, app_instance):
    """NEGATIVE (owner decision D6). The original first-slice fixture: the artefact is timestamped one hour before the e-mail and shares its hash,
    but nothing states a causal relationship. A pre-existing file (attached later, or observed through another time field) is not impossible, so
    there is no contradiction, the verdict is unchanged and the technique is still derived."""
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix="preexisting")
    async with Keep(client):
        imp = await client.post(IMPORT.format(cid=case.id), json={"records": scenario_c("2026-11-05T07:00:00Z", causal=False)}, headers=bearer(token))
        assert imp.status_code == 201 and imp.json()["accepted"] == 6
        r = await client.post(START.format(cid=case.id), json={}, headers=bearer(token))
    inc = max(r.json()["incidents"], key=lambda i: i["event_count"])
    assert inc["contradictions"] == [] and inc["sufficiency"]["verdict"] == "sufficient"
    assert "T1566.001" in {m["technique_id"] for m in inc["mitre"]}
    assert not any(c.startswith("CONTRADICTORY_EVIDENCE") for c in inc["sufficiency"]["reason_codes"])
