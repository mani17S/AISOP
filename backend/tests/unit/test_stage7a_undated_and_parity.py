"""
Stage 7A (owner decisions D1 and D2): undated evidence in case synthesis, and incident/case semantic parity.

Everything runs offline over SQLite through the real HTTP endpoints (nothing here validates PostgreSQL persistence).

D1: a record without a usable event time keeps ``event_time = unknown``. The NOT NULL column ``normalized_events.event_timestamp``
holds its INGESTION time only so the row can be stored; the payload says so. Case synthesis must not treat that column as an
event time (it never creates ordering, temporal corroboration or a time-window comparison) and must disclose the distinction.

D2: the normalized comparison projection (``project_incident`` / ``project_case``) compares MEANING, not bytes:
  compared  : sufficiency verdict, rule version, contradiction reason codes (kind-qualified), undated disclosure present/absent,
              the coded sufficiency disclosure line for contradictions, LLM-independence of the verdict.
  excluded  : investigation / incident / evidence ids and the assessment SHA-256 (the case path creates a fresh investigation id per
              call and binds a different context), timestamps of generation, the narrative text of the model, markdown layout,
              graph / timeline markers (the case path has no correlator), per-incident anchor.
  documented differences (asserted below so that a change is noticed): see ``test_documented_difference_*``.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.case import CaseAuditEventModel  # noqa: F401
from app.models.evidence import NormalizedEventModel
from app.modules.evidence_domains import scenarios as S
from app.modules.evidence_domains.model import stored_event_time_unknown
from tests.unit.test_adr013_case_service import (  # noqa: F401  (fixtures and helpers)
    FailingProvider,
    MockCaseLLMProvider,
    app_instance,
    auth_settings,
    build_valid_llm_json,
    case_path,
    identity_conflict,
    ordering_violation,
    outcome_conflict,
    seed_analyst_with_token,
    seed_case_with_lead,
    synthesis_audit,
    temporal_conflict,
)
from tests.unit.test_domain_evidence_api import IMPORT
from tests.unit.test_multisource_api import START, Keep, bearer, setup

env = S.env
IP = S.ATTACKER_IP
UNDATED_PREFIX = "UNDATED_OBSERVATIONS"


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------------------------------------------------------------- projections (D2)
def project_incident(start_body: dict) -> dict:
    """Normalized projection of the incident path (largest incident, else the batch assessment)."""
    incs = start_body["incidents"]
    suff = max(incs, key=lambda i: i["event_count"])["sufficiency"] if incs else start_body["batch_sufficiency"]
    codes = sorted(suff["reason_codes"])
    return {
        "verdict": suff["verdict"],
        "rule_version": suff["rule_version"],
        "contradiction_codes": [c for c in codes if c.startswith("CONTRADICTORY_EVIDENCE")],
        "undated_disclosed": start_body["observation_counts"]["undated"] > 0,
    }


async def project_case(resp, db_session, case_id) -> dict:
    audit = (await synthesis_audit(db_session, case_id))[-1]
    gaps = resp.json()["output"]["uncertainty_and_data_gaps"]
    return {
        "verdict": audit["sufficiency_verdict"],
        "rule_version": audit["sufficiency_rule_version"],
        "contradiction_codes": sorted(c for c in audit["sufficiency_reason_codes"] if c.startswith("CONTRADICTORY_EVIDENCE")),
        "undated_disclosed": any(g.startswith(UNDATED_PREFIX) for g in gaps),
        "_gaps": gaps,
        "_audit": audit,
    }


def public(p: dict) -> dict:
    return {k: v for k, v in p.items() if not k.startswith("_")}


async def run_both(db_session, app_instance, records, prefix, provider=None):
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix=prefix)
    async with Keep(client):
        imp = (await client.post(IMPORT.format(cid=case.id), json={"records": records}, headers=bearer(token))).json()
        inc_body = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
        resp = await case_path(client, app_instance, token, case.id, uuid.UUID(imp["evidence"][0]["evidence_id"]), provider=provider)
    assert resp.status_code == 200, resp.text
    return imp, inc_body, await project_case(resp, db_session, case.id), case


# ---------------------------------------------------------------- D1: the shared predicate
@pytest.mark.parametrize("payload, unknown", [
    ({"event_timestamp_is_ingestion_time": True, "time_status": "missing"}, True),
    ({"event_timestamp_is_ingestion_time": True}, True),
    ({"time_status": "missing"}, True),
    ({"time_status": "invalid"}, True),
    ({"time_status": "out_of_range"}, True),
    ({"time_status": "valid", "event_timestamp_is_ingestion_time": False}, False),
    ({"time_status": "naive_assumed_utc", "event_timestamp_is_ingestion_time": False}, False),
    ({}, False),                       # legacy SIEM / Sysmon rows carry no such keys: they are dated
    (None, False),
])
def test_stored_event_time_unknown_predicate(payload, unknown):
    assert stored_event_time_unknown(payload) is unknown


# ---------------------------------------------------------------- D1: import keeps the two times apart
@pytest.mark.anyio
async def test_undated_record_keeps_event_time_unknown_and_raw_payload_untouched(db_session, app_instance):
    rec = env("identity.signin", "idp-u", {"user": "una.example", "ip": IP, "result": "success"}, t=None, eid="u-1")
    dated = env("identity.signin", "idp-u", {"user": "una.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z", eid="d-1")
    imp, _inc, _case, case = await run_both(db_session, app_instance, [dated, rec], "u-import")
    rows = {r.event_id: r for r in (await db_session.execute(select(NormalizedEventModel))).scalars().all()}
    u, d = rows["u-1"], rows["d-1"]
    # event time unknown is stated, not invented; the column is declared to be the ingestion time
    assert u.normalized_payload["event_time"] is None
    assert u.normalized_payload["event_timestamp_is_ingestion_time"] is True
    assert u.normalized_payload["time_status"] == "missing"
    assert u.event_timestamp is not None and stored_event_time_unknown(u.normalized_payload)
    # a dated record is not swapped: column == its event time, flag false
    assert d.normalized_payload["event_timestamp_is_ingestion_time"] is False
    assert d.normalized_payload["event_time"].startswith("2026-11-07T09:00:00")
    assert d.event_timestamp.year == 2026 and d.event_timestamp.month == 11 and d.event_timestamp.day == 7
    assert not stored_event_time_unknown(d.normalized_payload)
    # the raw record is preserved exactly as submitted (no event_time key was added)
    raw = u.raw_evidence.raw_payload if u.raw_evidence is not None else None
    if raw is not None:
        assert "event_time" not in raw
    assert [e["time_status"] for e in imp["evidence"]] == ["valid", "missing"]


# ---------------------------------------------------------------- D1: case synthesis
@pytest.mark.anyio
async def test_case_synthesis_keeps_undated_evidence_out_of_the_timeline_and_discloses_it(db_session, app_instance):
    base = S.scenario_a_identity_cloud()
    imp, inc, case_p, _case = await run_both(db_session, app_instance, S.negative_bad_times()[:1] + base, "u-case")
    assert inc["observation_counts"]["undated"] == 1
    # the undated record is preserved and stored, but is not a time-ordered context event
    assert case_p["_audit"]["evidence_count"] == len(base)
    # disclosed in the analyst-facing output, same fixed wording as the incident path
    assert case_p["undated_disclosed"] is True
    assert any(g == f"{UNDATED_PREFIX}: 1 observation(s) have no usable event time and were not placed on the timeline" for g in case_p["_gaps"])
    assert any("no usable event time" in g for g in case_p["_gaps"]) and not any("ingest" in g.lower() and "event time" not in g.lower() for g in case_p["_gaps"])


@pytest.mark.anyio
async def test_undated_evidence_does_not_change_the_case_verdict_or_corroborate(db_session, app_instance):
    base = S.scenario_a_identity_cloud()
    undated_corroborator = env("identity.signin", "idp-other", {"user": "alice.example", "ip": S.ATTACKER_IP, "result": "success"}, t=None, eid="u-corr")
    _i, _inc1, with_undated, _c1 = await run_both(db_session, app_instance, base + [undated_corroborator], "u-corr-a")
    _i2, _inc2, without, _c2 = await run_both(db_session, app_instance, base, "u-corr-b")
    assert with_undated["verdict"] == without["verdict"]
    assert sorted(with_undated["_audit"]["sufficiency_reason_codes"]) == sorted(without["_audit"]["sufficiency_reason_codes"])
    assert with_undated["_audit"]["evidence_count"] == without["_audit"]["evidence_count"]
    assert without["undated_disclosed"] is False and with_undated["undated_disclosed"] is True


@pytest.mark.anyio
async def test_undated_evidence_creates_no_temporal_or_outcome_contradiction_on_either_path(db_session, app_instance):
    # a success and a failure of the same user/ip from two systems: dated 1 s apart this IS an outcome conflict (control);
    # with the failure undated there is no time to compare, so neither path may report a conflict
    control = outcome_conflict()
    undated = [dict(control[0]), {k: v for k, v in control[1].items() if k != "event_time"}]
    _i, inc_c, case_c, _ = await run_both(db_session, app_instance, control, "u-ctl")
    assert project_incident(inc_c)["contradiction_codes"] == ["CONTRADICTORY_EVIDENCE:outcome"]
    assert case_c["contradiction_codes"] == ["CONTRADICTORY_EVIDENCE:outcome"]
    _i, inc_u, case_u, _ = await run_both(db_session, app_instance, undated, "u-und")
    assert project_incident(inc_u)["contradiction_codes"] == []
    assert case_u["contradiction_codes"] == []
    assert not any(c.startswith("CONTRADICTORY") for c in case_u["_audit"]["sufficiency_reason_codes"])


@pytest.mark.anyio
async def test_undated_evidence_creates_no_ordering_or_temporal_conflict(db_session, app_instance):
    # ordering: drop the time of the forensic artefact that would otherwise be a verified ordering violation
    recs = ordering_violation()
    for r in recs:
        if r["evidence_type"] == "forensic.file":
            r.pop("event_time", None)
    _i, inc, case_p, _ = await run_both(db_session, app_instance, recs, "u-ord")
    assert project_incident(inc)["contradiction_codes"] == [] and case_p["contradiction_codes"] == []
    # temporal: same event stated twice, one copy undated
    t = temporal_conflict()
    t[1].pop("event_time")
    _i, inc2, case2, _ = await run_both(db_session, app_instance, t, "u-tmp")
    assert project_incident(inc2)["contradiction_codes"] == [] and case2["contradiction_codes"] == []


@pytest.mark.anyio
async def test_incident_report_discloses_unknown_event_time_separately(db_session, app_instance):
    client, token, _l, case = await setup(db_session, app_instance, [], prefix="u-rep")
    async with Keep(client):
        await client.post(IMPORT.format(cid=case.id), json={"records": S.negative_bad_times()[:1] + S.scenario_a_identity_cloud()}, headers=bearer(token))
        body = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()
    md = max(body["incidents"], key=lambda i: i["event_count"])["report_markdown"]
    assert "Event time unknown: 1 preserved record(s)" in md and "Their ingestion time is stored separately and is not an event time" in md
    assert body["observation_counts"]["undated"] == 1


# ---------------------------------------------------------------- D2: parity scenarios
@pytest.mark.anyio
@pytest.mark.parametrize("builder, code", [
    (ordering_violation, "CONTRADICTORY_EVIDENCE:ordering"),
    (outcome_conflict, "CONTRADICTORY_EVIDENCE:outcome"),
    (identity_conflict, "CONTRADICTORY_EVIDENCE:identity"),
    (temporal_conflict, "CONTRADICTORY_EVIDENCE:temporal"),
])
async def test_parity_material_contradictions_project_identically(db_session, app_instance, builder, code):
    _i, inc, case_p, _ = await run_both(db_session, app_instance, builder(), f"p-{code[-5:]}")
    a = project_incident(inc)
    b = public(case_p)
    assert a["verdict"] == b["verdict"] == "limited"
    assert a["rule_version"] == b["rule_version"] == "suff-v4"
    assert a["contradiction_codes"] == b["contradiction_codes"] == [code]
    assert case_p["_gaps"] and any(code in g for g in case_p["_gaps"])          # the coded disclosure reaches the analyst-facing output


@pytest.mark.anyio
async def test_parity_earlier_file_without_causal_relationship(db_session, app_instance):
    recs = [dict(r) for r in S.scenario_c_email_forensic()]
    for r in recs:
        if r["evidence_type"] == "forensic.file":
            r["event_time"] = "2026-11-05T07:00:00Z"
    _i, inc, case_p, _ = await run_both(db_session, app_instance, recs, "p-pre")
    assert project_incident(inc)["contradiction_codes"] == [] == case_p["contradiction_codes"]


@pytest.mark.anyio
async def test_parity_duplicate_and_mirrored_evidence_is_one_unit_on_both_paths(db_session, app_instance):
    dup = S.negative_duplicates()
    _i, inc, case_p, _ = await run_both(db_session, app_instance, dup, "p-dup")
    assert project_incident(inc)["contradiction_codes"] == [] == case_p["contradiction_codes"]
    # a declared shared upstream: the second system's copy is the same evidence, so the verdict equals the single-copy verdict
    one = env("identity.signin", "idp-m1", {"user": "mia.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z", upstream_id="collector-7")
    mirror = env("identity.signin", "idp-m2", {"user": "mia.example", "ip": IP, "result": "success"}, t="2026-11-07T09:00:00Z", upstream_id="collector-7")
    _i, inc_m, case_m, _ = await run_both(db_session, app_instance, [one, mirror], "p-mir")
    _i, inc_s, case_s, _ = await run_both(db_session, app_instance, [one], "p-one")
    assert project_incident(inc_m)["verdict"] == project_incident(inc_s)["verdict"]
    assert case_m["verdict"] == case_s["verdict"]


@pytest.mark.anyio
async def test_parity_undated_evidence_projects_the_same_disclosure_on_both_paths(db_session, app_instance):
    _i, inc, case_p, _ = await run_both(db_session, app_instance, S.negative_bad_times()[:1] + S.scenario_a_identity_cloud(), "p-und")
    assert project_incident(inc)["undated_disclosed"] is True and case_p["undated_disclosed"] is True


@pytest.mark.anyio
async def test_parity_llm_failure_cannot_change_verdict_or_findings(db_session, app_instance):
    _i, inc, ok, _ = await run_both(db_session, app_instance, identity_conflict(), "p-llm-ok")
    _i, _inc2, failed, _ = await run_both(db_session, app_instance, identity_conflict(), "p-llm-bad", provider=FailingProvider())
    assert public(ok) == public(failed)
    assert failed["_audit"]["model_name"] == "deterministic_fallback" or failed["_audit"].get("fallback_reason")
    assert project_incident(inc)["verdict"] == failed["verdict"]


@pytest.mark.anyio
async def test_parity_unsupported_ai_claim_cannot_resolve_a_contradiction(db_session, app_instance):
    # the model cites evidence that does not exist in the case: the output is not accepted as grounded, the finding and the verdict stand
    bogus = MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=uuid.uuid4()))
    _i, _inc, case_b, _ = await run_both(db_session, app_instance, outcome_conflict(), "p-bogus", provider=bogus)
    assert case_b["verdict"] == "limited" and case_b["contradiction_codes"] == ["CONTRADICTORY_EVIDENCE:outcome"]
    assert case_b["_audit"]["decision"] != "accepted"


# ---------------------------------------------------------------- D2: documented differences (pinned)
@pytest.mark.anyio
async def test_clean_domain_evidence_verdict_is_equal_on_both_paths_after_stage_7b(db_session, app_instance):
    """
    Stage 7A pinned a real difference here (incident SUFFICIENT, case LIMITED: the case context had no entities for domain records and
    exceeded the context budget). Stage 7B fixed the cause at the entity/context layer (see ``test_stage7b_parity.py``); this test now
    asserts the corrected behaviour instead of the old difference.
    """
    _i, inc, case_p, _ = await run_both(db_session, app_instance, S.scenario_a_identity_cloud(), "p-diff")
    assert project_incident(inc)["verdict"] == "sufficient" == case_p["verdict"]
    assert "UNCORROBORATED_QUESTION" not in case_p["_audit"]["sufficiency_reason_codes"]
    assert project_incident(inc)["contradiction_codes"] == [] == case_p["contradiction_codes"]
