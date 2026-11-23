"""
Stage 7B (owner decisions D1 and D2): clean-evidence parity at the entity/context layer, and the remaining report-synthesis parity.

Offline over SQLite through the real endpoints; nothing here validates PostgreSQL.

Root cause fixed (D1): domain evidence kept its entities only in ``normalized_payload["entities"]``; the case path built context entities from
ORM entity rows (none exist for domain records), so the case context had nothing to link and, with the stored metadata repeated in every event,
also exceeded the context budget (EVIDENCE_TRUNCATED). The case path now derives the context entities from the observation the approved adapter
re-parses from the PRESERVED raw payload (the incident path's source) and keeps only analytical attributes in the bounded context.
"""

from __future__ import annotations

import hashlib
import json
import uuid

import pytest
from sqlalchemy import select

from app.api.v1.endpoints.cases import get_case_llm_provider
from app.models.case import CaseAuditEventModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.evidence_domains import scenarios as S
from app.modules.evidence_domains.adapters import parse_record
from app.services.case_service import _context_attributes, _context_entities
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
REPORTS = "/api/v1/cases/{cid}/reports/synthesize"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _obs(record):
    raw = json.dumps(record, sort_keys=True).encode()
    return parse_record(record, key=uuid.uuid4(), record_index=0, raw_sha256=hashlib.sha256(raw).hexdigest())


class _Ev:                                           # the only attributes the helpers read
    def __init__(self, payload=None, entities=()):
        self.id, self.raw_evidence_id = uuid.uuid4(), uuid.uuid4()
        self.normalized_payload, self.entities = payload, list(entities)


# ------------------------------------------------------------------ D1 unit level: the derivation itself
def test_domain_context_entities_are_exactly_the_adapter_entities_of_the_preserved_record():
    rec = S.scenario_a_identity_cloud()[0]
    obs = _obs(rec)
    ev = _Ev({"entities": [["ip", "6.6.6.6"]]})                       # a stored/tampered list must not matter
    got = _context_entities(ev, obs)
    assert sorted((e.entity_type, e.entity_value) for e in got) == sorted(obs.entities)
    assert all(e.event_id == ev.id and e.raw_evidence_id == ev.raw_evidence_id for e in got)
    assert ("ip", "6.6.6.6") not in {(e.entity_type, e.entity_value) for e in got}
    assert [e.id for e in got] == [e.id for e in _context_entities(ev, obs)]        # deterministic ids


def test_forged_and_unsupported_entity_fields_create_no_canonical_entity():
    forged = dict(S.scenario_a_identity_cloud()[0])
    forged["data"] = dict(forged["data"], entities=[{"type": "ip", "value": "6.6.6.6"}], extra_entities=["user:root"])
    forged["entities"] = [["ip", "6.6.6.6"]]                                             # envelope-level forgery
    obs = _obs(forged)
    assert ("ip", "6.6.6.6") not in obs.entities and not any(v == "root" for _t, v in obs.entities)
    from app.modules.evidence_domains.adapters import EvidenceFormatError
    analyst = env("analyst.observation", "notes", {"analyst": "t1.example", "statement": "x", "entities": [{"type": "bogus", "value": "v"}]}, t="2026-11-07T09:00:00Z")
    with pytest.raises(EvidenceFormatError):
        _obs(analyst)


def test_unclassified_and_malformed_records_stay_without_entities():
    unk = _obs(S.negative_unknown_type()[0])
    assert unk.entities == () and unk.classification == "unclassified"
    assert _context_entities(_Ev({}), unk) == []
    bad = dict(S.scenario_a_identity_cloud()[0])
    bad["data"] = {"ip": "not-an-ip"}
    from app.modules.evidence_domains.adapters import EvidenceFormatError
    with pytest.raises(EvidenceFormatError):
        _obs(bad)


def test_legacy_events_keep_their_stored_entity_rows():
    class Row:
        def __init__(self):
            self.id, self.event_id, self.raw_evidence_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
            self.entity_type, self.entity_value, self.role, self.attributes = "ip", "203.0.113.9", None, {}
    row = Row()
    got = _context_entities(_Ev({}, [row]), None)
    assert [(e.entity_type, e.entity_value, e.role) for e in got] == [("ip", "203.0.113.9", "associated")]


def test_context_attributes_for_domain_events_exclude_storage_metadata_and_entities_but_keep_time_semantics():
    payload = {"aisop_domain": True, "schema": "x", "adapter": "a@1", "model_version": "1", "title": "t", "entities": [["ip", "1.2.3.4"]],
               "time_status": "missing", "event_time": None, "event_timestamp_is_ingestion_time": True, "trust_class": "raw_observed",
               "classification": "normalized", "source_system": "idp"}
    got = _context_attributes(_Ev(payload), True)
    assert got == {"time_status": "missing", "event_time": None, "event_timestamp_is_ingestion_time": True, "trust_class": "raw_observed",
                   "classification": "normalized", "source_system": "idp"}
    assert _context_attributes(_Ev(payload), False) == payload                          # legacy rows unchanged


# ------------------------------------------------------------------ projections
def project_inc(body):
    incs = body["incidents"]
    inc = max(incs, key=lambda i: i["event_count"]) if incs else None
    suff = inc["sufficiency"] if inc else body["batch_sufficiency"]
    return {"verdict": suff["verdict"], "rule_version": suff["rule_version"], "reason_codes": sorted(suff["reason_codes"])}


async def audit_last(db_session, case_id, action=None):
    rows = (await db_session.execute(select(CaseAuditEventModel).where(CaseAuditEventModel.case_id == case_id))).scalars().all()
    rows = [r for r in rows if isinstance(r.details, dict) and "sufficiency_reason_codes" in r.details and (action is None or r.action == action)]
    return rows[-1].details


def project_audit(d):
    return {"verdict": d["sufficiency_verdict"], "rule_version": d["sufficiency_rule_version"], "reason_codes": sorted(d["sufficiency_reason_codes"])}


async def run3(db_session, app_instance, records, prefix, provider=None, use_llm=False):
    """Import, run the incident path, the case investigation path and the case report path on the same evidence."""
    client, token, _lead, case = await setup(db_session, app_instance, [], prefix=prefix)
    async with Keep(client):
        imp = (await client.post(IMPORT.format(cid=case.id), json={"records": records}, headers=bearer(token))).json()
        eid = uuid.UUID(imp["evidence"][0]["evidence_id"])
        prov = provider or MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=eid))
        app_instance.dependency_overrides[get_case_llm_provider] = lambda: prov
        inc = (await client.post(START.format(cid=case.id), json={"use_llm": use_llm}, headers=bearer(token))).json()
        resp = await case_path(client, app_instance, token, case.id, eid, provider=prov)
        rep = await client.post(REPORTS.format(cid=case.id), json={}, headers=bearer(token))
    assert resp.status_code == 200, resp.text
    assert rep.status_code == 200, rep.text
    return {"inc": inc, "case": resp.json(), "bundle": rep.json(), "case_obj": case, "imp": imp,
            "audit_inv": await audit_last(db_session, case.id, "case_investigation_synthesized"),
            "audit_rep": await audit_last(db_session, case.id, "case_report_synthesized")}


# ------------------------------------------------------------------ D1 end to end: clean evidence parity
@pytest.mark.anyio
@pytest.mark.parametrize("builder", [S.scenario_a_identity_cloud, S.scenario_b_network_endpoint, S.scenario_c_email_forensic])
async def test_clean_evidence_gives_the_same_verdict_and_reason_codes_on_both_paths(db_session, app_instance, builder):
    r = await run3(db_session, app_instance, builder(), f"b-clean-{builder.__name__[9:13]}")
    a, b = project_inc(r["inc"]), project_audit(r["audit_inv"])
    assert a == b, (a, b)
    assert a["verdict"] == "sufficient" and not any(c.startswith("CONTRADICTORY") for c in a["reason_codes"])
    assert not any(g.startswith("CONTEXT_TRUNCATED") for g in r["case"]["output"]["uncertainty_and_data_gaps"])


@pytest.mark.anyio
async def test_clean_report_projection_is_equivalent_on_incident_and_case_report_paths(db_session, app_instance):
    r = await run3(db_session, app_instance, S.scenario_a_identity_cloud(), "b-clean-rep")
    inc = project_inc(r["inc"])
    assert project_audit(r["audit_rep"]) == inc                                          # case_report_synthesized: same verdict, codes, version
    tech = r["bundle"]["technical_report"]
    assert tech["context_sha256"] and r["bundle"]["provenance"]
    assert not any("CONTEXT_TRUNCATED" in g for g in tech["investigation_gaps"])
    assert r["inc"]["incidents"][0]["report_markdown"] and "Sufficiency" in r["inc"]["incidents"][0]["report_markdown"]


@pytest.mark.anyio
async def test_entity_derivation_does_not_change_the_preserved_record_digest_or_time_semantics(db_session, app_instance):
    recs = [S.negative_bad_times()[0]] + S.scenario_a_identity_cloud()
    r = await run3(db_session, app_instance, recs, "b-raw")
    rows = (await db_session.execute(select(RawEvidence))).scalars().all()
    by_id = {x.sha256_hash: x for x in rows}
    for rec in recs:
        digest = r["imp"]["evidence"][recs.index(rec)]["sha256"]
        assert digest in by_id and by_id[digest].raw_payload == rec                       # raw payload and digest unchanged
    undated = next(e for e in (await db_session.execute(select(NormalizedEventModel))).scalars().all() if e.event_id == "no-time" or e.normalized_payload.get("time_status") == "missing")
    assert undated.normalized_payload["event_time"] is None and undated.normalized_payload["event_timestamp_is_ingestion_time"] is True


@pytest.mark.anyio
async def test_case_a_evidence_cannot_create_entities_or_evidence_ids_in_case_b(db_session, app_instance):
    ra = await run3(db_session, app_instance, S.scenario_a_identity_cloud(), "b-iso-a")
    rb = await run3(db_session, app_instance, S.negative_unrelated(), "b-iso-b")
    ids_a = set(ra["audit_inv"]["sufficiency_evidence_ids"])
    ids_b = set(rb["audit_inv"]["sufficiency_evidence_ids"])
    assert ids_a and not (ids_a & ids_b)


@pytest.mark.anyio
async def test_clean_case_path_is_deterministic_with_the_llm_disabled(db_session, app_instance):
    ok = await run3(db_session, app_instance, S.scenario_a_identity_cloud(), "b-det-ok")
    bad = await run3(db_session, app_instance, S.scenario_a_identity_cloud(), "b-det-bad", provider=FailingProvider())
    assert project_audit(ok["audit_inv"]) == project_audit(bad["audit_inv"])
    assert bad["audit_inv"]["model_name"] == "deterministic_fallback" or bad["audit_inv"].get("fallback_reason")


# ------------------------------------------------------------------ D2: case_report_synthesized paired with the incident path
@pytest.mark.anyio
@pytest.mark.parametrize("builder, code", [
    (ordering_violation, "CONTRADICTORY_EVIDENCE:ordering"),
    (outcome_conflict, "CONTRADICTORY_EVIDENCE:outcome"),
    (identity_conflict, "CONTRADICTORY_EVIDENCE:identity"),
    (temporal_conflict, "CONTRADICTORY_EVIDENCE:temporal"),
])
async def test_report_path_projection_matches_the_incident_path_for_contradictions(db_session, app_instance, builder, code):
    r = await run3(db_session, app_instance, builder(), f"b-rep-{code[-5:]}")
    inc = project_inc(r["inc"])
    rep = project_audit(r["audit_rep"])
    assert inc["verdict"] == rep["verdict"] == "limited" and inc["rule_version"] == rep["rule_version"] == "suff-v4"
    assert [c for c in inc["reason_codes"] if c.startswith("CONTRADICTORY")] == [c for c in rep["reason_codes"] if c.startswith("CONTRADICTORY")] == [code]
    gaps = r["bundle"]["technical_report"]["investigation_gaps"]
    assert any(code in g for g in gaps)                                               # the contradiction is disclosed in the report bundle
    assert r["bundle"]["is_fallback_active"] in (True, False)


@pytest.mark.anyio
async def test_report_path_discloses_unknown_event_time_like_the_incident_path(db_session, app_instance):
    r = await run3(db_session, app_instance, S.negative_bad_times()[:1] + S.scenario_a_identity_cloud(), "b-rep-und")
    assert r["inc"]["observation_counts"]["undated"] == 1
    assert any(g.startswith("UNDATED_OBSERVATIONS") for g in r["bundle"]["technical_report"]["investigation_gaps"])
    assert "Event time unknown: 1 preserved record(s)" in r["inc"]["incidents"][0]["report_markdown"]


# ------------------------------------------------------------------ D2: unsupported AI claim, paired (the incident path DOES accept the same injectable provider)
@pytest.mark.anyio
async def test_unsupported_ai_claim_cannot_change_verdict_or_findings_on_either_path(db_session, app_instance):
    bogus = MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=uuid.uuid4()))      # cites evidence that is not in the case
    r = await run3(db_session, app_instance, outcome_conflict(), "b-bogus", provider=bogus, use_llm=True)
    baseline = await run3(db_session, app_instance, outcome_conflict(), "b-bogus-base", use_llm=False)
    inc_inc = max(r["inc"]["incidents"], key=lambda i: i["event_count"])
    code = "CONTRADICTORY_EVIDENCE:outcome"
    # verdict and findings: identical to the run without any model, on the incident path, the case path and the report path
    assert project_inc(r["inc"]) == project_inc(baseline["inc"])
    assert project_audit(r["audit_inv"])["verdict"] == project_audit(baseline["audit_inv"])["verdict"] == "limited"
    assert code in inc_inc["sufficiency"]["reason_codes"] and code in r["audit_inv"]["sufficiency_reason_codes"] and code in r["audit_rep"]["sufficiency_reason_codes"]
    # the ungrounded claim is not accepted as grounded on either path
    assert inc_inc["llm"] is not None and inc_inc["llm"]["decision"] != "accepted"
    assert r["audit_inv"]["decision"] != "accepted"
    assert not any(c["grounding"] == "validated_reference" for c in inc_inc["llm"]["claims"])
    assert r["bundle"]["technical_report"]["confirmed_findings"] == [] or all(
        c["grounding_status"] == "validated_reference" for c in r["bundle"]["technical_report"]["confirmed_findings"])


# ------------------------------------------------------------------ ADR-017: vantage-level independence has the same effect on both paths
@pytest.mark.anyio
async def test_same_vantage_evidence_gives_the_same_capped_verdict_on_both_paths(db_session, app_instance):
    records = [
        S.env("forensic.file", "dfir-collector-synthetic", {"host": "ws-fin-07", "path": "C:\\Users\\Public\\svc.exe", "sha256": S.SHA_TOOL},
              t="2026-11-04T09:59:50Z", method="triage_collection"),
        S.env("forensic.process_artifact", "dfir-collector-synthetic", {"host": "ws-fin-07", "image": "C:\\Users\\Public\\svc.exe", "sha256": S.SHA_TOOL,
                                                                       "source_artifact": "process_listing"}, t="2026-11-04T10:00:08Z", method="triage_collection"),
    ]
    r = await run3(db_session, app_instance, records, "b-vantage")
    a, b = project_inc(r["inc"]), project_audit(r["audit_inv"])
    assert a == b, (a, b)
    assert a["verdict"] == "limited" and "SAME_VANTAGE_ONLY" in a["reason_codes"]
