"""
Stage 6 (ADR-011): source-agnostic evidence-domain model, adapters, graph, threat-intelligence separation and
deterministic ATT&CK rules. Offline, pure (no database, no network, no LLM).
"""

from __future__ import annotations

import copy
import hashlib
import json
import uuid

import pytest

from app.modules.correlation.normalize import normalize_records, raw_digest
from app.modules.correlation.workflow import analyze
from app.modules.evidence_domains import scenarios as S
from app.modules.evidence_domains.adapters import ADAPTERS, EvidenceFormatError, import_file, parse_record, parse_time
from app.modules.evidence_domains.bridge import is_projectable, observation_to_event
from app.modules.evidence_domains.domain_attack import map_domain_techniques
from app.modules.evidence_domains.graph import build_graph
from app.modules.evidence_domains.model import EvidenceFamily, Observation, TimeStatus, TrustClass
from app.modules.evidence_domains.ti import IndicatorMatch, StaticIndicatorSet, enrich


def obs(record, index=0) -> Observation:
    d = raw_digest(record)
    return parse_record(record, key=uuid.uuid5(uuid.NAMESPACE_URL, f"{d}:{index}"), record_index=index, raw_sha256=d)


def code(record) -> str:
    with pytest.raises(EvidenceFormatError) as ei:
        obs(record)
    return ei.value.code


# ── adapter contract ─────────────────────────────────────────────────────────
def test_every_adapter_declares_contract_and_parses_its_types():
    for a in ADAPTERS:
        assert a.adapter_name and a.version and a.evidence_types and a.input_format
    recs = S.scenario_a_identity_cloud() + S.scenario_b_network_endpoint() + S.scenario_c_email_forensic()
    seen = {o.evidence_type for o in map(obs, recs)}
    for t in ("identity.signin", "identity.mfa", "cloud.api_call", "cloud.config_change", "network.dns", "network.flow",
              "email.message", "forensic.file", "forensic.registry", "forensic.memory_finding", "forensic.process_artifact", "analyst.observation"):
        assert t in seen


def test_no_alert_fields_are_required_and_no_siem_or_sysmon_identity_is_needed():
    o = obs(S.scenario_a_identity_cloud()[-1])
    assert o.family == EvidenceFamily.CLOUD and o.source_system == "cloudaudit-synthetic"
    assert o.evidence_id == "ct-2"                       # the source-native id is kept but never required
    bare = S.env("identity.signin", "x-idp", {"user": "u1", "ip": S.ATTACKER_IP}, t="2026-01-01T00:00:00Z")
    assert obs(bare).evidence_id is None


def test_raw_payload_and_digest_are_preserved_not_rewritten():
    rec = S.scenario_c_email_forensic()[0]
    before = copy.deepcopy(rec)
    o = obs(rec)
    assert rec == before                                    # parsing does not mutate the raw record
    assert o.raw_sha256 == raw_digest(before)
    assert o.attributes["from"] == "billing@invoice-portal.test"   # source-native fields survive in the bounded view
    assert o.adapter == "email" and o.adapter_version and o.collection_method == "api_export"


def test_unknown_but_valid_type_is_preserved_as_unclassified_not_rejected():
    o = obs(S.negative_unknown_type()[0])
    assert o.family == EvidenceFamily.UNCLASSIFIED and o.classification == "unclassified"
    assert o.entities == () and o.relations == () and o.attributes["foo"] == "bar"
    assert o.counts_for_corroboration is False
    assert o.event_time is not None


def test_partially_normalized_when_nothing_linkable_is_extracted():
    rec = S.env("cloud.api_call", "c", {"actor": "x", "action": "ListBuckets"}, t="2026-01-01T00:00:00Z")
    o = obs(rec)
    assert o.classification == "normalized" and o.entities        # the actor is a linkable entity
    rec = S.env("email.message", "m", {"message_id": "n/a", "from": "unknown"}, t="2026-01-01T00:00:00Z")
    assert obs(rec).classification == "partial"                   # placeholders are not emitted as link entities


@pytest.mark.parametrize("record, expected", [
    ({"schema": "aisop.evidence/9", "evidence_type": "identity.signin", "data": {}}, "SCHEMA_VERSION_UNSUPPORTED"),
    ({"schema": "aisop.evidence/1", "evidence_type": "identity.signin", "data": {"user": "u"}}, "FIELD_MISSING:source"),
    ({"schema": "aisop.evidence/1", "evidence_type": "Bad Type!", "source": {"system": "s"}, "data": {}}, "EVIDENCE_TYPE_INVALID"),
    ({"schema": "aisop.evidence/1", "evidence_type": "identity.signin", "source": {"system": "s"}, "data": "text"}, "FIELD_INVALID:data"),
    (S.env("identity.signin", "s", {"user": "u", "ip": "999.1.1.1"}, t="2026-01-01T00:00:00Z"), "FIELD_INVALID:ip"),
    (S.env("identity.signin", "s", {"ip": S.ATTACKER_IP}, t="2026-01-01T00:00:00Z"), "FIELD_MISSING:user"),
    (S.env("identity.signin", "s", {"user": "u" * 500}, t="2026-01-01T00:00:00Z"), "FIELD_TOO_LONG:user"),
    (S.env("forensic.file", "s", {"host": "h", "path": "C:\\a.exe", "sha256": "zz"}, t="2026-01-01T00:00:00Z"), "FIELD_INVALID:sha256"),
])
def test_malformed_records_are_rejected_with_fixed_codes_never_exception_text(record, expected):
    assert code(record) == expected


def test_malformed_records_are_quarantined_in_a_batch_and_do_not_stop_valid_ones():
    good = S.scenario_a_identity_cloud()[-1]
    res = normalize_records(S.malformed_records() + [good])
    assert {r.reason for r in res.rejected} >= {"SCHEMA_VERSION_UNSUPPORTED", "FIELD_MISSING:source", "FIELD_INVALID:ip", "NOT_AN_OBJECT", "FIELD_TOO_LONG:user"}
    assert len(res.events) == 1 and len(res.observations) == 1


# ── timestamps ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("value, status", [
    (None, TimeStatus.MISSING), ("", TimeStatus.MISSING), ("not a time", TimeStatus.INVALID), (True, TimeStatus.INVALID),
    (float("nan"), TimeStatus.INVALID), ("1850-01-01T00:00:00Z", TimeStatus.OUT_OF_RANGE), ("2999-01-01T00:00:00Z", TimeStatus.OUT_OF_RANGE),
    ("2026-01-01T00:00:00", TimeStatus.NAIVE_ASSUMED_UTC), ("2026-01-01T00:00:00Z", TimeStatus.VALID),
    ("2026-01-01T05:30:00+05:30", TimeStatus.VALID), (1767225600, TimeStatus.VALID),
])
def test_time_parsing_never_invents_a_time(value, status):
    dt, st = parse_time(value)
    assert st == status
    assert (dt is None) == (status in (TimeStatus.MISSING, TimeStatus.INVALID, TimeStatus.OUT_OF_RANGE))


def test_offset_time_is_converted_to_utc():
    dt, _ = parse_time("2026-01-01T05:30:00+05:30")
    assert dt.isoformat() == "2026-01-01T00:00:00+00:00"


def test_undated_observations_are_kept_but_not_projected_or_correlated():
    res = normalize_records(S.negative_bad_times())
    assert len(res.observations) == 3 and res.events == []
    assert {o.time_status for o in res.observations} == {TimeStatus.MISSING, TimeStatus.INVALID, TimeStatus.OUT_OF_RANGE}
    assert all(o.event_time is None and not is_projectable(o) for o in res.observations)
    with pytest.raises(ValueError):
        observation_to_event(res.observations[0])


def test_collected_at_is_kept_apart_from_event_time():
    rec = S.env("identity.signin", "s", {"user": "u1"}, t=None)
    rec["collected_at"] = "2026-02-02T00:00:00Z"
    o = obs(rec)
    assert o.event_time is None and o.collected_at is not None and o.time_status == TimeStatus.MISSING


# ── entity extraction and relationship validation ────────────────────────────
def test_entities_are_normalised_and_scoped_so_sharing_means_something():
    o = obs(S.scenario_b_network_endpoint()[0])
    assert ("file", "ws-fin-07:c:\\users\\public\\svc.exe") in o.entities           # path scoped to the host, lower-cased
    assert ("file_hash", S.SHA_TOOL) in o.entities
    sess = obs(S.scenario_a_identity_cloud()[5])
    assert ("logon_session", "idp-synthetic:sess-7f3a") in sess.entities             # session scoped to the issuing system


def test_bare_file_names_and_placeholders_are_not_link_entities():
    rec = S.env("forensic.file", "c", {"host": "h1", "path": "svc.exe", "sha256": "0" * 64}, t="2026-01-01T00:00:00Z")
    o = obs(rec)
    assert not [e for e in o.entities if e[0] == "file"]                             # no directory part: not a link entity
    assert not [e for e in o.entities if e[0] == "file_hash"]                        # all-zero digest carries no information


def test_relationships_are_only_those_the_record_states():
    o = obs(S.scenario_a_identity_cloud()[5])                                        # sign-in
    preds = {(r.subject[0], r.predicate.value, r.obj[0]) for r in o.relations}
    assert preds == {("user", "AUTHENTICATED_FROM", "ip"), ("user", "AUTHENTICATED_AS", "logon_session")}
    mail = obs(S.scenario_c_email_forensic()[0])
    assert {(r.predicate.value, r.obj[0]) for r in mail.relations if r.predicate.value == "CONTAINS"} == {("CONTAINS", "url"), ("CONTAINS", "file_hash")}
    assert any(e[0] == "domain" for e in mail.derived_entities)                      # computed, flagged as derived
    dns = obs(S.scenario_b_network_endpoint()[1])
    assert {r.predicate.value for r in dns.relations} == {"QUERIED", "RESOLVED_TO"}


def test_blocked_firewall_action_does_not_state_a_connection():
    rec = S.env("network.firewall", "fw", {"src_ip": "10.0.0.5", "dst_ip": S.C2_IP, "action": "deny"}, t="2026-01-01T00:00:00Z")
    o = obs(rec)
    assert o.outcome == "failure" and not o.relations


# ── projection onto the existing correlation engine ──────────────────────────
def test_projection_adds_no_severity_stage_or_classification():
    o = obs(S.scenario_a_identity_cloud()[5])
    e = observation_to_event(o)
    assert e.severity == "informational" and e.event_key == o.key and e.raw_sha256 == o.raw_sha256
    assert e.source_event_id == "identity.signin" and e.entities == tuple(sorted(o.entities))
    assert e.user == "alice.example" and e.src_ip == S.ATTACKER_IP


def test_analyst_statements_are_never_projected_to_correlation_events():
    res = normalize_records(S.negative_analyst_only())
    assert len(res.observations) == 2 and len(res.events) == 1
    note = next(o for o in res.observations if o.family == EvidenceFamily.ANALYST)
    assert note.trust_class == TrustClass.ANALYST_OBSERVATION and note.counts_for_corroboration is False


# ── graph ────────────────────────────────────────────────────────────────────
def test_graph_edges_keep_support_and_count_independent_evidence_once():
    res = analyze(S.negative_duplicates())
    g = res.incidents[0].graph
    edge = next(e for e in g.edges if e.predicate == "AUTHENTICATED_FROM")
    assert len(edge.observations) == 3 and edge.independent_support == 1          # 3 records, 1 evidence unit
    view = g.to_view()
    assert all(e["rationale"] for e in view["edges"]) and all(e["supporting_observations"] for e in view["edges"])
    json.dumps(view)                                                               # JSON-safe


def test_graph_does_not_join_on_weak_context_and_reports_it_as_weak():
    recs = [S.env("network.flow", "fw", {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.6", "action": "allow", "host": "hostx"}, t="2026-01-01T00:00:00Z"),
            S.env("forensic.process_artifact", "c", {"host": "hostx", "image": "C:\\Windows\\a.exe"}, t="2026-01-01T00:05:00Z")]
    res = analyze(recs)
    g = res.batch_graph
    assert all(c.strength == "weak" for c in g.correlations)
    assert not any(c["counts_as_corroboration"] for c in g.to_view()["correlations"])
    assert any(u["kind"] == "WEAK_CORRELATION_ONLY" for u in g.uncertainties)


def test_graph_records_uncertainty_for_undated_unclassified_and_tool_asserted():
    recs = S.negative_bad_times() + S.negative_unknown_type() + S.scenario_c_email_forensic()
    g = analyze(recs).batch_graph
    kinds = {u["kind"] for u in g.uncertainties}
    assert {"UNDATED_OBSERVATIONS", "UNCLASSIFIED_EVIDENCE", "TOOL_ASSERTED_ONLY"} <= kinds


def test_analyst_only_entities_are_flagged_and_do_not_become_nodes():
    note = obs(S.env("analyst.observation", "a", {"analyst": "t1", "statement": "s", "entities": [{"type": "ip", "value": "8.8.4.4"}]}, t="2026-01-01T00:00:00Z"))
    g = build_graph([], None, [note])
    assert ("ip", "8.8.4.4") not in g.nodes
    assert any(u["kind"] == "ANALYST_ONLY_ENTITIES" for u in g.uncertainties)


def test_contradictions_are_represented_in_graph_timeline_and_report():
    res = analyze(S.negative_contradiction())
    assert res.correlation.contradictions
    a = res.incidents[0]
    assert a.graph.contradictions and any(t.contradicts for t in a.timeline)
    assert "Contradictions: 1" in a.markdown


# ── threat intelligence separation ───────────────────────────────────────────
def _indicators() -> StaticIndicatorSet:
    s = StaticIndicatorSet()
    s.add("ip", S.ATTACKER_IP, IndicatorMatch(source="synthetic-feed", description="Listed as a password-spraying source", reference="syn-001"))
    s.add("ip", "10.0.0.5", IndicatorMatch(source="synthetic-feed", description="private address entry (must never be used)"))
    return s


def test_ti_is_context_attached_to_observed_entities_only_and_never_changes_the_verdict():
    recs = S.scenario_a_identity_cloud()
    plain = analyze(recs)
    enriched = analyze(recs, indicators=_indicators())
    a, b = plain.incidents[0], enriched.incidents[0]
    assert a.assessment.assessment_sha256 == b.assessment.assessment_sha256       # TI did not touch sufficiency
    assert [m.technique_id for m in a.mitre] == [m.technique_id for m in b.mitre]  # ... or ATT&CK mapping
    assert [t.title for t in a.timeline] == [t.title for t in b.timeline]
    en = b.enrichments
    assert len(en) == 1 and en[0].entity == ("ip", S.ATTACKER_IP) and en[0].trust_class == "ti_context"
    assert "not evidence" in en[0].statement
    assert "External intelligence (context only" in b.markdown and "password-spraying" in b.markdown


def test_ti_never_looks_up_private_addresses_and_survives_provider_failure():
    class Boom:
        def lookup(self, t, v):
            raise RuntimeError("feed down")

    recs = [obs(r) for r in S.scenario_b_network_endpoint()]
    assert enrich(recs, Boom()) == []
    looked: list = []

    class Spy:
        def lookup(self, t, v):
            looked.append((t, v))
            return []

    enrich(recs, Spy())
    assert ("ip", "10.0.4.21") not in looked and ("ip", S.C2_IP) in looked


def test_ti_is_not_looked_up_for_analyst_statements():
    note = obs(S.negative_analyst_only()[1])
    spy: list = []

    class Spy:
        def lookup(self, t, v):
            spy.append((t, v))
            return []

    enrich([note], Spy())
    assert spy == []


# ── ATT&CK mapping ───────────────────────────────────────────────────────────
def test_attack_rules_fire_on_structure_with_evidence_counts():
    a = {m.technique_id: m for m in map_domain_techniques([obs(r, i) for i, r in enumerate(S.scenario_a_identity_cloud())])}
    assert set(a) == {"T1621", "T1136.003", "T1098.003"} and a["T1621"].independent_evidence_count == 5
    c = {m.technique_id: m for m in map_domain_techniques([obs(r, i) for i, r in enumerate(S.scenario_c_email_forensic())])}
    assert set(c) == {"T1566.001", "T1566.002", "T1547.001", "T1055"}
    assert c["T1055"].vendor_asserted is True and "forensic memory tool" in c["T1055"].limitation   # tool-asserted is labelled
    assert c["T1566.002"].independent_evidence_count == 2                                            # needs two records


def test_suspicious_looking_text_alone_does_not_map_a_technique():
    recs = [S.env("cloud.api_call", "c", {"actor": "x.example", "action": "ListUsers", "resource": "AdministratorAccess createuser"}, t="2026-01-01T00:00:00Z"),
            S.env("forensic.registry", "d", {"host": "h", "key": "HKCU\\Software\\Vendor\\Settings\\Run"}, t="2026-01-01T00:01:00Z"),
            S.env("email.message", "m", {"message_id": "<a@b.test>", "from": "a@b.test", "to": ["c@d.test"], "subject": "powershell -enc AAAA phishing malware", "urls": ["https://l.test/x"]},
                  t="2026-01-01T00:02:00Z"),
            S.env("analyst.observation", "a", {"analyst": "t2", "statement": "This is T1566 phishing and CreateUser abuse"}, t="2026-01-01T00:03:00Z")]
    assert map_domain_techniques([obs(r, i) for i, r in enumerate(recs)]) == []


def test_email_link_without_a_later_dns_lookup_is_not_mapped_and_order_matters():
    mail, dns = S.scenario_c_email_forensic()[0], S.scenario_c_email_forensic()[1]
    assert not [m for m in map_domain_techniques([obs(mail)]) if m.technique_id == "T1566.002"]
    early = copy.deepcopy(dns)
    early["event_time"] = "2026-11-05T07:00:00Z"                                   # lookup BEFORE delivery
    assert not [m for m in map_domain_techniques([obs(mail, 0), obs(early, 1)]) if m.technique_id == "T1566.002"]


def test_four_mfa_denials_are_not_a_push_burst():
    recs = S.scenario_a_identity_cloud()[:4]
    assert map_domain_techniques([obs(r, i) for i, r in enumerate(recs)]) == []


def test_duplicated_records_cannot_inflate_a_rule_threshold():
    one = S.scenario_a_identity_cloud()[0]
    assert map_domain_techniques([obs(one, i) for i in range(10)]) == []           # same raw record x10 = 1 observation


def test_analyst_statements_never_satisfy_a_rule():
    claim = S.env("analyst.observation", "a", {"analyst": "t", "statement": "role assigned", "action": "AttachUserPolicy", "role": "Admin"}, t="2026-01-01T00:00:00Z")
    assert map_domain_techniques([obs(claim)]) == []


# ── file import path ─────────────────────────────────────────────────────────
def test_import_file_accepts_array_object_and_jsonl_and_is_bounded(tmp_path):
    recs = S.scenario_a_identity_cloud()
    (tmp_path / "a.json").write_text(json.dumps(recs))
    (tmp_path / "b.json").write_text(json.dumps({"evidence": recs}))
    (tmp_path / "c.jsonl").write_text("\n".join(json.dumps(r) for r in recs))
    for n in ("a.json", "b.json", "c.jsonl"):
        assert import_file(tmp_path / n) == recs
    (tmp_path / "bad.json").write_text("{not json")
    with pytest.raises(EvidenceFormatError) as ei:
        import_file(tmp_path / "bad.json")
    assert ei.value.code == "FILE_NOT_JSON"
    with pytest.raises(EvidenceFormatError):
        import_file(tmp_path / "a.json", max_records=2)
    with pytest.raises(EvidenceFormatError):
        import_file(tmp_path / "missing.json")
