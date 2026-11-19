"""
Offline regression tests for the revoked-ID ATT&CK guardrail (lifecycle + successor evidence + AI-claim handling).

Synthetic catalogue fixtures mirror the pinned v20.1 relationships (verified separately against the real file in
``test_synthetic_policy_matches_the_real_pinned_catalogue``, which reads the dataset once and is skipped if it is absent).
No network, DNS, socket, database, model call or application startup is involved.
"""

from __future__ import annotations

import ast
import re
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.modules.ai.guardrails import attack_policy as ap
from app.modules.ai.guardrails.attack_policy import (
    EVIDENCE_CONTRACTS, SUCCESSOR_TARGET_IDS, EvidenceStatus, assess_attack_technique,
)
from app.modules.ai.guardrails.validator import GuardrailDecision, InvestigationOutputValidator
from app.modules.attack_reference import try_load_catalogue
from app.modules.attack_reference.loader import ENTERPRISE_V20_1, PinnedRelease
from app.schemas.attack_taxonomy import TaxonomyState
from app.schemas.investigation import ContextEventItem, MitreAttackHypothesis
from tests.unit.test_attack_reference_loader import SENTINEL, mem, rel, sid, tactic, technique
from tests.unit.test_output_guardrails_p2 import VALID_SHA256, make_test_context, make_test_output

CLOCK = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
BACKEND = Path(__file__).resolve().parents[2]

#: Expected old -> successor relationships (a TEST expectation, from the corrected closeout matrix; the production code
#: never stores them and the real-file test below verifies this table against the pinned dataset).
OLD_TO_NEW = {
    "T1070.001": "T1685.005", "T1562": "T1685", "T1562.001": "T1685", "T1562.002": "T1685.001", "T1562.003": "T1690",
    "T1562.004": "T1686", "T1562.006": "T1685", "T1562.007": "T1686.001", "T1562.008": "T1685.002", "T1562.009": "T1688",
    "T1562.010": "T1689", "T1562.011": "T1685.003", "T1562.012": "T1685.004", "T1562.013": "T1686.002",
}
SHARED_T1685 = ("T1562", "T1562.001", "T1562.006")
CONTROLS = ("T1078", "T1059.001", "T1110")


def guardrail_document() -> dict:
    objs = [
        {"type": "x-mitre-collection", "id": sid("x-mitre-collection", 1), "spec_version": "2.1", "name": "Enterprise ATT&CK", "x_mitre_version": "20.1"},
        tactic(10, "TA0002", "Execution", "execution"), tactic(11, "TA0005", "Stealth", "stealth"),
        tactic(12, "TA0112", "Defense Impairment", "defense-impairment"), tactic(13, "TA0001", "Initial Access", "initial-access"),
        tactic(14, "TA0006", "Credential Access", "credential-access"),
    ]
    n, ids = 100, {}

    def add(aid, name, phases, **kw):
        nonlocal n
        n += 1
        ids[aid] = n
        objs.append(technique(n, aid, name, phases, **kw))

    for t in sorted(set(OLD_TO_NEW.values())):                                  # current successors (parents first)
        add(t, f"Synthetic {t}", ("defense-impairment",))
    for old in OLD_TO_NEW:
        add(old, f"Synthetic old {old}", ("stealth",), revoked=True)
    add("T1078", "Valid Accounts", ("initial-access",)); add("T1059", "Command and Scripting Interpreter", ("execution",))
    add("T1059.001", "PowerShell", ("execution",)); add("T1110", "Brute Force", ("credential-access",))
    add("T1043", "Commonly Used Port", ("execution",), x_mitre_deprecated=True)
    add("T1562.099", "Synthetic current technique that only shares an old prefix", ("defense-impairment",))
    add("T1404", "Mobile Only", ("execution",), domains=("mobile-attack",))
    r = 500
    for old, new in OLD_TO_NEW.items():
        r += 1
        objs.append(rel(r, "revoked-by", ids[old], ids[new]))
    for sub in sorted(t for t in set(OLD_TO_NEW.values()) if "." in t):
        r += 1
        objs.append(rel(r, "subtechnique-of", ids[sub], ids[sub.split(".")[0]]))
    r += 1
    objs.append(rel(r, "subtechnique-of", ids["T1059.001"], ids["T1059"]))
    r += 1
    objs.append(rel(r, "subtechnique-of", ids["T1562.099"], ids["T1562"]))      # a live sub-technique needs a parent link
    return {"type": "bundle", "id": "bundle--" + "0" * 8 + "-0000-4000-8000-" + "0" * 12, "objects": objs}


@pytest.fixture(scope="module")
def cat():
    return mem(guardrail_document())


def make_event(**over) -> ContextEventItem:
    base = dict(event_uuid=uuid.uuid4(), raw_evidence_sha256=VALID_SHA256, event_id="EVT-1", event_type="process_creation",
                timestamp_utc=datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc), action="start", outcome="success",
                severity="low", source_identifier="WIN-HOST-01", summary="a process started", attributes={})
    base.update(over)
    return ContextEventItem(**base)


def ev_1102(**over) -> ContextEventItem:
    attrs = {"source_type": "windows_security", "vendor_severity": "1102", "category": "defense_evasion",
             "provider": "Microsoft-Windows-Security-Auditing", "custom_fields": {"event_id": "1102"}}
    return make_event(event_id="winsec-1102-abc", event_type="alert.defense_evasion", action="alert_triggered", severity="critical",
                      summary="Windows Security 1102: Audit Log Cleared", attributes=attrs, **over)


def run(cat_or_none, hyps, events=None, **vkw):
    events = events or [make_event()]
    ctx = make_test_context(events=events)
    out = make_test_output(ctx, mitre_hypotheses=hyps)
    v = InvestigationOutputValidator(clock=lambda: CLOCK, attack_reference=cat_or_none, **vkw)
    return out, v.validate(out, ctx), v


def hyp(tid, events, conf=0.8, name="Model supplied name", tactics=("Defense Evasion",), reasoning="Model reasoning about the technique."):
    return MitreAttackHypothesis(technique_id=tid, technique_name=name, tactics=list(tactics),
                                 supporting_event_uuids=[e.event_uuid for e in events], confidence=conf, reasoning=reasoning)


def attack_rules(res):
    return [v for v in res.violations if v.rule_id.startswith("SEC-GR-ATTACK")]


# ── policy structure ────────────────────────────────────────────────────────────────────────────────────────────
def test_exactly_twelve_successor_targets_each_with_an_evidence_contract():
    assert len(SUCCESSOR_TARGET_IDS) == 12 == len(set(SUCCESSOR_TARGET_IDS))
    assert set(SUCCESSOR_TARGET_IDS) == set(EVIDENCE_CONTRACTS) == set(OLD_TO_NEW.values())


def test_only_the_windows_1102_target_has_a_telemetry_backed_contract_and_the_rest_name_their_prerequisite():
    supported = [t for t, c in EVIDENCE_CONTRACTS.items() if c.predicate is not None]
    assert supported == ["T1685.005"]
    for t, c in EVIDENCE_CONTRACTS.items():
        if t != "T1685.005":
            assert c.missing_prerequisite and c.required_observable and c.required_fields       # documented, never fabricated


def test_policy_module_stores_no_old_to_new_mapping():
    src = (BACKEND / "app" / "modules" / "ai" / "guardrails" / "attack_policy.py").read_text(encoding="utf-8")
    assert not re.search(r'"T1070\.001"|"T1562[\.\"]', src)           # old identifiers appear nowhere as data


# ── 12.1 the 14 revoked identifiers ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("old,new", sorted(OLD_TO_NEW.items()))
def test_each_old_id_is_obsolete_with_its_exact_successor_and_no_substitution(cat, old, new):
    a = assess_attack_technique(old, [], cat)
    assert a.taxonomy_status == TaxonomyState.REVOKED and a.catalogue_lifecycle == "revoked"
    assert [s.attack_id for s in a.successors] == [new]
    assert "not evidence" in ap.obsolete_description(a) and a.technique_id == old        # suggestion only; old id kept, never replaced
    assert a.evidence_status == EvidenceStatus.NOT_ASSESSED and a.inconclusive is False


@pytest.mark.parametrize("old", SHARED_T1685)
def test_shared_t1685_successor_requires_analyst_choice_and_is_not_collapsed(cat, old):
    a = assess_attack_technique(old, [], cat)
    s = a.successors[0]
    assert s.attack_id == "T1685" and set(s.shared_with) == set(SHARED_T1685) - {old}
    assert "analyst choice required" in ap.obsolete_tag(a)


def test_a_successor_with_a_unique_target_is_not_flagged_as_shared(cat):
    assert assess_attack_technique("T1070.001", [], cat).successors[0].shared_with == ()


# ── 12.2 the 12 successors ──────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("target", sorted(SUCCESSOR_TARGET_IDS))
def test_each_successor_is_current_in_the_catalogue_but_unsupported_without_structured_evidence(cat, target):
    a = assess_attack_technique(target, [make_event()], cat)
    assert a.taxonomy_status == TaxonomyState.CURRENT_VALID and a.evidence_status == EvidenceStatus.UNSUPPORTED and a.inconclusive


def test_t1685_005_is_supported_only_by_the_structured_windows_1102_signal(cat):
    e = ev_1102()
    a = assess_attack_technique("T1685.005", [make_event(), e], cat)
    assert a.evidence_status == EvidenceStatus.SUPPORTED and a.evidence_event_uuids == (e.event_uuid,) and not a.inconclusive
    assert a.taxonomy_status == TaxonomyState.CURRENT_VALID                  # the two statuses are independent fields


@pytest.mark.parametrize("not_support", [
    make_event(summary="Windows Security 1102: Audit Log Cleared"),                                   # free text only
    make_event(event_id="1102", summary="audit log cleared", attributes={"title": "Audit Log Cleared"}),  # native id without source_type
    ev_1102().model_copy(update={"attributes": {"source_type": "generic_siem", "custom_fields": {"event_id": "1102"}}}),
    ev_1102().model_copy(update={"attributes": {"source_type": "windows_security", "custom_fields": {"event_id": "4625"}}}),
    ev_1102().model_copy(update={"attributes": {"source_type": "windows_security", "custom_fields": "1102"}}),
    ev_1102().model_copy(update={"attributes": {"source_type": "windows_security"}}),
])
def test_other_events_do_not_support_t1685_005(cat, not_support):
    assert assess_attack_technique("T1685.005", [not_support], cat).evidence_status == EvidenceStatus.UNSUPPORTED


@pytest.mark.parametrize("other", sorted(set(SUCCESSOR_TARGET_IDS) - {"T1685.005"}))
def test_a_1102_event_does_not_support_any_other_successor(cat, other):
    assert assess_attack_technique(other, [ev_1102()], cat).evidence_status == EvidenceStatus.UNSUPPORTED


def test_the_replacement_relationship_alone_is_never_evidence(cat):
    old = assess_attack_technique("T1070.001", [ev_1102()], cat)             # revoked id cited with the very event
    assert old.taxonomy_status == TaxonomyState.REVOKED and old.evidence_status == EvidenceStatus.NOT_ASSESSED
    assert assess_attack_technique("T1685.005", [], cat).evidence_status == EvidenceStatus.UNSUPPORTED


# ── 12.3 general identifiers ────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("tid", CONTROLS)
def test_unrelated_valid_current_ids_remain_permitted(cat, tid):
    a = assess_attack_technique(tid, [make_event()], cat)
    assert a.taxonomy_status == TaxonomyState.CURRENT_VALID and a.evidence_status == EvidenceStatus.NOT_ASSESSED and not a.inconclusive


def test_a_current_technique_that_merely_shares_the_old_prefix_is_not_blocked(cat):
    a = assess_attack_technique("T1562.099", [make_event()], cat)
    assert a.taxonomy_status == TaxonomyState.CURRENT_VALID and not a.successors   # catalogue-driven, not prefix-driven


def test_sub_technique_and_parent_are_assessed_separately(cat):
    assert assess_attack_technique("T1059.001", [], cat).technique_id == "T1059.001"
    assert assess_attack_technique("T1059", [], cat).taxonomy_status == TaxonomyState.CURRENT_VALID
    assert assess_attack_technique("T1685", [ev_1102()], cat).evidence_status == EvidenceStatus.UNSUPPORTED  # no parent from sub


def test_unknown_wrong_domain_absent_and_invalid_ids_are_distinct_and_never_benign(cat):
    for tid in ("T9999", "T1404", "T1562.005"):
        a = assess_attack_technique(tid, [], cat)
        assert a.taxonomy_status == (TaxonomyState.WRONG_DOMAIN if tid == 'T1404' else TaxonomyState.UNKNOWN)
        assert a.inconclusive and not a.successors   # nothing inferred
    for tid in ("T12", "t1685.005", " T1685", "T1685.0050", ""):
        assert assess_attack_technique(tid, [], cat).taxonomy_status == TaxonomyState.INVALID


def test_deprecated_is_obsolete_without_inventing_a_successor(cat):
    a = assess_attack_technique("T1043", [], cat)
    assert a.taxonomy_status == TaxonomyState.DEPRECATED and a.catalogue_lifecycle == "deprecated" and a.successors == ()


def test_without_a_catalogue_taxonomy_is_unavailable_and_inconclusive_but_contracts_still_apply():
    a = assess_attack_technique("T1685.005", [make_event()], None)
    assert a.taxonomy_status == TaxonomyState.NOT_CONFIGURED and a.evidence_status == EvidenceStatus.UNSUPPORTED and a.inconclusive
    assert assess_attack_technique("T1078", [], None).taxonomy_status == TaxonomyState.NOT_CONFIGURED


def test_assessment_is_deterministic(cat):
    events = [ev_1102()]
    a, b = assess_attack_technique("T1685.005", events, cat), assess_attack_technique("T1685.005", events, cat)
    assert a == b and a.model_dump() == b.model_dump()


# ── validator integration ───────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("old,new", sorted(OLD_TO_NEW.items()))
def test_validator_does_not_accept_a_revoked_id_but_preserves_it_and_suggests_the_successor(cat, old, new):
    e = make_event()
    out, res, _ = run(cat, [hyp(old, [e], conf=0.85, name="Old Name", tactics=("Defense Evasion",))], [e])
    h = res.output.mitre_attack_hypotheses[0]
    assert (h.technique_id, h.technique_name, list(h.tactics)) == (old, "Old Name", ["Defense Evasion"])     # preserved as received
    assert h.confidence == 0.85 and ap.MARK_OBSOLETE in h.reasoning and new in h.reasoning     # evidence confidence is independent
    v = [x for x in attack_rules(res) if x.rule_id == ap.RULE_OBSOLETE]
    assert len(v) == 1 and new in v[0].description and "not evidence" in v[0].description
    assert "never substituted" in v[0].remediation_applied
    assert res.decision == GuardrailDecision.REMEDIATED and res.is_valid                 # a real remediation occurred; not benign
    assert out.mitre_attack_hypotheses[0].confidence == 0.85                             # the original record is untouched
    assert len(res.output.mitre_attack_hypotheses) == 1                                   # nothing was replaced or added


def test_a_revoked_id_is_not_rescued_by_matching_evidence(cat):
    e = ev_1102()
    _, res, _ = run(cat, [hyp("T1070.001", [e], conf=0.9)], [e])
    assert res.output.mitre_attack_hypotheses[0].confidence == 0.9 and attack_rules(res)[0].rule_id == ap.RULE_OBSOLETE


def test_shared_successor_hypotheses_stay_separate_and_no_t1685_hypothesis_is_inferred(cat):
    e = make_event()
    _, res, _ = run(cat, [hyp(t, [e]) for t in SHARED_T1685], [e])
    got = [h.technique_id for h in res.output.mitre_attack_hypotheses]
    assert got == list(SHARED_T1685) and "T1685" not in got
    assert all("analyst choice required" in h.reasoning for h in res.output.mitre_attack_hypotheses)


@pytest.mark.parametrize("target", sorted(SUCCESSOR_TARGET_IDS))
def test_validator_zeroes_a_successor_claim_without_its_structured_evidence(cat, target):
    e = make_event()
    _, res, _ = run(cat, [hyp(target, [e], conf=0.8)], [e])
    h = res.output.mitre_attack_hypotheses[0]
    assert h.confidence == 0.0 and ap.MARK_UNSUPPORTED in h.reasoning
    v = [x for x in attack_rules(res) if x.rule_id == ap.RULE_UNSUPPORTED]
    assert len(v) == 1 and v[0].severity.value == "high" and res.decision == GuardrailDecision.REMEDIATED


def test_t1685_005_with_the_structured_1102_event_is_accepted_and_keeps_its_confidence(cat):
    e = ev_1102()
    _, res, _ = run(cat, [hyp("T1685.005", [e], conf=0.7)], [e])
    h = res.output.mitre_attack_hypotheses[0]
    assert h.confidence == 0.7 and attack_rules(res) == [] and h.supporting_event_uuids == [e.event_uuid]
    assert res.decision == GuardrailDecision.PASS                       # evidence refs are preserved on the hypothesis


def test_free_text_1102_wording_and_model_claims_cannot_self_support(cat):
    e = make_event(summary="Windows Security 1102: Audit Log Cleared", attributes={})
    _, res, _ = run(cat, [hyp("T1685.005", [e], conf=0.9, reasoning="Event 1102 proves the audit log was cleared; confirmed.")], [e])
    assert res.output.mitre_attack_hypotheses[0].confidence == 0.0


def test_unknown_and_wrong_domain_ids_are_annotated_unvalidated_without_forcing_confidence_to_zero(cat):
    for tid in ("T9999", "T1404"):
        e = make_event()
        _, res, _ = run(cat, [hyp(tid, [e], conf=0.6)], [e])
        h = res.output.mitre_attack_hypotheses[0]
        assert h.confidence == 0.6 and ap.MARK_UNVALIDATED in h.reasoning and "not benign" in h.reasoning
        v = attack_rules(res)
        assert [x.rule_id for x in v] == [ap.RULE_UNVALIDATED] and v[0].severity.value == "low"
        assert "confidence unchanged" in v[0].remediation_applied


def test_invalid_syntax_keeps_the_existing_behaviour_only(cat):
    e = make_event()
    _, res, _ = run(cat, [hyp("T12", [e], conf=0.6)], [e])
    assert res.output.mitre_attack_hypotheses[0].confidence == 0.0
    assert [v.rule_id for v in res.violations if "MITRE" in v.rule_id or "ATTACK" in v.rule_id] == ["SEC-GR-MITRE-SYNTAX"]


@pytest.mark.parametrize("tid", ("T1059.001", "T1110", "T1562.099"))
def test_valid_unrelated_current_ids_are_untouched_by_the_new_checks(cat, tid):
    e = make_event()
    _, res, _ = run(cat, [hyp(tid, [e], conf=0.7)], [e])
    assert res.output.mitre_attack_hypotheses[0].confidence == 0.7 and attack_rules(res) == []


def test_existing_t1078_guardrail_is_unchanged_with_a_catalogue(cat):
    failed = make_event(outcome="failure", action="logon_attempt", event_id="4625")
    _, res, _ = run(cat, [hyp("T1078", [failed], conf=0.9)], [failed])
    h = res.output.mitre_attack_hypotheses[0]
    assert h.confidence == 0.35 and any(v.rule_id == "SEC-GR-MITRE-T1078-FAILED-LOGON" for v in res.violations)


# ── catalogue states ────────────────────────────────────────────────────────────────────────────────────────────
def test_not_configured_is_the_default_legacy_behaviour_plus_successor_evidence_rule():
    e = make_event()
    _, res, v = run(None, [hyp("T1070.001", [e], conf=0.8), hyp("T1685.005", [e], conf=0.8)], [e])
    assert v.attack_reference_state == "not_configured"
    old, new = res.output.mitre_attack_hypotheses
    assert old.confidence == 0.8 and ap.MARK_OBSOLETE not in old.reasoning       # lifecycle needs the catalogue: reported gap
    assert new.confidence == 0.0 and ap.MARK_UNSUPPORTED in new.reasoning       # evidence rule needs no catalogue


def test_legacy_keyword_guard_is_preserved_when_no_catalogue_is_available():
    e = make_event(summary="cmd.exe /c echo Disable-Antivirus", attributes={"command_line": 'cmd.exe /c echo "Disable-Antivirus"'})
    _, res, _ = run(None, [hyp("T1562.001", [e], conf=0.85)], [e])
    assert res.output.mitre_attack_hypotheses[0].confidence == 0.0 and "UNSUPPORTED_T1562" in res.output.mitre_attack_hypotheses[0].reasoning
    assert any(v.rule_id == "SEC-GR-MITRE-UNSUPPORTED-T1562" for v in res.violations)


def test_with_a_catalogue_the_revoked_path_replaces_the_keyword_guard(cat):
    e = make_event()
    _, res, _ = run(cat, [hyp("T1562.001", [e], conf=0.85)], [e])
    h = res.output.mitre_attack_hypotheses[0]
    assert ap.MARK_OBSOLETE in h.reasoning and "UNSUPPORTED_T1562" not in h.reasoning
    assert not any(v.rule_id == "SEC-GR-MITRE-UNSUPPORTED-T1562" for v in res.violations)


def test_an_unavailable_catalogue_is_explicit_and_never_valid(tmp_path):
    result = try_load_catalogue(tmp_path / "absent.json", PinnedRelease("20.1", "0" * 64, "enterprise-attack", "Enterprise ATT&CK"))
    e = make_event()
    _, res, v = run(result, [hyp("T1078", [e], conf=0.6)], [e])
    h = res.output.mitre_attack_hypotheses[0]
    assert v.attack_reference_state == "unavailable" and h.confidence == 0.6
    assert ap.MARK_UNAVAILABLE in h.reasoning and "not benign" in h.reasoning
    assert [x.rule_id for x in attack_rules(res)] == [ap.RULE_UNAVAILABLE]
    assert res.is_valid                                                   # unrelated deterministic processing is not broken


def test_a_loaded_result_object_works_like_the_catalogue(cat):
    from app.modules.attack_reference import CatalogueLoadResult

    e = make_event()
    _, res, v = run(CatalogueLoadResult(catalogue=cat), [hyp("T1070.001", [e])], [e])
    assert v.attack_reference_state == "available" and attack_rules(res)[0].rule_id == ap.RULE_OBSOLETE


def test_invalid_reference_argument_is_a_programming_error():
    with pytest.raises(TypeError):
        InvestigationOutputValidator(attack_reference="not-a-catalogue")  # type: ignore[arg-type]


# ── determinism, idempotence, safety ────────────────────────────────────────────────────────────────────────────
def test_identical_input_gives_identical_results(cat):
    e = make_event()
    ctx = make_test_context(events=[e])
    out = make_test_output(ctx, mitre_hypotheses=[hyp("T1562.003", [e]), hyp("T1690", [e]), hyp("T9999", [e])])
    v = InvestigationOutputValidator(clock=lambda: CLOCK, attack_reference=cat)
    assert v.validate(out, ctx).model_dump() == v.validate(out, ctx).model_dump()


def test_revalidating_an_already_remediated_output_adds_no_duplicate_annotations(cat):
    e = make_event()
    ctx = make_test_context(events=[e])
    out = make_test_output(ctx, mitre_hypotheses=[hyp("T1070.001", [e]), hyp("T1690", [e]), hyp("T9999", [e])])
    v = InvestigationOutputValidator(clock=lambda: CLOCK, attack_reference=cat)
    first = v.validate(out, ctx)
    second = v.validate(first.output, ctx)
    assert attack_rules(second) == []
    for h1, h2 in zip(first.output.mitre_attack_hypotheses, second.output.mitre_attack_hypotheses):
        assert h1.reasoning == h2.reasoning and h1.confidence == h2.confidence


def test_taxonomy_annotation_does_not_change_the_cited_evidence_or_other_claims(cat):
    e = make_event()
    _, res, _ = run(cat, [hyp("T9999", [e])], [e])
    assert res.output.mitre_attack_hypotheses[0].supporting_event_uuids == [e.event_uuid]


def test_no_descriptions_or_network_are_involved(cat, monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("network activity attempted")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refuse)
    e = make_event()
    _, res, _ = run(cat, [hyp("T1562.001", [e]), hyp("T1685", [e]), hyp("T9999", [e])], [e])
    assert SENTINEL not in res.model_dump_json()                            # catalogue descriptions never reach results


def test_policy_module_imports_only_stdlib_pydantic_and_project_modules():
    src = (BACKEND / "app" / "modules" / "ai" / "guardrails" / "attack_policy.py").read_text(encoding="utf-8")
    seen = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            seen |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            seen.add(node.module.split(".")[0])
    assert seen <= {"__future__", "uuid", "dataclasses", "enum", "typing", "pydantic", "app"}, sorted(seen)


def test_windows_adapter_default_for_event_1102_is_unchanged():
    from app.modules.alerts.adapters.windows_security_adapter import WindowsSecurityAdapter

    alert = WindowsSecurityAdapter().adapt({"Event": {"System": {"EventID": 1102, "Computer": "SRV-01"}, "EventData": {"SubjectUserName": "attacker"}}})
    m = alert.mitre_attack[0]
    assert (m.technique_id, m.tactic_id, m.tactic_name) == ("T1070.001", "TA0005", "Defense Evasion")
    assert alert.category == "defense_evasion" and alert.severity == "critical"


# ── consistency with the real pinned catalogue (read once; skipped when the file is absent) ─────────────────────
def test_synthetic_policy_matches_the_real_pinned_catalogue():
    result = try_load_catalogue()
    if not result.available:
        pytest.skip(f"pinned dataset unavailable: {result.error_code}")
    real = result.catalogue
    assert real.meta.release_version == ENTERPRISE_V20_1.release_version
    olds = sorted(t.attack_id for t in real.techniques() if t.revoked and (t.attack_id == "T1070.001" or t.attack_id.startswith("T1562")))
    assert olds == sorted(OLD_TO_NEW) and len(olds) == 14
    for old, new in OLD_TO_NEW.items():                                      # exact relationship per old id
        assert real.get_technique(old).replaced_by == (new,)
    targets = {s for old in olds for s in real.get_technique(old).replaced_by}
    assert targets == set(SUCCESSOR_TARGET_IDS)                              # the policy's 12 ids are exactly the catalogue's
    assert all(real.lookup_technique(t).status.value == "current" for t in targets)
    assert sorted(o for o in olds if real.get_technique(o).replaced_by == ("T1685",)) == sorted(SHARED_T1685)
    for old in OLD_TO_NEW:
        a = assess_attack_technique(old, [], real)
        assert a.taxonomy_status == TaxonomyState.REVOKED and [s.attack_id for s in a.successors] == [OLD_TO_NEW[old]]
    assert assess_attack_technique("T1562.005", [], real).taxonomy_status == TaxonomyState.UNKNOWN
