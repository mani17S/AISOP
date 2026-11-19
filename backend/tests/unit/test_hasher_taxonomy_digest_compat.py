"""
Backlog item 0: historical report-digest compatibility for the optional ``MitreAttackHypothesis.taxonomy`` field.

Offline and synthetic: no ``.env``, database, app start, network or model. LABEL: these are synthetic historical-format
regressions; no actual persisted historical record, report endpoint or database was verified.

Discriminator under test: raw field presence (``model_fields_set``) on the hypotheses, decided at report level.
"""

from __future__ import annotations

import copy
import importlib.util
import uuid
from pathlib import Path

import pytest
from pydantic import BaseModel

from app.modules.ai.context_builder.hasher import (
    CanonicalSerializationTypeError,
    compute_validation_output_sha256 as digest,
    filter_canonical_validation_output,
)
from app.schemas.attack_taxonomy import TaxonomyState, TechniqueTaxonomyStatus
from app.modules.ai.guardrails.validator import InvestigationValidationResult
from app.schemas.investigation import MitreAttackHypothesis
from tests.unit.test_deterministic_report_synthesizer import _make_sample_context, _make_sample_validation_result

PRE_TASK1_HASHER = Path(
    r"D:\AISOP-Backups\AISOP_Task1_Claim_Evidence_Verification_2026-11-14_0210\original_snapshots"
    r"\backend_app_modules_ai_context_builder_hasher.py"
)


def _tax(state=TaxonomyState.CURRENT_VALID, tid="T1059.001"):
    return TechniqueTaxonomyStatus(state=state, technique_id=tid, reason_code="X")


def _hyp(tid, ev, taxonomy):
    return MitreAttackHypothesis(technique_id=tid, technique_name="Some Technique", tactics=["Execution"],
                                 supporting_event_uuids=[ev], confidence=0.9, reasoning="Model reasoning.", taxonomy=taxonomy)


@pytest.fixture(scope="module")
def current_dict():
    """One current-format result (every hypothesis carries a taxonomy object), as a JSON-mode dict. All variants derive from it."""
    inv, ev = uuid.uuid4(), uuid.uuid4()
    ctx = _make_sample_context(inv, ev)
    res = _make_sample_validation_result(
        inv, ev, ctx.reproducibility.context_sha256,
        hypotheses=[_hyp("T1059.001", ev, _tax()), _hyp("T1070.001", ev, _tax(TaxonomyState.REVOKED, "T1070.001"))],
    )
    return res.model_dump(mode="json")


def _hyps(d):
    return d["output"]["mitre_attack_hypotheses"]


def model(d):
    return InvestigationValidationResult.model_validate(d)


def legacy_dict(d):
    """The pre-taxonomy payload: the same result with the key absent (not null) on every hypothesis."""
    out = copy.deepcopy(d)
    for h in _hyps(out):
        h.pop("taxonomy")
    return out


# 1 + 10 ---------------------------------------------------------------------------------------------------------
def test_historical_positive_pre_taxonomy_payload_keeps_its_historical_digest(current_dict):
    legacy = legacy_dict(current_dict)
    m = model(legacy)
    assert all("taxonomy" not in h.model_fields_set for h in m.output.mitre_attack_hypotheses)   # presence survives parsing
    assert all(h.taxonomy is None for h in m.output.mitre_attack_hypotheses)
    assert "taxonomy" not in filter_canonical_validation_output(m)["output"]["mitre_attack_hypotheses"][0]
    # the dict path never added the key, so it IS the historical projection
    assert digest(m) == digest(legacy)


def test_historical_digest_equals_the_pre_task1_hasher_on_the_same_payload(current_dict):
    if not PRE_TASK1_HASHER.exists():
        pytest.skip("pre-change hasher snapshot not present")
    spec = importlib.util.spec_from_file_location("hasher_pre_task1", PRE_TASK1_HASHER)
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    legacy = legacy_dict(current_dict)
    for c in legacy["output"].get("claims") or []:
        c.pop("assertions", None)
        c.pop("verification", None)
    assert digest(model(legacy_dict(current_dict))) == old.compute_validation_output_sha256(legacy)


def test_explicit_null_is_distinguishable_from_an_absent_key(current_dict):
    absent = legacy_dict(current_dict)
    nulled = copy.deepcopy(absent)
    for h in _hyps(nulled):
        h["taxonomy"] = None
    assert digest(model(absent)) != digest(model(nulled))
    assert digest(model(nulled)) == digest(nulled)                                  # explicit null is hashed as null, both paths


# 2 --------------------------------------------------------------------------------------------------------------
def test_current_positive_projection_still_covers_taxonomy_and_equals_the_dict_path(current_dict):
    m = model(current_dict)
    proj = filter_canonical_validation_output(m)["output"]["mitre_attack_hypotheses"]
    assert all(p["taxonomy"] is not None for p in proj)
    assert digest(m) == digest(current_dict)
    assert digest(m) != digest(model(legacy_dict(current_dict)))


# 3 --------------------------------------------------------------------------------------------------------------
def test_current_taxonomy_tamper_changes_the_digest(current_dict):
    t = copy.deepcopy(current_dict)
    _hyps(t)[0]["taxonomy"]["state"] = "REVOKED"
    assert digest(model(t)) != digest(model(current_dict))


# 4 + 5 ----------------------------------------------------------------------------------------------------------
def test_omitting_taxonomy_from_a_current_report_does_not_reproduce_the_current_digest(current_dict):
    assert digest(model(legacy_dict(current_dict))) != digest(model(current_dict))


def test_nulling_taxonomy_cannot_downgrade_into_the_historical_digest(current_dict):
    nulled = copy.deepcopy(current_dict)
    for h in _hyps(nulled):
        h["taxonomy"] = None
    assert digest(model(nulled)) != digest(model(current_dict))
    assert digest(model(nulled)) != digest(model(legacy_dict(current_dict)))


def test_a_non_null_taxonomy_is_never_dropped_even_if_presence_information_is_lost(current_dict):
    m = model(current_dict)
    object.__setattr__(m.output.mitre_attack_hypotheses[0], "__pydantic_fields_set__", set())   # simulate lost presence info
    proj = filter_canonical_validation_output(m)["output"]["mitre_attack_hypotheses"]
    assert all(p["taxonomy"] is not None for p in proj)


# 6 --------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("make", [lambda d: d, legacy_dict], ids=["current", "historical"])
def test_changing_covered_evidence_fields_fails_in_both_formats(current_dict, make):
    base = make(current_dict)
    t = copy.deepcopy(base)
    _hyps(t)[0]["supporting_event_uuids"] = [str(uuid.uuid4())]
    t2 = copy.deepcopy(base)
    _hyps(t2)[0]["confidence"] = 0.1
    assert digest(model(t)) != digest(model(base))
    assert digest(model(t2)) != digest(model(base))


# 7 --------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("make", [lambda d: d, legacy_dict], ids=["current", "historical"])
def test_canonicalization_is_deterministic(current_dict, make):
    d = make(current_dict)
    assert digest(model(d)) == digest(model(d)) == digest(model(copy.deepcopy(d)))
    assert filter_canonical_validation_output(model(d)) == filter_canonical_validation_output(model(d))


# 8 --------------------------------------------------------------------------------------------------------------
def test_mixed_report_selection_is_report_level_never_per_hypothesis(current_dict):
    mixed = copy.deepcopy(current_dict)
    _hyps(mixed)[1].pop("taxonomy")                                                  # one present, one absent
    m = model(mixed)
    proj = filter_canonical_validation_output(m)["output"]["mitre_attack_hypotheses"]
    assert proj[0]["taxonomy"] is not None and "taxonomy" in proj[1] and proj[1]["taxonomy"] is None   # current projection for all
    assert digest(m) != digest(model(legacy_dict(current_dict)))


def test_a_report_without_hypotheses_is_unaffected(current_dict):
    d = copy.deepcopy(current_dict)
    d["output"]["mitre_attack_hypotheses"] = []
    assert digest(model(d)) == digest(d)


# 9 --------------------------------------------------------------------------------------------------------------
def test_malformed_input_still_fails_closed_with_the_established_error():
    with pytest.raises(CanonicalSerializationTypeError):
        filter_canonical_validation_output("not a model or dict")                    # type: ignore[arg-type]


def test_an_unexpected_model_shape_keeps_the_current_projection():
    class Odd(BaseModel):                                                              # a plain pydantic model with no output
        x: int = 1
    assert filter_canonical_validation_output(Odd())["x"] == 1
