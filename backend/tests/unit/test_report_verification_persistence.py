"""
Task 1 final closure: claim-verification-v1 carried into the report bundle (``TechnicalReportClaim.verification``), additive and optional.

Integrity model proven here (see the report directory, 01_REPORT_SCHEMA_AND_DIGEST_COMPATIBILITY.md):
  * the bundle is generated on demand and has no stored report digest; the integrity anchors are ``context_sha256`` and the validation-output
    digest bound to the server audit record. ``verification`` is part of the output digest only when present, so historical outputs hash as before;
  * a submitted result whose verification was altered no longer matches the audited output digest, so it is not server-verified and its claims are
    demoted, and the unverified branch never carries verification.
"""

from __future__ import annotations

import json

from app.modules.ai.context_builder.hasher import compute_validation_output_sha256
from app.modules.ai.reporting.synthesizer import DeterministicReportSynthesizer
from app.schemas.claim_verification import VerificationOutcome as O
from app.schemas.report import TechnicalReportClaim
from tests.unit.test_claim_verifier import CTX, _validate, claim, field

LEGACY_KEYS = {"claim_id", "claim_text", "category", "grounding_status", "confidence", "supporting_event_uuids", "analyst_notes"}


def _all_claims(bundle):
    t = bundle.technical_report
    return [*t.confirmed_findings, *t.hypotheses_and_inferences, *t.unsupported_or_contradicted_claims]


def _four_outcome_result():
    claims = [
        claim([field("e0", "outcome", "equals", "success")], text="Supported one e0."),
        claim([field("e2", "outcome", "equals", "success")], cites=("e2",), text="Contradicted one e2."),
        claim([field("e1", "attributes.integrity", "equals", "high")], cites=("e1",), text="Insufficient one e1."),
        claim([{"kind": "event_field", "evidence_id": str(claim(None).supporting_evidence_ids[0]), "field": "outcome", "operator": "regex", "value": "x"}],
              text="Not verifiable one e0."),
        claim(None, text="Legacy one without assertions e0."),
    ]
    return _validate(claims)


def test_historical_claim_shape_is_unchanged_and_still_deserializes():
    old = {"claim_id": "11111111-1111-4111-8111-111111111111", "claim_text": "Old.", "category": "observed_fact",
           "grounding_status": "validated_reference", "confidence": 0.5, "supporting_event_uuids": [], "analyst_notes": None}
    c = TechnicalReportClaim.model_validate(old)
    assert c.verification is None
    assert set(json.loads(c.model_dump_json())) == LEGACY_KEYS                       # byte-compatible serialization: no new key appears
    assert set(c.model_dump(mode="json")) == LEGACY_KEYS


def test_server_verified_bundle_carries_all_four_outcomes_from_the_validator_only():
    result = _four_outcome_result()
    bundle = DeterministicReportSynthesizer().synthesize_bundle(validation_result=result, context=CTX, is_server_verified=True)
    by_text = {c.claim_text: c for c in _all_claims(bundle)}
    got = {t.split(" one")[0]: (c.verification.outcome if c.verification else None) for t, c in by_text.items()}
    assert got == {"Supported": O.SUPPORTED, "Contradicted": O.CONTRADICTED, "Insufficient": O.INSUFFICIENT_EVIDENCE, "Not verifiable": O.NOT_VERIFIABLE, "Legacy": None}
    validator_view = {c.claim_text: c.verification for c in result.output.claims}
    for text, c in by_text.items():
        assert c.verification == validator_view[text]                                # copied, never recomputed or altered
    dumped = json.loads(bundle.model_dump_json())
    keys = {tuple(sorted(c)) for c in dumped["technical_report"]["confirmed_findings"] + dumped["technical_report"]["hypotheses_and_inferences"]
            + dumped["technical_report"]["unsupported_or_contradicted_claims"]}
    assert any("verification" in k for k in keys) and any("verification" not in k for k in keys)   # legacy claim keeps the old shape


def test_unverified_or_default_input_never_carries_verification():
    result = _four_outcome_result()
    for flag in (False, None):
        bundle = DeterministicReportSynthesizer().synthesize_bundle(validation_result=result, context=CTX, is_server_verified=flag)
        if flag is False:
            assert all(c.claim_text.startswith("[UNVERIFIED]") for c in _all_claims(bundle))
        assert all(c.verification is None for c in _all_claims(bundle))             # a client-supplied verification is never trusted into a report


def test_digest_semantics_historical_stable_new_deterministic_and_tamper_evident():
    legacy = _validate([claim(None, text="Legacy claim e0.")])
    d_legacy = compute_validation_output_sha256(legacy)
    assert d_legacy == compute_validation_output_sha256(legacy)                      # deterministic
    new = _four_outcome_result()
    assert compute_validation_output_sha256(new) == compute_validation_output_sha256(new)
    tampered_claims = [c.model_copy(update={"verification": c.verification.model_copy(update={"outcome": O.SUPPORTED})}) if c.verification else c
                       for c in new.output.claims]
    tampered = new.model_copy(update={"output": new.output.model_copy(update={"claims": tampered_claims})})
    assert compute_validation_output_sha256(tampered) != compute_validation_output_sha256(new)   # /format compares this to the audit record
    stripped = [c.model_copy(update={"verification": None}) for c in new.output.claims]
    removed = new.model_copy(update={"output": new.output.model_copy(update={"claims": stripped})})
    assert compute_validation_output_sha256(removed) != compute_validation_output_sha256(new)


def test_markdown_wording_and_verification_line():
    bundle = DeterministicReportSynthesizer().synthesize_bundle(validation_result=_four_outcome_result(), context=CTX, is_server_verified=True)
    md = bundle.markdown_technical
    assert "Confirmed Forensic Findings" not in md and "Evidence-Linked Findings" in md and "not analyst-confirmed" in md
    assert "Assertion verification (listed assertions only; AI claim, not analyst-confirmed)" in md and "`contradicted`" in md
    legacy_md = DeterministicReportSynthesizer().synthesize_bundle(
        validation_result=_validate([claim(None, text="Legacy claim e0.")]), context=CTX, is_server_verified=True).markdown_technical
    assert "Assertion verification" not in legacy_md                                # historical-style claims render exactly as before
