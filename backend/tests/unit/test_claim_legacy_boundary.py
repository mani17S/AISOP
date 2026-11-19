"""
Task 1 closure: the legacy grounding path (citation existence + polarity + one-token overlap, ``InvestigationOutputValidator`` Tier 1/2) must stay a
separate, clearly-legacy signal. It must never decide, influence or override the deterministic ``claim-verification-v1`` result.
"""

from __future__ import annotations

import inspect

import app.modules.ai.guardrails.claim_verifier as verifier_module
from app.schemas.claim_verification import VerificationOutcome as O
from app.schemas.investigation import ClaimCategory, FactualClaimItem, GroundingStatus
from tests.unit.test_claim_verifier import CTX, _validate, claim, field, uid, verify


def test_verifier_source_does_not_use_text_overlap_or_the_legacy_grounding_status():
    src = inspect.getsource(verifier_module)
    for forbidden in ("_extract_content_tokens", "claim_text", "grounding_status", "token_overlap", "analyst_notes", "confidence"):
        assert forbidden not in src, f"verifier must not depend on {forbidden}"


def test_token_overlap_alone_never_yields_supported_or_contradicted():
    overlapping = "process started by user powershell.exe e0 alice"          # shares many words with the cited event's summary/attributes
    unrelated = "Quarterly budget approved."
    for text in (overlapping, unrelated):
        assert verify(claim(None, text=text)).outcome == O.NOT_VERIFIABLE      # no assertions: never supported/contradicted from words
    a = verify(claim([field("e0", "outcome", "equals", "success")], text=overlapping))
    b = verify(claim([field("e0", "outcome", "equals", "success")], text=unrelated))
    assert a.model_dump() == b.model_dump()                                    # claim text cannot change the deterministic result


def test_legacy_status_cannot_change_verification_and_verification_cannot_change_legacy_status():
    base = claim([field("e2", "outcome", "equals", "success")], cites=("e2",), text="The logon succeeded.")
    for status in (GroundingStatus.VALIDATED_REFERENCE, GroundingStatus.ANALYST_REVIEW_REQUIRED, GroundingStatus.UNSUPPORTED):
        c = base.model_copy(update={"grounding_status": status, "confidence": 0.1})
        assert verify(c).outcome == O.CONTRADICTED                              # same result whatever the legacy label says
    legacy_only = claim(None, text="The logon succeeded on e2.", cites=("e2",))
    with_a = claim([field("e2", "outcome", "equals", "failure")], cites=("e2",), text="The logon succeeded on e2.")
    g_legacy = _validate([legacy_only]).output.claims[0].grounding_status
    g_with = _validate([with_a]).output.claims[0].grounding_status
    assert g_legacy == g_with                                                   # attaching assertions did not alter the legacy grounding decision


def test_a_legacy_validated_claim_with_a_contradicted_verification_keeps_both_signals_distinct():
    c = claim([field("e2", "outcome", "equals", "success")], cites=("e2",), text="authentication e2 logon event occurred")
    got = _validate([c]).output.claims[0]
    assert got.verification.outcome == O.CONTRADICTED                           # authoritative deterministic result
    assert got.category == ClaimCategory.OBSERVED_FACT                          # legacy fields are reported as they are; the UI labels them "legacy grounding"


def test_historical_payloads_without_the_new_fields_remain_valid_and_digest_stable():
    raw = {"claim_text": "Old claim.", "category": "observed_fact", "supporting_evidence_ids": [str(uid("e0"))], "references_exist": True,
           "grounding_status": "validated_reference", "confidence": 0.5}
    old = FactualClaimItem.model_validate(raw)
    assert old.assertions is None and old.verification is None
    out = _validate([old])
    assert out.output.claims[0].verification is None
    # digest stability against the pre-Task-1 hasher is proven in test_claim_verifier.py (snapshot comparison)
