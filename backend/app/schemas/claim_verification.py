"""
AISOP claim-to-evidence verification v1: result contract.

A citation is a pointer. A structured assertion (``claim-assertion-v1``) is a testable statement. Verification is a bounded, deterministic check of
that statement against the exact cited evidence's own structured fields. None of these, by itself, proves an entire incident narrative.

This module only defines the RESULT types. The assertion INPUT is carried on ``FactualClaimItem.assertions`` as plain JSON values and is validated
strictly by ``app.modules.ai.guardrails.claim_verifier`` (so one malformed assertion can never reject a whole model response). Results hold
outcomes, fixed reason codes, evidence ids and field names; raw entity or attribute values are never placed in a result. Only the values of the
fixed-vocabulary event fields (event_type, action, outcome, severity) may be echoed, because they are not entity values.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

CLAIM_ASSERTION_SCHEMA = "claim-assertion-v1"
CLAIM_VERIFICATION_SCHEMA = "claim-verification-v1"

#: Fixed text carried by every result: what a verification does NOT establish.
VERIFICATION_LIMITS = (
    "Checks only the listed assertions against the cited evidence fields. It does not establish the claim text as a whole, "
    "malicious intent, attribution, independent sensors, authenticity of the records, or the correctness of the investigation."
)


class VerificationOutcome(StrEnum):
    SUPPORTED = "supported"                          # the exact assertion is directly supported by the cited evidence field(s)
    CONTRADICTED = "contradicted"                    # the cited evidence directly conflicts with the assertion
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # evidence missing, out of scope, uncited, incomplete or not establishing the assertion
    NOT_VERIFIABLE = "not_verifiable"                # absent, malformed or unsupported assertion structure; cannot be evaluated safely


class AssertionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    index: int = Field(ge=0)
    kind: Optional[str] = None
    outcome: VerificationOutcome
    reason: str = Field(description="Fixed reason code, never free text")
    evidence_ids: list[str] = Field(default_factory=list, max_length=10)
    field: Optional[str] = None
    operator: Optional[str] = None
    expected: Optional[str] = Field(default=None, description="Only for the fixed-vocabulary event fields; otherwise withheld")
    observed: Optional[str] = Field(default=None, description="Only for the fixed-vocabulary event fields; otherwise withheld")
    values_withheld: bool = False


class ClaimVerification(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default=CLAIM_VERIFICATION_SCHEMA)
    outcome: VerificationOutcome
    reason: str = Field(description="Fixed reason code for the claim-level outcome")
    assertions_total: int = Field(ge=0)
    assertions_evaluated: int = Field(ge=0)
    assertions_truncated: bool = False
    results: list[AssertionResult] = Field(default_factory=list)
    applies_to: Literal["listed_assertions_only"] = "listed_assertions_only"
    limits: str = Field(default=VERIFICATION_LIMITS)


__all__ = [
    "AssertionResult",
    "CLAIM_ASSERTION_SCHEMA",
    "CLAIM_VERIFICATION_SCHEMA",
    "ClaimVerification",
    "VERIFICATION_LIMITS",
    "VerificationOutcome",
]
