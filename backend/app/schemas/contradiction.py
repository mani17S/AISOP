"""
AISOP contradiction findings (ADR-013 Revision 2, sufficiency ``suff-v4``).

Typed, frozen, fixed-vocabulary records. They hold evidence ids, source system names, times, fixed proposition keys and fixed claim values:
never evidence payload text, summaries, attributes or secrets. The detector (``app.modules.evidence_domains.contradictions``) produces
``ContradictionCandidate`` facts; the single sufficiency gate (``sufficiency_gate``) decides materiality against the hypothesis and turns
candidates into ``ContradictionFinding`` entries of the assessment. Nothing here produces a verdict.

Implemented kinds: ``ordering``, ``outcome``, ``identity``, ``temporal``. ADR-013's STATE kind has no approved proposition definition and is
NOT declared. The values are lower-case so they can serve as the ``SufficiencyFinding.qualifier`` (pattern ``^[a-z_]*$``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ContradictionKind(StrEnum):
    ORDERING = "ordering"  # an artefact is timestamped before the event claimed to cause it
    OUTCOME = "outcome"    # opposite outcomes for the same proposition reported by independent sources
    IDENTITY = "identity"  # one issuer-scoped session attributed to two different canonical principals of the same directory
    TEMPORAL = "temporal"  # one issuer-scoped event correlation id reported with event times further apart than the tolerance


class Materiality(StrEnum):
    MATERIAL = "material"    # unresolved, touches the hypothesis: caps the verdict at LIMITED and excludes the pair from corroboration
    MINOR = "minor"          # disclosed, no verdict effect
    EXPLAINED = "explained"  # a closed-list benign explanation applies: disclosed, no verdict effect (no explanation produces it in this slice)


class Explanation(StrEnum):
    """Closed list (ADR-013). Only the members the implemented rules can produce are declared."""

    TIMEZONE_ASSUMED = "timezone_assumed"  # a source gave no time zone; UTC was assumed, so a time-based claim cannot be material
    CLOCK_SKEW_WITHIN_TOLERANCE = "clock_skew_within_tolerance"  # the reversal is within the approved 5-second tolerance


class HypothesisRelation(StrEnum):
    ANCHOR = "anchor"
    CORROBORATING = "corroborating"
    RELEVANT = "relevant"
    PERIPHERAL = "peripheral"


class ContradictionCandidate(BaseModel):
    """Detector output: facts about a conflicting pair, before the gate applies materiality."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ContradictionKind
    proposition: str = Field(max_length=64, pattern=r"^[a-z_]+$", description="Fixed key, e.g. signin_outcome, connection_allowed, attachment_delivery_order")
    evidence_ids: tuple[uuid.UUID, uuid.UUID]
    sources: tuple[str, str] = Field(description="Source system names (already present in the result)")
    times: tuple[datetime, datetime] = Field(description="Event times (UTC) of the two records, in evidence_ids order")
    time_quality: tuple[Literal["valid", "naive_assumed_utc"], Literal["valid", "naive_assumed_utc"]]
    claims: tuple[str, str] = Field(description="Fixed claim values, e.g. ('success','failure'), ('delivery','artefact_earlier')")
    link_strength: Literal["strong", "specific", "weak"]
    independence: Literal["independent", "same_source", "unknown"]
    overlap_seconds: float = Field(ge=0, description="Absolute time difference between the two records")
    reliability: tuple[str, str] = Field(description="TrustClass values of the two records")
    explanation: Optional[Explanation] = None
    resolution_hint: str = Field(max_length=64, pattern=r"^[A-Z_]+$")


class ContradictionFinding(ContradictionCandidate):
    """A candidate after the gate decided its relation to the hypothesis and its materiality."""

    relation: HypothesisRelation
    materiality: Materiality
    affects_verdict: bool


__all__ = ["ContradictionCandidate", "ContradictionFinding", "ContradictionKind", "Explanation", "HypothesisRelation", "Materiality"]
