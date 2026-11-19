"""
Per-hypothesis ATT&CK taxonomy validation status (additive, optional, deterministic).

This object answers ONE question only: what does the pinned local ATT&CK reference say about this identifier?
It is deliberately separate from evidence confidence, evidence sufficiency, support state and analyst confirmation:
- ``CURRENT_VALID`` does not mean the technique occurred or that evidence supports it;
- ``REVOKED`` / ``DEPRECATED`` do not mean evidence is absent or the incident is benign;
- ``UNKNOWN`` does not mean a false positive;
- ``NOT_CONFIGURED`` / ``CATALOGUE_UNAVAILABLE`` mean the identifier was NOT validated (neither valid nor invalid).
Successor candidates come only from the catalogue's explicit ``revoked-by`` relationships. They are suggestions, never
evidence, and never replace the identifier. No MITRE descriptions, model text or evidence values are carried here.

The value is set ONLY by the deterministic guardrail validator; anything a model supplies for it is discarded.
A missing value (historical records, or outputs that never passed the validator) means "not recorded", never "valid".
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class TaxonomyState(StrEnum):
    CURRENT_VALID = "CURRENT_VALID"                  # exists in the pinned Enterprise catalogue, not revoked/deprecated
    REVOKED = "REVOKED"                              # present but revoked: not acceptable as a current mapping
    DEPRECATED = "DEPRECATED"                        # present but deprecated: not acceptable as a current mapping
    UNKNOWN = "UNKNOWN"                              # well-formed but not found in the pinned Enterprise catalogue
    INVALID = "INVALID"                              # malformed identifier
    WRONG_DOMAIN = "WRONG_DOMAIN"                    # not an Enterprise technique
    NOT_CONFIGURED = "NOT_CONFIGURED"                # no catalogue was provided to the validation path
    CATALOGUE_UNAVAILABLE = "CATALOGUE_UNAVAILABLE"  # a catalogue was configured but could not be loaded/verified


_TechniqueId = Annotated[str, StringConstraints(strict=True, pattern=r"^T\d{4}(?:\.\d{3})?$")]
_Name = Annotated[str, StringConstraints(strict=True, max_length=256)]
_Short = Annotated[str, StringConstraints(strict=True, max_length=64)]
_Sha256 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9A-Fa-f]{64}$")]

_FROZEN = ConfigDict(frozen=True, extra="forbid")


class SuccessorCandidate(BaseModel):
    """A catalogue ``revoked-by`` target for a revoked identifier. A suggestion only: not evidence, never substituted."""

    model_config = _FROZEN

    attack_id: _TechniqueId
    name: _Name
    lifecycle: _Short
    #: other retired identifiers that point to the same successor (the successor then needs analyst choice)
    shared_with: tuple[_TechniqueId, ...] = ()


class TechniqueTaxonomyStatus(BaseModel):
    """Bounded, non-sensitive taxonomy validation result for one technique hypothesis."""

    model_config = _FROZEN

    state: TaxonomyState
    #: the identifier as safely parsed; absent when the identifier is malformed
    technique_id: Optional[_TechniqueId] = None
    catalogue_domain: Optional[_Short] = None
    catalogue_release: Optional[_Short] = None
    #: SHA-256 of the pinned catalogue file that answered (validation source identity)
    catalogue_sha256: Optional[_Sha256] = None
    canonical_name: Optional[_Name] = None
    lifecycle: Optional[_Short] = None
    successors: tuple[SuccessorCandidate, ...] = ()
    #: True when more than one successor exists or the successor is shared with other retired identifiers
    successor_ambiguous: bool = False
    unresolved_successor_refs: int = Field(default=0, ge=0)
    reference: _Short = "pinned local ATT&CK catalogue"
    #: stable, non-sensitive reason code
    reason_code: _Short
