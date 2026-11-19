"""
Typed projection of the pinned local ATT&CK reference catalogue (taxonomy reference data only).

This is AISOP's *minimal* view of an ATT&CK Enterprise STIX 2.1 collection: identifiers, canonical names, domain
membership, lifecycle flags, tactic and parent links, and explicit ``revoked-by`` successor pointers. It deliberately
holds no descriptions, no raw STIX dictionaries and no prompt text.

Pydantic validates this projection (and the raw fields the loader consumes). That does NOT prove that the upstream
JSON conforms to the full STIX 2.1 specification; no such claim is made anywhere in this package.

ATT&CK data here is reference data. It is not threat intelligence, not independent evidence, not corroboration and
not an input to severity. A valid identifier proves only that a taxonomy object exists.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Mapping, Optional, Sequence

from pydantic import BaseModel, ConfigDict, StringConstraints

TECHNIQUE_ID_PATTERN = r"^T\d{4}(?:\.\d{3})?$"
TACTIC_ID_PATTERN = r"^TA\d{4}$"
STIX_ID_PATTERN = r"^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
SHORTNAME_PATTERN = r"^[a-z][a-z0-9-]*$"
TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"

TECHNIQUE_ID_RE = re.compile(TECHNIQUE_ID_PATTERN)
TACTIC_ID_RE = re.compile(TACTIC_ID_PATTERN)

TechniqueId = Annotated[str, StringConstraints(strict=True, pattern=TECHNIQUE_ID_PATTERN)]
TacticId = Annotated[str, StringConstraints(strict=True, pattern=TACTIC_ID_PATTERN)]
StixId = Annotated[str, StringConstraints(strict=True, pattern=STIX_ID_PATTERN)]
Shortname = Annotated[str, StringConstraints(strict=True, pattern=SHORTNAME_PATTERN, max_length=64)]
Timestamp = Annotated[str, StringConstraints(strict=True, pattern=TIMESTAMP_PATTERN)]
DisplayName = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=256)]
ShortText = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=64)]


class Lifecycle(StrEnum):
    """Lifecycle of one catalogue object, from the dataset's own ``revoked`` / ``x_mitre_deprecated`` flags."""

    CURRENT = "current"
    REVOKED = "revoked"
    DEPRECATED = "deprecated"
    REVOKED_AND_DEPRECATED = "revoked_and_deprecated"


class ReferenceStatus(StrEnum):
    """Result of looking up an identifier. ``unknown`` is not ``benign`` and not ``valid``."""

    CURRENT = "current"
    REVOKED = "revoked"
    DEPRECATED = "deprecated"
    REVOKED_AND_DEPRECATED = "revoked_and_deprecated"
    UNKNOWN = "unknown"
    INVALID_SYNTAX = "invalid_syntax"
    WRONG_DOMAIN = "wrong_domain"


_LIFECYCLE_TO_STATUS = {
    Lifecycle.CURRENT: ReferenceStatus.CURRENT,
    Lifecycle.REVOKED: ReferenceStatus.REVOKED,
    Lifecycle.DEPRECATED: ReferenceStatus.DEPRECATED,
    Lifecycle.REVOKED_AND_DEPRECATED: ReferenceStatus.REVOKED_AND_DEPRECATED,
}


def lifecycle_of(revoked: bool, deprecated: bool) -> Lifecycle:
    if revoked and deprecated:
        return Lifecycle.REVOKED_AND_DEPRECATED
    if revoked:
        return Lifecycle.REVOKED
    if deprecated:
        return Lifecycle.DEPRECATED
    return Lifecycle.CURRENT


_FROZEN = ConfigDict(frozen=True, extra="forbid")


class TacticRecord(BaseModel):
    """One Enterprise tactic. The stable identity is ``tactic_id``; ``name`` is display metadata."""

    model_config = _FROZEN

    stix_id: StixId
    tactic_id: TacticId
    name: DisplayName
    shortname: Shortname
    domains: tuple[ShortText, ...]
    revoked: bool
    deprecated: bool
    created: Optional[Timestamp] = None
    modified: Optional[Timestamp] = None


class TechniqueRecord(BaseModel):
    """One Enterprise technique or sub-technique (no description is retained)."""

    model_config = _FROZEN

    stix_id: StixId
    attack_id: TechniqueId
    name: DisplayName
    domains: tuple[ShortText, ...]
    revoked: bool
    deprecated: bool
    lifecycle: Lifecycle
    is_subtechnique: bool
    parent_id: Optional[TechniqueId] = None
    tactic_ids: tuple[TacticId, ...] = ()
    #: Explicit ``revoked-by`` targets resolved to ATT&CK ids (direction: this object -> successor). Never inferred.
    replaced_by: tuple[TechniqueId, ...] = ()
    #: ``revoked-by`` targets that could not be resolved to an Enterprise technique in this file (STIX ids).
    unresolved_successor_refs: tuple[StixId, ...] = ()
    version: Optional[ShortText] = None
    created: Optional[Timestamp] = None
    modified: Optional[Timestamp] = None


class TechniqueLookup(BaseModel):
    """Outcome of ``AttackReferenceCatalogue.lookup_technique``."""

    model_config = _FROZEN

    query: str
    status: ReferenceStatus
    record: Optional[TechniqueRecord] = None


class CatalogueMeta(BaseModel):
    """Diagnostics about the loaded collection. ``sha256`` is the digest the loader verified before parsing."""

    model_config = _FROZEN

    loader_version: str
    source_path: str
    sha256: str
    size_bytes: int
    bundle_id: str
    collection_stix_id: str
    collection_name: str
    release_version: str
    attack_spec_version: Optional[str] = None
    domain: str
    object_count: int
    technique_count: int
    tactic_count: int
    revoked_count: int
    deprecated_count: int
    replacement_relationship_count: int
    unresolved_replacement_count: int
    excluded_other_domain_technique_count: int
    skipped_attack_patterns_without_attack_id: int


class AttackReferenceCatalogue:
    """
    Immutable, in-memory, deterministic reference view. Returned by value; never cached, persisted or serialised
    by this package. Construction is done only by the loader.
    """

    __slots__ = ("meta", "warnings", "_techniques", "_tactics", "_tactic_by_shortname", "_children", "_other_domain")

    def __init__(
        self,
        *,
        meta: CatalogueMeta,
        techniques: Mapping[str, TechniqueRecord],
        tactics: Mapping[str, TacticRecord],
        other_domain_technique_ids: Sequence[str],
        warnings: Sequence[str],
    ) -> None:
        self.meta = meta
        self.warnings = tuple(sorted(warnings))
        self._techniques = {k: techniques[k] for k in sorted(techniques)}
        self._tactics = {k: tactics[k] for k in sorted(tactics)}
        self._tactic_by_shortname = {t.shortname: t.tactic_id for t in self._tactics.values()}
        children: dict[str, list[str]] = {}
        for rec in self._techniques.values():
            if rec.parent_id is not None:
                children.setdefault(rec.parent_id, []).append(rec.attack_id)
        self._children = {k: tuple(sorted(v)) for k, v in children.items()}
        self._other_domain = frozenset(other_domain_technique_ids)

    # -- techniques ---------------------------------------------------------------------------------------------
    def lookup_technique(self, query: object) -> TechniqueLookup:
        """Exact-match lookup. No case folding, trimming or coercion: a malformed id is never turned into a valid one."""
        if not isinstance(query, str) or TECHNIQUE_ID_RE.fullmatch(query) is None:
            return TechniqueLookup(query=repr(query)[:80], status=ReferenceStatus.INVALID_SYNTAX)
        rec = self._techniques.get(query)
        if rec is not None:
            return TechniqueLookup(query=query, status=_LIFECYCLE_TO_STATUS[rec.lifecycle], record=rec)
        if query in self._other_domain:
            return TechniqueLookup(query=query, status=ReferenceStatus.WRONG_DOMAIN)
        return TechniqueLookup(query=query, status=ReferenceStatus.UNKNOWN)

    def get_technique(self, attack_id: str) -> Optional[TechniqueRecord]:
        return self._techniques.get(attack_id)

    def technique_ids(self) -> tuple[str, ...]:
        return tuple(self._techniques)

    def parent_of(self, attack_id: str) -> Optional[TechniqueRecord]:
        rec = self._techniques.get(attack_id)
        if rec is None or rec.parent_id is None:
            return None
        return self._techniques.get(rec.parent_id)

    def children_of(self, attack_id: str) -> tuple[str, ...]:
        return self._children.get(attack_id, ())

    def successors_of(self, attack_id: str) -> tuple[TechniqueRecord, ...]:
        """Explicit ``revoked-by`` successors only, in sorted id order. Empty when none is declared."""
        rec = self._techniques.get(attack_id)
        if rec is None:
            return ()
        return tuple(self._techniques[s] for s in rec.replaced_by if s in self._techniques)

    # -- tactics ------------------------------------------------------------------------------------------------
    def lookup_tactic(self, tactic_id: str) -> Optional[TacticRecord]:
        return self._tactics.get(tactic_id)

    def tactic_by_shortname(self, shortname: str) -> Optional[TacticRecord]:
        tid = self._tactic_by_shortname.get(shortname)
        return self._tactics.get(tid) if tid else None

    def tactic_ids(self) -> tuple[str, ...]:
        return tuple(self._tactics)

    def tactics(self) -> tuple[TacticRecord, ...]:
        return tuple(self._tactics.values())

    def techniques(self) -> tuple[TechniqueRecord, ...]:
        return tuple(self._techniques.values())
