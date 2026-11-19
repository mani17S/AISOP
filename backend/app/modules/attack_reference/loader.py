"""
Minimal, offline, deterministic loader for the pinned local ATT&CK Enterprise reference collection.

Behaviour (all fail-closed):
  1. the path must be an existing regular file within a size bound;
  2. its SHA-256 (and size, when pinned) is verified over the exact bytes that are then parsed, BEFORE any parsing;
  3. the JSON must parse, be a STIX ``bundle`` with an ``objects`` list, and contain exactly one ``x-mitre-collection``
     whose release version and name match the pinned release;
  4. only the object types AISOP needs are projected, each through strict Pydantic models that ignore (and therefore
     never retain) every other property, descriptions included;
  5. duplicates and inconsistent identities are rejected, never silently resolved.

NOT done here, by design: no network, no download, no auto-update, no database, no cache, no write to the source,
no application wiring, no mapping substitution, and no claim of complete STIX 2.1 conformance. Pydantic validates
AISOP's minimal projection only.

Pinning the SHA-256 in code means a changed file is refused, and adopting a new release needs a reviewed code change
plus a new pinned provenance record; the digest is never updated automatically.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.modules.attack_reference.models import (
    AttackReferenceCatalogue,
    CatalogueMeta,
    DisplayName,
    Shortname,
    ShortText,
    StixId,
    TACTIC_ID_RE,
    TacticRecord,
    TechniqueRecord,
    TECHNIQUE_ID_RE,
    Timestamp,
    lifecycle_of,
)

LOADER_VERSION = "attack-reference-loader-v1"
DEFAULT_MAX_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_OBJECTS = 100_000
_ATTACK_SOURCE_NAME = "mitre-attack"
_KILL_CHAIN_NAME = "mitre-attack"
_REL_REVOKED_BY = "revoked-by"
_REL_SUBTECHNIQUE_OF = "subtechnique-of"


@dataclass(frozen=True)
class PinnedRelease:
    """What the loader must find. Every field is checked; nothing is inferred or defaulted from the file."""

    release_version: str
    sha256: str
    domain: str
    collection_name: str
    size_bytes: Optional[int] = None
    tag: Optional[str] = None
    peeled_commit: Optional[str] = None


#: MITRE ATT&CK Enterprise v20.1 as acquired and registered (see the reference register). Hash and size were
#: recorded by the acquisition task; they are locally calculated identity records, not MITRE signatures.
ENTERPRISE_V20_1 = PinnedRelease(
    release_version="20.1",
    sha256="539A843A7B53ED9749740B2123DDDAE3726B1A4831841C32ACA740B011B910B5",
    domain="enterprise-attack",
    collection_name="Enterprise ATT&CK",
    size_bytes=55_277_605,
    tag="v20.1",
    peeled_commit="f59b03ecf828579d5f9e93683ce25b7e2e5fd9d7",
)

#: Approved production location (outside the repository). Tests pass an explicit path instead.
DEFAULT_DATASET_PATH = Path(r"D:\AISOP-Reference-Data\MITRE-ATT&CK\Enterprise\v20.1\enterprise-attack-20.1.json")


class ErrorCode(StrEnum):
    PATH_MISSING = "path_missing"
    NOT_A_FILE = "not_a_file"
    PATH_UNREADABLE = "path_unreadable"
    EMPTY_FILE = "empty_file"
    TOO_LARGE = "too_large"
    SIZE_MISMATCH = "size_mismatch"
    HASH_MISMATCH = "hash_mismatch"
    MALFORMED_JSON = "malformed_json"
    BAD_COLLECTION_TYPE = "bad_collection_type"
    MISSING_OBJECTS = "missing_objects"
    TOO_MANY_OBJECTS = "too_many_objects"
    NON_OBJECT_ENTRY = "non_object_entry"
    COLLECTION_MISSING = "collection_missing"
    MULTIPLE_COLLECTIONS = "multiple_collections"
    VERSION_MISMATCH = "version_mismatch"
    DOMAIN_MISMATCH = "domain_mismatch"
    INVALID_FIELD = "invalid_field"
    DUPLICATE_STIX_ID = "duplicate_stix_id"
    DUPLICATE_ATTACK_ID = "duplicate_attack_id"
    UNRESOLVED_TACTIC = "unresolved_tactic"
    SUBTECHNIQUE_WITHOUT_PARENT = "subtechnique_without_parent"
    INCONSISTENT_RELATIONSHIP = "inconsistent_relationship"


class AttackReferenceError(Exception):
    """Raised for every expected load failure. The message never echoes untrusted values from the file."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(f"{code.value}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class CatalogueLoadResult:
    """Non-raising result for callers that must keep working when the optional catalogue is unavailable."""

    catalogue: Optional[AttackReferenceCatalogue]
    error_code: Optional[ErrorCode] = None
    message: Optional[str] = None

    @property
    def available(self) -> bool:
        return self.catalogue is not None


# ── Raw (consumed) field models: strict, unknown properties ignored and therefore never retained ───────────────
_RAW = ConfigDict(strict=True, extra="ignore", frozen=True)


class _RawExternalRef(BaseModel):
    model_config = _RAW
    source_name: Optional[str] = None
    external_id: Optional[str] = None


class _RawKillChainPhase(BaseModel):
    model_config = _RAW
    kill_chain_name: str
    phase_name: str


class _RawCollection(BaseModel):
    model_config = _RAW
    type: Literal["x-mitre-collection"]
    id: StixId
    spec_version: Literal["2.1"]
    name: DisplayName
    x_mitre_version: ShortText
    x_mitre_attack_spec_version: Optional[ShortText] = None


class _RawTactic(BaseModel):
    model_config = _RAW
    type: Literal["x-mitre-tactic"]
    id: StixId
    spec_version: Literal["2.1"]
    name: DisplayName
    x_mitre_shortname: Shortname
    external_references: list[_RawExternalRef] = Field(default_factory=list)
    x_mitre_domains: list[ShortText]
    revoked: Optional[bool] = None
    x_mitre_deprecated: Optional[bool] = None
    created: Optional[Timestamp] = None
    modified: Optional[Timestamp] = None


class _RawAttackPattern(BaseModel):
    model_config = _RAW
    type: Literal["attack-pattern"]
    id: StixId
    spec_version: Literal["2.1"]
    name: DisplayName
    external_references: list[_RawExternalRef] = Field(default_factory=list)
    kill_chain_phases: Optional[list[_RawKillChainPhase]] = None
    x_mitre_domains: list[ShortText]
    revoked: Optional[bool] = None
    x_mitre_deprecated: Optional[bool] = None
    x_mitre_is_subtechnique: Optional[bool] = None
    x_mitre_version: Optional[ShortText] = None
    created: Optional[Timestamp] = None
    modified: Optional[Timestamp] = None


class _RawRelationship(BaseModel):
    model_config = _RAW
    type: Literal["relationship"]
    id: StixId
    spec_version: Literal["2.1"]
    relationship_type: str
    source_ref: StixId
    target_ref: StixId


def _validate(model: type[BaseModel], obj: dict[str, Any], index: int, kind: str) -> Any:
    try:
        return model.model_validate(obj)
    except ValidationError as exc:
        first = exc.errors(include_input=False, include_url=False, include_context=False)[0]
        loc = ".".join(str(p) for p in first["loc"]) or "<object>"
        raise AttackReferenceError(
            ErrorCode.INVALID_FIELD, f"{kind} at objects[{index}]: field '{loc}' invalid ({first['type']})"
        ) from None


def _attack_external_ids(refs: Sequence[_RawExternalRef]) -> list[str]:
    """Distinct ``external_id`` values of ATT&CK references; references from other sources are ignored."""
    out: list[str] = []
    for ref in refs:
        if ref.source_name == _ATTACK_SOURCE_NAME and ref.external_id is not None and ref.external_id not in out:
            out.append(ref.external_id)
    return out


def _has_attack_reference(obj: dict[str, Any]) -> bool:
    refs = obj.get("external_references")
    if not isinstance(refs, list):
        return False
    return any(isinstance(r, dict) and r.get("source_name") == _ATTACK_SOURCE_NAME for r in refs)


def _reject_json_constant(name: str) -> Any:
    raise ValueError(f"non-finite JSON constant {name!r} is not accepted")


# ── Public API ─────────────────────────────────────────────────────────────────────────────────────────────────
def load_catalogue(
    path: Path | str = DEFAULT_DATASET_PATH,
    expected: PinnedRelease = ENTERPRISE_V20_1,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_objects: int = DEFAULT_MAX_OBJECTS,
) -> AttackReferenceCatalogue:
    """Verify then parse the pinned local file. Raises ``AttackReferenceError`` on any failure; never partial."""
    p = Path(path)
    try:
        if not p.exists():
            raise AttackReferenceError(ErrorCode.PATH_MISSING, "dataset path does not exist")
        if not p.is_file():
            raise AttackReferenceError(ErrorCode.NOT_A_FILE, "dataset path is not a regular file")
        size = p.stat().st_size
        if size == 0:
            raise AttackReferenceError(ErrorCode.EMPTY_FILE, "dataset file is empty")
        if size > max_bytes:
            raise AttackReferenceError(ErrorCode.TOO_LARGE, f"dataset file exceeds the {max_bytes}-byte bound")
        if expected.size_bytes is not None and size != expected.size_bytes:
            raise AttackReferenceError(ErrorCode.SIZE_MISMATCH, "dataset size differs from the pinned release")
        data = p.read_bytes()
    except OSError:
        raise AttackReferenceError(ErrorCode.PATH_UNREADABLE, "dataset file could not be read") from None

    if len(data) != size:
        raise AttackReferenceError(ErrorCode.SIZE_MISMATCH, "dataset changed while being read")
    digest = hashlib.sha256(data).hexdigest().upper()
    if digest != expected.sha256.upper():
        raise AttackReferenceError(ErrorCode.HASH_MISMATCH, "dataset SHA-256 differs from the pinned release")

    try:
        document = json.loads(data, parse_constant=_reject_json_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise AttackReferenceError(ErrorCode.MALFORMED_JSON, "dataset is not valid JSON") from None
    finally:
        del data

    return catalogue_from_document(
        document, expected, sha256=digest, size_bytes=size, source_path=str(p), max_objects=max_objects
    )


def try_load_catalogue(
    path: Path | str = DEFAULT_DATASET_PATH,
    expected: PinnedRelease = ENTERPRISE_V20_1,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_objects: int = DEFAULT_MAX_OBJECTS,
) -> CatalogueLoadResult:
    """Never raises for expected failures: an unavailable catalogue is an explicit state, never 'valid'."""
    try:
        cat = load_catalogue(path, expected, max_bytes=max_bytes, max_objects=max_objects)
    except AttackReferenceError as exc:
        return CatalogueLoadResult(catalogue=None, error_code=exc.code, message=exc.message)
    return CatalogueLoadResult(catalogue=cat)


def catalogue_from_document(
    document: Any,
    expected: PinnedRelease,
    *,
    sha256: str,
    size_bytes: int,
    source_path: str = "<memory>",
    max_objects: int = DEFAULT_MAX_OBJECTS,
) -> AttackReferenceCatalogue:
    """Build the projection from an already-parsed document (used by ``load_catalogue`` and by synthetic tests)."""
    if not isinstance(document, dict) or document.get("type") != "bundle":
        raise AttackReferenceError(ErrorCode.BAD_COLLECTION_TYPE, "top-level value is not a STIX bundle")
    bundle_id = document.get("id")
    if not isinstance(bundle_id, str) or not bundle_id.startswith("bundle--") or len(bundle_id) > 80:
        raise AttackReferenceError(ErrorCode.INVALID_FIELD, "bundle id is missing or malformed")
    objects = document.get("objects")
    if not isinstance(objects, list):
        raise AttackReferenceError(ErrorCode.MISSING_OBJECTS, "bundle has no 'objects' list")
    if len(objects) > max_objects:
        raise AttackReferenceError(ErrorCode.TOO_MANY_OBJECTS, f"bundle exceeds the {max_objects}-object bound")

    seen: set[str] = set()
    collections: list[tuple[int, dict[str, Any]]] = []
    tactic_objs: list[tuple[int, dict[str, Any]]] = []
    tech_objs: list[tuple[int, dict[str, Any]]] = []
    rel_objs: list[tuple[int, dict[str, Any]]] = []
    skipped_no_attack_id = 0
    for i, obj in enumerate(objects):
        if not isinstance(obj, dict):
            raise AttackReferenceError(ErrorCode.NON_OBJECT_ENTRY, f"objects[{i}] is not a JSON object")
        oid, otype = obj.get("id"), obj.get("type")
        if not isinstance(oid, str) or not isinstance(otype, str):
            raise AttackReferenceError(ErrorCode.INVALID_FIELD, f"objects[{i}] lacks a string 'id' or 'type'")
        if oid in seen:
            raise AttackReferenceError(ErrorCode.DUPLICATE_STIX_ID, f"duplicate STIX id at objects[{i}]")
        seen.add(oid)
        if otype == "x-mitre-collection":
            collections.append((i, obj))
        elif otype == "x-mitre-tactic":
            tactic_objs.append((i, obj))
        elif otype == "attack-pattern":
            refs = obj.get("external_references")
            if refs is not None and not isinstance(refs, list):
                raise AttackReferenceError(ErrorCode.INVALID_FIELD, f"technique at objects[{i}]: 'external_references' is not a list")
            if _has_attack_reference(obj):
                tech_objs.append((i, obj))
            else:
                skipped_no_attack_id += 1
        elif otype == "relationship" and obj.get("relationship_type") in (_REL_REVOKED_BY, _REL_SUBTECHNIQUE_OF):
            rel_objs.append((i, obj))
    object_count = len(objects)
    del seen

    # collection identity ---------------------------------------------------------------------------------------
    if not collections:
        raise AttackReferenceError(ErrorCode.COLLECTION_MISSING, "no x-mitre-collection object found")
    if len(collections) > 1:
        raise AttackReferenceError(ErrorCode.MULTIPLE_COLLECTIONS, "more than one x-mitre-collection object found")
    ci, cobj = collections[0]
    coll: _RawCollection = _validate(_RawCollection, cobj, ci, "collection")
    if coll.x_mitre_version != expected.release_version:
        raise AttackReferenceError(ErrorCode.VERSION_MISMATCH, "collection release differs from the pinned release")
    if coll.name != expected.collection_name:
        raise AttackReferenceError(ErrorCode.DOMAIN_MISMATCH, "collection is not the pinned Enterprise collection")

    # tactics ---------------------------------------------------------------------------------------------------
    tactics: dict[str, TacticRecord] = {}
    shortname_to_tactic: dict[str, str] = {}
    for i, obj in tactic_objs:
        raw: _RawTactic = _validate(_RawTactic, obj, i, "tactic")
        if expected.domain not in raw.x_mitre_domains:
            continue
        ids = _attack_external_ids(raw.external_references)
        if len(ids) != 1 or TACTIC_ID_RE.fullmatch(ids[0]) is None:
            raise AttackReferenceError(ErrorCode.INVALID_FIELD, f"tactic at objects[{i}]: ATT&CK id missing, ambiguous or malformed")
        tid = ids[0]
        if tid in tactics or raw.x_mitre_shortname in shortname_to_tactic:
            raise AttackReferenceError(ErrorCode.DUPLICATE_ATTACK_ID, f"duplicate tactic identity at objects[{i}]")
        shortname_to_tactic[raw.x_mitre_shortname] = tid
        tactics[tid] = TacticRecord(
            stix_id=raw.id, tactic_id=tid, name=raw.name, shortname=raw.x_mitre_shortname,
            domains=tuple(raw.x_mitre_domains), revoked=bool(raw.revoked), deprecated=bool(raw.x_mitre_deprecated),
            created=raw.created, modified=raw.modified,
        )

    # techniques (first pass: identities and flags) -------------------------------------------------------------
    pending: dict[str, dict[str, Any]] = {}      # attack id -> projected fields
    stix_to_attack: dict[str, str] = {}
    other_domain_ids: set[str] = set()
    for i, obj in tech_objs:
        raw_t: _RawAttackPattern = _validate(_RawAttackPattern, obj, i, "technique")
        ids = _attack_external_ids(raw_t.external_references)
        if len(ids) != 1 or TECHNIQUE_ID_RE.fullmatch(ids[0]) is None:
            raise AttackReferenceError(ErrorCode.INVALID_FIELD, f"technique at objects[{i}]: ATT&CK id ambiguous or malformed")
        aid = ids[0]
        if expected.domain not in raw_t.x_mitre_domains:
            other_domain_ids.add(aid)
            continue
        if aid in pending:
            raise AttackReferenceError(ErrorCode.DUPLICATE_ATTACK_ID, f"duplicate ATT&CK technique id at objects[{i}]")
        shape_is_sub = "." in aid
        is_sub = raw_t.x_mitre_is_subtechnique if raw_t.x_mitre_is_subtechnique is not None else shape_is_sub
        if is_sub != shape_is_sub:
            raise AttackReferenceError(ErrorCode.INVALID_FIELD, f"technique at objects[{i}]: sub-technique flag contradicts the id shape")
        tactic_ids: list[str] = []
        for phase in raw_t.kill_chain_phases or []:
            if phase.kill_chain_name != _KILL_CHAIN_NAME:
                continue
            tid = shortname_to_tactic.get(phase.phase_name)
            if tid is None:
                raise AttackReferenceError(ErrorCode.UNRESOLVED_TACTIC, f"technique at objects[{i}]: kill-chain phase does not resolve to a tactic")
            if tid not in tactic_ids:
                tactic_ids.append(tid)
        revoked, deprecated = bool(raw_t.revoked), bool(raw_t.x_mitre_deprecated)
        pending[aid] = dict(
            stix_id=raw_t.id, attack_id=aid, name=raw_t.name, domains=tuple(raw_t.x_mitre_domains),
            revoked=revoked, deprecated=deprecated, lifecycle=lifecycle_of(revoked, deprecated),
            is_subtechnique=is_sub, tactic_ids=tuple(sorted(tactic_ids)), version=raw_t.x_mitre_version,
            created=raw_t.created, modified=raw_t.modified,
        )
        stix_to_attack[raw_t.id] = aid

    # relationships ---------------------------------------------------------------------------------------------
    warnings: list[str] = []
    parent_refs: dict[str, list[str]] = {}
    successor_refs: dict[str, list[str]] = {}
    for i, obj in rel_objs:
        rel: _RawRelationship = _validate(_RawRelationship, obj, i, "relationship")
        src = stix_to_attack.get(rel.source_ref)
        if src is None:
            warnings.append(f"{rel.relationship_type} relationship at objects[{i}] has a source outside the Enterprise technique set")
            continue
        if rel.relationship_type == _REL_SUBTECHNIQUE_OF:
            parent_refs.setdefault(src, []).append(rel.target_ref)
        else:
            successor_refs.setdefault(src, []).append(rel.target_ref)
    del rel_objs, tech_objs, tactic_objs

    techniques: dict[str, TechniqueRecord] = {}
    replacement_edges = 0
    unresolved_edges = 0
    for aid in sorted(pending):
        fields = pending[aid]
        parents = parent_refs.get(aid, [])
        parent_id: Optional[str] = None
        if len(parents) > 1:
            raise AttackReferenceError(ErrorCode.INCONSISTENT_RELATIONSHIP, f"{aid}: more than one parent relationship")
        if parents:
            if not fields["is_subtechnique"]:
                raise AttackReferenceError(ErrorCode.INCONSISTENT_RELATIONSHIP, f"{aid}: a top-level technique declares a parent")
            parent_id = stix_to_attack.get(parents[0])
            if parent_id is None:
                if not (fields["revoked"] or fields["deprecated"]):
                    raise AttackReferenceError(ErrorCode.SUBTECHNIQUE_WITHOUT_PARENT, f"{aid}: parent is not an Enterprise technique in this file")
                warnings.append(f"{aid}: parent reference does not resolve")
            elif not aid.startswith(parent_id + ".") or pending[parent_id]["is_subtechnique"]:
                raise AttackReferenceError(ErrorCode.INCONSISTENT_RELATIONSHIP, f"{aid}: parent id does not match the sub-technique id")
        elif fields["is_subtechnique"] and not (fields["revoked"] or fields["deprecated"]):
            raise AttackReferenceError(ErrorCode.SUBTECHNIQUE_WITHOUT_PARENT, f"{aid}: current sub-technique has no parent relationship")

        resolved: list[str] = []
        unresolved: list[str] = []
        for target in successor_refs.get(aid, []):
            tgt = stix_to_attack.get(target)
            if tgt is None:
                unresolved.append(target)
            elif tgt not in resolved:
                resolved.append(tgt)
        if successor_refs.get(aid) and not (fields["revoked"] or fields["deprecated"]):
            warnings.append(f"{aid}: revoked-by relationship on an object that is not marked revoked or deprecated")
        replacement_edges += len(resolved)
        unresolved_edges += len(unresolved)
        techniques[aid] = TechniqueRecord(
            parent_id=parent_id, replaced_by=tuple(sorted(resolved)),
            unresolved_successor_refs=tuple(sorted(set(unresolved))), **fields,
        )

    meta = CatalogueMeta(
        loader_version=LOADER_VERSION, source_path=source_path, sha256=sha256.upper(), size_bytes=size_bytes,
        bundle_id=bundle_id, collection_stix_id=coll.id, collection_name=coll.name, release_version=coll.x_mitre_version,
        attack_spec_version=coll.x_mitre_attack_spec_version, domain=expected.domain, object_count=object_count,
        technique_count=len(techniques), tactic_count=len(tactics),
        revoked_count=sum(1 for t in techniques.values() if t.revoked),
        deprecated_count=sum(1 for t in techniques.values() if t.deprecated),
        replacement_relationship_count=replacement_edges, unresolved_replacement_count=unresolved_edges,
        excluded_other_domain_technique_count=len(other_domain_ids),
        skipped_attack_patterns_without_attack_id=skipped_no_attack_id,
    )
    return AttackReferenceCatalogue(
        meta=meta, techniques=techniques, tactics=tactics,
        other_domain_technique_ids=sorted(other_domain_ids), warnings=warnings,
    )
