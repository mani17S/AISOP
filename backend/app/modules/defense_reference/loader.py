"""
Minimal, offline loader for the pinned MITRE D3FEND reference files (ATT&CK technique -> D3FEND defensive technique).

Same pattern as the pinned ATT&CK loader and equally fail-closed:
  1. the path must be a directory holding exactly the two pinned files, each a regular file within a size bound;
  2. each file's size and SHA-256 are verified over the exact bytes that are then parsed, BEFORE any parsing;
  3. only the columns AISOP needs are projected through strict Pydantic models; every other column (including the long
     artifact labels and IRIs) is ignored and never retained; definitions are kept only if short (bounded);
  4. duplicates and inconsistencies (repeated D3FEND id or name, a mapped technique missing from the ontology list,
     the same technique under two tactics, a malformed ATT&CK id) are rejected, never silently resolved.

The mapping file is MITRE's own artifact-based inference (an ATT&CK technique and a D3FEND technique are related when
they act on the same digital artifact). It is a reference suggestion, not a statement of efficacy, and not evidence.
Only rows whose framework is ``ATTACKEnterpriseTechnique`` are used (ICS and SPARTA rows are counted and skipped).

NOT done here, by design: no network, no download, no auto-update, no database, no cache, no write to the source.
Adopting a new D3FEND release needs a reviewed code change and a new pinned provenance record.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

LOADER_VERSION = "defense-reference-loader-v1"
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_DEFINITION_CHARS = 500
_ENTERPRISE_IRI = "http://d3fend.mitre.org/ontologies/d3fend.owl#ATTACKEnterpriseTechnique"
_ATTACK_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
_SAFE_NAME = r"[A-Za-z0-9][A-Za-z0-9 .,/()+&'\-]*"


@dataclass(frozen=True)
class PinnedD3fend:
    """What the loader must find. Every field is checked; nothing is inferred or defaulted from the files."""

    version: str
    mappings_file: str
    mappings_sha256: str
    mappings_size: int
    ontology_file: str
    ontology_sha256: str
    ontology_size: int


#: MITRE D3FEND ontology release 1.6.0 as acquired 2026-11-22 from https://d3fend.mitre.org/ontologies/d3fend/1.6.0/.
#: Hashes and sizes are locally calculated identity records, not MITRE signatures.
D3FEND_1_6_0 = PinnedD3fend(
    version="1.6.0",
    mappings_file="d3fend-full-mappings.csv",
    mappings_sha256="2B86A5A19DE143560B75FB2B443A7AC60335D60DFB6B08A7A6E9A53A052AD79F",
    mappings_size=14_751_588,
    ontology_file="d3fend.csv",
    ontology_sha256="979C5B82324893DD3F3C6BB2ACBCD6B2A14B49566CBFB2052564665DE13506C6",
    ontology_size=38_047,
)

#: Approved production location (outside the repository). Tests pass an explicit path instead.
DEFAULT_DATASET_DIR = Path(r"D:\AISOP-Reference-Data\MITRE-D3FEND\1.6.0")


class Category(StrEnum):
    """D3FEND defensive tactics, in display order. ``Model`` is a real D3FEND tactic and is kept, not dropped."""

    HARDEN = "Harden"
    DETECT = "Detect"
    ISOLATE = "Isolate"
    DECEIVE = "Deceive"
    EVICT = "Evict"
    RESTORE = "Restore"
    MODEL = "Model"


_CATEGORY_ORDER = {c: i for i, c in enumerate(Category)}


class ErrorCode(StrEnum):
    PATH_MISSING = "path_missing"
    NOT_A_FILE = "not_a_file"
    PATH_UNREADABLE = "path_unreadable"
    EMPTY_FILE = "empty_file"
    TOO_LARGE = "too_large"
    SIZE_MISMATCH = "size_mismatch"
    HASH_MISMATCH = "hash_mismatch"
    MALFORMED_CSV = "malformed_csv"
    INVALID_FIELD = "invalid_field"
    DUPLICATE_ID = "duplicate_id"
    INCONSISTENT = "inconsistent"


class DefenseReferenceError(Exception):
    """Raised for every expected load failure. The message never echoes untrusted values from the files."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(f"{code.value}: {message}")
        self.code = code
        self.message = message


class DefensiveTechnique(BaseModel):
    """One D3FEND defensive technique as AISOP keeps it: id, name, category and an optional short definition."""

    model_config = ConfigDict(frozen=True)
    d3fend_id: str = Field(pattern=r"D3-[A-Z0-9]{1,12}", max_length=16)
    name: Annotated[str, StringConstraints(pattern=_SAFE_NAME, max_length=100)]
    category: Category
    definition: Optional[str] = Field(default=None, max_length=MAX_DEFINITION_CHARS)


class DefenseCatalogue(BaseModel):
    """Immutable projection: ATT&CK Enterprise technique id -> defensive techniques, plus source identity."""

    model_config = ConfigDict(frozen=True)
    loader_version: str
    d3fend_version: str
    mappings_sha256: str
    ontology_sha256: str
    attack_technique_count: int
    defensive_technique_count: int
    skipped_non_enterprise_rows: int
    by_attack: dict[str, tuple[DefensiveTechnique, ...]]

    def lookup(self, technique_ids: list[str] | tuple[str, ...]) -> dict[str, tuple[DefensiveTechnique, ...]]:
        """
        Exact-id lookup, input order preserved, duplicates collapsed. A technique with no mapping is simply absent.
        A sub-technique is NOT resolved through its parent: the pinned mapping does not define that inheritance, so
        nothing is inferred.
        """
        out: dict[str, tuple[DefensiveTechnique, ...]] = {}
        for raw in technique_ids:
            tid = str(raw).strip().upper()
            if tid in out:
                continue
            found = self.by_attack.get(tid)
            if found:
                out[tid] = found
        return out


@dataclass(frozen=True)
class DefenseLoadResult:
    """Non-raising result for callers that must keep working when the optional reference is unavailable."""

    catalogue: Optional[DefenseCatalogue]
    error_code: Optional[ErrorCode] = None
    message: Optional[str] = None

    @property
    def available(self) -> bool:
        return self.catalogue is not None


_RAW = ConfigDict(extra="ignore", frozen=True)  # CSV cells are always str; enum coercion from str needs non-strict mode


class _MappingRow(BaseModel):
    model_config = _RAW
    off_tech_id: str
    def_tech_label: Annotated[str, StringConstraints(pattern=_SAFE_NAME, max_length=100)]
    def_tactic_label: Category


class _OntologyRow(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, populate_by_name=True)
    id: str = Field(alias="ID")
    tactic: Category = Field(alias="D3FEND Tactic")
    technique: str = Field(alias="D3FEND Technique")
    level0: str = Field(alias="D3FEND Technique Level 0")
    level1: str = Field(alias="D3FEND Technique Level 1")
    definition: str = Field(alias="Definition", max_length=MAX_DEFINITION_CHARS)


def _read_verified(directory: Path, name: str, size: int, sha256: str) -> str:
    p = directory / name
    try:
        if not p.exists():
            raise DefenseReferenceError(ErrorCode.PATH_MISSING, f"{name} does not exist in the configured directory")
        if not p.is_file():
            raise DefenseReferenceError(ErrorCode.NOT_A_FILE, f"{name} is not a regular file")
        actual = p.stat().st_size
        if actual == 0:
            raise DefenseReferenceError(ErrorCode.EMPTY_FILE, f"{name} is empty")
        if actual > MAX_FILE_BYTES:
            raise DefenseReferenceError(ErrorCode.TOO_LARGE, f"{name} exceeds the {MAX_FILE_BYTES}-byte bound")
        if actual != size:
            raise DefenseReferenceError(ErrorCode.SIZE_MISMATCH, f"{name} size differs from the pinned release")
        data = p.read_bytes()
    except OSError:
        raise DefenseReferenceError(ErrorCode.PATH_UNREADABLE, f"{name} could not be read") from None
    if len(data) != size:
        raise DefenseReferenceError(ErrorCode.SIZE_MISMATCH, f"{name} changed while being read")
    if hashlib.sha256(data).hexdigest().upper() != sha256.upper():
        raise DefenseReferenceError(ErrorCode.HASH_MISMATCH, f"{name} SHA-256 differs from the pinned release")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise DefenseReferenceError(ErrorCode.MALFORMED_CSV, f"{name} is not valid UTF-8") from None


def _rows(text: str, name: str) -> list[dict[str, str]]:
    try:
        return list(csv.DictReader(io.StringIO(text, newline="")))
    except csv.Error:
        raise DefenseReferenceError(ErrorCode.MALFORMED_CSV, f"{name} is not valid CSV") from None


def _validate(model: type[BaseModel], row: dict[str, str], line: int, name: str):  # type: ignore[no-untyped-def]
    try:
        return model.model_validate(row)
    except ValidationError as exc:
        first = exc.errors(include_input=False, include_url=False, include_context=False)[0]
        loc = ".".join(str(p) for p in first["loc"]) or "<row>"
        raise DefenseReferenceError(
            ErrorCode.INVALID_FIELD, f"{name} row {line}: field '{loc}' invalid ({first['type']})"
        ) from None


def load_defense_catalogue(
    directory: Path | str = DEFAULT_DATASET_DIR, expected: PinnedD3fend = D3FEND_1_6_0
) -> DefenseCatalogue:
    """Verify then parse the pinned local files. Raises ``DefenseReferenceError`` on any failure; never partial."""
    d = Path(directory)
    if not d.is_dir():
        raise DefenseReferenceError(ErrorCode.PATH_MISSING, "defense reference directory does not exist")
    onto_text = _read_verified(d, expected.ontology_file, expected.ontology_size, expected.ontology_sha256)
    map_text = _read_verified(d, expected.mappings_file, expected.mappings_size, expected.mappings_sha256)

    # ontology list: id, tactic, name (deepest non-empty level), short definition ----------------------------------
    techniques: dict[str, DefensiveTechnique] = {}
    ids_seen: set[str] = set()
    for i, raw in enumerate(_rows(onto_text, expected.ontology_file), start=2):
        row: _OntologyRow = _validate(_OntologyRow, raw, i, expected.ontology_file)
        name = row.level1 or row.level0 or row.technique
        if not name:
            raise DefenseReferenceError(ErrorCode.INVALID_FIELD, f"{expected.ontology_file} row {i}: no technique name")
        if row.id in ids_seen or name in techniques:
            raise DefenseReferenceError(ErrorCode.DUPLICATE_ID, f"{expected.ontology_file} row {i}: duplicate id or name")
        ids_seen.add(row.id)
        try:
            techniques[name] = DefensiveTechnique(
                d3fend_id=row.id, name=name, category=row.tactic, definition=row.definition or None
            )
        except ValidationError:
            raise DefenseReferenceError(ErrorCode.INVALID_FIELD, f"{expected.ontology_file} row {i}: invalid technique") from None

    # mapping: ATT&CK Enterprise id -> distinct defensive techniques ------------------------------------------------
    collected: dict[str, dict[str, DefensiveTechnique]] = {}
    skipped = 0
    for i, raw in enumerate(_rows(map_text, expected.mappings_file), start=2):
        if raw.get("framework_root_iri") != _ENTERPRISE_IRI:
            skipped += 1
            continue
        m: _MappingRow = _validate(_MappingRow, raw, i, expected.mappings_file)
        if _ATTACK_ID_RE.fullmatch(m.off_tech_id) is None:
            raise DefenseReferenceError(ErrorCode.INVALID_FIELD, f"{expected.mappings_file} row {i}: malformed ATT&CK id")
        tech = techniques.get(m.def_tech_label)
        if tech is None or tech.category != m.def_tactic_label:
            raise DefenseReferenceError(
                ErrorCode.INCONSISTENT, f"{expected.mappings_file} row {i}: defensive technique not in the ontology list or tactic differs"
            )
        collected.setdefault(m.off_tech_id, {})[tech.d3fend_id] = tech  # identical repeats (one per shared artifact) collapse
    if not collected:
        raise DefenseReferenceError(ErrorCode.INCONSISTENT, "mapping contains no ATT&CK Enterprise rows")

    by_attack = {
        aid: tuple(sorted(ts.values(), key=lambda t: (_CATEGORY_ORDER[t.category], t.name)))
        for aid, ts in sorted(collected.items())
    }
    return DefenseCatalogue(
        loader_version=LOADER_VERSION, d3fend_version=expected.version, mappings_sha256=expected.mappings_sha256.upper(),
        ontology_sha256=expected.ontology_sha256.upper(), attack_technique_count=len(by_attack),
        defensive_technique_count=len(techniques), skipped_non_enterprise_rows=skipped, by_attack=by_attack,
    )


def try_load_defense_catalogue(
    directory: Path | str = DEFAULT_DATASET_DIR, expected: PinnedD3fend = D3FEND_1_6_0
) -> DefenseLoadResult:
    """Never raises for expected failures: an unavailable reference is an explicit state, never 'valid'."""
    try:
        return DefenseLoadResult(catalogue=load_defense_catalogue(directory, expected))
    except DefenseReferenceError as exc:
        return DefenseLoadResult(catalogue=None, error_code=exc.code, message=exc.message)
