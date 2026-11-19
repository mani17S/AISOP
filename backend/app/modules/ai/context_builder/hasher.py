"""
AISOP Deterministic Context Serializer and Cryptographic Hasher.

Implements the AISOP-CJSON-1.0 canonical JSON serialization specification and
forensic SHA-256 context hashing for investigation reproducibility.

Key Invariants:
1. Determinism: Lexicographically sorted dictionary keys at all nesting levels.
2. Compact formatting: Standard compact separators (',', ':') with zero whitespace.
3. Native UTF-8: No Unicode escaping (ensure_ascii=False).
4. Numeric & Floating-Point Safety: Non-finite floats (NaN, +Inf, -Inf) are strictly rejected.
5. Temporal Integrity: Naive datetimes are strictly rejected; timezone-aware datetimes
   are normalized to UTC with strict 'Z' ISO-8601 formatting.
6. Ephemeral Field Exclusion: Exactly four documented ephemeral fields are excluded
   from the hash projection (context_sha256, assembled_at, created_at_utc, request_id).
7. Uncertainty Flags Normalization: Categorical flags are normalized into a sorted,
   deduplicated list of non-empty strings. Element types are validated before stripping.
8. Explicit Null Retention: None values are preserved as JSON null, ensuring predictable keys.
9. Zero-Billing / Local-First: Pure Python 3.12 standard library and existing Pydantic V2.
"""

from __future__ import annotations

import copy
import enum
import hashlib
import json
import math
import uuid
from datetime import date, datetime, timezone
from typing import Any

from pydantic import BaseModel


class CanonicalSerializationError(Exception):
    """Base exception for all canonical serialization and hashing errors."""


class CanonicalSerializationTypeError(CanonicalSerializationError, TypeError):
    """Raised when an unsupported Python type is passed to the canonical serializer."""


class CanonicalSerializationValueError(CanonicalSerializationError, ValueError):
    """Raised when an invalid value (such as a non-finite float) is encountered."""


# Documented ephemeral fields excluded from the forensic context SHA-256 digest
EPHEMERAL_FIELDS: frozenset[str] = frozenset({
    "context_sha256",
    "assembled_at",
    "created_at_utc",
    "request_id",
})

CANONICALIZATION_ALGORITHM_IDENTIFIER: str = "AISOP-CJSON-1.0"


def normalize_uncertainty_flags(flags: Any) -> list[str]:
    """
    Normalize uncertainty_flags into a lexicographically sorted, deduplicated list
    of non-empty strings.

    Validates that each element is a string before calling .strip().
    Rejects invalid types with CanonicalSerializationTypeError.
    """
    if flags is None:
        return []
    if not isinstance(flags, (list, tuple, set)):
        raise CanonicalSerializationTypeError(
            f"uncertainty_flags must be an iterable sequence of strings, got {type(flags).__name__}"
        )
    normalized: set[str] = set()
    for item in flags:
        if not isinstance(item, str):
            raise CanonicalSerializationTypeError(
                f"uncertainty_flags elements must be strings, got {type(item).__name__} ({item!r})"
            )
        stripped = item.strip()
        if stripped:
            normalized.add(stripped)
    return sorted(normalized)


def _normalize_dict_key(k: Any) -> str:
    """
    Validate and normalize a dictionary key into a canonical string.

    Permitted key types:
    - str (standard JSON key)
    - uuid.UUID (converted to lowercase hyphenated string)
    - int (excluding bool)
    - enum.Enum with scalar str/int value

    Raises:
    - CanonicalSerializationTypeError: For unsupported key types (tuples, floats, bools, custom objects).
    """
    if isinstance(k, enum.Enum):
        k = k.value

    if isinstance(k, str):
        return k
    if isinstance(k, uuid.UUID):
        return str(k).lower()
    if isinstance(k, int) and not isinstance(k, bool):
        return str(k)

    raise CanonicalSerializationTypeError(
        f"Unsupported dictionary key type: {type(k).__name__} ({k!r}). "
        "Dictionary keys must be strings, integers, or UUIDs."
    )


def normalize_value(val: Any) -> Any:
    """
    Recursively normalize Python objects into deterministic canonical JSON-compatible types.

    Conversions:
    - None -> None (serializes to explicit null)
    - bool -> bool (checked before int)
    - int -> int
    - float -> float (rejects non-finite floats: NaN, +Inf, -Inf)
    - str -> str
    - datetime -> UTC ISO-8601 string with 'Z' suffix (rejects naive datetimes)
    - date (not datetime) -> ISO-8601 string (YYYY-MM-DD)
    - uuid.UUID -> lowercase hyphenated string
    - enum.Enum -> normalized scalar value
    - pydantic.BaseModel -> normalized dict
    - dict -> dict with string keys and normalized values
    - list / tuple -> list with normalized items
    - set / complex / unhandled -> raises CanonicalSerializationTypeError
    """
    if val is None:
        return None

    # bool must be checked before int because bool is a subclass of int in Python
    if isinstance(val, bool):
        return val

    if isinstance(val, int):
        return val

    if isinstance(val, float):
        if not math.isfinite(val):
            raise CanonicalSerializationValueError(
                f"Non-finite float value {val!r} is not permitted in canonical serialization"
            )
        return val

    if isinstance(val, str):
        return val

    if isinstance(val, datetime):
        if val.tzinfo is None or val.tzinfo.utcoffset(val) is None:
            raise ValueError(
                f"Naive datetime encountered without timezone: {val!r}. "
                "All datetimes must be timezone-aware and normalized to UTC."
            )
        val_utc = val.astimezone(timezone.utc)
        iso_str = val_utc.isoformat()
        if iso_str.endswith("+00:00"):
            iso_str = iso_str[:-6] + "Z"
        elif not iso_str.endswith("Z"):
            iso_str = iso_str + "Z"
        return iso_str

    if isinstance(val, date):
        return val.isoformat()

    if isinstance(val, uuid.UUID):
        return str(val).lower()

    if isinstance(val, enum.Enum):
        return normalize_value(val.value)

    if isinstance(val, BaseModel):
        return normalize_value(val.model_dump(mode="python"))

    if isinstance(val, dict):
        normalized_dict: dict[str, Any] = {}
        for k, v in val.items():
            k_str = _normalize_dict_key(k)
            if k_str in normalized_dict:
                raise CanonicalSerializationValueError(
                    f"Dictionary key collision detected: key {k!r} coerced to already present key {k_str!r}"
                )
            normalized_dict[k_str] = normalize_value(v)
        return normalized_dict

    if isinstance(val, (list, tuple)):
        return [normalize_value(item) for item in val]

    if isinstance(val, set):
        raise CanonicalSerializationTypeError(
            f"Sets are not permitted in canonical serialization due to non-deterministic ordering: {val!r}"
        )

    if isinstance(val, complex):
        raise CanonicalSerializationTypeError(
            f"Complex numbers are not permitted in canonical serialization: {val!r}"
        )

    raise CanonicalSerializationTypeError(
        f"Unsupported type for canonical serialization: {type(val).__name__} ({val!r})"
    )


def filter_canonical_payload(
    context_data: BaseModel | dict[str, Any]
) -> dict[str, Any]:
    """
    Extract and filter the canonical hash projection from an InvestigationContext
    or equivalent dictionary.

    Operations:
    1. Injects 'canonicalization_algorithm': 'AISOP-CJSON-1.0'.
    2. Excludes documented ephemeral fields (assembled_at, created_at_utc, request_id, context_sha256).
    3. Normalizes uncertainty_flags to a sorted, deduplicated list of non-empty strings.
    4. Recursively normalizes all values for deterministic canonical serialization.
    """
    if isinstance(context_data, BaseModel):
        raw = context_data.model_dump(mode="python")
    elif isinstance(context_data, dict):
        raw = copy.deepcopy(context_data)
    else:
        raise CanonicalSerializationTypeError(
            f"context_data must be a Pydantic BaseModel or dict, got {type(context_data).__name__}"
        )

    # 1. Strip top-level ephemeral fields
    for field in EPHEMERAL_FIELDS:
        raw.pop(field, None)

    # 2. Strip ephemeral fields from nested reproducibility structures
    for repro_key in ("reproducibility", "reproducibility_parameters"):
        repro_val = raw.get(repro_key)
        if isinstance(repro_val, dict):
            for field in EPHEMERAL_FIELDS:
                repro_val.pop(field, None)

    # 3. Normalize uncertainty_flags if present
    if "uncertainty_flags" in raw:
        raw["uncertainty_flags"] = normalize_uncertainty_flags(raw["uncertainty_flags"])

    # 4. Bind the canonicalization algorithm identifier
    raw["canonicalization_algorithm"] = raw.get("canonicalization_algorithm") or CANONICALIZATION_ALGORITHM_IDENTIFIER

    # 5. Normalize all substantive values recursively
    return normalize_value(raw)


def canonicalize_payload(data: Any) -> str:
    """
    Produce a deterministic, canonical UTF-8 JSON string adhering to AISOP-CJSON-1.0.

    Guarantees:
    - All dictionary keys are recursively sorted.
    - Zero non-significant whitespace: compact separators (',', ':').
    - Native UTF-8 characters are unescaped (ensure_ascii=False).
    - Explicit None is preserved as null.
    - Non-finite floats (NaN, Inf, -Inf) are rejected.
    """
    normalized = normalize_value(data)
    try:
        return json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except ValueError as exc:
        raise CanonicalSerializationValueError(str(exc)) from exc
    except TypeError as exc:
        raise CanonicalSerializationTypeError(str(exc)) from exc


def compute_context_sha256(context: BaseModel | dict[str, Any]) -> str:
    """
    Compute the cryptographic SHA-256 hexadecimal digest for an investigation context.

    Workflow:
    1. Extracts and filters the substantive payload (excluding ephemeral fields).
    2. Serializes the payload to canonical AISOP-CJSON-1.0 string.
    3. Encodes the canonical string to UTF-8 bytes.
    4. Computes and returns the lowercase 64-character SHA-256 hex digest.
    """
    canonical_dict = filter_canonical_payload(context)
    canonical_str = canonicalize_payload(canonical_dict)
    canonical_bytes = canonical_str.encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest().lower()


VALIDATION_OUTPUT_CANONICALIZATION_ALGORITHM: str = "AISOP-OUTPUT-CJSON-1.0"


def _drop_taxonomy_of_pre_taxonomy_report(model: BaseModel, raw: dict[str, Any]) -> None:
    """
    Historical-digest compatibility for the optional ``MitreAttackHypothesis.taxonomy`` field (backlog item 0).

    A result hashed before that field existed has a stored digest whose projection has NO ``taxonomy`` key. A model parsed from
    such a payload dumps ``"taxonomy": null`` for every hypothesis (the field default), which would change the digest. The dict
    input path already behaves correctly (an absent key stays absent), so only the model path needs this.

    Discriminator: RAW FIELD PRESENCE, read from ``model_fields_set`` before ``model_dump`` erases it. The report is treated as
    pre-taxonomy only if it has at least one hypothesis and NO hypothesis has ``taxonomy`` in its fields set. The decision is
    report-level, never per hypothesis (a report with any explicit ``taxonomy``, including an explicit null, keeps the current
    projection for all of its hypotheses).

    Why a current-format report cannot downgrade into this branch: the only production constructor of a hypothesis (the guardrail
    validator) always passes ``taxonomy=...``, so every current report carries the key and keeps its taxonomy in the digest.
    Nulling it keeps the key present (explicit null), so it is hashed as null and no longer matches the stored digest. Deleting the
    key makes the report hash as a pre-taxonomy one, but its digest then covers different content than the stored current digest,
    so it still fails verification; it can only match a stored digest that was genuinely computed without the field.

    Fails closed: any unexpected structure leaves the current projection untouched, and a non-null taxonomy is never dropped.
    """
    hypotheses = getattr(getattr(model, "output", None), "mitre_attack_hypotheses", None)
    out = raw.get("output")
    dumped = out.get("mitre_attack_hypotheses") if isinstance(out, dict) else None
    if not isinstance(hypotheses, (list, tuple)) or not isinstance(dumped, list) or not hypotheses or len(hypotheses) != len(dumped):
        return
    for hyp, item in zip(hypotheses, dumped):
        if not isinstance(hyp, BaseModel) or not isinstance(item, dict) or "taxonomy" not in type(hyp).model_fields:
            return
        if "taxonomy" in hyp.model_fields_set or item.get("taxonomy") is not None:
            return
    for item in dumped:
        item.pop("taxonomy", None)


def filter_canonical_validation_output(
    validation_data: BaseModel | dict[str, Any],
) -> dict[str, Any]:
    """
    Extract and filter the canonical hash projection from an InvestigationValidationResult
    or equivalent dictionary.

    Operations:
    1. Converts Pydantic model to dict or deepcopies raw dictionary.
    2. Strips self-referential or ephemeral digest fields if present (output_sha256).
    3. Injects versioned 'canonicalization_algorithm': 'AISOP-OUTPUT-CJSON-1.0'.
    4. Recursively normalizes all substantive values for deterministic canonical serialization.
    """
    if isinstance(validation_data, BaseModel):
        raw = validation_data.model_dump(mode="python")
        _drop_taxonomy_of_pre_taxonomy_report(validation_data, raw)
    elif isinstance(validation_data, dict):
        raw = copy.deepcopy(validation_data)
    else:
        raise CanonicalSerializationTypeError(
            f"validation_data must be a Pydantic BaseModel or dict, got {type(validation_data).__name__}"
        )

    # Exclude any self-referential or ephemeral hash fields
    raw.pop("output_sha256", None)
    raw.pop("validation_output_sha256", None)

    # Task 1 compatibility: the additive claim fields ``assertions`` and ``verification`` default to None. They are omitted from the canonical
    # projection while absent/empty, so the digest of any result that predates them (and of any claim without structured assertions) is
    # byte-identical to before. When present they are part of the digest, consistently at synthesis time and when a result is re-submitted.
    out = raw.get("output")
    if isinstance(out, dict):
        for claim in out.get("claims") or []:
            if isinstance(claim, dict):
                if not claim.get("assertions"):
                    claim.pop("assertions", None)
                if claim.get("verification") is None:
                    claim.pop("verification", None)

    # Bind the canonicalization algorithm identifier
    raw["canonicalization_algorithm"] = (
        raw.get("canonicalization_algorithm") or VALIDATION_OUTPUT_CANONICALIZATION_ALGORITHM
    )

    return normalize_value(raw)


def compute_validation_output_sha256(
    validation_data: BaseModel | dict[str, Any],
) -> str:
    """
    Compute the cryptographic SHA-256 hexadecimal digest for an investigation validation output.

    Workflow:
    1. Extracts and filters the substantive validation output payload.
    2. Serializes the payload to canonical AISOP-OUTPUT-CJSON-1.0 string.
    3. Encodes the canonical string to UTF-8 bytes.
    4. Computes and returns the lowercase 64-character SHA-256 hex digest.
    """
    canonical_dict = filter_canonical_validation_output(validation_data)
    canonical_str = canonicalize_payload(canonical_dict)
    canonical_bytes = canonical_str.encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest().lower()

    