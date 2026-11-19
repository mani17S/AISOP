"""
AISOP Evaluation Metrics & Normalization Utilities.

Provides pure mathematical scoring functions, syntactic/schema validity checks,
and indicator normalization routines for offline benchmark evaluation.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from pydantic import ValidationError

from app.schemas.evaluation import FallbackReasonCategory
from app.schemas.investigation import StructuredInvestigationOutput


def canonicalize_prompt_artifact(prompt: str | bytes) -> bytes:
    """
    Produce deterministic canonical byte sequence for prompt verification.
    Normalizes Windows/POSIX newlines (CRLF -> LF, CR -> LF), strips trailing whitespace,
    and encodes as UTF-8.
    """
    if isinstance(prompt, bytes):
        text = prompt.decode("utf-8", errors="replace")
    else:
        text = str(prompt)
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    return normalized.encode("utf-8")


def safe_division(numerator: float, denominator: float) -> float | None:
    """Compute division safely; returns None if denominator is zero."""
    if denominator == 0.0:
        return None
    return numerator / denominator


def compute_precision_recall_f1(
    tp: int, fp: int, fn: int, zero_target_penalty: bool = True
) -> tuple[float | None, float | None, float | None]:
    """
    Compute Precision, Recall, and F1 score with strict division-by-zero handling.

    Mathematical Conventions:
    - If tp == 0, fp == 0, fn == 0 (clean empty target, no predictions):
      Returns (None, None, None).
    - If tp == 0, fp > 0, fn == 0 (false-positive prediction on an empty ground truth):
      Precision is 0.0 (0 / (0 + fp)). Recall is mathematically undefined (None)
      because there were zero positive expected targets.
      Under the zero-target penalty convention (zero_target_penalty=True),
      F1 is assigned 0.0 so that false-positive hallucinations on clean baselines
      are penalized and not silently omitted from macro-evaluation scorecards.
    - If tp == 0, fp == 0, fn > 0 (zero predictions on target with expected techniques):
      Precision is mathematically undefined (None) because there were zero predictions made.
      Recall is 0.0 (0 / (0 + fn)).
      Under the zero-prediction penalty convention (zero_target_penalty=True),
      F1 is assigned 0.0 so that complete misses are penalized in macro-evaluation scorecards
      rather than silently excluded due to undefined precision denominators.

    Returns:
        (precision, recall, f1)
    """
    prec = safe_division(float(tp), float(tp + fp))
    rec = safe_division(float(tp), float(tp + fn))

    if tp == 0 and fp > 0 and fn == 0:
        prec = 0.0
        rec = None  # Undefined denominator: 0 expected targets
        f1 = 0.0 if zero_target_penalty else None
        return (prec, rec, f1)

    if tp == 0 and fp == 0 and fn > 0:
        prec = None  # Undefined denominator: 0 model predictions
        rec = 0.0   # Missed all expected targets: 0 / fn = 0.0
        f1 = 0.0 if zero_target_penalty else None  # Zero-prediction penalty convention
        return (prec, rec, f1)

    if prec is None or rec is None:
        f1 = None
    elif (prec + rec) == 0.0:
        f1 = 0.0
    else:
        f1 = 2.0 * (prec * rec) / (prec + rec)

    return (prec, rec, f1)


def is_syntactic_json(raw_text: str) -> tuple[bool, Any, str | None]:
    """
    Evaluate whether raw text is syntactically valid JSON.

    Supports stripping markdown code fences (```json ... ```) defensively.

    Returns:
        (is_valid, parsed_data_or_none, error_message_or_none)
    """
    if not isinstance(raw_text, str) or not raw_text.strip():
        return (False, None, "Empty or non-string input")

    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*\n?", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned)
        cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
        return (True, parsed, None)
    except json.JSONDecodeError as exc:
        return (False, None, f"JSONDecodeError: {exc.msg} at line {exc.lineno} col {exc.colno}")


def is_schema_valid_output(
    data: Any,
) -> tuple[bool, StructuredInvestigationOutput | None, str | None]:
    """
    Evaluate whether data conforms strictly to StructuredInvestigationOutput Pydantic contract.

    Returns:
        (is_valid, validated_model_or_none, error_message_or_none)
    """
    if not isinstance(data, dict):
        return (False, None, f"Expected dictionary payload, got {type(data).__name__}")

    try:
        model = StructuredInvestigationOutput.model_validate(data)
        return (True, model, None)
    except ValidationError as exc:
        return (False, None, f"Schema ValidationError: {exc.error_count()} error(s): {exc}")


def normalize_ioc(val: str, ioc_type: str) -> str:
    """
    Deterministically normalize an observable value for comparison.

    Rules:
    - ipv4 / ipv6: Parsed via ipaddress module and returned in canonical string form.
    - domain: Lowercased, stripped of trailing dots and protocol prefixes.
    - sha256 / md5 / sha1: Lowercased and stripped.
    - executable: Lowercased basename (e.g. 'c:\\windows\\system32\\powershell.exe' -> 'powershell.exe').
    - other: Trimmed whitespace.
    """
    clean = str(val).strip()
    clean_type = ioc_type.lower().strip()

    if clean_type in ("ipv4", "ipv6", "ip"):
        try:
            addr = ipaddress.ip_address(clean)
            return str(addr)
        except ValueError:
            return clean.lower()

    if clean_type == "domain":
        clean = re.sub(r"^https?://", "", clean, flags=re.IGNORECASE)
        clean = clean.split("/")[0].split(":")[0]  # remove path and port
        return clean.lower().rstrip(".")

    if clean_type in ("sha256", "md5", "sha1", "hash"):
        return clean.lower()

    if clean_type in ("executable", "process", "image"):
        # Extract filename only
        normalized_path = clean.replace("/", "\\")
        basename = normalized_path.split("\\")[-1]
        return basename.lower()

    return clean.lower()


def categorize_fallback(
    raw_text: str | None,
    parsed_json: Any | None,
    validated_model: StructuredInvestigationOutput | None,
    output_source_type: str | None = None,
) -> FallbackReasonCategory:
    """
    Determine whether an output is genuine model generation or deterministic fallback.
    """
    if output_source_type == "missing_fixture":
        return FallbackReasonCategory.UNMEASURED_MISSING_FIXTURE

    if output_source_type == "legacy_unverified_fixture":
        return FallbackReasonCategory.LEGACY_UNVERIFIED_FIXTURE

    if output_source_type in (
        "missing_prompt_artifact",
        "prompt_hash_mismatch",
        "fixture_misbound",
        "fixture_hash_mismatch",
        "model_identifier_mismatch",
        "corrupt_fixture_envelope",
    ):
        return FallbackReasonCategory.INVALID_RESPONSE

    if output_source_type in ("harness_self_test", "harness_self_test_mock"):
        return FallbackReasonCategory.HARNESS_SELF_TEST

    if validated_model is not None and validated_model.model_identifier in (
        "harness_self_test",
        "harness_self_test_mock",
        "HARNESS_SELF_TEST",
    ):
        return FallbackReasonCategory.HARNESS_SELF_TEST

    if raw_text is None or not str(raw_text).strip():
        return FallbackReasonCategory.INVALID_RESPONSE

    if parsed_json is None:
        return FallbackReasonCategory.PARSER_REJECTION

    if validated_model is None:
        return FallbackReasonCategory.INVALID_RESPONSE

    # Check for explicit deterministic fallback marker
    if validated_model.model_identifier == "deterministic_fallback":
        # Check summary or flags for provider failure / timeout
        flags_text = " ".join(validated_model.uncertainty_and_data_gaps).lower()
        if "timeout" in flags_text:
            return FallbackReasonCategory.TIMEOUT
        if "guardrail" in flags_text:
            return FallbackReasonCategory.GUARDRAIL_REJECTION
        return FallbackReasonCategory.DETERMINISTIC_FALLBACK

    return FallbackReasonCategory.GENUINE_MODEL_OUTPUT

