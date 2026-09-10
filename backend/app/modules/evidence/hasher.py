"""
AISOP Cryptographic Evidence Hasher.

Implements the Evidence-First Principle:
Every ingested raw evidence payload is hashed with SHA-256 to ensure data immutability,
chain-of-custody verification, and duplicate detection.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonicalize_payload(data: dict[str, Any] | str | bytes) -> str:
    """
    Produce a deterministic, canonical string representation of raw evidence.
    For dicts, keys are sorted recursively and compact separators are used.
    """
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    # For lists or primitives
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_sha256(data: dict[str, Any] | str | bytes) -> str:
    """
    Compute the SHA-256 hexadecimal digest for raw telemetry data.
    """
    canonical_str = canonicalize_payload(data)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
