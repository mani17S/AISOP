"""
Unit tests for AISOP P2-H4 Canonical Serializer and Forensic Hasher.

Tests cover:
1. TC-2.1-01: Deterministic key sorting across nested structures.
2. TC-2.1-02: Exact canonical bytes, compact separators, and native UTF-8 encoding.
3. TC-2.1-03: Repeated serialization idempotence under key permutations.
4. TC-2.1-04: Substantive field sensitivity (avalanche effect).
5. TC-2.1-05: Excluded ephemeral field invariance (assembled_at, created_at_utc, request_id, context_sha256).
6. TC-2.1-06: Uncertainty flags set normalization (permutation and duplicate invariance, element type validation).
7. TC-2.1-07: Equivalent UTC instant normalization across differing timezone offsets.
8. TC-2.1-08: Deterministic rejection of naive datetimes without timezone awareness.
9. TC-2.1-09: Canonicalization algorithm version binding ("AISOP-CJSON-1.0").
10. TC-2.1-10: Strict rejection of non-finite floats (NaN, +Infinity, -Infinity).
11. TC-2.1-11: Deterministic rejection of unsupported Python types (sets, complex numbers, custom classes).
12. TC-2.1-12: Explicit null retention for None values.
13. TC-2.1-13: Full InvestigationContext model hashing and roundtrip verification.
"""

from __future__ import annotations

import copy
import math
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import pytest

from app.modules.ai.context_builder.hasher import (
    CANONICALIZATION_ALGORITHM_IDENTIFIER,
    CanonicalSerializationError,
    CanonicalSerializationTypeError,
    CanonicalSerializationValueError,
    canonicalize_payload,
    compute_context_sha256,
    filter_canonical_payload,
    normalize_uncertainty_flags,
    normalize_value,
)
from app.schemas.investigation import (
    BudgetMetrics,
    ContextEntityItem,
    ContextEventItem,
    ContextKnowledgeChunkItem,
    ContextTIFindingItem,
    InvestigationContext,
    InvestigationScopeType,
    ReproducibilityRecord,
)


# ---------------------------------------------------------------------------
# Test Helpers & Fixtures
# ---------------------------------------------------------------------------

VALID_SHA256_A = "a" * 64
VALID_SHA256_B = "b" * 64
FIXED_EVENT_UUID = uuid.UUID("11111111-1111-1111-1111-111111111111")
FIXED_INVESTIGATION_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")


def build_sample_event(
    event_uuid: uuid.UUID | None = None,
    summary: str = "Test Sysmon Event 1",
    action: str = "created",
    severity: str = "informational",
) -> ContextEventItem:
    t = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    return ContextEventItem(
        event_uuid=event_uuid or FIXED_EVENT_UUID,
        raw_evidence_sha256=VALID_SHA256_A,
        event_id="1",
        event_type="process_creation",
        timestamp_utc=t,
        action=action,
        outcome="success",
        severity=severity,
        source_identifier="WORKSTATION-01",
        summary=summary,
        attributes={"command_line": "powershell.exe -NoProfile", "pid": 4012},
    )


def build_sample_context(
    uncertainty_flags: list[str] | None = None,
    target_hosts: list[str] | None = None,
    event_uuid: uuid.UUID | None = None,
    investigation_id: uuid.UUID | None = None,
) -> InvestigationContext:
    t_start = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    ev = build_sample_event(event_uuid=event_uuid)

    budget = BudgetMetrics(
        total_events_in_scope=1,
        events_included=1,
        events_omitted_count=0,
    )

    repro = ReproducibilityRecord(
        time_window_start=t_start,
        time_window_end=t_end,
        context_sha256="0" * 64,
        selected_event_uuids=[ev.event_uuid],
        selected_chunk_ids=[],
    )

    return InvestigationContext(
        investigation_id=investigation_id or FIXED_INVESTIGATION_ID,
        scope_type=InvestigationScopeType.SINGLE_EVENT,
        time_window_start=t_start,
        time_window_end=t_end,
        target_hosts=target_hosts or ["WORKSTATION-01"],
        events=[ev],
        budget_metrics=budget,
        reproducibility=repro,
        uncertainty_flags=uncertainty_flags or ["FLAG_A"],
    )


# ---------------------------------------------------------------------------
# 1. TC-2.1-01: Deterministic Key Sorting
# ---------------------------------------------------------------------------

def test_canonical_json_deterministic_key_sorting():
    """Verify that nested dictionary key insertion order does not affect canonical JSON output."""
    d1 = {
        "z": {"b": 1, "a": 2},
        "m": "middle",
        "a": [{"k2": "val2", "k1": "val1"}, 42],
    }
    d2 = {
        "a": [{"k1": "val1", "k2": "val2"}, 42],
        "z": {"a": 2, "b": 1},
        "m": "middle",
    }
    s1 = canonicalize_payload(d1)
    s2 = canonicalize_payload(d2)

    assert s1 == s2
    expected = '{"a":[{"k1":"val1","k2":"val2"},42],"m":"middle","z":{"a":2,"b":1}}'
    assert s1 == expected


# ---------------------------------------------------------------------------
# 2. TC-2.1-02: Exact Canonical Bytes and UTF-8 Encoding
# ---------------------------------------------------------------------------

def test_exact_canonical_bytes_and_utf8_encoding():
    """Verify compact formatting (no whitespace after ',' or ':') and native unescaped UTF-8 bytes."""
    data = {
        "cmd": 'powershell.exe -Command "Защита и безопасность"',
        "path": "C:\\Program Files\\测试\\münchen_ärztin.dll",
        "emoji": "🛡️",
        "count": 10,
    }
    canonical_str = canonicalize_payload(data)

    # Must NOT contain whitespace after delimiters
    assert ", " not in canonical_str
    assert ": " not in canonical_str

    # Must contain native characters without \uXXXX escaping
    assert "Защита" in canonical_str
    assert "测试" in canonical_str
    assert "münchen_ärztin" in canonical_str
    assert "🛡️" in canonical_str
    assert "\\u" not in canonical_str

    # Must encode cleanly to UTF-8 bytes
    canonical_bytes = canonical_str.encode("utf-8")
    assert isinstance(canonical_bytes, bytes)
    assert canonical_bytes.decode("utf-8") == canonical_str


# ---------------------------------------------------------------------------
# 3. TC-2.1-03: Repeated Serialization Idempotence
# ---------------------------------------------------------------------------

def test_repeated_serialization_idempotence():
    """100 repeated serializations of a complex payload with randomized key order yield identical output."""
    base_items = [
        ("event_id", "1"),
        ("source", "HOST-99"),
        ("action", "network_connection"),
        ("attributes", {"dest_ip": "10.0.0.5", "dest_port": 443, "protocol": "tcp"}),
        ("tags", ["critical", "lateral_movement", "apt29"]),
        ("score", 0.985),
    ]

    baseline_str = None
    baseline_hash = None

    for _ in range(100):
        shuffled = list(base_items)
        random.shuffle(shuffled)
        payload = dict(shuffled)

        result_str = canonicalize_payload(payload)
        result_hash = compute_context_sha256(payload)

        if baseline_str is None:
            baseline_str = result_str
            baseline_hash = result_hash
        else:
            assert result_str == baseline_str
            assert result_hash == baseline_hash


# ---------------------------------------------------------------------------
# 4. TC-2.1-04: Substantive Field Sensitivity
# ---------------------------------------------------------------------------

def test_substantive_field_sensitivity():
    """Mutating any substantive evidence or metadata field alters the SHA-256 digest."""
    ctx_base = build_sample_context()
    base_hash = compute_context_sha256(ctx_base)

    # 1. Mutate target_hosts
    ctx_host = build_sample_context(target_hosts=["WORKSTATION-02"])
    assert compute_context_sha256(ctx_host) != base_hash

    # 2. Mutate event attribute
    ctx_event_mod = copy.deepcopy(ctx_base.model_dump(mode="python"))
    ctx_event_mod["events"][0]["attributes"]["command_line"] = "powershell.exe -ExecutionPolicy Bypass"
    assert compute_context_sha256(ctx_event_mod) != base_hash

    # 3. Mutate event severity
    ctx_sev_mod = copy.deepcopy(ctx_base.model_dump(mode="python"))
    ctx_sev_mod["events"][0]["severity"] = "high"
    assert compute_context_sha256(ctx_sev_mod) != base_hash

    # 4. Mutate budget metrics count
    ctx_budget_mod = copy.deepcopy(ctx_base.model_dump(mode="python"))
    ctx_budget_mod["budget_metrics"]["total_events_in_scope"] = 99
    assert compute_context_sha256(ctx_budget_mod) != base_hash


# ---------------------------------------------------------------------------
# 5. TC-2.1-05: Excluded Ephemeral Field Invariance
# ---------------------------------------------------------------------------

def test_excluded_ephemeral_field_invariance():
    """Mutating assembled_at, created_at_utc, request_id, or context_sha256 preserves identical hash."""
    ctx1 = build_sample_context()
    hash1 = compute_context_sha256(ctx1)

    # Create ctx2 with identical substantive data but different ephemeral values
    t_start = ctx1.time_window_start
    t_end = ctx1.time_window_end
    ev_uuid = ctx1.events[0].event_uuid

    repro2 = ReproducibilityRecord(
        request_id=uuid.uuid4(),  # Different request_id
        time_window_start=t_start,
        time_window_end=t_end,
        context_sha256=VALID_SHA256_B,  # Different recorded hash!
        selected_event_uuids=[ev_uuid],
        selected_chunk_ids=[],
        created_at_utc=datetime(2026, 10, 23, 15, 45, 0, tzinfo=timezone.utc),  # Different created_at_utc
    )

    ctx2 = InvestigationContext(
        investigation_id=ctx1.investigation_id,
        scope_type=ctx1.scope_type,
        time_window_start=t_start,
        time_window_end=t_end,
        target_hosts=ctx1.target_hosts,
        events=ctx1.events,
        budget_metrics=ctx1.budget_metrics,
        reproducibility=repro2,
        uncertainty_flags=ctx1.uncertainty_flags,
        assembled_at=datetime(2026, 10, 23, 15, 50, 0, tzinfo=timezone.utc),  # Different assembled_at
    )

    hash2 = compute_context_sha256(ctx2)
    assert hash1 == hash2


# ---------------------------------------------------------------------------
# 6. TC-2.1-06: Uncertainty Flags Set Normalization Invariance
# ---------------------------------------------------------------------------

def test_uncertainty_flags_permutation_and_duplicate_invariance():
    """Uncertainty flags are normalized to a sorted, deduplicated list of non-empty strings."""
    # Permutation, duplication, and whitespace trimming
    raw_flags_1 = ["TI_UNAVAILABLE", "BUDGET_OMISSION", "TI_UNAVAILABLE", "  BUDGET_OMISSION  ", ""]
    raw_flags_2 = ["BUDGET_OMISSION", "TI_UNAVAILABLE"]

    norm1 = normalize_uncertainty_flags(raw_flags_1)
    norm2 = normalize_uncertainty_flags(raw_flags_2)

    assert norm1 == ["BUDGET_OMISSION", "TI_UNAVAILABLE"]
    assert norm1 == norm2

    # Verification via compute_context_sha256
    ctx1 = build_sample_context(uncertainty_flags=raw_flags_1)
    ctx2 = build_sample_context(uncertainty_flags=raw_flags_2)
    assert compute_context_sha256(ctx1) == compute_context_sha256(ctx2)


def test_uncertainty_flags_invalid_element_type_rejection():
    """Non-string elements in uncertainty_flags are rejected deterministically before calling .strip()."""
    with pytest.raises(CanonicalSerializationTypeError) as exc1:
        normalize_uncertainty_flags(["FLAG_A", 12345])
    assert "uncertainty_flags elements must be strings" in str(exc1.value)

    with pytest.raises(CanonicalSerializationTypeError) as exc2:
        normalize_uncertainty_flags(["FLAG_A", None])
    assert "uncertainty_flags elements must be strings" in str(exc2.value)

    with pytest.raises(CanonicalSerializationTypeError) as exc3:
        normalize_uncertainty_flags(["FLAG_A", {"nested": "dict"}])
    assert "uncertainty_flags elements must be strings" in str(exc3.value)

    with pytest.raises(CanonicalSerializationTypeError) as exc4:
        normalize_uncertainty_flags("not-a-list")
    assert "uncertainty_flags must be an iterable" in str(exc4.value)


# ---------------------------------------------------------------------------
# 7. TC-2.1-07: Equivalent UTC Instant Normalization
# ---------------------------------------------------------------------------

def test_equivalent_utc_instant_normalization():
    """Timezone-aware datetimes with differing offsets for the same instant serialize identically."""
    # 10:00:00 UTC == 15:30:00 UTC+05:30 == 06:00:00 UTC-04:00
    t_utc = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    t_ist = datetime(2026, 10, 23, 15, 30, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    t_edt = datetime(2026, 10, 23, 6, 0, 0, tzinfo=timezone(timedelta(hours=-4)))

    s_utc = canonicalize_payload({"time": t_utc})
    s_ist = canonicalize_payload({"time": t_ist})
    s_edt = canonicalize_payload({"time": t_edt})

    assert s_utc == s_ist == s_edt == '{"time":"2026-10-23T10:00:00Z"}'


# ---------------------------------------------------------------------------
# 8. TC-2.1-08: Naive Datetime Rejection
# ---------------------------------------------------------------------------

def test_naive_datetime_rejection():
    """Passing a naive datetime without timezone raises an explicit ValueError."""
    naive_dt = datetime(2026, 10, 23, 10, 0, 0)  # tzinfo is None
    with pytest.raises(ValueError) as exc:
        canonicalize_payload({"time": naive_dt})
    assert "Naive datetime encountered without timezone" in str(exc.value)


# ---------------------------------------------------------------------------
# 9. TC-2.1-09: Canonicalization Version Commitment
# ---------------------------------------------------------------------------

def test_canonicalization_version_commitment():
    """filter_canonical_payload binds CANONICALIZATION_ALGORITHM_IDENTIFIER; changing it changes the hash."""
    ctx = build_sample_context()
    filtered = filter_canonical_payload(ctx)

    assert filtered["canonicalization_algorithm"] == CANONICALIZATION_ALGORITHM_IDENTIFIER
    assert filtered["canonicalization_algorithm"] == "AISOP-CJSON-1.0"

    hash_default = compute_context_sha256(ctx)

    # Mutate version identifier
    filtered_mutated = copy.deepcopy(filtered)
    filtered_mutated["canonicalization_algorithm"] = "AISOP-CJSON-2.0"
    hash_mutated = compute_context_sha256(filtered_mutated)

    assert hash_default != hash_mutated


# ---------------------------------------------------------------------------
# 10. TC-2.1-10: Non-Finite Float Rejection
# ---------------------------------------------------------------------------

def test_non_finite_float_rejection():
    """NaN, +Infinity, and -Infinity are rejected with CanonicalSerializationValueError."""
    with pytest.raises(CanonicalSerializationValueError):
        canonicalize_payload({"score": float("nan")})

    with pytest.raises(CanonicalSerializationValueError):
        canonicalize_payload({"score": float("inf")})

    with pytest.raises(CanonicalSerializationValueError):
        canonicalize_payload({"score": float("-inf")})

    # Finite floats must pass
    assert canonicalize_payload({"score": 0.0}) == '{"score":0.0}'
    assert canonicalize_payload({"score": 1.25}) == '{"score":1.25}'


# ---------------------------------------------------------------------------
# 11. TC-2.1-11: Unsupported Type Error Handling
# ---------------------------------------------------------------------------

def test_unsupported_type_error_handling():
    """Sets, complex numbers, and unhandled custom classes raise CanonicalSerializationTypeError."""
    # Sets
    with pytest.raises(CanonicalSerializationTypeError) as exc1:
        canonicalize_payload({"items": {1, 2, 3}})
    assert "Sets are not permitted" in str(exc1.value)

    # Complex numbers
    with pytest.raises(CanonicalSerializationTypeError) as exc2:
        canonicalize_payload({"val": complex(1, 2)})
    assert "Complex numbers are not permitted" in str(exc2.value)

    # Unhandled class
    class UnhandledObject:
        pass

    with pytest.raises(CanonicalSerializationTypeError) as exc3:
        canonicalize_payload({"obj": UnhandledObject()})
    assert "Unsupported type for canonical serialization" in str(exc3.value)


# ---------------------------------------------------------------------------
# 12. TC-2.1-12: Explicit Null Retention
# ---------------------------------------------------------------------------

def test_optional_fields_null_retention():
    """Explicit None values are serialized as JSON null, preserving key structure."""
    data = {
        "root_event_id": None,
        "query_filter": None,
        "description": "Valid string",
    }
    canonical = canonicalize_payload(data)
    assert canonical == '{"description":"Valid string","query_filter":null,"root_event_id":null}'


# ---------------------------------------------------------------------------
# 13. TC-2.1-13: Full InvestigationContext Model Roundtrip
# ---------------------------------------------------------------------------

def test_investigation_context_model_roundtrip():
    """Verify that a fully populated InvestigationContext generates a valid 64-character SHA-256 digest."""
    t_start = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    ev_uuid = uuid.uuid4()
    chunk_uuid = uuid.uuid4()

    event = ContextEventItem(
        event_uuid=ev_uuid,
        raw_evidence_sha256=VALID_SHA256_A,
        event_id="3",
        event_type="network_connection",
        timestamp_utc=t_start,
        action="connected",
        outcome="success",
        severity="low",
        source_identifier="WORKSTATION-01",
        summary="Outbound connection to DNS",
        attributes={"dest_ip": "1.1.1.1", "dest_port": 53},
    )

    entity = ContextEntityItem(
        entity_type="ip",
        entity_value="1.1.1.1",
        roles=["destination"],
        occurrence_count=1,
        associated_event_uuids=[ev_uuid],
    )

    ti = ContextTIFindingItem(
        observable="1.1.1.1",
        observable_type="ipv4",
        verdict="benign",
        threat_state="active",
        confidence=0.9,
    )

    chunk = ContextKnowledgeChunkItem(
        chunk_id=chunk_uuid,
        source_document="mitre/T1071.md",
        section_title="Standard Application Layer Protocol",
        chunk_index=0,
        similarity_score=0.88,
        content="Adversaries may communicate using standard protocols.",
    )

    budget = BudgetMetrics(
        total_events_in_scope=1,
        events_included=1,
        events_omitted_count=0,
        total_entities_in_scope=1,
        entities_included=1,
        knowledge_chunks_included=1,
        estimated_character_count=1500,
        estimated_tokens=429,
        context_truncated=False,
    )

    repro = ReproducibilityRecord(
        time_window_start=t_start,
        time_window_end=t_end,
        context_sha256="0" * 64,
        selected_event_uuids=[ev_uuid],
        selected_chunk_ids=[chunk_uuid],
        model_name="qwen3:4b",
    )

    ctx = InvestigationContext(
        scope_type=InvestigationScopeType.SINGLE_EVENT,
        time_window_start=t_start,
        time_window_end=t_end,
        target_hosts=["WORKSTATION-01"],
        events=[event],
        entities=[entity],
        threat_intel=[ti],
        knowledge_chunks=[chunk],
        budget_metrics=budget,
        reproducibility=repro,
        uncertainty_flags=["INFO: Test investigation complete"],
    )

    digest = compute_context_sha256(ctx)
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)

    # Re-computing on the exact same context gives identical digest
    digest2 = compute_context_sha256(ctx)
    assert digest == digest2


# ---------------------------------------------------------------------------
# 14. Dictionary Key Coercion Collision & Unsupported Key Type Rejection
# ---------------------------------------------------------------------------

def test_dict_key_coercion_collision_detection():
    """Verify that dictionary keys coercing to the same string raise CanonicalSerializationValueError."""
    # Mixed str and int collision: "1" and 1
    with pytest.raises(CanonicalSerializationValueError) as exc1:
        canonicalize_payload({"1": "str_one", 1: "int_one"})
    assert "Dictionary key collision detected" in str(exc1.value)

    # Reverse insertion order
    with pytest.raises(CanonicalSerializationValueError) as exc2:
        canonicalize_payload({1: "int_one", "1": "str_one"})
    assert "Dictionary key collision detected" in str(exc2.value)

    # UUID and string collision
    u_str = "33333333-3333-3333-3333-333333333333"
    u_obj = uuid.UUID(u_str)
    with pytest.raises(CanonicalSerializationValueError) as exc3:
        canonicalize_payload({u_obj: "uuid_obj", u_str: "uuid_str"})
    assert "Dictionary key collision detected" in str(exc3.value)


def test_dict_key_unsupported_compound_types_rejected():
    """Verify that compound or non-scalar dictionary key types raise CanonicalSerializationTypeError."""
    # Tuple key
    with pytest.raises(CanonicalSerializationTypeError) as exc1:
        canonicalize_payload({("compound", "key"): "value"})
    assert "Unsupported dictionary key type: tuple" in str(exc1.value)

    # Bool key (rejected to prevent ambiguous integer/bool JSON key mapping)
    with pytest.raises(CanonicalSerializationTypeError) as exc2:
        canonicalize_payload({True: "value"})
    assert "Unsupported dictionary key type: bool" in str(exc2.value)

    # Float key
    with pytest.raises(CanonicalSerializationTypeError) as exc3:
        canonicalize_payload({3.14: "value"})
    assert "Unsupported dictionary key type: float" in str(exc3.value)


def test_dict_key_uuid_and_int_normalization_supported():
    """Supported integer and UUID keys normalize deterministically to strings without collision."""
    u = uuid.UUID("11111111-1111-1111-1111-111111111111")
    data = {
        u: "uuid_val",
        42: "int_val",
        "regular": "str_val",
    }
    canonical = canonicalize_payload(data)
    expected = '{"11111111-1111-1111-1111-111111111111":"uuid_val","42":"int_val","regular":"str_val"}'
    assert canonical == expected
