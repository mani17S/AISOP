"""
AISOP deterministic claim-to-evidence verifier (Task 1, ``claim-assertion-v1``).

Evaluates the OPTIONAL structured assertions a claim carries against the exact evidence fields of the CURRENT investigation context. It is
independent of any model provider and never asks a model whether a claim is true. It does not read prose: ``summary`` text, claim text, retrieved
knowledge and any instruction-like content are ignored by construction, only structured fields are compared.

Contract (claim-assertion-v1). Each assertion is a JSON object with an explicit ``kind`` and exactly the keys listed for that kind (unknown keys
are rejected); ``version`` is optional and, if present, must equal ``claim-assertion-v1``:
  event_field      evidence_id, field, operator in {equals, in, exists}, value (scalar | list of 1..16 scalars | absent for exists)
                   field in {event_type, action, outcome, severity, source_identifier, event_id} or ``attributes.<name>`` (single level,
                   name matches [A-Za-z][A-Za-z0-9_]{0,39}); no traversal, no dunder names
  entity_link      evidence_id, entity_type, entity_value, operator = involves
  temporal_order   evidence_id, other_evidence_id, operator = before          (strictly earlier by event time)
  distinct_evidence evidence_ids (2..10), operator = min_distinct_units, value (int 2..10)
                   counts distinct evidence units under the existing record-level clustering; this is NOT source independence

Scope: every referenced event id must be an event of the current context AND be cited by the claim. Ids from another investigation, retrieved
knowledge, fabricated ids and uncited ids can only yield ``insufficient_evidence``. Outcomes: supported, contradicted, insufficient_evidence,
not_verifiable. Claim-level: contradicted if any assertion is contradicted; supported only if every assertion is evaluated and supported;
not_verifiable if none can be evaluated; otherwise insufficient_evidence. A result applies to the listed assertions only.

Security: allowlisted kinds, operators and fields; scalar-only values with length bounds; no recursion into supplied values; at most
``MAX_ASSERTIONS`` assertions are evaluated (the rest are disclosed as truncated); no exception text leaves this module.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Mapping, Optional

from app.modules.evidence.independence import canonical_entity_value
from app.schemas.claim_verification import (
    CLAIM_ASSERTION_SCHEMA,
    AssertionResult,
    ClaimVerification,
    VerificationOutcome as O,
)
from app.schemas.investigation import ContextEventItem, InvestigationContext

MAX_ASSERTIONS = 8
MAX_STRING = 512
MAX_LIST = 16
MAX_IDS = 10

_TOP_FIELDS = frozenset({"event_type", "action", "outcome", "severity", "source_identifier", "event_id"})
#: Fixed-vocabulary fields whose values may appear in a rationale (they are not entity values).
_ECHO_FIELDS = frozenset({"event_type", "action", "outcome", "severity"})
_ATTR_RE = re.compile(r"^attributes\.([A-Za-z][A-Za-z0-9_]{0,39})$")
_ENTITY_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,39}$")

_KEYS = {
    "event_field": {"kind", "version", "evidence_id", "field", "operator", "value"},
    "entity_link": {"kind", "version", "evidence_id", "entity_type", "entity_value", "operator"},
    "temporal_order": {"kind", "version", "evidence_id", "other_evidence_id", "operator"},
    "distinct_evidence": {"kind", "version", "evidence_ids", "operator", "value"},
}
_OPERATORS = {
    "event_field": {"equals", "in", "exists"},
    "entity_link": {"involves"},
    "temporal_order": {"before"},
    "distinct_evidence": {"min_distinct_units"},
}


class _Bad(Exception):
    """Internal: carries a fixed reason code only."""

    def __init__(self, code: str, outcome: O = O.NOT_VERIFIABLE) -> None:
        self.code = code
        self.outcome = outcome


def _norm(v: Any) -> str:
    return str(v).strip().casefold()


def _is_scalar(v: Any) -> bool:
    return isinstance(v, (str, int, float, bool))  # None, dict, list and everything else are rejected without recursion


def _scalar(v: Any) -> Any:
    if not _is_scalar(v):
        raise _Bad("MALFORMED_VALUE_NOT_SCALAR")
    if isinstance(v, str) and len(v) > MAX_STRING:
        raise _Bad("MALFORMED_VALUE_TOO_LONG")
    return v


def _uuid(v: Any) -> uuid.UUID:
    if not isinstance(v, str) or len(v) > 64:
        raise _Bad("MALFORMED_EVIDENCE_ID")
    try:
        return uuid.UUID(v)
    except ValueError:
        raise _Bad("MALFORMED_EVIDENCE_ID") from None


class _Scope:
    """The only evidence the verifier may touch: this context's events, cited by this claim."""

    def __init__(self, context: InvestigationContext, cited: set[uuid.UUID], clusters: Optional[Mapping[Any, int]], contested: frozenset[str]) -> None:
        self.events: dict[uuid.UUID, ContextEventItem] = {e.event_uuid: e for e in context.events}
        self.cited = cited
        self.clusters = clusters
        self.contested = contested
        self.entity_events: dict[tuple[str, str], set[uuid.UUID]] = {}
        for ent in context.entities:
            key = (ent.entity_type.strip().lower(), canonical_entity_value(ent.entity_type, ent.entity_value))
            self.entity_events.setdefault(key, set()).update(ent.associated_event_uuids)

    def resolve(self, ev_id: uuid.UUID) -> ContextEventItem:
        ev = self.events.get(ev_id)
        if ev is None:
            raise _Bad("EVIDENCE_NOT_IN_INVESTIGATION", O.INSUFFICIENT_EVIDENCE)
        if ev_id not in self.cited:
            raise _Bad("EVIDENCE_NOT_CITED_BY_CLAIM", O.INSUFFICIENT_EVIDENCE)
        return ev


def _check_keys(item: Mapping[str, Any], kind: str) -> None:
    if not set(item) <= _KEYS[kind]:
        raise _Bad("MALFORMED_UNKNOWN_KEYS")
    version = item.get("version")
    if version is not None and version != CLAIM_ASSERTION_SCHEMA:
        raise _Bad("MALFORMED_UNSUPPORTED_VERSION")
    op = item.get("operator")
    if not isinstance(op, str) or op not in _OPERATORS[kind]:
        raise _Bad("UNSUPPORTED_OPERATOR")


def _event_field(item: Mapping[str, Any], scope: _Scope) -> AssertionResult:
    _check_keys(item, "event_field")
    ev_id = _uuid(item.get("evidence_id"))
    field = item.get("field")
    if not isinstance(field, str) or len(field) > 64:
        raise _Bad("MALFORMED_FIELD")
    attr = _ATTR_RE.match(field)
    if field not in _TOP_FIELDS and not attr:
        raise _Bad("FIELD_NOT_ALLOWED")
    op = item["operator"]
    if op == "exists":
        if "value" in item and item["value"] is not None:
            raise _Bad("MALFORMED_VALUE_NOT_ALLOWED")
        expected: Any = None
    elif op == "equals":
        if "value" not in item:
            raise _Bad("MALFORMED_VALUE_MISSING")
        expected = _scalar(item["value"])
    else:  # in
        vals = item.get("value")
        if not isinstance(vals, list) or not (1 <= len(vals) <= MAX_LIST):
            raise _Bad("MALFORMED_VALUE_LIST")
        expected = [_scalar(x) for x in vals]
    ev = scope.resolve(ev_id)
    if attr:
        present = attr.group(1) in ev.attributes and ev.attributes[attr.group(1)] is not None
        actual = ev.attributes.get(attr.group(1))
    else:
        actual = getattr(ev, field, None)
        present = actual is not None and actual != ""   # an empty/None top-level field is absent, never 'exists'
    base = dict(kind="event_field", evidence_ids=[str(ev_id)], field=field, operator=op)
    echo = field in _ECHO_FIELDS
    if op == "exists":
        if present:
            return _supported(scope, ev_id, base, "FIELD_PRESENT", values_withheld=False)
        return AssertionResult(index=0, outcome=O.INSUFFICIENT_EVIDENCE, reason="FIELD_ABSENT", **base)
    if not present:
        return AssertionResult(index=0, outcome=O.INSUFFICIENT_EVIDENCE, reason="FIELD_ABSENT", **base)
    if not _is_scalar(actual):
        return AssertionResult(index=0, outcome=O.NOT_VERIFIABLE, reason="FIELD_TYPE_UNSUPPORTED", **base)
    match = _norm(actual) == _norm(expected) if op == "equals" else _norm(actual) in {_norm(x) for x in expected}
    extra: dict[str, Any] = {"values_withheld": not echo}
    if echo:
        extra["expected"] = str(expected) if op == "equals" else ",".join(str(x) for x in expected)[:128]
        extra["observed"] = str(actual)[:128]
    if match:
        return _supported(scope, ev_id, {**base, **extra}, "FIELD_MATCHES_ASSERTED_VALUE", values_withheld=not echo)
    return AssertionResult(index=0, outcome=O.CONTRADICTED, reason="FIELD_DIFFERS_FROM_ASSERTED_VALUE", **base, **extra)


def _supported(scope: _Scope, ev_id: uuid.UUID, base: dict[str, Any], reason: str, values_withheld: bool = False) -> AssertionResult:
    """A match is downgraded when the cited event is part of a MATERIAL contradiction disclosed by the sufficiency gate."""
    base = {**base}
    base.setdefault("values_withheld", values_withheld)
    if str(ev_id) in scope.contested:
        return AssertionResult(index=0, outcome=O.INSUFFICIENT_EVIDENCE, reason="CITED_EVIDENCE_IN_MATERIAL_CONTRADICTION", **base)
    return AssertionResult(index=0, outcome=O.SUPPORTED, reason=reason, **base)


def _entity_link(item: Mapping[str, Any], scope: _Scope) -> AssertionResult:
    _check_keys(item, "entity_link")
    ev_id = _uuid(item.get("evidence_id"))
    etype, evalue = item.get("entity_type"), item.get("entity_value")
    if not isinstance(etype, str) or not _ENTITY_TYPE_RE.match(etype):
        raise _Bad("MALFORMED_ENTITY_TYPE")
    if not isinstance(evalue, str) or not (1 <= len(evalue) <= MAX_STRING):
        raise _Bad("MALFORMED_ENTITY_VALUE")
    scope.resolve(ev_id)
    base = dict(kind="entity_link", evidence_ids=[str(ev_id)], field=f"entity:{etype.lower()}", operator="involves", values_withheld=True)
    linked = scope.entity_events.get((etype.lower(), canonical_entity_value(etype, evalue)), set())
    if ev_id in linked:
        return _supported(scope, ev_id, base, "ENTITY_LINKED_TO_EVIDENCE", values_withheld=True)
    return AssertionResult(index=0, outcome=O.INSUFFICIENT_EVIDENCE, reason="ENTITY_NOT_LINKED_TO_EVIDENCE", **base)


def _temporal(item: Mapping[str, Any], scope: _Scope) -> AssertionResult:
    _check_keys(item, "temporal_order")
    a_id, b_id = _uuid(item.get("evidence_id")), _uuid(item.get("other_evidence_id"))
    base = dict(kind="temporal_order", evidence_ids=[str(a_id), str(b_id)], field="timestamp_utc", operator="before")
    a, b = scope.resolve(a_id), scope.resolve(b_id)
    ta, tb = a.timestamp_utc, b.timestamp_utc
    if not isinstance(ta, datetime) or not isinstance(tb, datetime):
        return AssertionResult(index=0, outcome=O.INSUFFICIENT_EVIDENCE, reason="TIMESTAMP_MISSING", **base)
    if ta < tb:
        if str(a_id) in scope.contested or str(b_id) in scope.contested:
            return AssertionResult(index=0, outcome=O.INSUFFICIENT_EVIDENCE, reason="CITED_EVIDENCE_IN_MATERIAL_CONTRADICTION", **base)
        return AssertionResult(index=0, outcome=O.SUPPORTED, reason="EVENT_TIME_ORDER_HOLDS", **base)
    if ta > tb:
        return AssertionResult(index=0, outcome=O.CONTRADICTED, reason="EVENT_TIME_ORDER_REVERSED", **base)
    return AssertionResult(index=0, outcome=O.INSUFFICIENT_EVIDENCE, reason="TIMESTAMPS_EQUAL_ORDER_UNDETERMINED", **base)


def _distinct(item: Mapping[str, Any], scope: _Scope) -> AssertionResult:
    _check_keys(item, "distinct_evidence")
    raw_ids = item.get("evidence_ids")
    if not isinstance(raw_ids, list) or not (2 <= len(raw_ids) <= MAX_IDS):
        raise _Bad("MALFORMED_EVIDENCE_IDS")
    ids = [_uuid(x) for x in raw_ids]
    n = item.get("value")
    if isinstance(n, bool) or not isinstance(n, int) or not (2 <= n <= MAX_IDS):
        raise _Bad("MALFORMED_VALUE_COUNT")
    base = dict(kind="distinct_evidence", evidence_ids=[str(i) for i in ids], field="evidence_unit", operator="min_distinct_units")
    for i in ids:
        scope.resolve(i)
    if scope.clusters is None:
        raise _Bad("CLUSTERS_UNAVAILABLE")
    units = {scope.clusters[i] for i in ids if i in scope.clusters}
    if len(units) >= n:
        if any(str(i) in scope.contested for i in ids):
            return AssertionResult(index=0, outcome=O.INSUFFICIENT_EVIDENCE, reason="CITED_EVIDENCE_IN_MATERIAL_CONTRADICTION", **base)
        return AssertionResult(index=0, outcome=O.SUPPORTED, reason="DISTINCT_EVIDENCE_UNITS_REACHED", **base)
    return AssertionResult(index=0, outcome=O.INSUFFICIENT_EVIDENCE, reason="FEWER_DISTINCT_UNITS_THAN_ASSERTED", **base)


_EVALUATORS = {"event_field": _event_field, "entity_link": _entity_link, "temporal_order": _temporal, "distinct_evidence": _distinct}


def _one(index: int, item: Any, scope: _Scope) -> AssertionResult:
    try:
        if not isinstance(item, Mapping):
            raise _Bad("MALFORMED_NOT_AN_OBJECT")
        kind = item.get("kind")
        if not isinstance(kind, str) or kind not in _EVALUATORS:
            raise _Bad("MALFORMED_UNKNOWN_KIND")
        return _EVALUATORS[kind](item, scope).model_copy(update={"index": index})
    except _Bad as bad:
        kind = item.get("kind") if isinstance(item, Mapping) and isinstance(item.get("kind"), str) and item.get("kind") in _EVALUATORS else None
        return AssertionResult(index=index, kind=kind, outcome=bad.outcome, reason=bad.code)
    except Exception:  # noqa: BLE001 - never leak an exception, never crash the claim list
        return AssertionResult(index=index, outcome=O.NOT_VERIFIABLE, reason="INTERNAL_ASSERTION_ERROR")


def _aggregate(results: list[AssertionResult], truncated: bool) -> tuple[O, str]:
    outcomes = [r.outcome for r in results]
    if O.CONTRADICTED in outcomes:
        return O.CONTRADICTED, "ASSERTION_CONTRADICTED_BY_CITED_EVIDENCE"
    if outcomes and all(o == O.NOT_VERIFIABLE for o in outcomes):
        return O.NOT_VERIFIABLE, "NO_ASSERTION_COULD_BE_EVALUATED"
    if truncated:
        return O.INSUFFICIENT_EVIDENCE, "ASSERTIONS_TRUNCATED_NOT_ALL_EVALUATED"
    if outcomes and all(o == O.SUPPORTED for o in outcomes):
        return O.SUPPORTED, "ALL_LISTED_ASSERTIONS_SUPPORTED"
    return O.INSUFFICIENT_EVIDENCE, "NOT_ALL_ASSERTIONS_ESTABLISHED"


def verify_claim(
    claim: Any,
    context: InvestigationContext,
    *,
    clusters: Optional[Mapping[Any, int]] = None,
    contested_event_ids: frozenset[str] = frozenset(),
) -> ClaimVerification:
    """
    Deterministic verification of one claim. ``claim`` needs ``assertions`` and ``supporting_evidence_ids``; ``clusters`` maps event uuid to its
    evidence-unit id (``sufficiency_gate.evidence_clusters_for_context``); ``contested_event_ids`` are events in a MATERIAL contradiction.
    """
    raw = getattr(claim, "assertions", None)
    if raw is None or (isinstance(raw, list) and len(raw) == 0):
        return ClaimVerification(outcome=O.NOT_VERIFIABLE, reason="NO_STRUCTURED_ASSERTIONS", assertions_total=0, assertions_evaluated=0)
    if not isinstance(raw, list):
        return ClaimVerification(outcome=O.NOT_VERIFIABLE, reason="MALFORMED_ASSERTIONS_CONTAINER", assertions_total=0, assertions_evaluated=0)
    scope = _Scope(context, set(getattr(claim, "supporting_evidence_ids", []) or []), clusters, frozenset(contested_event_ids))
    total = len(raw)
    results = [_one(i, item, scope) for i, item in enumerate(raw[:MAX_ASSERTIONS])]
    truncated = total > MAX_ASSERTIONS
    outcome, reason = _aggregate(results, truncated)
    return ClaimVerification(
        outcome=outcome, reason=reason, assertions_total=total, assertions_evaluated=len(results),
        assertions_truncated=truncated, results=results,
    )


__all__ = ["MAX_ASSERTIONS", "verify_claim"]
