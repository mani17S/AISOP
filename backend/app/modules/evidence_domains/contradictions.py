"""
Pure, deterministic contradiction detector and materiality table (ADR-013 Revision 2, ``suff-v4``).

No I/O, no database, no model, no randomness. It PRODUCES FACTS (``ContradictionCandidate``); it never produces a verdict. The single
sufficiency gate applies ``classify_materiality`` (below) with its own hypothesis partition and decides the verdict. The SAME functions
serve the incident path (``correlation.workflow.analyze``) and the case path (``services.case_service``).

A contradiction requires the SAME proposition with values that cannot both be true. A shared entity, host, file name, local id or time
proximity is never enough. Source-local identifiers are never assumed to be globally equal; a relationship counts only when the record
STATES it (issuer-scoped ids, explicit origin links), never when it is guessed.

Kinds (owner decisions D1 to D6, 2026-11-12):
* ORDERING  proposition ``attachment_delivery_order``. A verified causal relationship is required: the artefact record states
            ``origin_message_id`` = the e-mail, the e-mail states it CONTAINS the artefact's hash, and the artefact's ``timestamp_semantics``
            says its event time is an ``arrival`` or ``creation`` time. An earlier timestamp alone is NOT a contradiction (D6). Reversal of
            5 s or less is within the clock-skew tolerance (EXPLAINED); more than 5 s is evaluated by the materiality table.
* OUTCOME   propositions ``signin_outcome(user, ip)`` and ``connection_allowed(src, dst, port)``: opposite polarity, independent sources,
            gap <= 2.0 s. The window means ONLY "two records of the same proposition describe the same attempt"; it is not a general
            correlation window (link windows are separate).
* IDENTITY  proposition ``session_principal``: one ISSUER-SCOPED session (a record names its ``session_issuer``, otherwise the id is
            local to the record's own system) attributed to two DIFFERENT canonical principals of the SAME directory (``canonical_id`` +
            ``canonical_id_issuer``). Different user names, a matching local id string in two systems, a missing canonical id, or different
            directories are unresolved: no finding (D3).
* TEMPORAL  proposition ``event_time``: two records that state the SAME issuer-scoped ``correlation`` and describe the same event (same
            evidence type, action and outcome) with reliable event times further apart than 5 s. Source-native event ids are never used
            to establish identity of an event (D4).
NOT implemented: STATE (no approved proposition definition); the 10-minute retry window (same-source OUTCOME pairs stay with the existing
same-sensor detectors).

Independence (D5): ``same_source`` (same system, or the same declared upstream collection), ``independent`` (different systems and no
shared upstream declared: a MINIMUM signal, not a guarantee), ``unknown`` (different systems but exactly one side declares an upstream
collection, so sharing cannot be excluded). Only ``independent`` can make a finding MATERIAL; ``unknown`` is disclosed, never overstated.

All thresholds are named constants in this module. No additive score, no point deductions.
"""

from __future__ import annotations

from typing import Any, Iterable, Literal, Optional, Sequence
import uuid

from app.modules.evidence.independence import LINK_STRONG, LINK_SPECIFIC, LINK_WEAK, entity_link_strength
from app.modules.evidence_domains.adapters import EvidenceFormatError, is_domain_record, parse_record
from app.modules.evidence_domains.model import Observation, Predicate, TimeStatus
from app.schemas.contradiction import (
    ContradictionCandidate,
    ContradictionKind,
    Explanation,
    HypothesisRelation,
    Materiality,
)

#: D1: approved clock-skew tolerance. A time difference of this many seconds or less never independently establishes a material
#: ordering or temporal contradiction. One value, used by ORDERING and TEMPORAL.
CLOCK_SKEW_TOLERANCE_SECONDS = 5.0
#: D2: outcome comparison window = the existing correlator constant ``CONTRADICTION_WINDOW_SECONDS`` (equality asserted by a test).
#: Inclusive: a gap of exactly this many seconds is compared; a larger gap is not.
OUTCOME_CONFLICT_WINDOW_SECONDS = 2.0
#: Temporal relevance of an IDENTITY pair = the existing specific-link window ``correlator.SPECIFIC_WINDOW_SECONDS`` (86400 s; equality
#: asserted by a test). Records further apart than this are not joined into one incident anyway.
IDENTITY_RELEVANCE_WINDOW_SECONDS = 86400.0
MAX_CANDIDATES = 100

HINT_ORDERING = "ARTEFACT_TIME_PROVENANCE"
HINT_OUTCOME = "NATIVE_LOG_OR_THIRD_SOURCE"
HINT_IDENTITY = "CANONICAL_IDENTITY_RECORD"
HINT_TEMPORAL = "TIME_SYNC_AND_ORIGINAL_LOGS"
#: Fixed analyst-facing text per resolution hint (rendered by the report and the API).
HINT_TEXT = {
    HINT_ORDERING: "Obtain the creation and modification times of the artefact with their provenance, and the delivery time from the mail gateway.",
    HINT_OUTCOME: "Obtain the native log of either source for that exact attempt, or a third independent source.",
    HINT_IDENTITY: "Obtain the identity directory's record for the session and the principals involved, and confirm which principal the session was issued to.",
    HINT_TEMPORAL: "Obtain the original logs of both sources with their time zone, and the time-synchronisation status of each source.",
}

_DATED = (TimeStatus.VALID, TimeStatus.NAIVE_ASSUMED_UTC)
Independence = Literal["independent", "same_source", "unknown"]


# ── independence (D5) ───────────────────────────────────────────────────────
def source_independence(a: Observation, b: Observation) -> Independence:
    if a.source_system == b.source_system:
        return "same_source"
    if a.upstream_id and b.upstream_id:
        return "same_source" if a.upstream_id == b.upstream_id else "independent"
    if a.upstream_id or b.upstream_id:
        return "unknown"
    return "independent"


def sources_independent(a: Observation, b: Observation) -> bool:
    return source_independence(a, b) == "independent"


# ── helpers ─────────────────────────────────────────────────────────────────
def _link_strength(a: Observation, b: Observation) -> str:
    rank = {LINK_WEAK: 0, LINK_SPECIFIC: 1, LINK_STRONG: 2}
    best = LINK_WEAK
    for t, v in set(a.entities) & set(b.entities):
        s = entity_link_strength(t, v)
        if rank[s] > rank[best]:
            best = s
    return best


def _dated(o: Observation) -> bool:
    """Event time only (never ``collected_at`` or ingestion time) and only when real: a missing or invalid time is never replaced."""
    return o.counts_for_corroboration and o.time_status in _DATED and o.event_time is not None


def _tq(o: Observation) -> Literal["valid", "naive_assumed_utc"]:
    return "valid" if o.time_status == TimeStatus.VALID else "naive_assumed_utc"


def _verified_causal_link(mail: Observation, artefact: Observation) -> bool:
    """
    BOTH records state the relationship: the artefact says it derives from this e-mail (``origin_message_id``) and the e-mail says it
    CONTAINS the artefact's hash. Anything weaker (a shared hash alone) is not a verified causal relationship (D6).
    """
    origin = str(artefact.attributes.get("origin_message_id") or "").strip().lower()
    if not origin or ("email_message", origin) not in set(mail.entities):
        return False
    derived = {(r.subject, r.obj) for r in artefact.relations if r.predicate == Predicate.DERIVED_FROM}
    contains = {(r.subject, r.obj) for r in mail.relations if r.predicate == Predicate.CONTAINS}
    hashes = {v for t, v in artefact.entities if t == "file_hash"}
    return any((("file_hash", h), ("email_message", origin)) in derived and (("email_message", origin), ("file_hash", h)) in contains for h in hashes)


def _event_time_means_arrival(artefact: Observation) -> bool:
    return str(artefact.attributes.get("timestamp_semantics") or "").strip().lower() in ("arrival", "creation")


def _ordering_pair_ok(mail: Observation, artefact: Observation) -> bool:
    return (
        mail.evidence_type == "email.message" and artefact.evidence_type == "forensic.file"
        and _dated(mail) and _dated(artefact) and _verified_causal_link(mail, artefact) and _event_time_means_arrival(artefact)
    )


def attachment_precedes_delivery(mail: Observation, artefact: Observation) -> bool:
    """
    True only for a VERIFIED causal-ordering violation that is not excused: verified causal link, the artefact's time means arrival or
    creation, both times real (``valid``), independent sources, and the artefact earlier than the e-mail by MORE than the 5 s tolerance.
    Used by both the detector (as a contradiction) and the ATT&CK rule ``MAP-T1566.001-ATTACHMENT-ON-HOST`` (which must not derive
    "attachment delivered" from such a pair). An artefact merely timestamped earlier is NOT such a pair (D6).
    """
    if not _ordering_pair_ok(mail, artefact) or mail.time_status != TimeStatus.VALID or artefact.time_status != TimeStatus.VALID:
        return False
    reversal = (mail.event_time - artefact.event_time).total_seconds()  # type: ignore[operator]
    return reversal > CLOCK_SKEW_TOLERANCE_SECONDS and source_independence(mail, artefact) == "independent"


# ── detectors ───────────────────────────────────────────────────────────────
def _ordering(observations: Sequence[Observation]) -> list[ContradictionCandidate]:
    out: list[ContradictionCandidate] = []
    mails = [o for o in observations if o.evidence_type == "email.message"]
    files = [o for o in observations if o.evidence_type == "forensic.file"]
    for m in mails:
        for f in files:
            if not _ordering_pair_ok(m, f):
                continue
            reversal = (m.event_time - f.event_time).total_seconds()  # type: ignore[operator]
            if reversal <= 0:
                continue  # artefact not earlier: consistent
            both_valid = m.time_status == TimeStatus.VALID and f.time_status == TimeStatus.VALID
            if not both_valid:
                expl: Optional[Explanation] = Explanation.TIMEZONE_ASSUMED
            elif reversal <= CLOCK_SKEW_TOLERANCE_SECONDS:
                expl = Explanation.CLOCK_SKEW_WITHIN_TOLERANCE
            else:
                expl = None
            out.append(ContradictionCandidate(
                kind=ContradictionKind.ORDERING, proposition="attachment_delivery_order",
                evidence_ids=(m.key, f.key), sources=(m.source_system, f.source_system),
                times=(m.event_time, f.event_time),  # type: ignore[arg-type]
                time_quality=(_tq(m), _tq(f)), claims=("delivery", "artefact_earlier"),
                link_strength=_link_strength(m, f), independence=source_independence(m, f), overlap_seconds=abs(reversal),
                reliability=(m.trust_class.value, f.trust_class.value), explanation=expl, resolution_hint=HINT_ORDERING,
            ))
    return out


def _outcome_key(o: Observation) -> Optional[tuple]:
    a = o.attributes
    if o.evidence_type == "identity.signin" and a.get("user") and a.get("ip"):
        return ("signin_outcome", str(a["user"]).lower(), str(a["ip"]).lower())
    if o.evidence_type in ("network.firewall", "network.flow") and a.get("src_ip") and a.get("dst_ip"):
        return ("connection_allowed", str(a["src_ip"]).lower(), str(a["dst_ip"]).lower(), str(a.get("dst_port", "")))
    return None


def _outcome(observations: Sequence[Observation]) -> list[ContradictionCandidate]:
    groups: dict[tuple, list[Observation]] = {}
    for o in observations:
        if not _dated(o) or o.outcome not in ("success", "failure"):
            continue
        k = _outcome_key(o)
        if k is not None:
            groups.setdefault(k, []).append(o)
    out: list[ContradictionCandidate] = []
    for key, items in sorted(groups.items(), key=lambda kv: kv[0]):
        items.sort(key=lambda o: (o.event_time, str(o.key)))
        for i, a in enumerate(items):
            for b in items[i + 1:]:
                gap = (b.event_time - a.event_time).total_seconds()  # type: ignore[operator]
                if gap > OUTCOME_CONFLICT_WINDOW_SECONDS:
                    break
                ind = source_independence(a, b)
                if a.outcome == b.outcome or ind == "same_source":
                    continue  # same-source pairs stay with the existing same-sensor detectors
                allow = key[0] == "connection_allowed"
                names = {"success": "allowed" if allow else "success", "failure": "denied" if allow else "failure"}
                out.append(ContradictionCandidate(
                    kind=ContradictionKind.OUTCOME, proposition=key[0],
                    evidence_ids=(a.key, b.key), sources=(a.source_system, b.source_system), times=(a.event_time, b.event_time),  # type: ignore[arg-type]
                    time_quality=(_tq(a), _tq(b)), claims=(names[a.outcome], names[b.outcome]),
                    link_strength=_link_strength(a, b), independence=ind, overlap_seconds=abs(gap),
                    reliability=(a.trust_class.value, b.trust_class.value), explanation=None, resolution_hint=HINT_OUTCOME,
                ))
    return out


def _principal(o: Observation) -> Optional[tuple[str, str]]:
    vals = [v for t, v in o.entities if t == "principal"]
    if len(vals) != 1 or ":" not in vals[0]:
        return None
    issuer, _, ident = vals[0].partition(":")
    return (issuer, ident) if issuer and ident else None


def _identity(observations: Sequence[Observation]) -> list[ContradictionCandidate]:
    groups: dict[str, list[Observation]] = {}
    for o in observations:
        if not _dated(o):
            continue
        sess = [v for t, v in o.entities if t == "logon_session"]
        if len(sess) == 1:
            groups.setdefault(sess[0], []).append(o)
    out: list[ContradictionCandidate] = []
    for sess, items in sorted(groups.items()):
        items.sort(key=lambda o: (o.event_time, str(o.key)))
        for i, a in enumerate(items):
            for b in items[i + 1:]:
                pa, pb = _principal(a), _principal(b)
                if pa is None or pb is None:
                    continue  # no canonical identity on one side: linkage unknown, never guessed
                if pa[0] != pb[0]:
                    continue  # canonical ids from different directories are not comparable: unresolved
                if pa[1] == pb[1]:
                    continue  # same canonical principal: compatible
                gap = (b.event_time - a.event_time).total_seconds()  # type: ignore[operator]
                if gap > IDENTITY_RELEVANCE_WINDOW_SECONDS:
                    continue
                out.append(ContradictionCandidate(
                    kind=ContradictionKind.IDENTITY, proposition="session_principal",
                    evidence_ids=(a.key, b.key), sources=(a.source_system, b.source_system), times=(a.event_time, b.event_time),  # type: ignore[arg-type]
                    time_quality=(_tq(a), _tq(b)), claims=("principal_a", "principal_b"),
                    link_strength=_link_strength(a, b), independence=source_independence(a, b), overlap_seconds=abs(gap),
                    reliability=(a.trust_class.value, b.trust_class.value), explanation=None, resolution_hint=HINT_IDENTITY,
                ))
    return out


def _temporal(observations: Sequence[Observation]) -> list[ContradictionCandidate]:
    groups: dict[str, list[Observation]] = {}
    for o in observations:
        if not _dated(o):
            continue
        for t, v in o.entities:
            if t == "event_correlation":
                groups.setdefault(v, []).append(o)
    out: list[ContradictionCandidate] = []
    for _corr, items in sorted(groups.items()):
        items.sort(key=lambda o: (o.event_time, str(o.key)))
        for i, a in enumerate(items):
            for b in items[i + 1:]:
                same_event = (
                    a.evidence_type == b.evidence_type and a.outcome == b.outcome
                    and str(a.attributes.get("action", "")).lower() == str(b.attributes.get("action", "")).lower()
                )
                gap = (b.event_time - a.event_time).total_seconds()  # type: ignore[operator]
                if not same_event or gap <= CLOCK_SKEW_TOLERANCE_SECONDS:
                    continue  # a different phase of the request, or a difference within the clock-skew tolerance
                both_valid = a.time_status == TimeStatus.VALID and b.time_status == TimeStatus.VALID
                out.append(ContradictionCandidate(
                    kind=ContradictionKind.TEMPORAL, proposition="event_time",
                    evidence_ids=(a.key, b.key), sources=(a.source_system, b.source_system), times=(a.event_time, b.event_time),  # type: ignore[arg-type]
                    time_quality=(_tq(a), _tq(b)), claims=("earlier_time", "later_time"),
                    link_strength=_link_strength(a, b), independence=source_independence(a, b), overlap_seconds=abs(gap),
                    reliability=(a.trust_class.value, b.trust_class.value),
                    explanation=None if both_valid else Explanation.TIMEZONE_ASSUMED, resolution_hint=HINT_TEMPORAL,
                ))
    return out


def detect_contradictions(observations: Iterable[Observation]) -> tuple[ContradictionCandidate, ...]:
    """Deterministic: same input, same output, same order. Bounded to ``MAX_CANDIDATES``."""
    obs = [o for o in observations if o.counts_for_corroboration]  # analyst statements, unclassified evidence and TI never take part
    found = _ordering(obs) + _outcome(obs) + _identity(obs) + _temporal(obs)
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[ContradictionCandidate] = []
    for c in sorted(found, key=lambda c: (c.kind.value, c.proposition, str(c.evidence_ids[0]), str(c.evidence_ids[1]))):
        k = (c.kind.value, c.proposition, str(c.evidence_ids[0]), str(c.evidence_ids[1]))
        if k not in seen:
            seen.add(k)
            unique.append(c)
    return tuple(unique[:MAX_CANDIDATES])


def observations_from_stored(rows: Iterable[tuple[uuid.UUID, Any, Optional[str]]]) -> list[Observation]:
    """
    Re-derive observations from PRESERVED raw payloads, for callers that start from stored rows (``case_service``). ``rows`` are
    ``(normalized_event_id, raw_payload, stored_sha256)``; the normalized event id becomes the observation key so findings refer to the
    same ids the context uses. Non-envelope or invalid payloads are skipped (they are not domain evidence); nothing is invented.
    """
    out: list[Observation] = []
    for index, (key, payload, sha) in enumerate(rows):
        if not isinstance(payload, dict) or not is_domain_record(payload) or not isinstance(sha, str) or len(sha) != 64:
            continue
        try:
            out.append(parse_record(payload, key=key, record_index=index, raw_sha256=sha.lower(), integrity="digest_attested"))
        except EvidenceFormatError:
            continue
    return out


def classify_materiality(c: ContradictionCandidate, relation: HypothesisRelation) -> Materiality:
    """
    ADR-013 decision table, first match wins; no numeric score. Rule 2 (retry window) is not reachable (same-source OUTCOME pairs are not
    candidates). Independence other than ``independent`` can never be MATERIAL (same source is MINOR by the table; unknown is not overstated).
    """
    if c.link_strength == "weak":                                                         # rule 1
        return Materiality.MINOR
    if c.explanation is Explanation.TIMEZONE_ASSUMED:                                     # rule 3 (ordering and temporal)
        return Materiality.MINOR
    if c.explanation is Explanation.CLOCK_SKEW_WITHIN_TOLERANCE:                          # rule 4 (D1)
        return Materiality.EXPLAINED
    if c.independence == "independent" and c.link_strength in ("strong", "specific"):
        if relation in (HypothesisRelation.ANCHOR, HypothesisRelation.CORROBORATING, HypothesisRelation.RELEVANT):   # rules 5 and 6
            return Materiality.MATERIAL
    return Materiality.MINOR                                                              # rule 7 and fall-through


__all__ = [
    "CLOCK_SKEW_TOLERANCE_SECONDS", "HINT_IDENTITY", "HINT_ORDERING", "HINT_OUTCOME", "HINT_TEMPORAL", "HINT_TEXT",
    "IDENTITY_RELEVANCE_WINDOW_SECONDS", "MAX_CANDIDATES", "OUTCOME_CONFLICT_WINDOW_SECONDS",
    "attachment_precedes_delivery", "classify_materiality", "detect_contradictions", "observations_from_stored",
    "source_independence", "sources_independent",
]
