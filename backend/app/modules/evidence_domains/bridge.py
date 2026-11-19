"""
Bridge from canonical observations to the existing correlation engine (Stage 6, ADR-011).

The correlator, evidence-sufficiency gate, claim verifier and report builder (ADR-008/009) operate on
``CorrelationEvent``. Rather than build a second engine, a dated, machine-observed ``Observation`` is projected onto
that event type. The projection never adds information:

* severity is ``informational`` (a source-agnostic observation has no alert severity; none is invented),
* category is the evidence type (it maps to no kill-chain stage, so the timeline stage is ``unclassified``),
* ``source_type`` is the source system (so two records from different systems are different sources),
* ``source_event_id`` is the evidence type (the identity of the observation class used by the independence rules),
* the entities are exactly those the adapter extracted.

Not projected (kept as observations, reported separately): undated evidence (no time is fabricated), analyst
statements (never corroboration), and unclassified evidence (no entities to link).
"""

from __future__ import annotations

from typing import Optional

from app.modules.correlation.models import CorrelationEvent
from app.modules.evidence_domains.model import EvidenceFamily, Observation, TimeStatus

DATED = (TimeStatus.VALID, TimeStatus.NAIVE_ASSUMED_UTC)


def is_machine(o: Observation) -> bool:
    """Evidence produced by a collector or tool (including unclassified records): everything except analyst statements."""
    return o.family != EvidenceFamily.ANALYST


def is_dated(o: Observation) -> bool:
    return o.time_status in DATED and o.event_time is not None


def is_projectable(o: Observation) -> bool:
    """Machine-observed, dated evidence that can take part in correlation, sufficiency and the timeline."""
    return o.counts_for_corroboration and o.time_status in DATED and o.event_time is not None


def _first(o: Observation, etype: str) -> Optional[str]:
    vals = [v for t, v in o.entities if t == etype]
    return vals[0] if len(vals) == 1 else None


def _attr(o: Observation, *names: str) -> Optional[str]:
    for n in names:
        v = o.attributes.get(n)
        if isinstance(v, (str, int)) and str(v).strip():
            return str(v).strip().lower()
    return None


def observation_to_event(o: Observation) -> CorrelationEvent:
    if not is_projectable(o):
        raise ValueError("observation is not projectable")
    hashes = tuple(sorted(v for t, v in o.entities if t == "file_hash" and len(v) == 64))
    return CorrelationEvent(
        event_key=o.key,
        record_index=o.record_index,
        source_type=o.source_system[:64] or "unknown",
        provider=o.source_system[:64] or "unknown",
        timestamp=o.event_time,  # type: ignore[arg-type]
        title=o.title[:200],
        category=o.evidence_type,
        severity="informational",
        outcome=o.outcome if o.outcome in ("success", "failure") else "unknown",
        host=o.host,
        user=_attr(o, "user", "actor") if o.family in (EvidenceFamily.IDENTITY, EvidenceFamily.CLOUD) else None,
        src_ip=_attr(o, "src_ip", "ip", "source_ip"),
        dst_ip=_attr(o, "dst_ip", "remote_ip"),
        domain=_attr(o, "query"),
        process_name=_first(o, "process"),
        file_hashes=hashes,
        source_event_id=o.evidence_type[:64],
        evidence_type=o.evidence_type,
        upstream_id=o.upstream_id or "",
        raw_sha256=o.raw_sha256,
        entities=tuple(sorted(o.entities)),
    )


__all__ = ["DATED", "is_dated", "is_machine", "is_projectable", "observation_to_event"]
