"""
AISOP investigation timeline (Stage 3C-R vertical slice, ADR-009).

Builds the ordered, provenance-annotated timeline of an incident from correlation output:
chronological entries (UTC), kill-chain stage per entry, whether the entry belongs to the strongly
linked core or is weak context only, how many duplicate/near-duplicate records were collapsed
into it, and any contradiction it takes part in. Each entry carries the first 12 hex characters of
the raw-evidence SHA-256 so it can be traced to preserved evidence.

AiSOC concept adapted: ordered incident narrative / attack-chain view (``attack_chain_grouper``
ordering by kill-chain stage, ``narrative.py`` deterministic, LLM-free narrative). Pure, no I/O.
"""

from __future__ import annotations

import uuid

from app.modules.correlation.correlator import stage_of
from app.modules.correlation.models import CorrelationResult, Incident, TimelineEntry


def build_timeline(result: CorrelationResult, incident: Incident) -> list[TimelineEntry]:
    by_key = {e.event_key: e for e in result.events}
    core = set(incident.core_clusters)
    conflicts: dict[uuid.UUID, list[uuid.UUID]] = {}
    for con in result.contradictions:
        for k in con.event_keys:
            conflicts.setdefault(k, []).extend(x for x in con.event_keys if x != k)

    entries: list[TimelineEntry] = []
    for cluster in sorted(
        (result.clusters[i] for i in (*incident.core_clusters, *incident.weak_context_clusters)),
        key=lambda c: (c.first_seen, c.cluster_id),
    ):
        rep = by_key[cluster.representative]
        entries.append(
            TimelineEntry(
                position=0,
                timestamp=rep.timestamp,
                source_type=rep.source_type,
                host=rep.host,
                user=rep.user,
                title=rep.title,
                stage=stage_of(rep.category) or "unclassified",
                severity=rep.severity,
                outcome=rep.outcome,
                raw_sha256_prefix=rep.raw_sha256[:12],
                membership="core" if cluster.cluster_id in core else "weak_context",
                duplicates_collapsed=len(cluster.members) - 1,
                contradicts=tuple(sorted({x for m in cluster.members for x in conflicts.get(m, [])}, key=str)),
                event_key=rep.event_key,
            )
        )
    return [e.model_copy(update={"position": i + 1}) for i, e in enumerate(entries)]


__all__ = ["build_timeline"]
