"""
AISOP explainable multi-source correlator (Stage 3C-R vertical slice, ADR-009).

Groups normalized events from different sources into incidents by *explainable, typed links*.

AiSOC concepts adapted (``services/fusion/app/services/attack_chain_grouper.py``,
``correlator.py``, ``deduplicator.py``):
* **Link tiers** STRONG / SPECIFIC / WEAK. STRONG = one authenticated context or process instance
  (logon session, process GUID); SPECIFIC = an artefact that is not shared by accident (file hash,
  domain, public IP...); WEAK = a bare context string (host, user, internal IP, process name).
* **Weak links may not weld stories together.** A weak link can attach a lone observation as
  *context*, but it never merges two multi-evidence groups and never counts as corroboration
  (the same rule the sufficiency gate applies). Weakly related incidents are reported, not merged.
* **Deduplication before correlation**: exact duplicates, same-raw-record events and near-duplicates
  collapse into one evidence cluster (AiSOC fingerprint dedup, extended with near-duplicates).
* **Kill-chain ordering and escalation**: incidents record the ordered kill-chain stages present;
  three or more distinct stages in the strongly-linked core raise severity to at least ``high``.

Pure, deterministic, no I/O. Quadratic in the number of evidence clusters (fine for incident-sized
batches; not a streaming engine).
"""

from __future__ import annotations

import uuid
from typing import Optional

from app.modules.correlation.models import (
    Contradiction,
    CorrelationEvent,
    CorrelationResult,
    EvidenceCluster,
    Incident,
    Link,
)
from app.modules.evidence.independence import (
    LINK_SPECIFIC,
    LINK_STRONG,
    LINK_WEAK,
    EvidenceItem,
    cluster_evidence,
    entity_link_strength,
)

INCIDENT_NAMESPACE = uuid.UUID("7c0f3a52-1b7e-4a54-9d3e-6b1f2a9c8e07")

#: Kill-chain ordinal per ATT&CK tactic (from AiSOC ``_TACTIC_ORDER``).
STAGE_ORDER = {
    "reconnaissance": 0, "resource-development": 1, "initial-access": 2, "execution": 3,
    "persistence": 4, "privilege-escalation": 5, "defense-evasion": 6, "credential-access": 7,
    "discovery": 8, "lateral-movement": 9, "collection": 10, "command-and-control": 11,
    "exfiltration": 12, "impact": 13,
}
CATEGORY_TO_STAGE = {
    "initial_access": "initial-access", "execution": "execution", "persistence": "persistence",
    "privilege_escalation": "privilege-escalation", "defense_evasion": "defense-evasion",
    "credential_access": "credential-access", "discovery": "discovery",
    "lateral_movement": "lateral-movement", "collection": "collection",
    "command_and_control": "command-and-control", "exfiltration": "exfiltration", "impact": "impact",
    "malware": "execution",
}
SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")
ESCALATION_MIN_STAGES = 3
WEAK_WINDOW_SECONDS = 1800.0
SPECIFIC_WINDOW_SECONDS = 86400.0
CONTRADICTION_WINDOW_SECONDS = 2.0
_RANK = {LINK_WEAK: 0, LINK_SPECIFIC: 1, LINK_STRONG: 2}


def stage_of(category: str) -> str:
    return CATEGORY_TO_STAGE.get(category, "")


def _sev(s: str) -> int:
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 0


class _UF:
    def __init__(self, n: int) -> None:
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def build_clusters(events: list[CorrelationEvent]) -> tuple[list[EvidenceCluster], dict[uuid.UUID, int]]:
    """Collapse duplicates / same-record / near-duplicate events; return clusters and key->cluster id."""
    ordered = sorted(events, key=lambda e: (e.timestamp, e.record_index))
    items = [
        EvidenceItem(
            key=e.event_key,
            timestamp=e.timestamp,
            digest=e.raw_sha256,
            identity=(e.host, e.source_type, e.source_event_id or e.title, e.outcome),
            entities=frozenset(e.entities),
        )
        for e in ordered
    ]
    raw = cluster_evidence(items)
    members: dict[int, list[CorrelationEvent]] = {}
    for e in ordered:
        members.setdefault(raw[e.event_key], []).append(e)
    firsts = sorted(members.values(), key=lambda m: (m[0].timestamp, m[0].record_index))
    clusters: list[EvidenceCluster] = []
    cid_of: dict[uuid.UUID, int] = {}
    for cid, mem in enumerate(firsts):
        clusters.append(
            EvidenceCluster(
                cluster_id=cid,
                representative=mem[0].event_key,
                members=tuple(m.event_key for m in mem),
                first_seen=mem[0].timestamp,
                last_seen=mem[-1].timestamp,
            )
        )
        for m in mem:
            cid_of[m.event_key] = cid
    return clusters, cid_of


def find_contradictions(events: list[CorrelationEvent]) -> list[Contradiction]:
    """Same host/user/source address, opposite outcomes within a couple of seconds."""
    groups: dict[tuple, list[CorrelationEvent]] = {}
    for e in events:
        if e.outcome in ("success", "failure"):
            groups.setdefault((e.host, e.user, e.src_ip), []).append(e)
    found: list[Contradiction] = []
    for g in groups.values():
        g.sort(key=lambda e: (e.timestamp, e.record_index))
        for a, b in zip(g, g[1:]):
            if a.outcome != b.outcome and (b.timestamp - a.timestamp).total_seconds() <= CONTRADICTION_WINDOW_SECONDS:
                found.append(Contradiction(event_keys=(a.event_key, b.event_key), reason="OUTCOME_CONFLICT_WITHIN_2S"))
    return found


def correlate(
    events: list[CorrelationEvent],
    weak_window_seconds: float = WEAK_WINDOW_SECONDS,
    specific_window_seconds: float = SPECIFIC_WINDOW_SECONDS,
) -> CorrelationResult:
    """Cluster, link, group into incidents. Deterministic for a given event list."""
    if not events:
        return CorrelationResult(events=[], clusters=[], links=[], incidents=[], contradictions=[])

    by_key = {e.event_key: e for e in events}
    clusters, cid_of = build_clusters(events)
    n = len(clusters)
    c_events: list[list[CorrelationEvent]] = [[by_key[k] for k in c.members] for c in clusters]
    c_ents: list[set[tuple[str, str]]] = [set().union(*(set(e.entities) for e in mem)) for mem in c_events]

    # ── typed pairwise links between evidence clusters ───────────────────────
    links: list[Link] = []
    for i in range(n):
        for j in range(i + 1, n):
            shared = c_ents[i] & c_ents[j]
            if not shared:
                continue
            best = max((entity_link_strength(t, v) for t, v in shared), key=lambda s: _RANK[s])
            dt = abs((clusters[j].first_seen - clusters[i].first_seen).total_seconds())
            limit = weak_window_seconds if best == LINK_WEAK else specific_window_seconds
            if dt > limit:
                continue
            links.append(Link(cluster_a=i, cluster_b=j, strength=best, shared_entities=tuple(sorted(shared))))

    # ── core components: STRONG and SPECIFIC links only ──────────────────────
    uf = _UF(n)
    for lk in links:
        if lk.strength in (LINK_STRONG, LINK_SPECIFIC):
            uf.union(lk.cluster_a, lk.cluster_b)
    comp: dict[int, list[int]] = {}
    for i in range(n):
        comp.setdefault(uf.find(i), []).append(i)
    components = sorted(comp.values(), key=lambda m: (-len(m), clusters[m[0]].first_seen))

    # ── weak attachment of lone observations; weak links never merge multi-evidence groups ──
    comp_of = {i: idx for idx, members in enumerate(components) for i in members}
    weak_links = [lk for lk in links if lk.strength == LINK_WEAK]
    attached: dict[int, list[int]] = {idx: [] for idx in range(len(components))}
    weakly_related: dict[int, set[int]] = {idx: set() for idx in range(len(components))}
    absorbed: set[int] = set()
    for idx, members in enumerate(components):
        if len(members) != 1:
            continue
        counts: dict[int, int] = {}
        for lk in weak_links:
            a, b = comp_of[lk.cluster_a], comp_of[lk.cluster_b]
            if idx in (a, b):
                other = b if a == idx else a
                if other != idx and len(components[other]) >= 2:
                    counts[other] = counts.get(other, 0) + 1
        if counts:
            best_other = sorted(counts, key=lambda o: (-counts[o], clusters[components[o][0]].first_seen))[0]
            attached[best_other].append(members[0])
            absorbed.add(idx)
    for lk in weak_links:
        a, b = comp_of[lk.cluster_a], comp_of[lk.cluster_b]
        if a != b and len(components[a]) >= 2 and len(components[b]) >= 2:
            weakly_related[a].add(b)
            weakly_related[b].add(a)

    # ── build incidents ──────────────────────────────────────────────────────
    incident_ids: dict[int, uuid.UUID] = {}
    drafts: list[tuple[int, list[int], list[int]]] = []
    for idx, members in enumerate(components):
        if idx in absorbed:
            continue
        core = list(members)
        ctx = attached[idx]
        keys = sorted(str(k) for i in core + ctx for k in clusters[i].members)
        incident_ids[idx] = uuid.uuid5(INCIDENT_NAMESPACE, "|".join(keys))
        drafts.append((idx, core, ctx))

    incidents: list[Incident] = []
    for idx, core, ctx in drafts:
        all_clusters = core + ctx
        evs = [e for i in all_clusters for e in c_events[i]]
        core_evs = [e for i in core for e in c_events[i]]
        stages = sorted({stage_of(e.category) for e in core_evs if stage_of(e.category)}, key=lambda s: STAGE_ORDER[s])
        severity = max((e.severity for e in evs), key=_sev)
        escalated = False
        if len(stages) >= ESCALATION_MIN_STAGES and _sev(severity) < _sev("high"):
            severity, escalated = "high", True
        counts = {LINK_STRONG: 0, LINK_SPECIFIC: 0, LINK_WEAK: 0}
        member_set = set(all_clusters)
        for lk in links:
            if lk.cluster_a in member_set and lk.cluster_b in member_set:
                counts[lk.strength] += 1
        evs_sorted = sorted(evs, key=lambda e: (e.timestamp, e.record_index))
        incidents.append(
            Incident(
                incident_id=incident_ids[idx],
                core_clusters=tuple(sorted(core)),
                weak_context_clusters=tuple(sorted(ctx)),
                event_keys=tuple(e.event_key for e in evs_sorted),
                first_seen=evs_sorted[0].timestamp,
                last_seen=evs_sorted[-1].timestamp,
                hosts=tuple(sorted({e.host for e in evs if e.host})),
                users=tuple(sorted({e.user for e in evs if e.user})),
                severity=severity,
                stages=tuple(stages),
                escalated=escalated,
                link_counts=counts,
                weakly_related=tuple(sorted(incident_ids[o] for o in weakly_related[idx] if o in incident_ids)),
            )
        )
    incidents.sort(key=lambda inc: (-_sev(inc.severity), -len(inc.event_keys), inc.first_seen))
    return CorrelationResult(
        events=sorted(events, key=lambda e: (e.timestamp, e.record_index)),
        clusters=clusters,
        links=links,
        incidents=incidents,
        contradictions=find_contradictions(events),
    )


def first_event_of_max_severity(events: list[CorrelationEvent], core_keys: Optional[set[uuid.UUID]] = None) -> CorrelationEvent:
    """Question anchor: the earliest event of the highest severity (restricted to the core when given)."""
    pool = [e for e in events if core_keys is None or e.event_key in core_keys] or events
    top = max(_sev(e.severity) for e in pool)
    return sorted((e for e in pool if _sev(e.severity) == top), key=lambda e: (e.timestamp, e.record_index))[0]


__all__ = [
    "CATEGORY_TO_STAGE",
    "STAGE_ORDER",
    "build_clusters",
    "correlate",
    "find_contradictions",
    "first_event_of_max_severity",
    "stage_of",
]
