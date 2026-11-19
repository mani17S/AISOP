"""
AISOP investigation graph (Stage 6, ADR-011): a deterministic, evidence-backed view over canonical observations.

Nodes are entities (user, ip, host, domain, file, registry key, process, e-mail message, ...). Edges are TYPED
relationships (``Predicate``) that at least one record STATES directly; every edge keeps the observations that
support it, how many of those are independent (distinct evidence clusters, so duplicates and near-duplicates never
inflate it) and the rationale. Cross-source *correlations* are kept separate from stated edges: a correlation is
"these two evidence units share this entity", with the link strength and the time distance, and it is produced by the
existing correlator (``app.modules.correlation.correlator``), not re-implemented here.

What the graph deliberately does NOT do:
* It does not invent relationships: there is no edge without a record that states it.
* It does not join on weak context (a bare user name, host name, internal IP or process name creates a node, never an
  inferred edge); weak sharing is reported as a weak correlation, which is context, not corroboration.
* It does not count analyst statements as support: analyst observations annotate nodes (``analyst_notes``) and are
  reported separately.
* It does not hide gaps: undated, unclassified and partially normalised observations, plus entities that only ever
  appear in analyst statements, are listed under ``uncertainties``.

Storage: the graph is derived on demand from the preserved raw evidence (re-computable); it is held in memory and
stored only as a bounded JSON view inside the investigation result. No graph database is required: incident-sized
graphs are small and the quadratic correlation step already runs in process (see ADR-011).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from app.modules.correlation.models import CorrelationResult
from app.modules.evidence.independence import LINK_WEAK, entity_link_strength
from app.modules.evidence_domains.model import EvidenceFamily, Observation, TimeStatus, TrustClass

MAX_NODES = 300
MAX_EDGES = 500
MAX_CORRELATIONS = 200
MAX_UNCERTAINTIES = 100

Entity = tuple[str, str]


@dataclass
class GraphNode:
    entity_type: str
    value: str
    observations: list[uuid.UUID] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    derived: bool = False
    analyst_notes: list[uuid.UUID] = field(default_factory=list)

    @property
    def node_id(self) -> str:
        return f"{self.entity_type}:{self.value}"


@dataclass
class GraphEdge:
    subject: Entity
    predicate: str
    obj: Entity
    observations: list[uuid.UUID] = field(default_factory=list)
    evidence_units: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    trust: set[str] = field(default_factory=set)

    @property
    def independent_support(self) -> int:
        return len(self.evidence_units)


@dataclass
class GraphCorrelation:
    observation_a: uuid.UUID
    observation_b: uuid.UUID
    strength: str
    shared: tuple[Entity, ...]
    seconds_apart: float
    rationale: str


@dataclass
class InvestigationGraph:
    nodes: dict[Entity, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    correlations: list[GraphCorrelation] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    uncertainties: list[dict[str, Any]] = field(default_factory=list)
    observation_count: int = 0

    def to_view(self) -> dict[str, Any]:
        """Bounded, JSON-safe, payload-free view (no raw records, no command lines)."""
        nodes = sorted(self.nodes.values(), key=lambda n: (-len(n.observations), n.entity_type, n.value))
        edges = sorted(self.edges, key=lambda e: (-e.independent_support, e.predicate, e.subject, e.obj))
        return {
            "observation_count": self.observation_count,
            "nodes": [
                {"id": n.node_id, "type": n.entity_type, "value": n.value, "observation_count": len(n.observations),
                 "sources": sorted(n.sources), "derived": n.derived,
                 "analyst_note_count": len(n.analyst_notes)}
                for n in nodes[:MAX_NODES]
            ],
            "edges": [
                {"subject": f"{e.subject[0]}:{e.subject[1]}", "predicate": e.predicate, "object": f"{e.obj[0]}:{e.obj[1]}",
                 "kind": "stated", "supporting_observations": [str(k) for k in e.observations[:10]],
                 "independent_support": e.independent_support, "sources": sorted(e.sources),
                 "trust": sorted(e.trust),
                 "rationale": "Stated directly by the supporting record(s); no relationship was inferred."}
                for e in edges[:MAX_EDGES]
            ],
            "correlations": [
                {"observations": [str(c.observation_a), str(c.observation_b)], "strength": c.strength,
                 "shared_entities": [f"{t}:{v}" for t, v in c.shared[:4]], "seconds_apart": c.seconds_apart,
                 "rationale": c.rationale, "counts_as_corroboration": c.strength != LINK_WEAK}
                for c in self.correlations[:MAX_CORRELATIONS]
            ],
            "contradictions": self.contradictions[:MAX_UNCERTAINTIES],
            "uncertainties": self.uncertainties[:MAX_UNCERTAINTIES],
            "truncated": len(nodes) > MAX_NODES or len(edges) > MAX_EDGES or len(self.correlations) > MAX_CORRELATIONS,
        }


_CORRELATION_RATIONALE = {
    "strong": "Same authenticated context or process instance in two independent evidence units.",
    "specific": "Same artefact that is not shared by accident (file hash, domain, URL, file path, registry key, e-mail address or public IP) in two independent evidence units.",
    "weak": "Only a bare context value (host, user, internal IP, process name) is shared: this places evidence in the same area but is NOT corroboration.",
}


def build_graph(
    observations: list[Observation],
    correlation: Optional[CorrelationResult] = None,
    analyst_observations: Optional[list[Observation]] = None,
    rejected: int = 0,
) -> InvestigationGraph:
    """
    Build the graph for ``observations`` (machine evidence). ``correlation`` supplies evidence clusters, links and
    contradictions from the existing correlator; without it every distinct raw digest is its own evidence unit.
    """
    g = InvestigationGraph(observation_count=len(observations))
    unit_of: dict[uuid.UUID, str] = {}
    cid_of: dict[uuid.UUID, int] = {}
    if correlation is not None:
        for c in correlation.clusters:
            for k in c.members:
                cid_of[k] = c.cluster_id
    for o in observations:
        unit_of[o.key] = f"c{cid_of[o.key]}" if o.key in cid_of else f"d{o.raw_sha256}"

    def node(ent: Entity, o: Observation, derived: bool = False) -> GraphNode:
        n = g.nodes.get(ent)
        if n is None:
            n = g.nodes[ent] = GraphNode(entity_type=ent[0], value=ent[1], derived=derived)
        elif not derived:
            n.derived = False  # also stated directly by a record
        if o.key not in n.observations:
            n.observations.append(o.key)
        n.sources.add(o.source_system)
        return n

    edge_index: dict[tuple[Entity, str, Entity], GraphEdge] = {}
    for o in observations:
        derived = set(o.derived_entities)
        for ent in o.entities:
            node(ent, o, derived=ent in derived)
        for rel in o.relations:
            key = (rel.subject, rel.predicate.value, rel.obj)
            e = edge_index.get(key)
            if e is None:
                e = edge_index[key] = GraphEdge(subject=rel.subject, predicate=rel.predicate.value, obj=rel.obj)
                g.edges.append(e)
            for ent in (rel.subject, rel.obj):
                node(ent, o, derived=ent in derived)
            if o.key not in e.observations:
                e.observations.append(o.key)
            e.evidence_units.add(unit_of[o.key])
            e.sources.add(o.source_system)
            e.trust.add(o.trust_class.value)

    for a in analyst_observations or []:
        for ent in a.entities:
            if ent in g.nodes and a.key not in g.nodes[ent].analyst_notes:
                g.nodes[ent].analyst_notes.append(a.key)

    if correlation is not None:
        keys = {o.key for o in observations}
        cluster_rep = {c.cluster_id: c for c in correlation.clusters}
        for lk in correlation.links:
            ca, cb = cluster_rep[lk.cluster_a], cluster_rep[lk.cluster_b]
            if ca.representative not in keys or cb.representative not in keys:
                continue
            g.correlations.append(GraphCorrelation(
                observation_a=ca.representative, observation_b=cb.representative, strength=lk.strength,
                shared=lk.shared_entities,
                seconds_apart=abs((cb.first_seen - ca.first_seen).total_seconds()),
                rationale=_CORRELATION_RATIONALE[lk.strength],
            ))
        for con in correlation.contradictions:
            if set(con.event_keys) & keys:
                g.contradictions.append({"observations": [str(k) for k in con.event_keys], "reason": con.reason})

    # ── uncertainty and missing information ──────────────────────────────────
    def unc(kind: str, detail: str, obs: list[uuid.UUID]) -> None:
        g.uncertainties.append({"kind": kind, "detail": detail, "observations": [str(k) for k in obs[:20]]})

    undated = [o.key for o in observations if o.time_status in (TimeStatus.MISSING, TimeStatus.INVALID, TimeStatus.OUT_OF_RANGE)]
    if undated:
        unc("UNDATED_OBSERVATIONS", "No usable event time: preserved and shown, but not placed on the timeline or in time-windowed correlation.", undated)
    naive = [o.key for o in observations if o.time_status == TimeStatus.NAIVE_ASSUMED_UTC]
    if naive:
        unc("TIMEZONE_ASSUMED", "The source gave no time zone; UTC was assumed and is disclosed here.", naive)
    unclassified = [o.key for o in observations if o.family == EvidenceFamily.UNCLASSIFIED]
    if unclassified:
        unc("UNCLASSIFIED_EVIDENCE", "Evidence type not recognised: preserved, not interpreted, cannot corroborate.", unclassified)
    partial = [o.key for o in observations if o.classification == "partial"]
    if partial:
        unc("PARTIALLY_NORMALIZED", "Valid record, but no linkable entity could be extracted from it.", partial)
    tool = [o.key for o in observations if o.trust_class == TrustClass.TOOL_ASSERTED]
    if tool:
        unc("TOOL_ASSERTED_ONLY", "Interpretation produced by a forensic tool; not independently verified by AISOP.", tool)
    weak_only = {c.observation_a for c in g.correlations if c.strength == LINK_WEAK} | {c.observation_b for c in g.correlations if c.strength == LINK_WEAK}
    strong_or_specific = {c.observation_a for c in g.correlations if c.strength != LINK_WEAK} | {c.observation_b for c in g.correlations if c.strength != LINK_WEAK}
    weak_only -= strong_or_specific
    if weak_only:
        unc("WEAK_CORRELATION_ONLY", "Related to other evidence only through host, user, internal IP or process name.", sorted(weak_only, key=str))
    analyst_only = sorted(
        {ent for a in analyst_observations or [] for ent in a.entities if ent not in g.nodes}
    )
    if analyst_only:
        unc("ANALYST_ONLY_ENTITIES", "Entities mentioned only by an analyst statement; no machine evidence supports them: " +
            ", ".join(f"{t}:{v}" for t, v in analyst_only[:10]), [])
    if rejected:
        unc("REJECTED_RECORDS", f"{rejected} record(s) failed validation and were quarantined (not part of the graph).", [])
    return g


def entity_strength(ent: Entity) -> str:
    return entity_link_strength(ent[0], ent[1])


__all__ = ["GraphCorrelation", "GraphEdge", "GraphNode", "InvestigationGraph", "build_graph"]
