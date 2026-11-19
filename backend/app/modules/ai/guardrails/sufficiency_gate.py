"""
AISOP Deterministic Evidence-Sufficiency Gate (Stage 3C / 3C-R, ADR-008, rule table ``suff-v3``).

Runs BEFORE every production model invocation. Pure, deterministic, no I/O, no LLM, no network.
It reads only the already-built InvestigationContext and returns an immutable
EvidenceSufficiencyAssessment:

  SUFFICIENT   - evidence meets the criteria; model-assisted investigation may proceed.
  LIMITED      - bounded investigation only; limitations are preserved and disclosed.
  INSUFFICIENT - required evidence absent/inadequate; NO model invocation is permitted.

Design rules:
* Classification depends on the investigation question (the root anchor event if given, else
  the target hosts and time window), on the relevance of each evidence unit to that question,
  and on its reliability (valid raw-evidence digest, de-duplication, independence). There is NO
  universal event-count threshold.
* **Independence (3C-R).** Events are first collapsed into evidence clusters (same event, same
  attested raw digest, identical content, or near-duplicate; see
  ``app.modules.evidence.independence``). The question is *corroborated* only by a different,
  attested evidence cluster joined to the anchor by a **specific** shared entity (file hash,
  domain, file, registry key, URL, e-mail, public IP). Shared host, user, process name or
  internal IP are context, not corroboration (reason ``WEAK_LINK_ONLY`` is disclosed).
* Fixed-vocabulary reason codes and event UUID references only. Evidence text is never
  interpreted, echoed or placed in findings, so injected instructions cannot influence or leak
  through the gate.
* Fail closed: any exception yields INSUFFICIENT (``evaluate_sufficiency``).
* Source-recognition and injection-pattern rules are not implemented (ADR-008).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta
from typing import Any, Optional, Sequence

from app.modules.evidence.independence import (
    LINK_SPECIFIC,
    LINK_STRONG,
    NEAR_DUPLICATE_WINDOW_SECONDS,
    EvidenceItem,
    canonical_entity_value,
    cluster_evidence,
    entity_link_strength,
    explain_clusters,
    is_unattested_digest,
    normalize_digest,
)
from app.modules.ai.guardrails.sufficiency_trace import SufficiencyTrace
from app.modules.evidence_domains.contradictions import classify_materiality
from app.schemas.contradiction import ContradictionCandidate, ContradictionFinding, HypothesisRelation, Materiality
from app.schemas.investigation import ContextEventItem, InvestigationContext
from app.schemas.sufficiency import (
    SUFFICIENCY_RULE_VERSION,
    EvidenceSufficiencyAssessment,
    FindingEffect,
    ReasonCode,
    SufficiencyFinding,
    SufficiencyVerdict,
)

__all__ = [
    "FUTURE_SKEW",
    "REQUIRED_ENTITY_TYPES_BY_EVENT_TYPE",
    "apply_sufficiency_disclosure",
    "assess_evidence_sufficiency",
    "evaluate_sufficiency",
    "evidence_clusters_for_context",
    "is_unattested_digest",
]

#: Tolerated clock skew for events dated after the context assembly time.
FUTURE_SKEW = timedelta(minutes=5)

#: Entity types the extractor must have associated with the anchor for a known canonical event
#: type (types not listed impose no requirement).
REQUIRED_ENTITY_TYPES_BY_EVENT_TYPE: dict[str, tuple[str, ...]] = {
    "process_creation": ("process",),
    "network_connection": ("ip",),
}


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _finding(
    code: ReasonCode,
    effect: FindingEffect,
    ids: list[uuid.UUID] | list[str],
    qualifier: Optional[str] = None,
) -> SufficiencyFinding:
    return SufficiencyFinding(
        code=code,
        effect=effect,
        qualifier=qualifier,
        evidence_ids=sorted({str(i) for i in ids}),
    )


def _build(
    findings: list[SufficiencyFinding],
    *,
    context_sha256: Optional[str],
    evidence_ids: list[str],
    total: int,
    effective: int,
    relevant: int,
    attested: int,
    corroborating: int,
    contradictions: Sequence[ContradictionFinding] = (),
) -> EvidenceSufficiencyAssessment:
    if any(f.effect == FindingEffect.INSUFFICIENT for f in findings):
        verdict = SufficiencyVerdict.INSUFFICIENT
    elif any(f.effect == FindingEffect.LIMITED for f in findings):
        verdict = SufficiencyVerdict.LIMITED
    else:
        verdict = SufficiencyVerdict.SUFFICIENT

    ordered = sorted(findings, key=lambda f: (f.code.value, f.qualifier or ""))
    reason_codes = sorted({f.coded for f in ordered})
    payload = {
        "verdict": verdict.value,
        "rule_version": SUFFICIENCY_RULE_VERSION,
        "findings": [
            {"code": f.code.value, "effect": f.effect.value, "qualifier": f.qualifier, "evidence_ids": f.evidence_ids}
            for f in ordered
        ],
        "reason_codes": reason_codes,
        "evidence_ids": evidence_ids,
        "total_events": total,
        "effective_events": effective,
        "relevant_events": relevant,
        "attested_events": attested,
        "corroborating_events": corroborating,
        "contradictions": sorted(
            (c.model_dump(mode="json") for c in contradictions),
            key=lambda d: (d["kind"], d["proposition"], d["evidence_ids"]),
        ),
        "context_sha256": context_sha256,
    }
    digest = hashlib.sha256(_canon(payload).encode("utf-8")).hexdigest()
    return EvidenceSufficiencyAssessment(
        verdict=verdict,
        findings=ordered,
        reason_codes=reason_codes,
        evidence_ids=evidence_ids,
        total_events=total,
        effective_events=effective,
        relevant_events=relevant,
        attested_events=attested,
        corroborating_events=corroborating,
        contradictions=list(contradictions),
        context_sha256=context_sha256,
        assessment_sha256=digest,
    )


def _entities_by_event(context: InvestigationContext) -> dict[uuid.UUID, set[tuple[str, str]]]:
    out: dict[uuid.UUID, set[tuple[str, str]]] = {}
    for ent in context.entities:
        for ev_id in ent.associated_event_uuids:
            out.setdefault(ev_id, set()).add(
                (ent.entity_type.strip().lower(), canonical_entity_value(ent.entity_type, ent.entity_value))
            )
    return out


def _evidence_items(
    events: list[ContextEventItem],
    ents_by_event: dict[uuid.UUID, set[tuple[str, str]]],
) -> list[EvidenceItem]:
    return [
        EvidenceItem(
            key=e.event_uuid,
            timestamp=e.timestamp_utc,
            # D5: records that declare the same upstream collection (forwarded / mirrored / replicated copies) are one evidence unit, never
            # independent corroboration. The declared id is used as the unit key; the raw digest stays the provenance digest elsewhere.
            digest=(f"upstream:{e.attributes['upstream_id']}" if e.attributes.get("upstream_id") else normalize_digest(e.raw_evidence_sha256)),
            identity=(e.source_identifier, e.event_id, e.event_type, e.action, e.outcome),
            entities=frozenset(ents_by_event.get(e.event_uuid, ())),
            content=_canon(e.attributes),
        )
        for e in events
    ]


def evidence_clusters_for_context(context: InvestigationContext) -> dict[uuid.UUID, int]:
    """Cluster id per context event UUID (same notion the gate uses); used by the validator."""
    ents = _entities_by_event(context)
    return cluster_evidence(_evidence_items(list(context.events), ents))  # type: ignore[return-value]


def _populate_trace(
    trace: SufficiencyTrace,
    *,
    stage: str,
    items_fn: Any,
    clusters: dict[Any, int],
    unit_ids: list[int],
    members: dict[int, list[ContextEventItem]],
    rep: dict[int, ContextEventItem],
    unit_ents: dict[int, set[tuple[str, str]]],
    unit_digest: dict[int, Optional[str]],
    anomalous_units: set[int],
    relevant_units: list[int],
    anchor_unit: Optional[int],
    root_id: Optional[uuid.UUID],
    root_present: bool,
    anchor_dropped: bool,
    corroborating: set[int],
    repeated_only: set[int],
    weak_only: set[int],
    excluded_pairs: set[frozenset[int]],
    rec: Optional[list[tuple[str, int, int]]],
) -> None:
    """
    TRACE ONLY (Sprint 1). Copies what the evaluation above ALREADY decided into the trace; it reads, never writes, the evaluation state and
    never raises into the gate (a failure only marks ``trace.error`` with the exception TYPE). Entity values are never stored: only entity
    type and link strength.
    """
    try:
        def uid(c: int) -> str:
            return str(rep[c].event_uuid)

        trace.stage = stage
        trace.anchor_event_id = str(root_id) if root_id is not None else None
        if root_id is None:
            trace.anchor_status = "none"
        elif not root_present:
            trace.anchor_status = "absent_from_evidence"
        elif anchor_dropped:
            trace.anchor_status = "dropped_temporal_anomaly"
        else:
            trace.anchor_status = "used"
        trace.pairwise_without_anchor = stage == "complete" and anchor_unit is None
        relevant_set = set(relevant_units)
        in_excluded_pair = {c for pair in excluded_pairs for c in pair}
        trace.units, trace.exclusions = [], []
        for c in unit_ids:
            if c in anomalous_units:
                role = "excluded"
            elif c == anchor_unit:
                role = "anchor"
            elif c in corroborating:
                role = "corroborating"
            elif c in repeated_only:
                role = "repeated_observation"
            elif c in weak_only:
                role = "weak_link"
            else:
                role = "context" if c in relevant_set else "excluded"
            trace.units.append({
                "unit": uid(c),
                "members": [str(m.event_uuid) for m in members[c]],
                "attested_digest_format": unit_digest[c] is not None,
                "relevant": c in relevant_set,
                "role": role,
            })
            if c == anchor_unit or c in corroborating:
                continue
            if c in anomalous_units:
                reason = "temporal_anomaly"
            elif c not in relevant_set:
                reason = "irrelevant_to_question"
            elif unit_digest[c] is None:
                reason = "unattested_digest_format"
            elif c in in_excluded_pair:
                reason = "contradiction_removed_pair"
            elif c in repeated_only:
                reason = "repeated_observation"
            elif c in weak_only:
                reason = "weak_link_only"
            elif stage == "complete":
                reason = "no_qualifying_shared_entity"
            else:
                continue
            trace.exclusions.append({"unit": uid(c), "reason": reason})
        trace.collapsed = [
            {"into": str(e["into"]), "duplicate": str(e["duplicate"]), "basis": list(e["basis"]), "direct": bool(e["direct"])}
            for e in explain_clusters(items_fn(), clusters)
        ]
        order = {"corroborating": 0, "repeated": 1, "weak": 2}
        pairs: list[dict[str, Any]] = []
        for kind, a, b in sorted(rec or [], key=lambda r: (order[r[0]], uid(r[1]), uid(r[2]))):
            shared = sorted({(t, entity_link_strength(t, v)) for (t, v) in (unit_ents[a] & unit_ents[b])})
            specific = any(s in (LINK_STRONG, LINK_SPECIFIC) for _t, s in shared)
            pairs.append({
                "kind": kind,
                "unit_a": uid(a),
                "unit_b": uid(b),
                "shared_entities": [{"type": t, "strength": s} for t, s in shared],
                "tests": {
                    "different_evidence_unit": True,
                    "attested_digest_format": True,
                    "specific_or_strong_link": specific,
                    "different_observation_class": kind == "corroborating",
                },
            })
        trace.pairs = pairs
    except Exception as exc:  # noqa: BLE001 - tracing must never alter or break the verdict
        trace.error = type(exc).__name__


def assess_evidence_sufficiency(
    context: InvestigationContext,
    contradictions: Sequence[ContradictionCandidate] = (),
    trace: Optional[SufficiencyTrace] = None,
) -> EvidenceSufficiencyAssessment:
    """
    Deterministic core. May raise on malformed input; production callers must use
    ``evaluate_sufficiency`` which fails closed.

    ``trace`` (Sprint 1, optional): when given it is filled, in this same pass, with an explanation of the decision (units, anchor, merge
    basis, candidate pairs by entity type/strength, exclusions). It never changes a decision; with ``trace=None`` behaviour is unchanged.
    """
    events: list[ContextEventItem] = list(context.events)
    ctx_hash = context.reproducibility.context_sha256
    findings: list[SufficiencyFinding] = []

    if not events:
        findings.append(_finding(ReasonCode.NO_EVIDENCE, FindingEffect.INSUFFICIENT, []))
        if trace is not None:
            trace.stage = "no_evidence"
        return _build(
            findings, context_sha256=ctx_hash, evidence_ids=[], total=0,
            effective=0, relevant=0, attested=0, corroborating=0,
        )

    ents_by_event = _entities_by_event(context)

    # ── Contradictions (on raw events, before clustering) ────────────────────
    by_identity: dict[tuple, list[ContextEventItem]] = {}
    by_content: dict[tuple, list[ContextEventItem]] = {}
    by_logical: dict[tuple, list[ContextEventItem]] = {}
    for e in events:
        ident = (e.source_identifier, e.event_id, e.timestamp_utc, e.action)
        by_identity.setdefault(ident, []).append(e)
        by_content.setdefault(ident + (e.outcome, _canon(e.attributes)), []).append(e)
        who = frozenset(t for t in ents_by_event.get(e.event_uuid, ()) if t[0] in ("host", "user", "ip", "domain"))
        by_logical.setdefault((e.source_identifier, e.event_id, e.action, who), []).append(e)
    contradictory: set[uuid.UUID] = set()
    for group in by_identity.values():
        if len({g.outcome for g in group}) > 1:
            contradictory.update(g.event_uuid for g in group)
    for group in by_content.values():
        if len({g.raw_evidence_sha256.strip().lower() for g in group}) > 1:
            contradictory.update(g.event_uuid for g in group)
    # Same logical event (host, event id, action, same actors) seen with opposite outcomes within the
    # near-duplicate window: one source says success, another says failure.
    for group in by_logical.values():
        ordered_group = sorted(group, key=lambda g: g.timestamp_utc)
        for first, second in zip(ordered_group, ordered_group[1:]):
            if (
                first.outcome != second.outcome
                and {first.outcome, second.outcome} == {"success", "failure"}
                and abs((second.timestamp_utc - first.timestamp_utc).total_seconds()) <= NEAR_DUPLICATE_WINDOW_SECONDS
            ):
                contradictory.update((first.event_uuid, second.event_uuid))
    if contradictory:
        findings.append(_finding(ReasonCode.CONTRADICTORY_EVIDENCE, FindingEffect.LIMITED, list(contradictory)))

    # ── Evidence clusters: duplicates, same-record and near-duplicates collapse ─
    clusters = cluster_evidence(_evidence_items(events, ents_by_event))
    members: dict[int, list[ContextEventItem]] = {}
    for e in events:
        members.setdefault(clusters[e.event_uuid], []).append(e)
    unit_ids = sorted(members, key=lambda c: min(events.index(m) for m in members[c]))
    rep: dict[int, ContextEventItem] = {c: members[c][0] for c in unit_ids}
    unit_of: dict[uuid.UUID, int] = {e.event_uuid: clusters[e.event_uuid] for e in events}
    unit_ents: dict[int, set[tuple[str, str]]] = {
        c: set().union(*(ents_by_event.get(m.event_uuid, set()) for m in members[c])) for c in unit_ids
    }
    unit_digest: dict[int, Optional[str]] = {
        c: next((normalize_digest(m.raw_evidence_sha256) for m in members[c] if not is_unattested_digest(m.raw_evidence_sha256)), None)
        for c in unit_ids
    }
    duplicate_ids = [m.event_uuid for c in unit_ids for m in members[c][1:]]
    if duplicate_ids:
        findings.append(_finding(ReasonCode.DUPLICATE_EVIDENCE_COLLAPSED, FindingEffect.DISCLOSURE, duplicate_ids))

    # ── Truncation (coverage) ─────────────────────────────────────────────────
    bm = context.budget_metrics
    if bm.context_truncated or bm.events_omitted_count > 0:
        findings.append(_finding(ReasonCode.EVIDENCE_TRUNCATED, FindingEffect.LIMITED, list(bm.omitted_event_ids_summary)))

    # ── Temporal consistency (per unit representative) ────────────────────────
    ws, we = context.time_window_start, context.time_window_end
    assembled = context.assembled_at
    anomalous_units: set[int] = set()
    for c in unit_ids:
        ts = rep[c].timestamp_utc
        if ts < ws or ts > we or ts > assembled + FUTURE_SKEW:
            anomalous_units.add(c)
    if anomalous_units:
        findings.append(_finding(ReasonCode.TEMPORAL_ANOMALY, FindingEffect.LIMITED, [rep[c].event_uuid for c in anomalous_units]))

    # ── Question anchor ───────────────────────────────────────────────────────
    root_id = context.reproducibility.root_event_id
    anchor_unit: Optional[int] = None
    if root_id is not None:
        if root_id in unit_of:
            anchor_unit = unit_of[root_id]
        else:
            findings.append(_finding(ReasonCode.ROOT_ABSENT, FindingEffect.LIMITED, []))
    anchor_dropped = anchor_unit is not None and anchor_unit in anomalous_units
    if anchor_dropped:
        anchor_unit = None

    # ── Relevance to the question ─────────────────────────────────────────────
    hosts = set(context.target_hosts)

    def relevant(c: int) -> bool:
        if c in anomalous_units:
            return False
        if anchor_unit is not None:
            return (
                c == anchor_unit
                or rep[c].source_identifier == rep[anchor_unit].source_identifier
                or bool(unit_ents[c] & unit_ents[anchor_unit])
            )
        return (not hosts) or (rep[c].source_identifier in hosts)

    relevant_units = [c for c in unit_ids if relevant(c)]
    excluded_ids = [rep[c].event_uuid for c in unit_ids if c not in anomalous_units and c not in relevant_units]
    if excluded_ids:
        findings.append(_finding(ReasonCode.IRRELEVANT_EVIDENCE_EXCLUDED, FindingEffect.DISCLOSURE, excluded_ids))

    evidence_ids = [str(rep[c].event_uuid) for c in unit_ids]
    if not relevant_units:
        findings.append(_finding(ReasonCode.NO_RELEVANT_EVIDENCE, FindingEffect.INSUFFICIENT, [rep[c].event_uuid for c in unit_ids]))
        if trace is not None:
            _populate_trace(
                trace, stage="no_relevant_evidence", items_fn=lambda: _evidence_items(events, ents_by_event), clusters=clusters,
                unit_ids=unit_ids, members=members, rep=rep, unit_ents=unit_ents, unit_digest=unit_digest, anomalous_units=anomalous_units,
                relevant_units=relevant_units, anchor_unit=anchor_unit, root_id=root_id, root_present=root_id in unit_of if root_id else False,
                anchor_dropped=anchor_dropped, corroborating=set(), repeated_only=set(), weak_only=set(), excluded_pairs=set(), rec=None,
            )
        return _build(
            findings, context_sha256=ctx_hash, evidence_ids=evidence_ids, total=len(events),
            effective=len(unit_ids), relevant=0, attested=0, corroborating=0,
        )

    # ── Provenance / reliability ──────────────────────────────────────────────
    attested_units = [c for c in relevant_units if unit_digest[c] is not None]
    unattested_ids = [rep[c].event_uuid for c in relevant_units if unit_digest[c] is None]
    if not attested_units:
        findings.append(_finding(ReasonCode.PROVENANCE_UNVERIFIED_ALL, FindingEffect.LIMITED, unattested_ids))
    elif unattested_ids:
        findings.append(_finding(ReasonCode.PROVENANCE_PARTIAL, FindingEffect.DISCLOSURE, unattested_ids))
    if anchor_unit is not None and unit_digest[anchor_unit] is None:
        findings.append(_finding(ReasonCode.ROOT_PROVENANCE_MISSING, FindingEffect.LIMITED, [rep[anchor_unit].event_uuid]))

    # ── Independent corroboration: different attested cluster + SPECIFIC link ─
    def specific_shared(a: int, b: int) -> bool:
        return any(entity_link_strength(t, v) in (LINK_STRONG, LINK_SPECIFIC) for (t, v) in (unit_ents[a] & unit_ents[b]))

    def any_shared(a: int, b: int) -> bool:
        return bool(unit_ents[a] & unit_ents[b])

    def same_observation_class(a: int, b: int) -> bool:
        """Same sensor/host, event id, type and action: a repetition of one observation, not a second source of proof."""
        ra, rb = rep[a], rep[b]
        return (ra.source_identifier, ra.event_id, ra.event_type, ra.action) == (rb.source_identifier, rb.event_id, rb.event_type, rb.action)

    def corroborates(a: int, b: int) -> bool:
        return specific_shared(a, b) and not same_observation_class(a, b)

    def classify(excluded: set[frozenset[int]], rec: Optional[list[tuple[str, int, int]]] = None) -> tuple[set[int], set[int], set[int]]:
        # ``rec`` (Sprint 1, trace only) records each classified pair as it is decided; it never influences a branch.
        corroborating_: set[int] = set()
        repeated_: set[int] = set()
        weak_: set[int] = set()
        if anchor_unit is not None:
            for c in attested_units:
                if c == anchor_unit or frozenset((c, anchor_unit)) in excluded:
                    continue
                if corroborates(c, anchor_unit):
                    corroborating_.add(c)
                    if rec is not None:
                        rec.append(("corroborating", c, anchor_unit))
                elif specific_shared(c, anchor_unit):
                    repeated_.add(c)
                    if rec is not None:
                        rec.append(("repeated", c, anchor_unit))
                elif any_shared(c, anchor_unit) or rep[c].source_identifier == rep[anchor_unit].source_identifier:
                    weak_.add(c)
                    if rec is not None:
                        rec.append(("weak", c, anchor_unit))
        else:
            for i, a in enumerate(attested_units):
                for b in attested_units[i + 1:]:
                    if frozenset((a, b)) in excluded:
                        continue
                    if corroborates(a, b):
                        corroborating_.update((a, b))
                        if rec is not None:
                            rec.append(("corroborating", a, b))
                    elif specific_shared(a, b):
                        repeated_.update((a, b))
                        if rec is not None:
                            rec.append(("repeated", a, b))
                    elif any_shared(a, b) or rep[a].source_identifier == rep[b].source_identifier:
                        weak_.update((a, b))
                        if rec is not None:
                            rec.append(("weak", a, b))
        return corroborating_, repeated_, weak_

    rec_first: Optional[list[tuple[str, int, int]]] = [] if trace is not None else None
    rec_final: Optional[list[tuple[str, int, int]]] = rec_first
    trace_excluded_pairs: set[frozenset[int]] = set()
    corroborating, repeated_only, weak_only = classify(set(), rec_first)

    # ── ADR-013 Revision 2 (suff-v4): contradiction findings ─────────────────
    # The detector (pure, outside this gate) supplies FACTS; the verdict is decided only here. A MATERIAL contradiction (unresolved, touches
    # the hypothesis) caps the verdict at LIMITED and removes the conflicting pair from the corroborating set: two statements that disagree
    # cannot corroborate each other. MINOR / EXPLAINED contradictions are disclosed with no verdict effect. Nothing here can raise a verdict.
    contradiction_findings: list[ContradictionFinding] = []
    if contradictions:
        relevant_set = set(relevant_units)
        preliminary = set(corroborating)   # relation is judged on the corroboration as it stood BEFORE the conflict is applied
        material_pairs: set[frozenset[int]] = set()
        seen_pairs: set[tuple[str, str, frozenset[int]]] = set()
        for cand in contradictions:
            ia, ib = cand.evidence_ids
            if ia not in unit_of or ib not in unit_of or (ia in contradictory and ib in contradictory):
                continue  # not in this context, or already reported by the same-sensor detectors above
            ua, ub = unit_of[ia], unit_of[ib]
            if ua == ub:
                continue  # one evidence unit (collapsed duplicates) cannot contradict itself
            pair_key = (cand.kind.value, cand.proposition, frozenset((ua, ub)))
            if pair_key in seen_pairs:
                continue  # duplicates of one side of a conflict are one evidence unit: one finding
            seen_pairs.add(pair_key)
            if anchor_unit is not None and anchor_unit in (ua, ub):
                relation = HypothesisRelation.ANCHOR
            elif ua in preliminary or ub in preliminary:
                relation = HypothesisRelation.CORROBORATING
            elif ua in relevant_set or ub in relevant_set:
                relation = HypothesisRelation.RELEVANT
            else:
                relation = HypothesisRelation.PERIPHERAL
            materiality = classify_materiality(cand, relation)
            material = materiality == Materiality.MATERIAL
            contradiction_findings.append(
                ContradictionFinding(**cand.model_dump(), relation=relation, materiality=materiality, affects_verdict=material)
            )
            findings.append(
                _finding(ReasonCode.CONTRADICTORY_EVIDENCE, FindingEffect.LIMITED if material else FindingEffect.DISCLOSURE, [ia, ib], qualifier=cand.kind.value)
            )
            if material:
                material_pairs.add(frozenset((ua, ub)))
        if material_pairs:
            rec_final = [] if trace is not None else None
            trace_excluded_pairs = set(material_pairs)
            corroborating, repeated_only, weak_only = classify(material_pairs, rec_final)
    if not corroborating:
        findings.append(
            _finding(ReasonCode.UNCORROBORATED_QUESTION, FindingEffect.LIMITED, [rep[c].event_uuid for c in relevant_units])
        )
        if repeated_only:
            findings.append(
                _finding(ReasonCode.REPEATED_OBSERVATION_ONLY, FindingEffect.DISCLOSURE, [rep[c].event_uuid for c in repeated_only])
            )
        if weak_only:
            findings.append(
                _finding(ReasonCode.WEAK_LINK_ONLY, FindingEffect.DISCLOSURE, [rep[c].event_uuid for c in weak_only])
            )

    # ── Missing required evidence for the question's anchor ───────────────────
    target_unit = anchor_unit if anchor_unit is not None else (relevant_units[0] if len(relevant_units) == 1 else None)
    if target_unit is not None:
        present_types = {t for (t, _v) in unit_ents[target_unit]}
        for required in REQUIRED_ENTITY_TYPES_BY_EVENT_TYPE.get(rep[target_unit].event_type, ()):
            if required not in present_types:
                findings.append(
                    _finding(ReasonCode.MISSING_REQUIRED_FIELD, FindingEffect.LIMITED, [rep[target_unit].event_uuid], qualifier=required)
                )

    if trace is not None:
        _populate_trace(
            trace, stage="complete", items_fn=lambda: _evidence_items(events, ents_by_event), clusters=clusters,
            unit_ids=unit_ids, members=members, rep=rep, unit_ents=unit_ents, unit_digest=unit_digest, anomalous_units=anomalous_units,
            relevant_units=relevant_units, anchor_unit=anchor_unit, root_id=root_id, root_present=root_id in unit_of if root_id else False,
            anchor_dropped=anchor_dropped, corroborating=corroborating, repeated_only=repeated_only, weak_only=weak_only,
            excluded_pairs=trace_excluded_pairs, rec=rec_final,
        )
    return _build(
        findings,
        context_sha256=ctx_hash,
        evidence_ids=evidence_ids,
        total=len(events),
        effective=len(unit_ids),
        relevant=len(relevant_units),
        attested=len(attested_units),
        corroborating=len(corroborating),
        contradictions=contradiction_findings,
    )


def _error_assessment(context: Any) -> EvidenceSufficiencyAssessment:
    """Build the fail-closed assessment. Must never raise."""
    ctx_hash: Optional[str] = None
    try:
        candidate = context.reproducibility.context_sha256
        if isinstance(candidate, str) and len(candidate) == 64:
            ctx_hash = candidate
    except Exception:  # noqa: BLE001 - best effort only
        ctx_hash = None
    return _build(
        [_finding(ReasonCode.GATE_EVALUATION_ERROR, FindingEffect.INSUFFICIENT, [])],
        context_sha256=ctx_hash, evidence_ids=[], total=0, effective=0, relevant=0, attested=0, corroborating=0,
    )


def evaluate_sufficiency(
    context: InvestigationContext,
    contradictions: Sequence[ContradictionCandidate] = (),
    trace: Optional[SufficiencyTrace] = None,
) -> EvidenceSufficiencyAssessment:
    """
    Fail-closed entry point used by production code. Any Exception (including a malformed or
    non-context argument) yields INSUFFICIENT / GATE_EVALUATION_ERROR, which forbids model
    invocation. asyncio cancellation (BaseException) is not swallowed.

    ``trace`` (optional, Sprint 1): see ``assess_evidence_sufficiency``. When it is None the call into the core is byte-for-byte the previous
    one (two positional arguments); a trace never changes the returned assessment.
    """
    try:
        if trace is None:
            return assess_evidence_sufficiency(context, contradictions)
        return assess_evidence_sufficiency(context, contradictions, trace=trace)
    except Exception:  # noqa: BLE001 - deliberate fail-closed boundary
        if trace is not None:
            trace.stage = "error"
        return _error_assessment(context)


def apply_sufficiency_disclosure(result: Any, assessment: Optional[EvidenceSufficiencyAssessment]) -> Any:
    """
    Make the sufficiency verdict visible in the FINAL analyst-facing output (not only in the
    prompt): append the coded, fixed-vocabulary disclosure to ``uncertainty_and_data_gaps`` of the
    validated output. Returns ``result`` unchanged for abstentions (already disclosed), when no
    disclosure is needed, or when the flags are already present. Hash-safe: it runs before the
    output digest is computed by callers.
    """
    if assessment is None or assessment.abstain:
        return result
    flags = assessment.disclosure_flags()
    if not flags:
        return result
    out = result.output
    existing = list(out.uncertainty_and_data_gaps)
    additions = [f for f in flags if f not in existing]
    if not additions:
        return result
    new_out = out.model_copy(update={"uncertainty_and_data_gaps": existing + additions})
    return result.model_copy(update={"output": new_out})
