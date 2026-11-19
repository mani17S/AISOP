"""
AISOP suff-v4 rationale trace (Implementation Sprint 1).

An OPTIONAL, behaviour-preserving explanation of the existing evidence-sufficiency evaluation. The gate
(``sufficiency_gate.assess_evidence_sufficiency``) fills a ``SufficiencyTrace`` from the SAME in-memory units, anchor, candidate pairs and
exclusions that produce the verdict; nothing here is recomputed afterwards and nothing here influences a decision. With no trace requested the
gate behaves exactly as before.

Privacy (owner decision: RESTRICTED shared-entity visibility): the trace and the rationale built from it contain evidence identifiers (event
UUIDs), fixed-vocabulary codes and entity TYPE and STRENGTH only. Raw entity values are never stored in the trace and never returned to any role.

The rationale explains the CURRENT record-level rule. It does not establish, and must not be read as establishing, sensor or source
independence, authenticity of a record, or trust in any payload-declared identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

RATIONALE_SCHEMA = "suff-rationale-v1"

# Bounds (per assessment). Truncation is always disclosed in ``rationale["truncated"]``.
MAX_UNITS = 25
MAX_MEMBERS_PER_UNIT = 10
MAX_COLLAPSED = 40
MAX_PAIRS = 25
MAX_EXCLUSIONS = 40
MAX_FINDINGS = 40
MAX_IDS_PER_FINDING = 10
MAX_CONTRADICTIONS = 25

STATUS_MEANING = {
    "sufficient": (
        "Under the current record-level rule at least one different evidence unit corroborates the anchor. A model call is permitted. "
        "This is not proof of independent sensors and not proof of authenticity."
    ),
    "limited": (
        "The deterministic check found a limitation (see findings). A bounded model call is permitted with a limitation note; "
        "the deterministic report is produced in any case."
    ),
    "insufficient": (
        "The model call is blocked. The deterministic report is still produced; nothing here means the report is missing."
    ),
}

LIMITATIONS = (
    "Distinct evidence units are distinct records under the current rule. They are not proof of independent sensors or sources.",
    "'Digest attested' means a stored digest is present and well formed. The record content is not re-hashed, so this is not authenticity.",
    "A shared entity shows a relationship between records. It does not show that either record is authentic. Entity values are withheld; only type and strength are shown.",
    "Source labels, host names and upstream ids declared inside a submitted record are claimed by whoever submitted it and are not verified by AISOP. A declared upstream id can merge records into one unit.",
    "Records without a usable event time never reach this assessment.",
)


@dataclass
class SufficiencyTrace:
    """Mutable collector filled by the gate. Holds ids, codes and entity type/strength only (never entity values)."""

    stage: str = "not_started"  # not_started | no_evidence | no_relevant_evidence | complete | error
    error: Optional[str] = None  # exception TYPE name if trace collection itself failed; never a message
    anchor_event_id: Optional[str] = None
    anchor_status: str = "none"  # used | dropped_temporal_anomaly | absent_from_evidence | none
    pairwise_without_anchor: bool = False
    units: list[dict[str, Any]] = field(default_factory=list)
    collapsed: list[dict[str, Any]] = field(default_factory=list)
    pairs: list[dict[str, Any]] = field(default_factory=list)
    exclusions: list[dict[str, Any]] = field(default_factory=list)


def _cap(items: list[Any], limit: int) -> tuple[list[Any], bool]:
    return items[:limit], len(items) > limit


def build_rationale(trace: SufficiencyTrace, assessment: Any, *, llm_status: str = "not_requested") -> dict[str, Any]:
    """
    Canonical serialiser used for BOTH the run response and the stored audit document (one dict, so they cannot drift).
    ``assessment`` is the ``EvidenceSufficiencyAssessment`` produced in the same pass. Deterministic ordering, bounded size.
    """
    verdict = assessment.verdict.value
    completeness = "complete" if trace.stage == "complete" and trace.error is None else ("unavailable" if trace.stage in ("not_started",) else "partial")

    units, t_units = _cap(trace.units, MAX_UNITS)
    units = [{**u, "members": u["members"][:MAX_MEMBERS_PER_UNIT], "members_truncated": len(u["members"]) > MAX_MEMBERS_PER_UNIT} for u in units]
    collapsed, t_collapsed = _cap(trace.collapsed, MAX_COLLAPSED)
    pairs, t_pairs = _cap(trace.pairs, MAX_PAIRS)
    exclusions, t_excl = _cap(trace.exclusions, MAX_EXCLUSIONS)
    findings_all = [
        {"code": f.code.value, "qualifier": f.qualifier, "effect": f.effect.value, "evidence_ids": list(f.evidence_ids)[:MAX_IDS_PER_FINDING],
         "evidence_ids_truncated": len(f.evidence_ids) > MAX_IDS_PER_FINDING}
        for f in assessment.findings
    ]
    findings, t_find = _cap(findings_all, MAX_FINDINGS)
    contra_all = [
        {"kind": c.kind.value, "proposition": c.proposition, "materiality": c.materiality.value, "affects_verdict": c.affects_verdict,
         "evidence_ids": [str(i) for i in c.evidence_ids]}
        for c in assessment.contradictions
    ]
    contradictions, t_contra = _cap(contra_all, MAX_CONTRADICTIONS)

    return {
        "schema": RATIONALE_SCHEMA,
        "rule_version": assessment.rule_version,
        "completeness": completeness,
        "trace_error": trace.error,
        "independence_notion": "record_level",  # fixed: never "sensor" or "source"
        "digest_check": "format_only",           # fixed: never "verified" or "authentic"
        "entity_values": "withheld",             # RESTRICTED visibility: type and strength only for every role
        "status": {
            "verdict": verdict,
            "meaning": STATUS_MEANING.get(verdict, ""),
            "model_call_permitted": not assessment.abstain,
            "llm_status": llm_status,
            "deterministic_report_available": True,
        },
        "anchor": {"event_id": trace.anchor_event_id, "status": trace.anchor_status, "pairwise_without_anchor": trace.pairwise_without_anchor},
        "units": units,
        "collapsed": collapsed,
        "corroboration": pairs,
        "exclusions": exclusions,
        "findings": findings,
        "contradictions": contradictions,
        "truncated": {
            "units": t_units, "collapsed": t_collapsed, "corroboration": t_pairs, "exclusions": t_excl,
            "findings": t_find, "contradictions": t_contra,
        },
        "limitations": list(LIMITATIONS),
    }


__all__ = ["LIMITATIONS", "RATIONALE_SCHEMA", "STATUS_MEANING", "SufficiencyTrace", "build_rationale"]
