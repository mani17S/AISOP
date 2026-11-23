"""
Evaluation baselines B0 and B1 (docs/10_Research/Evaluation.md, "Arms"). Pure functions over the existing InvestigationContext.

B0  naive correlation: any two records sharing an entity corroborate each other.
B1  B0 plus exact-duplicate removal: records with the same raw-evidence SHA-256 count once.

Both are deliberately naive comparison arms, not product code, and not imported by any service or API. They look only at which records share
an entity; they ignore source independence, analyst statements, threat-intelligence items, replay and time. Output labels use the same
vocabulary as the gate so the same metrics apply, but a baseline can only say SUFFICIENT or INSUFFICIENT: it has no notion of LIMITED.

The verdict rule is fixed here and must not be tuned on the held-out split: SUFFICIENT when some entity is shared by at least two (counted)
records, otherwise INSUFFICIENT.
"""
from __future__ import annotations

from typing import Any

from app.schemas.investigation import InvestigationContext

ARMS = ("B0", "B1")


def _counted_events(context: InvestigationContext, arm: str) -> dict[Any, str]:
    """event_uuid -> the unit it counts as. B0: every record is its own unit. B1: records with the same raw SHA-256 share one unit."""
    if arm == "B0":
        return {e.event_uuid: str(e.event_uuid) for e in context.events}
    if arm == "B1":
        return {e.event_uuid: e.raw_evidence_sha256 for e in context.events}
    raise ValueError(f"unknown arm {arm!r}; expected one of {ARMS}")


def baseline_verdict(context: InvestigationContext, arm: str) -> str:
    units = _counted_events(context, arm)
    for entity in context.entities:
        counted = {units[u] for u in entity.associated_event_uuids if u in units}
        if len(counted) >= 2:
            return "SUFFICIENT"
    return "INSUFFICIENT"


def baseline_verdicts(contexts: dict[str, InvestigationContext], arm: str) -> dict[str, str]:
    """case_id -> verdict. The caller builds the contexts (for the evaluation: from manifest-verified cases), so this module stays independent of the harness."""
    return {case_id: baseline_verdict(ctx, arm) for case_id, ctx in contexts.items()}


# ── Ablation arms (2026-11-23) ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
# They add AISOP's own rules to the naive baseline ONE AT A TIME, so a comparison can say which rule changes a verdict. Like B0 and B1 they
# are evaluation code only, they say SUFFICIENT or INSUFFICIENT only (no LIMITED), and the rule is fixed before any labelled run.
#
#   B2  B1 (a record counts once per raw digest) but only STRONG or SPECIFIC shared artefacts corroborate (hash, domain, file, public IP,
#       process GUID, ...). A shared host, user, process name or internal address does not.
#   B3  B2 with AISOP's own duplicate clustering instead of the raw digest (identical content, upstream copies, near-duplicates within 2 s).
#   B4  B3 plus: the corroborating records must also be different observations (not the same host, event id, type and action). This
#       approximates the gate's "different observation class" rule; it is not the gate (no provenance, contradictions, truncation or LIMITED).

ABLATION_ARMS = ("B2", "B3", "B4")


def ablation_verdict(context: InvestigationContext, arm: str) -> str:
    # Imported here so that importing the plain baselines never pulls in the gate.
    from app.modules.ai.guardrails.sufficiency_gate import evidence_clusters_for_context
    from app.modules.evidence.independence import LINK_SPECIFIC, LINK_STRONG, canonical_entity_value, entity_link_strength

    if arm not in ABLATION_ARMS:
        raise ValueError(f"unknown arm {arm!r}; expected one of {ABLATION_ARMS}")
    by_uuid = {e.event_uuid: e for e in context.events}
    if arm == "B2":
        unit = {e.event_uuid: e.raw_evidence_sha256 for e in context.events}
    else:
        unit = {u: str(c) for u, c in evidence_clusters_for_context(context).items()}
    for entity in context.entities:
        if entity_link_strength(entity.entity_type, canonical_entity_value(entity.entity_type, entity.entity_value)) not in (LINK_STRONG, LINK_SPECIFIC):
            continue
        events = [by_uuid[u] for u in entity.associated_event_uuids if u in by_uuid and u in unit]
        if len({unit[e.event_uuid] for e in events}) < 2:
            continue
        if arm != "B4":
            return "SUFFICIENT"
        observations = {(e.source_identifier, e.event_id, e.event_type, e.action) for e in events}
        if len(observations) >= 2:
            return "SUFFICIENT"
    return "INSUFFICIENT"
