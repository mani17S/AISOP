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
