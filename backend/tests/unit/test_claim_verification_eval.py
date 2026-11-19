"""
Task 1: independently authored planted-claim evaluation (``datasets/claim_verification_eval/scenarios.json``).

The scenario file (evidence, claims, expected outcomes and the reasoning for each) was written BEFORE the verifier and is stored outside production
code. This harness only builds contexts from the specification, runs the verifier, and compares with the stored expectations; it never derives an
expected label from the verifier or from its helpers. It is an internally authored controlled set, not a real-world benchmark.

Set ``AISOP_CLAIM_EVAL_REPORT`` to a file path (on D:) to also write the per-class results as JSON.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from app.modules.ai.guardrails.claim_verifier import verify_claim
from app.modules.ai.guardrails.sufficiency_gate import evidence_clusters_for_context
from app.modules.ai.guardrails.validator import InvestigationOutputValidator
from app.modules.evaluation.sufficiency_evaluator import CASE_NAMESPACE, build_context_from_case
from app.schemas.investigation import ClaimCategory, FactualClaimItem, GroundingStatus, StructuredInvestigationOutput

ROOT = Path(__file__).resolve().parents[3] / "datasets" / "claim_verification_eval"
SPEC_PATH = ROOT / "scenarios.json"
MANIFEST_PATH = ROOT / "MANIFEST.sha256"
BAD_ID = "00000000-0000-4000-8000-000000000bad"
SPEC = json.loads(SPEC_PATH.read_text(encoding="utf-8"))


def _ctx(name: str):
    inc = SPEC["incidents"][name]
    events = [{
        "key": e["key"], "event_id": e["event_id"], "event_type": e["event_type"], "timestamp_offset_s": e["off"], "action": e["action"],
        "outcome": e["outcome"], "severity": "low", "source_identifier": e["host"], "summary": e.get("summary") or f'{e["event_type"]} {e["key"]}',
        "attributes": e.get("attrs", {}), "raw_evidence_sha256": hashlib.sha256(f'{name}:{e["key"]}'.encode()).hexdigest(),
    } for e in inc["events"]]
    offs = [e["timestamp_offset_s"] for e in events]
    return build_context_from_case({
        "case_id": name, "base_time_utc": "2026-10-23T10:00:00+00:00", "events": events,
        "entities": [{"entity_type": x["type"], "entity_value": x["value"], "event_keys": x["keys"]} for x in inc["entities"]],
        "window": {"start_offset_s": min(offs) - 1, "end_offset_s": max(offs) + 1},
        "question": {"root_event_key": events[0]["key"], "target_hosts": sorted({e["source_identifier"] for e in events})},
        "omitted_events": 0,
    })


CONTEXTS = {name: _ctx(name) for name in SPEC["incidents"]}


def ev_uuid(incident: str, key: str) -> str:
    return str(uuid.uuid5(CASE_NAMESPACE, f"{incident}:{key}"))


def resolve(ref: Any, incident: str) -> Any:
    if not isinstance(ref, str):
        return ref
    if ref == "unknown-uuid":
        return BAD_ID
    if ref.startswith("@"):
        body = ref[1:]
        if body in SPEC["knowledge_chunk_ids"]:
            return SPEC["knowledge_chunk_ids"][body]
        inc, _, key = body.rpartition("/")
        return ev_uuid(inc or incident, key)
    return ref


def build_assertions(case: dict) -> Any:
    hostile = case.get("hostile")
    template = {"kind": "event_field", "evidence_id": ev_uuid(case["incident"], "a0"), "field": "outcome", "operator": "equals", "value": "success"}
    if hostile == "deep_nesting":
        deep: Any = "x"
        for _ in range(60):
            deep = {"n": deep}
        return [{**template, "value": deep}]
    if hostile == "oversized_string":
        return [{**template, "value": "A" * 100_000}]
    if hostile == "many_assertions":
        return [dict(template) for _ in range(500)]
    raw = case["assertions"]
    if raw is None:
        return None
    out = []
    for a in raw:
        if isinstance(a, dict):
            a = dict(a)
            for k in ("evidence_id", "other_evidence_id"):
                if k in a:
                    a[k] = resolve(a[k], case["incident"])
            if "evidence_ids" in a:
                a["evidence_ids"] = [resolve(x, case["incident"]) for x in a["evidence_ids"]]
        out.append(a)
    return out


def build_claim(case: dict) -> FactualClaimItem:
    cites = [uuid.UUID(resolve(f"@{c}" if "/" in c else f"@{c}", case["incident"])) for c in case["cites"]]
    cites += [uuid.UUID(resolve(x, case["incident"])) for x in case.get("also_cite_ids", [])]
    category = ClaimCategory(case["category"])
    return FactualClaimItem(
        claim_text=case["claim_text"], category=category, supporting_evidence_ids=cites, references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE if category == ClaimCategory.OBSERVED_FACT else GroundingStatus.ANALYST_REVIEW_REQUIRED,
        confidence=0.5, assertions=build_assertions(case),
    )


def run_all() -> list[dict[str, Any]]:
    rows = []
    for case in SPEC["cases"]:
        ctx = CONTEXTS[case["incident"]]
        claim = build_claim(case)
        v = verify_claim(claim, ctx, clusters=evidence_clusters_for_context(ctx))
        rows.append({"id": case["id"], "class": case["class"], "expected": case["expected"], "actual": v.outcome.value, "reason": v.reason})
    return rows


def test_dataset_is_versioned_and_hash_locked():
    digest = hashlib.sha256(SPEC_PATH.read_bytes()).hexdigest()
    recorded = MANIFEST_PATH.read_text(encoding="utf-8").split()[0]
    assert digest == recorded, "scenarios.json changed after its manifest was recorded: bump the dataset version and re-record deliberately"
    assert SPEC["dataset_version"] == "1.0.0" and "NOT a real-world benchmark" in SPEC["authoring_note"]


def test_the_required_scenario_classes_are_present_with_negative_and_positive_labels():
    classes = {c["class"][:2] for c in SPEC["cases"]}
    assert {f"{i:02d}" for i in range(1, 21)} <= classes                                 # the 20 required classes
    expected = {c["expected"] for c in SPEC["cases"]}
    assert expected == set(SPEC["outcome_vocabulary"])                                   # every outcome is exercised
    assert len(SPEC["cases"]) >= 40
    assert all(c.get("why") for c in SPEC["cases"])                                      # every expectation carries its reasoning


def test_every_planted_case_gets_its_independently_authored_outcome():
    rows = run_all()
    by_class: dict[str, dict[str, Any]] = defaultdict(lambda: {"total": 0, "passed": 0, "failed": []})
    false_support = []
    for r in rows:
        b = by_class[r["class"]]
        b["total"] += 1
        if r["actual"] == r["expected"]:
            b["passed"] += 1
        else:
            b["failed"].append(r)
        if r["expected"] != "supported" and r["actual"] == "supported":
            false_support.append(r["id"])
    summary = {
        "dataset_id": SPEC["dataset_id"], "dataset_version": SPEC["dataset_version"],
        "dataset_sha256": hashlib.sha256(SPEC_PATH.read_bytes()).hexdigest(),
        "cases": len(rows), "passed": sum(b["passed"] for b in by_class.values()),
        "false_support_cases": false_support, "false_support_count": len(false_support),
        "per_class": {k: {"total": v["total"], "passed": v["passed"], "failed": [f["id"] for f in v["failed"]]} for k, v in sorted(by_class.items())},
        "rows": rows,
    }
    target = os.environ.get("AISOP_CLAIM_EVAL_REPORT")
    if target:
        Path(target).write_text(json.dumps(summary, indent=1, sort_keys=True), encoding="utf-8")
    failures = [r for r in rows if r["actual"] != r["expected"]]
    assert false_support == [], f"FALSE SUPPORT: {false_support}"
    assert failures == [], failures


def test_stated_scope_limits_hold_for_the_narrow_versus_broad_case():
    case = next(c for c in SPEC["cases"] if c["id"] == "C19")
    ctx = CONTEXTS[case["incident"]]
    claim = build_claim(case)
    out = StructuredInvestigationOutput(investigation_id=ctx.investigation_id, model_identifier="scripted",
                                        investigation_summary="Scripted summary for the planted evaluation.", claims=[claim],
                                        recommended_analyst_actions=["Review"], overall_grounding_score=0.0)
    got = InvestigationOutputValidator().validate(out, ctx).output.claims[0]
    assert got.verification.outcome.value == case["expected"]
    assert got.category.value == case["must_stay"]["category"] and got.verification.applies_to == case["must_stay"]["scope"]
    assert got.grounding_status != GroundingStatus.VALIDATED_REFERENCE


def test_hostile_cases_complete_quickly_and_leave_other_incidents_unaffected():
    import time
    t = time.perf_counter()
    first = {r["id"]: r["actual"] for r in run_all()}
    elapsed = time.perf_counter() - t
    second = {r["id"]: r["actual"] for r in run_all()}
    assert first == second                                                                # deterministic and repeatable
    assert elapsed < 5.0                                                                  # bounded work even with 100 KB / 500-assertion / deep inputs
    assert first["C27"] == "supported" and first["C15"] == "not_verifiable"               # INC-B result is independent of INC-A hostile claims
