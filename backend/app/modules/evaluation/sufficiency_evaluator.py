"""
AISOP Evidence-Sufficiency Evaluation Harness (Stage 3C, ADR-008).

Loads the hash-locked derived evaluation cases under
``datasets/sufficiency_eval/{dev,heldout}``, runs the deterministic
sufficiency gate on them, and reports classification metrics against
OWNER-AUTHORED labels (``labels.json`` per split; never generated here), plus a
gate-on versus gate-off ablation with a call-counting scripted provider.

Protection of evaluation data:
* ``verify_manifest`` checks every case/template file against ``MANIFEST.sha256``
  before any use; a mismatch raises ``SufficiencyDatasetIntegrityError``.
* This module only opens dataset files for reading.
* The held-out split is refused unless labels exist AND ``final_heldout=True`` is
  passed explicitly (it must be run once, after thresholds are frozen on dev).

This is evaluation of engineering behaviour on synthetic derived cases with a
scripted provider. It is not evidence of real-world performance and does not
establish research novelty. The gate-off arm below is the ONLY production-tree
code path besides ``GatedGenerator`` that calls ``provider.generate``; it is
allow-listed in the architecture test and is not imported by any service or API.
"""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from app.modules.ai.context_builder.hasher import compute_context_sha256
from app.modules.ai.guardrails.gated_generation import GatedGenerator
from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency
from app.modules.ai.guardrails.validator import InvestigationOutputValidator
from app.schemas.ai import LLMMessage, LLMRequest, LLMResponse, MessageRole
from app.schemas.investigation import (
    BudgetMetrics,
    ClaimCategory,
    ContextEntityItem,
    ContextEventItem,
    FactualClaimItem,
    GroundingStatus,
    InvestigationContext,
    InvestigationScopeType,
    ReproducibilityRecord,
    StructuredInvestigationOutput,
)
from app.schemas.sufficiency import SufficiencyVerdict

CASE_NAMESPACE = uuid.UUID("5f0c1a5e-3c00-4c1d-9a55-0a1f5e7c0b3c")
LABELS = ("SUFFICIENT", "LIMITED", "INSUFFICIENT")
DEFAULT_BASE_DIR = Path(__file__).resolve().parents[4] / "datasets" / "sufficiency_eval"


class SufficiencyDatasetIntegrityError(Exception):
    """Evaluation data failed manifest verification or protection rules."""


# ── Dataset protection ────────────────────────────────────────────────────────
def verify_manifest(base_dir: Path | str | None = None) -> None:
    """Verify every file listed in MANIFEST.sha256 (and the absence of unlisted case files)."""
    base = Path(base_dir) if base_dir else DEFAULT_BASE_DIR
    manifest = base / "MANIFEST.sha256"
    if not manifest.is_file():
        raise SufficiencyDatasetIntegrityError("MANIFEST.sha256 is missing")
    listed: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        listed[rel.strip()] = digest.strip()
    problems: list[str] = []
    for rel, digest in sorted(listed.items()):
        path = base / rel
        if not path.is_file():
            problems.append(f"missing: {rel}")
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            problems.append(f"hash mismatch: {rel}")
    for split in ("dev", "heldout"):
        cases_dir = base / split / "cases"
        if cases_dir.is_dir():
            for f in cases_dir.glob("*.json"):
                rel = f.relative_to(base).as_posix()
                if rel not in listed:
                    problems.append(f"unlisted case file: {rel}")
    if problems:
        raise SufficiencyDatasetIntegrityError("; ".join(problems[:10]))


def load_cases(split: str, base_dir: Path | str | None = None) -> list[dict[str, Any]]:
    if split not in ("dev", "heldout"):
        raise ValueError("split must be 'dev' or 'heldout'")
    base = Path(base_dir) if base_dir else DEFAULT_BASE_DIR
    verify_manifest(base)
    cases = [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted((base / split / "cases").glob("*.json"))
    ]
    return cases


def load_labels(
    split: str,
    base_dir: Path | str | None = None,
    filename: str = "labels.json",
) -> Optional[dict[str, dict[str, Any]]]:
    """Owner-authored labels (or a second reviewer's file); None when absent. Never created here."""
    base = Path(base_dir) if base_dir else DEFAULT_BASE_DIR
    path = base / split / filename
    if not path.is_file():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    labels = raw.get("labels", raw)
    out: dict[str, dict[str, Any]] = {}
    for case_id, entry in labels.items():
        if entry is None or entry.get("label") is None:
            continue
        label = str(entry["label"]).upper()
        if label not in LABELS:
            raise SufficiencyDatasetIntegrityError(f"invalid label for {case_id}")
        out[case_id] = {"label": label, "justification": entry.get("justification", "")}
    return out


# ── Case -> InvestigationContext ──────────────────────────────────────────────
def build_context_from_case(case: dict[str, Any]) -> InvestigationContext:
    """Deterministically build a valid InvestigationContext (real context SHA-256) from a case."""
    base = datetime.fromisoformat(case["base_time_utc"]).astimezone(timezone.utc)
    cid = case["case_id"]

    def ts(offset: float) -> datetime:
        return base + timedelta(seconds=offset)

    events: list[ContextEventItem] = []
    key_to_uuid: dict[str, uuid.UUID] = {}
    for ev in case["events"]:
        ev_uuid = uuid.uuid5(CASE_NAMESPACE, f"{cid}:{ev['key']}")
        key_to_uuid[ev["key"]] = ev_uuid
        events.append(
            ContextEventItem(
                event_uuid=ev_uuid,
                raw_evidence_sha256=ev["raw_evidence_sha256"],
                event_id=str(ev["event_id"]),
                event_type=ev["event_type"],
                timestamp_utc=ts(ev["timestamp_offset_s"]),
                action=ev["action"],
                outcome=ev["outcome"],
                severity=ev.get("severity", "informational"),
                source_identifier=ev["source_identifier"],
                summary=ev["summary"],
                attributes=ev.get("attributes", {}),
            )
        )
    events.sort(key=lambda e: e.timestamp_utc)

    entities: list[ContextEntityItem] = []
    for ent in case.get("entities", []):
        ids = [key_to_uuid[k] for k in ent["event_keys"] if k in key_to_uuid]
        if ids:
            entities.append(
                ContextEntityItem(
                    entity_type=ent["entity_type"],
                    entity_value=ent["entity_value"],
                    roles=[],
                    occurrence_count=len(ids),
                    associated_event_uuids=ids,
                )
            )

    omitted = int(case.get("omitted_events", 0))
    omitted_ids = [uuid.uuid5(CASE_NAMESPACE, f"{cid}:omitted:{i}") for i in range(omitted)]
    budget = BudgetMetrics(
        total_events_in_scope=len(events) + omitted,
        events_included=len(events),
        events_omitted_count=omitted,
        omitted_event_ids_summary=omitted_ids,
        total_entities_in_scope=len(entities),
        entities_included=len(entities),
        context_truncated=omitted > 0,
    )

    root_key = case.get("question", {}).get("root_event_key")
    if root_key is None:
        root_id = None
    elif root_key in key_to_uuid:
        root_id = key_to_uuid[root_key]
    else:  # a root that is deliberately not part of the context
        root_id = uuid.uuid5(CASE_NAMESPACE, f"{cid}:absent-root")

    w_start = ts(case["window"]["start_offset_s"])
    w_end = ts(case["window"]["end_offset_s"])
    assembled = ts(case.get("assembled_offset_s", case["window"]["end_offset_s"] + 3600))
    hosts = sorted(case.get("question", {}).get("target_hosts", []))
    flags = ["CONTEXT_TRUNCATED_TO_BUDGET"] if omitted else []
    scope = InvestigationScopeType.SINGLE_EVENT if len(events) == 1 else InvestigationScopeType.INCIDENT_TIMELINE

    def make(sha: str) -> InvestigationContext:
        return InvestigationContext(
            investigation_id=uuid.uuid5(CASE_NAMESPACE, cid),
            scope_type=scope,
            time_window_start=w_start,
            time_window_end=w_end,
            target_hosts=hosts,
            events=events,
            entities=entities,
            budget_metrics=budget,
            reproducibility=ReproducibilityRecord(
                request_id=uuid.uuid5(CASE_NAMESPACE, f"{cid}:request"),
                time_window_start=w_start,
                time_window_end=w_end,
                root_event_id=root_id,
                selected_event_uuids=[e.event_uuid for e in events],
                context_sha256=sha,
                created_at_utc=assembled,
            ),
            uncertainty_flags=flags,
            assembled_at=assembled,
        )

    return make(compute_context_sha256(make("a" * 64)))


# ── Scripted provider and ablation ────────────────────────────────────────────
class CountingProvider:
    """Scripted provider that records how many times it is invoked."""

    model_name = "scripted-evaluation-provider"

    def __init__(self) -> None:
        self.calls = 0

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls += 1
        return LLMResponse(content="{}", model=self.model_name)


def _scripted_request() -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role=MessageRole.USER, content="evaluation")], model=CountingProvider.model_name)


def _scripted_output(context: InvestigationContext) -> StructuredInvestigationOutput:
    """Fixed scripted 'model output': one grounded observation, one single-event inference and one fabricated reference."""
    first = context.events[0].event_uuid if context.events else uuid.uuid5(CASE_NAMESPACE, "none")
    observed = FactualClaimItem(
        claim_id=uuid.uuid5(CASE_NAMESPACE, f"{context.investigation_id}:observed"),
        claim_text=(context.events[0].summary if context.events else "An event was observed."),
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[first],
        references_exist=bool(context.events),
        grounding_status=GroundingStatus.VALIDATED_REFERENCE if context.events else GroundingStatus.UNSUPPORTED,
        confidence=0.9 if context.events else 0.0,
    )
    inference = FactualClaimItem(
        claim_id=uuid.uuid5(CASE_NAMESPACE, f"{context.investigation_id}:inference"),
        claim_text="The observed activity may indicate a coordinated sequence of actions.",
        category=ClaimCategory.INFERENCE,
        supporting_evidence_ids=[first],
        references_exist=bool(context.events),
        grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED,
        confidence=0.6,
    )
    fabricated = FactualClaimItem(
        claim_id=uuid.uuid5(CASE_NAMESPACE, f"{context.investigation_id}:fabricated"),
        claim_text="A second host was compromised.",
        category=ClaimCategory.INFERENCE,
        supporting_evidence_ids=[uuid.uuid5(CASE_NAMESPACE, f"{context.investigation_id}:nonexistent")],
        references_exist=True,
        grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED,
        confidence=0.6,
    )
    return StructuredInvestigationOutput(
        investigation_id=context.investigation_id,
        model_identifier=CountingProvider.model_name,
        investigation_summary="Scripted evaluation output used to exercise the guardrails.",
        claims=[observed, inference, fabricated],
        recommended_analyst_actions=["Review the cited events."],
        uncertainty_and_data_gaps=[],
        overall_grounding_score=round((1 if context.events else 0) / 3, 4),
    )


async def run_arm(cases: list[dict[str, Any]], gate_on: bool) -> list[dict[str, Any]]:
    """Run every case through the gate-on or gate-off arm with a fresh counting provider."""
    results: list[dict[str, Any]] = []
    validator = InvestigationOutputValidator()
    for case in cases:
        context = build_context_from_case(case)
        provider = CountingProvider()
        assessment = evaluate_sufficiency(context)
        invoked = False
        score: Optional[float] = None
        review_required = 0
        claims_generated = 0
        if gate_on:
            if not assessment.abstain:
                await GatedGenerator.generate(provider, _scripted_request(), assessment, context)
                invoked = True
        else:
            await provider.generate(_scripted_request())  # ABLATION ONLY: bypasses the gate
            invoked = True
        if invoked:
            try:
                scripted = _scripted_output(context)
                claims_generated = len(scripted.claims)
                validated = validator.validate(scripted, context, assessment if gate_on else None)
                score = validated.output.overall_grounding_score
                review_required = sum(
                    1 for c in validated.output.claims if c.grounding_status != GroundingStatus.VALIDATED_REFERENCE
                )
            except Exception:  # noqa: BLE001 - scripted output may be invalid for degenerate contexts
                score = None
        results.append(
            {
                "case_id": case["case_id"],
                "predicted": assessment.verdict.value.upper(),
                "calls": provider.calls,
                "grounding_score": score,
                "claims_needing_review": review_required,
                "claims_generated": claims_generated,
                "assessment": assessment,
                "context": context,
            }
        )
    return results


# ── Metrics ───────────────────────────────────────────────────────────────────
def _rate(num: int, den: int) -> Optional[float]:
    return None if den == 0 else round(num / den, 4)


_ORD = {"INSUFFICIENT": 0, "LIMITED": 1, "SUFFICIENT": 2}


def wilson_interval(k: int, n: int, z: float = 1.96) -> Optional[list[float]]:
    """95% Wilson score interval for a proportion k/n (None when n == 0)."""
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def per_class_metrics(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    """
    Precision = TP / predicted-as-c (None if nothing predicted c); recall = TP / labelled-c (None if
    no case is labelled c); F1 = 2TP / (2TP + FP + FN) for classes with at least one labelled case;
    macro F1 = mean F1 over classes that have labelled cases (undefined classes are listed).
    """
    out: dict[str, Any] = {}
    f1s: list[float] = []
    undefined: list[str] = []
    for c in LABELS:
        tp = sum(1 for l, p in pairs if l == c and p == c)
        fp = sum(1 for l, p in pairs if l != c and p == c)
        fn = sum(1 for l, p in pairs if l == c and p != c)
        support = tp + fn
        f1 = None if support == 0 else round(2 * tp / (2 * tp + fp + fn), 4)
        if f1 is None:
            undefined.append(c)
        else:
            f1s.append(f1)
        out[c] = {
            "support": support, "predicted": tp + fp,
            "precision": _rate(tp, tp + fp), "recall": _rate(tp, tp + fn), "f1": f1,
        }
    return {
        "per_class": out,
        "macro_f1": round(sum(f1s) / len(f1s), 4) if f1s else None,
        "macro_f1_classes_undefined": undefined,
    }


def coverage_risk(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    """
    Two operating points of the gate as a selective predictor.
    abstain_only: coverage = share of cases the gate lets proceed (predicted not INSUFFICIENT);
                  risk = share of those whose owner label is INSUFFICIENT.
    strict:       coverage = share predicted SUFFICIENT; risk = share of those whose label is not SUFFICIENT.
    """
    n = len(pairs)
    proceed = [(l, p) for l, p in pairs if p != "INSUFFICIENT"]
    strict = [(l, p) for l, p in pairs if p == "SUFFICIENT"]
    return {
        "abstain_only": {
            "coverage": _rate(len(proceed), n),
            "risk": _rate(sum(1 for l, _p in proceed if l == "INSUFFICIENT"), len(proceed)),
        },
        "strict": {
            "coverage": _rate(len(strict), n),
            "risk": _rate(sum(1 for l, _p in strict if l != "SUFFICIENT"), len(strict)),
        },
    }


def weighted_kappa(a: list[str], b: list[str]) -> Optional[float]:
    """Linear-weighted Cohen's kappa for two raters over the ordinal labels (None if undefined)."""
    n = len(a)
    if n == 0 or n != len(b):
        return None
    k = len(_ORD)
    obs = [[0.0] * k for _ in range(k)]
    for x, y in zip(a, b):
        obs[_ORD[x]][_ORD[y]] += 1
    row = [sum(r) for r in obs]
    col = [sum(obs[i][j] for i in range(k)) for j in range(k)]
    num = den = 0.0
    for i in range(k):
        for j in range(k):
            w = abs(i - j) / (k - 1)
            num += w * obs[i][j]
            den += w * row[i] * col[j] / n
    if den == 0:
        return None
    return round(1 - num / den, 4)


def compute_agreement(
    labels_a: dict[str, dict[str, Any]],
    labels_b: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Inter-reviewer agreement over the cases both reviewers labelled."""
    common = sorted(set(labels_a) & set(labels_b))
    a = [labels_a[c]["label"] for c in common]
    b = [labels_b[c]["label"] for c in common]
    agree = sum(1 for x, y in zip(a, b) if x == y)
    return {
        "n_common": len(common),
        "raw_agreement": _rate(agree, len(common)),
        "weighted_kappa": weighted_kappa(a, b),
        "disagreements": [c for c, x, y in zip(common, a, b) if x != y],
    }


def compute_metrics(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    """pairs = [(label, predicted)] with values in LABELS."""
    confusion = {lab: {pred: 0 for pred in LABELS} for lab in LABELS}
    for label, pred in pairs:
        confusion[label][pred] += 1
    n = len(pairs)
    correct = sum(confusion[x][x] for x in LABELS)
    not_sufficient = [(l, p) for l, p in pairs if l in ("LIMITED", "INSUFFICIENT")]
    insufficient = [(l, p) for l, p in pairs if l == "INSUFFICIENT"]
    supported = [(l, p) for l, p in pairs if l in ("SUFFICIENT", "LIMITED")]
    return {
        "n": n,
        "confusion_matrix": confusion,
        "accuracy": _rate(correct, n),
        "false_sufficient_rate": _rate(sum(1 for _l, p in not_sufficient if p == "SUFFICIENT"), len(not_sufficient)),
        "false_sufficient_on_insufficient_rate": _rate(sum(1 for _l, p in insufficient if p == "SUFFICIENT"), len(insufficient)),
        "false_insufficient_rate": _rate(sum(1 for _l, p in supported if p == "INSUFFICIENT"), len(supported)),
        "predicted_abstention_rate": _rate(sum(1 for _l, p in pairs if p == "INSUFFICIENT"), n),
        "label_insufficient_rate": _rate(sum(1 for l, _p in pairs if l == "INSUFFICIENT"), n),
        **per_class_metrics(pairs),
        "coverage_risk": coverage_risk(pairs),
        "confidence_intervals_95": {
            "false_sufficient_rate": wilson_interval(sum(1 for _l, p in not_sufficient if p == "SUFFICIENT"), len(not_sufficient)),
            "false_insufficient_rate": wilson_interval(sum(1 for _l, p in supported if p == "INSUFFICIENT"), len(supported)),
        },
    }


def _reference_validity(results: list[dict[str, Any]]) -> float:
    ok = 0
    for r in results:
        ctx: InvestigationContext = r["context"]
        known = {str(e.event_uuid) for e in ctx.events} | {str(i) for i in ctx.budget_metrics.omitted_event_ids_summary}
        a = r["assessment"]
        ids = set(a.evidence_ids)
        for f in a.findings:
            ids.update(f.evidence_ids)
        if ids <= known:
            ok += 1
    return round(ok / len(results), 4) if results else 1.0


async def evaluate_split(
    split: str,
    base_dir: Path | str | None = None,
    final_heldout: bool = False,
) -> dict[str, Any]:
    """Evaluate one split. Held-out requires owner labels and an explicit final_heldout flag."""
    cases = load_cases(split, base_dir)
    labels = load_labels(split, base_dir)
    if split == "heldout" and not final_heldout:
        raise SufficiencyDatasetIntegrityError("held-out evaluation requires final_heldout=True after dev thresholds are frozen")
    if split == "heldout" and labels is None:
        raise SufficiencyDatasetIntegrityError("held-out evaluation requires owner-authored labels.json")

    gate_on = await run_arm(cases, gate_on=True)
    gate_off = await run_arm(cases, gate_on=False)
    deterministic = all(
        evaluate_sufficiency(build_context_from_case(c)).assessment_sha256 == r["assessment"].assessment_sha256
        for c, r in zip(cases, gate_on)
    )
    predicted = {r["case_id"]: r["predicted"] for r in gate_on}
    predicted_insufficient = [r for r in gate_on if r["predicted"] == "INSUFFICIENT"]

    report: dict[str, Any] = {
        "split": split,
        "cases": len(cases),
        "labels_available": labels is not None,
        "predicted_distribution": {lab: sum(1 for p in predicted.values() if p == lab) for lab in LABELS},
        "deterministic_on_rerun": deterministic,
        "evidence_reference_validity": _reference_validity(gate_on),
        "model_invocation_prevention_rate_predicted_insufficient": _rate(
            sum(1 for r in predicted_insufficient if r["calls"] == 0), len(predicted_insufficient)
        ),
        "ablation": {
            "gate_on_model_calls": sum(r["calls"] for r in gate_on),
            "gate_off_model_calls": sum(r["calls"] for r in gate_off),
            "gate_on_mean_grounding": _mean([r["grounding_score"] for r in gate_on]),
            "gate_off_mean_grounding": _mean([r["grounding_score"] for r in gate_off]),
            "gate_on_claims_needing_review": sum(r["claims_needing_review"] for r in gate_on),
            "gate_off_claims_needing_review": sum(r["claims_needing_review"] for r in gate_off),
            "gate_on_claims_generated_on_predicted_insufficient": sum(
                r["claims_generated"] for r in gate_on if r["predicted"] == "INSUFFICIENT"
            ),
            "gate_off_claims_generated_on_predicted_insufficient": sum(
                r["claims_generated"] for r in gate_off if r["predicted"] == "INSUFFICIENT"
            ),
        },
        "limitations": "Synthetic derived cases and a scripted provider; engineering behaviour only, not model quality or real-world performance.",
    }
    if labels is not None:
        labelled = [(labels[c["case_id"]]["label"], predicted[c["case_id"]]) for c in cases if c["case_id"] in labels]
        report["labelled_cases"] = len(labelled)
        report["metrics"] = compute_metrics(labelled)
        insuff_ids = {cid for cid, v in labels.items() if v["label"] == "INSUFFICIENT"}
        label_insuff_results = [r for r in gate_on if r["case_id"] in insuff_ids]
        report["model_invocation_prevention_rate_label_insufficient"] = _rate(
            sum(1 for r in label_insuff_results if r["calls"] == 0), len(label_insuff_results)
        )
        report["ablation"]["gate_off_calls_on_label_insufficient"] = sum(
            r["calls"] for r in gate_off if r["case_id"] in insuff_ids
        )
    else:
        report["metrics"] = "UNAVAILABLE: owner-authored labels.json not present for this split"
    reviewer2 = load_labels(split, base_dir, "labels.reviewer2.json")
    if labels is not None and reviewer2 is not None:
        report["inter_reviewer_agreement"] = compute_agreement(labels, reviewer2)
    else:
        report["inter_reviewer_agreement"] = "UNAVAILABLE: owner labels and/or labels.reviewer2.json not present"
    return report


def _mean(values: list[Optional[float]]) -> Optional[float]:
    nums = [v for v in values if v is not None]
    return round(sum(nums) / len(nums), 4) if nums else None
