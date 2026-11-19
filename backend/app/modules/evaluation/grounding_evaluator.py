"""
AISOP Evidence Grounding & Epistemic Claim Evaluator.

P3-H3A.2: Evaluation Integrity Remediation.
Evaluates factual claims against scenario ground truth and context evidence:
- Explicitly separates syntactic UUID validation, context presence, diagnostic lexical overlap,
  contradictions, unverified assertions, and verified semantic support.
- Does NOT claim automated semantic entailment from lexical keyword matching.
- Flags unadjudicated claims as requiring human review.
- Distinguishes contradicted claims from unverifiable claims.
- Evaluates fact coverage against expected ground-truth claims.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence
import uuid

from app.modules.evaluation.metrics import safe_division
from app.schemas.evaluation import (
    ClaimEvaluationItem,
    EvaluationScenario,
    FactCoverageItem,
    FactCoverageStatus,
    GroundingEvaluationCategory,
    HumanClaimAdjudication,
)
from app.schemas.investigation import FactualClaimItem, StructuredInvestigationOutput


class GroundingEvaluator:
    """
    Evaluates factual grounding and epistemic integrity of investigation outputs.
    """

    def evaluate_claims(
        self,
        scenario: EvaluationScenario,
        investigation_output: StructuredInvestigationOutput,
        context_event_uuids: set[str] | None = None,
        adjudication_registry: (
            Mapping[str | uuid.UUID, HumanClaimAdjudication]
            | Sequence[HumanClaimAdjudication]
            | None
        ) = None,
    ) -> tuple[list[ClaimEvaluationItem], float | None, float | None, dict[str, Any]]:
        """
        Evaluate all asserted claims in the investigation output.

        BLK-H3A-01: Model outputs CANNOT self-certify human verification.
        Human approval must originate strictly from an independently supplied
        adjudication_registry (trusted application input).

        Returns:
            (claim_evaluations, verified_grounding_precision, unsupported_claim_rate, detailed_metrics)
        """
        asserted_claims = investigation_output.claims
        if not asserted_claims:
            empty_metrics = {
                "reference_validity_rate": None,
                "lexical_diagnostic_overlap_rate": None,
                "contradicted_claim_rate": None,
                "unverifiable_claim_rate": None,
                "claims_requiring_human_adjudication": 0,
            }
            return ([], None, None, empty_metrics)

        # Process and validate independent human adjudication registry (trusted input)
        adjudication_map: dict[str, HumanClaimAdjudication] = {}
        if adjudication_registry is not None:
            if isinstance(adjudication_registry, (dict, Mapping)):
                items = list(adjudication_registry.values())
            else:
                items = list(adjudication_registry)

            for rec in items:
                if not isinstance(rec, HumanClaimAdjudication):
                    raise ValueError(f"Expected HumanClaimAdjudication record, got {type(rec).__name__}")
                cid_str = str(rec.claim_id)
                if cid_str in adjudication_map:
                    prior = adjudication_map[cid_str]
                    if prior.review_status != rec.review_status:
                        raise ValueError(
                            f"Conflicting human adjudication records for claim '{cid_str}': "
                            f"'{prior.review_status}' vs '{rec.review_status}'"
                        )
                adjudication_map[cid_str] = rec

        evaluations: list[ClaimEvaluationItem] = []
        verified_supported_count = 0
        unsupported_count = 0
        contradicted_count = 0
        unverifiable_count = 0
        valid_ref_count = 0
        lexical_match_count = 0
        requires_human_review_count = 0

        # Build lookup of expected claims and prohibited claims
        expected_claim_texts = [c.statement.lower() for c in scenario.expected_claims]
        prohibited_claims = scenario.prohibited_claims

        for claim in asserted_claims:
            claim_text = getattr(claim, "claim_text", getattr(claim, "statement", "")).strip()
            claim_lower = claim_text.lower()
            cited_ids_str = [str(u) for u in claim.supporting_evidence_ids]

            # 1. Syntactic Reference Existence in Investigation Context
            if context_event_uuids is not None:
                has_valid_refs = bool(cited_ids_str) and all(cid in context_event_uuids for cid in cited_ids_str)
            else:
                has_valid_refs = bool(cited_ids_str)

            if has_valid_refs:
                valid_ref_count += 1

            # 2. Check for Contradicted Claims (Violates prohibited claims or documented facts)
            is_contradicted = False
            contradiction_note = ""
            for pro in prohibited_claims:
                keywords = [k for k in pro.prohibited_assertion.lower().split() if len(k) > 4]
                if keywords and all(k in claim_lower for k in keywords[:3]):
                    is_contradicted = True
                    contradiction_note = f"Contradicted: Violates prohibited assertion [{pro.prohibited_claim_id}]: {pro.reason}"
                    break

            # 3. Check for Independent Trusted Human Adjudication (BLK-H3A-01)
            # NEVER inspect claim.analyst_notes or any model-controlled field for human verification!
            cid_str = str(claim.claim_id)
            human_adj = adjudication_map.get(cid_str)

            if is_contradicted:
                category = GroundingEvaluationCategory.CONTRADICTED
                notes = contradiction_note
                contradicted_count += 1
                unsupported_count += 1

            elif not has_valid_refs:
                # Missing or hallucinated evidence references
                category = GroundingEvaluationCategory.UNSUPPORTED
                notes = "Unsupported: Missing or invalid evidence UUID references in cited context"
                unsupported_count += 1

            elif human_adj is not None:
                # Independent human adjudication record is present
                if human_adj.review_status == GroundingEvaluationCategory.SUPPORTED:
                    category = GroundingEvaluationCategory.SUPPORTED
                    notes = f"Supported: Confirmed by trusted reviewer '{human_adj.reviewer_id}' at {human_adj.reviewed_at_utc.isoformat()}"
                    verified_supported_count += 1
                elif human_adj.review_status == GroundingEvaluationCategory.PARTIALLY_SUPPORTED:
                    category = GroundingEvaluationCategory.PARTIALLY_SUPPORTED
                    notes = f"Partially Supported: Confirmed by trusted reviewer '{human_adj.reviewer_id}'"
                    requires_human_review_count += 1
                elif human_adj.review_status == GroundingEvaluationCategory.CONTRADICTED:
                    category = GroundingEvaluationCategory.CONTRADICTED
                    notes = f"Contradicted: Identified as contradictory by reviewer '{human_adj.reviewer_id}'"
                    contradicted_count += 1
                    unsupported_count += 1
                elif human_adj.review_status == GroundingEvaluationCategory.UNSUPPORTED:
                    category = GroundingEvaluationCategory.UNSUPPORTED
                    notes = f"Unsupported: Deemed unsupported by reviewer '{human_adj.reviewer_id}'"
                    unsupported_count += 1
                else:
                    category = GroundingEvaluationCategory.UNVERIFIABLE
                    notes = f"Unverifiable: Classified as unverifiable by reviewer '{human_adj.reviewer_id}'"
                    unverifiable_count += 1
            else:
                # No human adjudication record: evaluate diagnostic lexical surface overlap
                matched_expected = False
                for exp_statement in expected_claim_texts:
                    exp_words = [w for w in exp_statement.split() if len(w) > 3]
                    matching_words = sum(1 for w in exp_words if w in claim_lower)
                    overlap_ratio = matching_words / max(len(exp_words), 1)

                    if overlap_ratio >= 0.6:
                        matched_expected = True
                        break

                if matched_expected:
                    category = GroundingEvaluationCategory.LEXICAL_HEURISTIC_MATCH
                    notes = (
                        "Diagnostic: Lexical keyword overlap with expected claim >= 60%. "
                        "Automated semantic entailment not claimed; pending human adjudication."
                    )
                    lexical_match_count += 1
                    requires_human_review_count += 1
                elif any(w in claim_lower for exp in expected_claim_texts for w in exp.split() if len(w) > 4):
                    category = GroundingEvaluationCategory.PARTIALLY_SUPPORTED
                    notes = (
                        "Diagnostic: Partial lexical alignment with expected scenario claims. "
                        "Pending human adjudication."
                    )
                    requires_human_review_count += 1
                else:
                    category = GroundingEvaluationCategory.UNVERIFIABLE
                    notes = (
                        "Unverifiable: Valid evidence UUID cited, but substantive claim is unverified "
                        "against expected scenario facts; requires human adjudication."
                    )
                    unverifiable_count += 1
                    requires_human_review_count += 1

            evaluations.append(
                ClaimEvaluationItem(
                    claim_id=str(claim.claim_id),
                    claim_text=claim_text,
                    category=category,
                    cited_evidence_ids=cited_ids_str,
                    is_syntactically_grounded=has_valid_refs,
                    factual_notes=notes,
                )
            )

        total_claims = len(asserted_claims)

        # Verified grounding precision is computed ONLY over human-verified claims.
        # If no claims have been human-adjudicated, precision is None with explicit disclosure.
        verified_grounding_precision = (
            safe_division(float(verified_supported_count), float(total_claims))
            if verified_supported_count > 0
            else None
        )
        unsupported_rate = safe_division(float(unsupported_count), float(total_claims))
        contradicted_rate = safe_division(float(contradicted_count), float(total_claims))
        unverifiable_rate = safe_division(float(unverifiable_count), float(total_claims))
        ref_validity_rate = safe_division(float(valid_ref_count), float(total_claims))
        lexical_rate = safe_division(float(lexical_match_count), float(total_claims))

        detailed_metrics = {
            "reference_validity_rate": ref_validity_rate,
            "lexical_diagnostic_overlap_rate": lexical_rate,
            "contradicted_claim_rate": contradicted_rate,
            "unverifiable_claim_rate": unverifiable_rate,
            "claims_requiring_human_adjudication": requires_human_review_count,
            "human_verified_supported_count": verified_supported_count,
        }

        return (evaluations, verified_grounding_precision, unsupported_rate, detailed_metrics)

    def evaluate_fact_coverage(
        self,
        scenario: EvaluationScenario,
        investigation_output: StructuredInvestigationOutput,
    ) -> list[FactCoverageItem]:
        """
        Evaluate whether the expected ground-truth facts were covered in the output claims.
        """
        asserted_claims = investigation_output.claims
        coverage_results: list[FactCoverageItem] = []

        for expected in scenario.expected_claims:
            exp_words = [w for w in expected.statement.lower().split() if len(w) > 3]
            matched_claim_id: str | None = None
            status = FactCoverageStatus.OMITTED

            for claim in asserted_claims:
                claim_lower = getattr(claim, "claim_text", getattr(claim, "statement", "")).lower()
                matching_words = sum(1 for w in exp_words if w in claim_lower)
                overlap_ratio = matching_words / max(len(exp_words), 1)

                if overlap_ratio >= 0.5:
                    status = FactCoverageStatus.COVERED
                    matched_claim_id = str(claim.claim_id)
                    break

            coverage_results.append(
                FactCoverageItem(
                    fact_id=expected.claim_id,
                    description=expected.statement,
                    status=status,
                    matched_claim_id=matched_claim_id,
                )
            )

        return coverage_results
