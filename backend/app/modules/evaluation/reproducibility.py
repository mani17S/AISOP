"""
AISOP Evaluation Reproducibility Comparator.

P3-H3A: Ground-Truth AI Evaluation Framework.
Evaluates multi-run consistency for identical investigation scenarios:
- Structural consistency across repeated outputs.
- Canonical context and output hash stability.
- Factual claim and evidence reference consistency.
"""

from __future__ import annotations

from typing import Any, Sequence

from app.schemas.investigation import StructuredInvestigationOutput


class ReproducibilityComparator:
    """
    Compares multiple investigation outputs generated from identical inputs.
    """

    def compare_runs(
        self,
        outputs: Sequence[StructuredInvestigationOutput],
        output_hashes: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """
        Evaluate multi-run consistency across outputs.

        Returns:
            Dictionary containing structural, hash, and claim consistency metrics.
        """
        if len(outputs) < 2:
            return {
                "runs_evaluated": len(outputs),
                "is_reproducible": True if len(outputs) == 1 else False,
                "notes": "Insufficient runs for comparative reproducibility analysis (minimum 2 required)",
            }

        # 1. Output hash consistency
        hash_identical = False
        if output_hashes and len(output_hashes) == len(outputs):
            hash_identical = len(set(output_hashes)) == 1

        # 2. Claim count consistency
        claim_counts = [len(o.claims) for o in outputs]
        claim_count_consistent = len(set(claim_counts)) == 1

        # 3. MITRE hypothesis count consistency
        mitre_counts = [len(o.mitre_attack_hypotheses) for o in outputs]
        mitre_count_consistent = len(set(mitre_counts)) == 1

        # 4. Model identifier consistency
        model_identifiers = [o.model_identifier for o in outputs]
        model_consistent = len(set(model_identifiers)) == 1

        # 5. Evidence UUID set overlap across runs
        evidence_sets = [
            frozenset(str(u) for c in o.claims for u in c.supporting_evidence_ids)
            for o in outputs
        ]
        evidence_overlap = len(set(evidence_sets)) == 1

        # Overall reproducibility flag
        is_reproducible = (
            claim_count_consistent
            and mitre_count_consistent
            and model_consistent
            and evidence_overlap
        )

        return {
            "runs_evaluated": len(outputs),
            "is_reproducible": is_reproducible,
            "hash_identical": hash_identical,
            "claim_count_consistent": claim_count_consistent,
            "mitre_count_consistent": mitre_count_consistent,
            "model_consistent": model_consistent,
            "evidence_overlap_consistent": evidence_overlap,
            "claim_counts": claim_counts,
            "mitre_counts": mitre_counts,
        }

