"""
AISOP MITRE ATT&CK Mapping Evaluator.

P3-H3A: Ground-Truth AI Evaluation Framework.
Evaluates model-generated MITRE hypotheses against scenario ground truth:
- Exact technique ID matching (e.g. T1059.001).
- Parent-technique tolerance (e.g. T1059 vs T1059.001).
- Distinguishes mandatory vs uncertain technique expectations.
- Calculates Precision, Recall, and F1 with division-by-zero safety.
"""

from __future__ import annotations

import re
from typing import Sequence

from app.modules.evaluation.metrics import compute_precision_recall_f1
from app.schemas.evaluation import EvaluationScenario, MitreEvaluationResult
from app.schemas.investigation import MitreAttackHypothesis, StructuredInvestigationOutput


class MitreEvaluator:
    """
    Evaluator for MITRE ATT&CK technique prediction quality.
    """

    @staticmethod
    def _normalize_tech_id(tech_id: str) -> str:
        """
        Extract and canonicalize valid MITRE ATT&CK technique ID.
        Supports clean IDs ('T1059.001'), un-normalized casing ('t1059.001'),
        and descriptive strings ('T1059: PowerShell', 'T1059.001 - PowerShell').
        Returns canonical uppercase ID (e.g. 'T1059.001') or stripped input if unparseable.
        """
        raw = str(tech_id).strip().upper()
        match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", raw)
        if match:
            return match.group(1)
        return raw

    @staticmethod
    def _get_parent_id(tech_id: str) -> str:
        """Extract parent technique ID (e.g. T1059.001 -> T1059)."""
        return tech_id.split(".")[0]

    def evaluate_mitre_hypotheses(
        self,
        scenario: EvaluationScenario,
        investigation_output: StructuredInvestigationOutput,
    ) -> MitreEvaluationResult:
        """
        Compare predicted MITRE hypotheses against scenario expected techniques.
        """
        predicted_hypotheses = investigation_output.mitre_attack_hypotheses or []
        predicted_ids = {
            self._normalize_tech_id(h.technique_id)
            for h in predicted_hypotheses
            if getattr(h, "technique_id", None)
        }

        expected_mappings = scenario.expected_mitre_techniques or []
        expected_mandatory_ids = {
            self._normalize_tech_id(e.technique_id)
            for e in expected_mappings
            if e.is_mandatory and not e.is_uncertain
        }
        expected_all_ids = {
            self._normalize_tech_id(e.technique_id)
            for e in expected_mappings
        }
        uncertain_expected_ids = {
            self._normalize_tech_id(e.technique_id)
            for e in expected_mappings
            if e.is_uncertain
        }

        true_positives: list[str] = []
        false_positives: list[str] = []
        false_negatives: list[str] = []
        uncertain_matches: list[str] = []
        exact_matches: list[str] = []
        parent_matches: list[str] = []
        subtechnique_matches: list[str] = []
        tolerated_matches: list[str] = []
        matching_notes: list[str] = []

        # 1. Handle uncertain expected mappings (exempt from FP penalty)
        for pred in sorted(predicted_ids):
            if pred in uncertain_expected_ids:
                uncertain_matches.append(pred)
                matching_notes.append(
                    f"Predicted technique '{pred}' matches an uncertain scenario expectation; excluded from penalties."
                )

        candidates = {p for p in predicted_ids if p not in uncertain_expected_ids}
        unmatched_expected = set(expected_mandatory_ids)
        consumed_predictions: set[str] = set()

        # 2. Exact Matching (highest precedence)
        for exp in sorted(unmatched_expected):
            if exp in candidates:
                exact_matches.append(exp)
                true_positives.append(exp)
                matching_notes.append(f"Exact match: expected '{exp}' matched predicted '{exp}'.")
                consumed_predictions.add(exp)

        unmatched_expected -= set(exact_matches)

        # 3. Tolerated Matching: Parent/Sub-technique ONLY (Strict: Sibling sub-techniques are REJECTED)
        for exp in sorted(list(unmatched_expected)):
            unconsumed = candidates - consumed_predictions

            # Case A: Expected is specific sub-technique (e.g. T1059.001); model predicted general parent (T1059)
            if "." in exp:
                exp_parent = exp.split(".")[0]
                if exp_parent in unconsumed:
                    parent_matches.append(f"{exp_parent} (for expected {exp})")
                    tolerated_matches.append(exp_parent)
                    true_positives.append(exp_parent)
                    matching_notes.append(
                        f"Parent-level match: predicted '{exp_parent}' satisfies expected sub-technique '{exp}'."
                    )
                    consumed_predictions.add(exp_parent)
                    unmatched_expected.remove(exp)
                    continue

            # Case B: Expected is general parent (e.g. T1059); model predicted specific sub-technique (e.g. T1059.001)
            else:
                matching_subs = [p for p in unconsumed if p.startswith(f"{exp}.")]
                if matching_subs:
                    chosen_sub = sorted(matching_subs)[0]
                    subtechnique_matches.append(f"{chosen_sub} (for expected {exp})")
                    tolerated_matches.append(chosen_sub)
                    true_positives.append(chosen_sub)
                    matching_notes.append(
                        f"Sub-technique match: predicted '{chosen_sub}' satisfies expected parent technique '{exp}'."
                    )
                    consumed_predictions.add(chosen_sub)
                    unmatched_expected.remove(exp)
                    continue

        # 4. Leftover Predictions -> False Positives (includes sibling sub-technique mismatches!)
        for pred in sorted(candidates - consumed_predictions):
            false_positives.append(pred)
            pred_parent = pred.split(".")[0]
            sibling_exps = [e for e in expected_mandatory_ids if e.split(".")[0] == pred_parent and e != pred]
            if sibling_exps:
                matching_notes.append(
                    f"False positive '{pred}': sibling sub-technique of expected '{sibling_exps[0]}'; distinct execution mechanism, not credited."
                )
            else:
                matching_notes.append(f"False positive '{pred}': unevidenced or incorrect technique prediction.")

        # 5. Leftover Expected -> False Negatives
        for exp in sorted(unmatched_expected):
            false_negatives.append(exp)
            matching_notes.append(f"False negative '{exp}': expected mandatory technique was omitted in prediction.")

        # 6. Compute Precision, Recall, F1 over definitive mappings
        tp_count = len(true_positives)
        fp_count = len(false_positives)
        fn_count = len(false_negatives)

        precision, recall, f1 = compute_precision_recall_f1(
            tp=tp_count, fp=fp_count, fn=fn_count, zero_target_penalty=True
        )

        return MitreEvaluationResult(
            precision=precision,
            recall=recall,
            f1=f1,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            uncertain_mappings=uncertain_matches,
            exact_matches=exact_matches,
            parent_matches=parent_matches,
            subtechnique_matches=subtechnique_matches,
            tolerated_matches=tolerated_matches,
            matching_notes=matching_notes,
        )

