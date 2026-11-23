"""
AISOP Evaluation Benchmark Report Generator.

P3-H3A.2: Evaluation Integrity Remediation.
Translates BenchmarkRunSummary into structured, GitHub-flavored Markdown reports:
- Strictly distinguishes 'HARNESS SELF-TEST' from authentic 'CAPTURED MODEL EVALUATION'.
- Marks missing fixtures as 'UNMEASURED — NO CAPTURED MODEL OUTPUT'.
- Reports dataset micro-averaging and benign false-positive rates.
- Discloses unadjudicated claims pending human semantic review.
"""

from __future__ import annotations

from typing import Any

from app.schemas.evaluation import BenchmarkRunSummary, ScenarioEvaluationResult


class BenchmarkReportGenerator:
    """
    Renders BenchmarkRunSummary models into standardized Markdown reports.
    """

    @staticmethod
    def _format_metric(val: float | None, percentage: bool = False) -> str:
        """Format metric safely, displaying N/A if None."""
        if val is None:
            return "N/A *(unmeasured / 0 denominator)*"
        if percentage:
            return f"{val * 100:.1f}%"  # callers pass a fraction in [0, 1] (benign_false_positive_rate)
        return f"{val:.4f}"

    def generate_markdown_report(self, summary: BenchmarkRunSummary) -> str:
        """
        Generate full Markdown report from BenchmarkRunSummary.
        """
        ts_str = summary.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        is_self_test = summary.benchmark_mode == "harness_self_test"

        lines: list[str] = [
            f"# AISOP AI Investigation Benchmark Report",
            f"",
        ]

        if is_self_test:
            lines.extend([
                f"> [!WARNING]",
                f"> **HARNESS SELF-TEST — NOT MODEL PERFORMANCE**",
                f"> This run executed synthetic test fixtures to validate evaluator logic, path safety, and metric bounds. It does NOT represent measured AI model performance.",
                f"",
            ])
        else:
            lines.extend([
                f"> [!NOTE]",
                f"> **CAPTURED MODEL EVALUATION REPORT**",
                f"> Target Model: `{summary.evaluated_model_identifier}` | Measured Scenarios: {summary.measured_scenarios_count} / {summary.official_approved_scenarios} (Unmeasured: {summary.unmeasured_scenarios_count})",
                f"",
            ])

        scoring_set = [
            r for r in summary.scenario_results
            if r.is_official_score_eligible and (r.is_measured or is_self_test)
        ]
        effective_measured = len(scoring_set)
        valid_json_count = sum(1 for r in scoring_set if r.is_json_valid)
        valid_schema_count = sum(1 for r in scoring_set if r.is_schema_valid)
        fallback_count = sum(1 for r in scoring_set if r.fallback_category.value != "genuine_model_output")

        lines.extend([
            f"| Metric / Metadata Field | Value | Classification |",
            f"|:---|:---|:---:|",
            f"| **Evaluation Run ID** | `{summary.run_id}` | Measured |",
            f"| **Evaluation Timestamp** | {ts_str} | Measured |",
            f"| **Benchmark Execution Mode** | `{summary.benchmark_mode}` | Provenance |",
            f"| **Evaluated Model Identifier** | `{summary.evaluated_model_identifier}` | Provenance |",
            f"| **Dataset Version** | `{summary.dataset_version}` | Provenance |",
            f"| **Total Scenarios Processed** | {summary.total_scenarios_evaluated} | Measured |",
            f"| **Official Approved Scenarios** | {summary.official_approved_scenarios} | Measured |",
            f"| **Draft / Excluded Scenarios** | {summary.draft_excluded_scenarios} | Provenance |",
            f"| **Scenarios with Authentic Output** | {summary.measured_scenarios_count} | Measured |",
            f"| **Missing Fixtures (Unmeasured)** | {summary.unmeasured_scenarios_count} | Measured |",
            f"| **JSON Validity Rate** | {summary.overall_json_validity_rate:.1f}% ({valid_json_count}/{effective_measured} measured scenarios) | Measured |",
            f"| **Schema Validity Rate** | {summary.overall_schema_validity_rate:.1f}% ({valid_schema_count}/{effective_measured} measured scenarios) | Measured |",
            f"| **Evidence Grounding Precision** | {self._format_metric(summary.overall_evidence_grounding_precision)} | Human Adjudication Required |",
            f"| **Claims Pending Human Review** | {summary.claims_requiring_human_adjudication_count} | Measured |",
            f"| **Unsupported Claim Rate** | {self._format_metric(summary.overall_unsupported_claim_rate)} | Measured |",
            f"| **MITRE Macro Precision** | {self._format_metric(summary.overall_mitre_precision)} | Measured |",
            f"| **MITRE Macro Recall** | {self._format_metric(summary.overall_mitre_recall)} | Measured |",
            f"| **MITRE Macro F1 Score** | {self._format_metric(summary.overall_mitre_f1)} ({effective_measured}/{summary.official_approved_scenarios} approved scenarios measured) | Measured |",
            f"| **Dataset Micro MITRE F1** | {self._format_metric(summary.dataset_micro_mitre_f1)} | Measured |",
            f"| **Benign Scenarios Evaluated** | {summary.benign_scenarios_evaluated} | Measured |",
            f"| **Benign False Positive Count** | {summary.benign_false_positive_count} | Measured |",
            f"| **Benign False Positive Rate** | {self._format_metric(summary.benign_false_positive_rate, percentage=True)} ({summary.benign_false_positive_count} FP / {summary.benign_scenarios_evaluated} benign scenarios) | Measured |",
            f"| **Aggregate IOC Extraction F1** | {self._format_metric(summary.overall_ioc_f1)} | Measured |",
            f"| **Fallback Rate** | {summary.fallback_rate:.1f}% ({fallback_count}/{effective_measured} measured scenarios) | Measured |",
            f"| **Execution Latencies** | *Unavailable for offline replay* | Unavailable |",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary & Quality Scorecard",
            f"",
        ])

        if summary.measured_scenarios_count == 0 and not is_self_test:
            lines.extend([
                f"- **Evaluation Status:** **0 scenarios possess authentic captured model responses**. All model-performance metrics are reported as `UNMEASURED`.",
                f"- **Data Integrity Protection:** The benchmark runner refused to auto-manufacture passing answers from expected ground truth.",
            ])
        else:
            lines.extend([
                f"- **Dataset Evaluation Scope:** Evaluated {summary.total_scenarios_evaluated} scenarios ({summary.official_approved_scenarios} approved; {summary.measured_scenarios_count} measured with authentic outputs).",
                f"- **Structural Integrity:** Syntactic JSON validity: **{summary.overall_json_validity_rate:.1f}%**; Pydantic V2 schema conformance: **{summary.overall_schema_validity_rate:.1f}%**.",
                f"- **Grounding Integrity:** Verified grounding precision is **{self._format_metric(summary.overall_evidence_grounding_precision)}** ({summary.claims_requiring_human_adjudication_count} claims require manual human semantic review). Unsupported claim rate is **{self._format_metric(summary.overall_unsupported_claim_rate)}**.",
                f"- **MITRE Attribution Quality:** Macro Technique F1 is **{self._format_metric(summary.overall_mitre_f1)}** (Recall: **{self._format_metric(summary.overall_mitre_recall)}**, Precision: **{self._format_metric(summary.overall_mitre_precision)}**). Dataset Micro F1 across all evaluated techniques is **{self._format_metric(summary.dataset_micro_mitre_f1)}**.",
                f"- **Benign False Alarm Restraint:** Across {summary.benign_scenarios_evaluated} clean benign scenarios, produced **{summary.benign_false_positive_count} false positive technique predictions** (Benign FP Rate: **{self._format_metric(summary.benign_false_positive_rate, percentage=True)}**).",
            ])

        lines.extend([
            f"",
            f"---",
            f"",
            f"## 2. Per-Scenario Evaluation Ledger",
            f"",
            f"| Scenario ID | Category | Status | Measured? | JSON Valid | Schema Valid | Fallback State | Grounding Prec. | Unsupported Rate | MITRE F1 | Output Origin / Hash |",
            f"|:---|:---|:---:|:---:|:---:|:---:|:---|:---:|:---:|:---:|:---|",
        ])

        for sc in summary.scenario_results:
            if not sc.is_measured and sc.output_source_type == "missing_fixture":
                lines.append(
                    f"| `{sc.scenario_id}` | {sc.category.value} | {sc.review_status.value} | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |"
                )
            elif not sc.is_measured and sc.output_source_type == "legacy_unverified_fixture":
                j_valid = "PASS" if sc.is_json_valid else "**FAIL**"
                s_valid = "PASS" if sc.is_schema_valid else "**FAIL**"
                lines.append(
                    f"| `{sc.scenario_id}` | {sc.category.value} | {sc.review_status.value} | **NO** | {j_valid} | {s_valid} | {sc.fallback_category.value} | N/A | N/A | N/A | *LEGACY_UNVERIFIED — NO ENVELOPE PROVENANCE* |"
                )
            elif not sc.is_measured and sc.output_source_type != "harness_self_test_mock":
                j_valid = "PASS" if sc.is_json_valid else "**FAIL**"
                s_valid = "PASS" if sc.is_schema_valid else "**FAIL**"
                lines.append(
                    f"| `{sc.scenario_id}` | {sc.category.value} | {sc.review_status.value} | **NO** | {j_valid} | {s_valid} | {sc.fallback_category.value} | N/A | N/A | N/A | *REJECTED — {sc.output_source_type.upper()}* |"
                )
            else:
                j_valid = "PASS" if sc.is_json_valid else "**FAIL**"
                s_valid = "PASS" if sc.is_schema_valid else "**FAIL**"
                meas = "YES" if sc.is_measured else "SELF-TEST"
                g_prec = f"{sc.grounding_precision:.2f}" if sc.grounding_precision is not None else "N/A"
                u_rate = f"{sc.unsupported_claim_rate:.2f}" if sc.unsupported_claim_rate is not None else "N/A"
                m_f1 = f"{sc.mitre_eval.f1:.2f}" if sc.mitre_eval.f1 is not None else "N/A"
                hash_display = f"`{sc.reproducibility_hash[:12]}...`" if sc.reproducibility_hash else sc.output_source_type

                lines.append(
                    f"| `{sc.scenario_id}` | {sc.category.value} | {sc.review_status.value} | {meas} | {j_valid} | {s_valid} | {sc.fallback_category.value} | {g_prec} | {u_rate} | {m_f1} | {hash_display} |"
                )

        lines.extend([
            f"",
            f"---",
            f"",
            f"## 3. Known Methodological Limitations",
            f"",
        ])
        for lim in summary.known_limitations:
            lines.append(f"- {lim}")

        lines.append("")
        return "\n".join(lines)
