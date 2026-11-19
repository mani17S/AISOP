"""
AISOP AI Model Evaluation Benchmark CLI Runner.

P3-H3A.2: Evaluation Integrity Remediation.
Executes offline benchmark evaluation across curated ground-truth scenarios:
- Strictly decoupled from ground-truth answer synthesis; never manufactures model outputs.
- Supports two distinct, unambiguous execution modes:
  1. captured (alias 'replay'): Evaluates ONLY authentic captured outputs from datasets/ground_truth/fixtures/.
     Missing outputs are strictly reported as UNMEASURED.
  2. self-test: Evaluates static diagnostic mock payloads to validate evaluator harness mechanisms.
     Clearly labeled as HARNESS SELF-TEST, never as model performance.
- Emits markdown evaluation report to docs/04_Testing/AI_Model_Benchmark_Report.md.
- Guarantees 0 database connections and 0 external network calls.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Ensure backend root is on sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.modules.evaluation.dataset_loader import ScenarioDatasetLoader
from app.modules.evaluation.evaluation_runner import EvaluationReplayRunner
from app.modules.evaluation.report_generator import BenchmarkReportGenerator
from app.schemas.evaluation import CapturedInvestigationFixture, HumanClaimAdjudication


def generate_harness_test_mock(scenario) -> dict:
    """
    Generate an explicitly labeled diagnostic mock payload for harness self-testing only.
    Clearly identifies itself as a harness mock, never as authentic model output.
    """
    first_event = scenario.raw_telemetry_events[0]
    dummy_event_id = "a1b2c3d4-e5f6-7890-1234-56789abcdef0"

    claims = []
    if scenario.expected_claims:
        claims.append(
            {
                "claim_id": "00112233-4455-6677-8899-aabbccddeeff",
                "claim_text": f"Harness diagnostic claim for {scenario.scenario_id}",
                "category": "observed_fact",
                "confidence": 0.90,
                "supporting_evidence_ids": [dummy_event_id],
                "references_exist": True,
                "grounding_status": "validated_reference",
                "analyst_notes": "Diagnostic self-test payload",
            }
        )

    hypotheses = []
    if scenario.expected_mitre_techniques:
        first_tech = scenario.expected_mitre_techniques[0]
        hypotheses.append(
            {
                "technique_id": first_tech.technique_id,
                "technique_name": first_tech.technique_name,
                "tactics": [first_tech.tactic or "Execution"],
                "confidence": 0.90,
                "reasoning": f"Diagnostic self-test reasoning for {first_tech.technique_id}",
                "supporting_event_uuids": [dummy_event_id],
            }
        )

    return {
        "investigation_id": "00112233-4455-6677-8899-aabbccddeeff",
        "generated_at": "2026-10-30T12:00:00Z",
        "model_identifier": "harness_self_test_mock",
        "investigation_summary": f"Harness self-test execution summary for {scenario.scenario_id} telemetry verification.",
        "claims": claims,
        "mitre_attack_hypotheses": hypotheses,
        "alternative_explanations": [],
        "recommended_analyst_actions": ["Review raw event telemetry"],
        "uncertainty_and_data_gaps": scenario.known_uncertainty,
        "overall_grounding_score": 1.0 if claims else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="AISOP AI Investigation Benchmark Runner")
    parser.add_argument(
        "--mode",
        choices=["captured", "replay", "self-test"],
        default="captured",
        help="Execution mode: 'captured' (evaluates authentic model outputs), 'self-test' (harness validation)",
    )
    parser.add_argument(
        "--include-unapproved",
        action="store_true",
        default=False,
        help="Include draft and unapproved scenarios in evaluation run",
    )
    parser.add_argument(
        "--adjudications",
        type=str,
        default=None,
        help="Optional path to trusted human claim adjudications JSON file",
    )
    parser.add_argument(
        "--prompts-dir",
        type=str,
        default=str(PROJECT_ROOT / "datasets" / "ground_truth" / "prompts"),
        help="Optional directory containing canonical prompt text files (<scenario_id>.txt)",
    )
    parser.add_argument(
        "--output-report",
        type=str,
        default=str(PROJECT_ROOT / "docs" / "04_Testing" / "AI_Model_Benchmark_Report.md"),
        help="Destination path for generated Markdown report",
    )
    args = parser.parse_args()

    mode = "captured_evaluation" if args.mode in ("captured", "replay") else "harness_self_test"

    print("=" * 70)
    print(" AISOP AI Investigation Benchmark Engine — Milestone P3-H3A.6")
    print("=" * 70)
    print(f"Benchmark Mode: {mode.upper()} (Offline-First)")
    print(f"Target Directory: {PROJECT_ROOT / 'datasets' / 'ground_truth'}")

    loader = ScenarioDatasetLoader(base_dir=PROJECT_ROOT / "datasets" / "ground_truth")
    scenarios = loader.load_all_scenarios(include_unapproved=True)

    if not scenarios:
        print("[ERROR] No scenarios found in datasets/ground_truth/")
        return 1

    print(f"Loaded {len(scenarios)} total ground-truth scenarios across all categories.")

    adjudication_registry: dict[str, HumanClaimAdjudication] = {}
    if args.adjudications:
        adj_path = Path(args.adjudications)
        if adj_path.exists():
            with open(adj_path, "r", encoding="utf-8") as f:
                adj_data = json.load(f)
            if isinstance(adj_data, list):
                for item in adj_data:
                    record = HumanClaimAdjudication.model_validate(item)
                    adjudication_registry[str(record.claim_id)] = record
                print(f"Loaded {len(adjudication_registry)} trusted claim adjudications.")
            elif isinstance(adj_data, dict):
                for cid, item in adj_data.items():
                    record = HumanClaimAdjudication.model_validate(item)
                    adjudication_registry[str(record.claim_id)] = record
                print(f"Loaded {len(adjudication_registry)} trusted claim adjudications.")

    fixtures_dir = PROJECT_ROOT / "datasets" / "ground_truth" / "fixtures"
    fixtures_by_id: dict[str, Any] = {}
    envelopes_by_id: dict[str, CapturedInvestigationFixture] = {}
    prompts_by_id: dict[str, str] = {}

    prompts_dir = Path(args.prompts_dir)
    if prompts_dir.exists():
        for p_file in prompts_dir.glob("*.txt"):
            try:
                prompts_by_id[p_file.stem] = p_file.read_text(encoding="utf-8")
            except Exception as exc:
                print(f"[WARN] Failed to read prompt artifact {p_file.name}: {exc}")
        if prompts_by_id:
            print(f"Loaded {len(prompts_by_id)} canonical prompt artifacts from {prompts_dir}.")

    if mode == "captured_evaluation":
        for scenario in scenarios:
            # Check for authentic captured fixture
            fixture_captured = fixtures_dir / f"{scenario.scenario_id}-captured.json"
            fixture_replay = fixtures_dir / f"{scenario.scenario_id}-replay.json"

            fixture_path = None
            if fixture_captured.exists():
                fixture_path = fixture_captured
            elif fixture_replay.exists():
                fixture_path = fixture_replay

            if fixture_path is not None:
                with open(fixture_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and "raw_response_sha256" in data and "scenario_id" in data:
                    try:
                        envelope = CapturedInvestigationFixture.model_validate(data)
                        envelopes_by_id[scenario.scenario_id] = envelope
                    except Exception as exc:
                        print(f"[WARN] Failed to parse fixture envelope for {scenario.scenario_id}: {exc}")
                        fixtures_by_id[scenario.scenario_id] = data
                else:
                    # Legacy unverified fixture
                    fixtures_by_id[scenario.scenario_id] = data
            else:
                # Strictly UNMEASURED: NEVER manufacture expected outputs!
                fixtures_by_id[scenario.scenario_id] = None
    else:
        # Harness Self-Test mode: evaluate harness test mocks
        for scenario in scenarios:
            fixtures_by_id[scenario.scenario_id] = generate_harness_test_mock(scenario)

    runner = EvaluationReplayRunner()
    summary = runner.run_benchmark(
        scenarios=scenarios,
        fixtures_by_scenario_id=fixtures_by_id,
        fixture_envelopes_by_scenario_id=envelopes_by_id,
        prompt_artifacts_by_scenario_id=prompts_by_id,
        adjudication_registry=adjudication_registry,
        dataset_version="1.0.0",
        benchmark_mode=mode,
    )

    # Render Markdown report
    generator = BenchmarkReportGenerator()
    report_content = generator.generate_markdown_report(summary)

    out_path = Path(args.output_report)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"\n[SUCCESS] Benchmark completed successfully.")
    print(f"- Execution Mode: {summary.benchmark_mode}")
    print(f"- Evaluated Model: {summary.evaluated_model_identifier}")
    print(f"- Requested Model Tag: {summary.requested_model_tag}")
    print(f"- Provider-Reported Identity: {summary.provider_reported_model_identifier}")
    print(f"- Certified Model Digest: {summary.certified_model_digest}")
    print(f"- Identity Binding Status: {summary.identity_binding_status}")
    print(f"- Identity Evidence Source: {summary.identity_evidence_source}")
    print(f"- Total Scenarios: {summary.total_scenarios_evaluated}")
    print(f"- Official Approved Scenarios: {summary.official_approved_scenarios}")
    print(f"- Measured Scenarios with Authentic Output: {summary.measured_scenarios_count}")
    print(f"- Missing / Unmeasured Scenarios: {summary.unmeasured_scenarios_count}")
    print(f"- JSON Validity Rate: {summary.overall_json_validity_rate}%")
    print(f"- Schema Validity Rate: {summary.overall_schema_validity_rate}%")
    print(f"- MITRE Macro F1: {summary.overall_mitre_f1}")
    print(f"- Dataset Micro MITRE F1: {summary.dataset_micro_mitre_f1}")
    print(f"- Benign FP Count: {summary.benign_false_positive_count}")
    print(f"- Fallback Rate: {summary.fallback_rate}%")
    print(f"- Report Saved To: {out_path}")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
