"""
Unit tests for AISOP AI Model Evaluation Framework.

Milestone: P3-H3A: Ground-Truth AI Evaluation Framework.
Governing Policy: AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001.

Validates all 18 requirements:
1. Valid dataset loading.
2. Invalid dataset rejection.
3. Missing provenance validation.
4. Unapproved scenario exclusion from official score.
5. JSON validity checking (syntactic).
6. Schema validity checking (Pydantic).
7. Evidence-reference validation.
8. Unsupported claim detection.
9. IOC precision, recall, and F1.
10. MITRE technique evaluation and parent/sub-technique tolerance.
11. Fallback categorization.
12. Missing metric handling (safe division, no fabricated zeroes).
13. Reproducibility comparisons.
14. Dataset version handling.
15. Report generation and Markdown formatting.
16. Malformed input handling.
17. Path traversal protection.
18. Deterministic replay runner behavior.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import uuid

import pytest
from pydantic import ValidationError

from app.modules.evaluation.dataset_loader import (
    DatasetLoadingError,
    DuplicateScenarioIdError,
    ScenarioDatasetLoader,
)
from app.modules.evaluation.evaluation_runner import EvaluationReplayRunner
from app.modules.evaluation.grounding_evaluator import GroundingEvaluator
from app.modules.evaluation.metrics import (
    canonicalize_prompt_artifact,
    categorize_fallback,
    compute_precision_recall_f1,
    is_schema_valid_output,
    is_syntactic_json,
    normalize_ioc,
    safe_division,
)
from app.modules.evaluation.mitre_evaluator import MitreEvaluator
from app.modules.evaluation.report_generator import BenchmarkReportGenerator
from app.modules.evaluation.reproducibility import ReproducibilityComparator
from app.schemas.evaluation import (
    BenchmarkRunSummary,
    CapturedInvestigationFixture,
    EvaluationScenario,
    ExpectedClaim,
    ExpectedInterpretation,
    ExpectedMitreMapping,
    ExpectedObservable,
    FallbackReasonCategory,
    GroundTruthProvenance,
    GroundingEvaluationCategory,
    HumanClaimAdjudication,
    ProhibitedClaim,
    ReviewerStatus,
    ScenarioCategory,
)
from app.schemas.investigation import (
    ClaimCategory,
    FactualClaimItem,
    GroundingStatus,
    MitreAttackHypothesis,
    StructuredInvestigationOutput,
)


def _build_test_scenario(
    scenario_id: str = "SCN-ATO-001",
    review_status: ReviewerStatus = ReviewerStatus.APPROVED,
    reviewer: str | None = "Security Auditor",
    is_synthetic: bool = False,
    synthetic_rationale: str | None = None,
    category: ScenarioCategory = ScenarioCategory.ATOMIC_TECHNIQUE,
    expected_interpretation: ExpectedInterpretation = ExpectedInterpretation.MALICIOUS,
    expected_mitre_techniques: list[ExpectedMitreMapping] | None = None,
    expected_observables: list[ExpectedObservable] | None = None,
) -> EvaluationScenario:
    """Helper to construct a valid EvaluationScenario."""
    default_mitre = [
        ExpectedMitreMapping(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            is_mandatory=True,
        )
    ]
    default_observables = [
        ExpectedObservable(observable_type="executable", observable_value="powershell.exe"),
        ExpectedObservable(observable_type="user", observable_value="CORP\\victim_user"),
    ]

    return EvaluationScenario(
        scenario_id=scenario_id,
        dataset_version="1.0.0",
        category=category,
        title="Test PowerShell Scenario",
        description="Execution of powershell.exe with encoded arguments for testing.",
        raw_telemetry_events=[
            {
                "EventID": 1,
                "UtcTime": "2026-09-09 14:15:20.123",
                "ProcessId": 5412,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -Enc SQBFAFgA...",
                "User": "CORP\\victim_user",
                "Computer": "CORP-FIN-WS01",
            }
        ],
        expected_interpretation=expected_interpretation,
        expected_observables=default_observables if expected_observables is None else expected_observables,
        expected_mitre_techniques=default_mitre if expected_mitre_techniques is None else expected_mitre_techniques,
        expected_claims=[
            ExpectedClaim(
                claim_id="EXP-01",
                statement="powershell.exe was launched with encoded arguments by victim_user",
                category="behavioral",
                required_evidence_indices=[0],
            )
        ],
        prohibited_claims=[
            ProhibitedClaim(
                prohibited_claim_id="PRO-01",
                prohibited_assertion="This activity is normal corporate system administration",
                reason="Encoded powershell without admin justification is anomalous",
            )
        ],
        known_uncertainty=["Download URL not visible in process creation event"],
        expected_limitations=["Single event test"],
        provenance=GroundTruthProvenance(
            author="Test Lead",
            dataset_source="unit_test_fixture",
            creation_timestamp_utc=datetime.now(timezone.utc),
            review_status=review_status,
            reviewer=reviewer,
            review_notes="Automated test fixture",
        ),
        is_synthetic=is_synthetic,
        synthetic_generation_rationale=synthetic_rationale,
    )


def _build_test_investigation_output(
    summary: str = "powershell.exe execution detected.",
    claims: list[FactualClaimItem] | None = None,
    hypotheses: list[MitreAttackHypothesis] | None = None,
    model_identifier: str = "llama3.1:8b",
) -> StructuredInvestigationOutput:
    """Helper to construct a valid StructuredInvestigationOutput."""
    claim_list = claims or []
    if claim_list:
        validated = sum(1 for c in claim_list if c.grounding_status == GroundingStatus.VALIDATED_REFERENCE)
        grounding_score = validated / len(claim_list)
    else:
        grounding_score = 0.0

    return StructuredInvestigationOutput(
        investigation_id=uuid.uuid4(),
        generated_at=datetime.now(timezone.utc),
        model_identifier=model_identifier,
        investigation_summary=summary,
        claims=claim_list,
        mitre_attack_hypotheses=hypotheses or [],
        alternative_explanations=[],
        recommended_analyst_actions=["Investigate host"],
        uncertainty_and_data_gaps=[],
        overall_grounding_score=grounding_score,
    )


def _build_test_envelope(
    scenario_id: str = "SCN-ATO-001",
    output: StructuredInvestigationOutput | dict[str, Any] | None = None,
    prompt_text: str = "Test prompt artifact text for scenario",
    model_identifier: str = "llama3.1:8b",
    provider_reported_model_identifier: str | None = None,
) -> CapturedInvestigationFixture:
    """Helper to construct a cryptographically verified CapturedInvestigationFixture envelope."""
    if output is None:
        out_obj = _build_test_investigation_output(model_identifier=model_identifier)
        raw_dict = out_obj.model_dump(mode="json")
    elif isinstance(output, StructuredInvestigationOutput):
        raw_dict = output.model_dump(mode="json")
    else:
        raw_dict = output
    raw_str = json.dumps(raw_dict)
    resp_sha = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()
    prompt_bytes = canonicalize_prompt_artifact(prompt_text)
    prompt_sha = hashlib.sha256(prompt_bytes).hexdigest()

    return CapturedInvestigationFixture(
        scenario_id=scenario_id,
        capture_timestamp_utc=datetime.now(timezone.utc),
        model_identifier=model_identifier,
        provider_reported_model_identifier=provider_reported_model_identifier,
        prompt_sha256=prompt_sha,
        prompt_artifact=prompt_text,
        raw_response_sha256=resp_sha,
        raw_response=raw_str,
        capture_method="captured_verified_envelope",
    )


# ── TEST SUITE ───────────────────────────────────────────────────────────────

class TestDatasetLoadingAndProvenance:
    """Tests 1, 2, 3, 4, 14, 17: Dataset loading, validation, provenance, path safety."""

    def test_01_valid_dataset_loading(self):
        """1. Valid dataset files in repository datasets/ground_truth/ load without error."""
        loader = ScenarioDatasetLoader()
        scenarios = loader.load_all_scenarios(include_unapproved=True)
        assert len(scenarios) >= 20, f"Expected at least 20 scenarios, got {len(scenarios)}"

        # Check category distribution
        categories = {s.category for s in scenarios}
        assert ScenarioCategory.ATOMIC_TECHNIQUE in categories
        assert ScenarioCategory.MULTI_STAGE_CHAIN in categories
        assert ScenarioCategory.BENIGN_BASELINE in categories
        assert ScenarioCategory.ADVERSARIAL_AMBIGUOUS in categories

    def test_02_invalid_dataset_schema_rejection(self):
        """2. Malformed scenario records are rejected with DatasetLoadingError."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_file = Path(tmp_dir) / "SCN-BAD-001.json"
            bad_file.write_text(json.dumps({"invalid_key": 123}), encoding="utf-8")

            loader = ScenarioDatasetLoader(base_dir=tmp_dir)
            with pytest.raises(DatasetLoadingError):
                loader.load_scenario_from_file(bad_file)

    def test_03_missing_provenance_reviewer_on_approved_raises(self):
        """3. Approved scenario without independent reviewer fails schema validation."""
        with pytest.raises(ValidationError, match="Approved scenario must specify an independent reviewer"):
            _build_test_scenario(
                review_status=ReviewerStatus.APPROVED,
                reviewer=None,  # Missing required reviewer
            )

    def test_04_unapproved_scenario_exclusion(self):
        """4. Unapproved draft scenarios are excluded when include_unapproved=False."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1 Approved scenario
            appr = _build_test_scenario(scenario_id="SCN-ATO-001", review_status=ReviewerStatus.APPROVED)
            (Path(tmp_dir) / "appr.json").write_text(appr.model_dump_json(), encoding="utf-8")

            # 1 Draft scenario
            draft = _build_test_scenario(
                scenario_id="SCN-ATO-002",
                review_status=ReviewerStatus.DRAFT,
                reviewer=None,
            )
            (Path(tmp_dir) / "draft.json").write_text(draft.model_dump_json(), encoding="utf-8")

            loader = ScenarioDatasetLoader(base_dir=tmp_dir)
            official_only = loader.load_all_scenarios(include_unapproved=False)
            all_scenarios = loader.load_all_scenarios(include_unapproved=True)

            assert len(official_only) == 1
            assert official_only[0].scenario_id == "SCN-ATO-001"
            assert len(all_scenarios) == 2

    def test_14_dataset_version_handling(self):
        """14. Semver dataset_version is strictly enforced."""
        scenario = _build_test_scenario()
        assert scenario.dataset_version == "1.0.0"

        with pytest.raises(ValidationError, match="Invalid dataset_version"):
            scenario_dict = scenario.model_dump()
            scenario_dict["dataset_version"] = "invalid-v1"
            EvaluationScenario.model_validate(scenario_dict)

    def test_17_path_traversal_protection(self):
        """17. Path traversal attempts outside dataset base directory fail closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_path = Path(tmp_dir) / "safe_dir"
            base_path.mkdir()
            outside_file = Path(tmp_dir) / "secret.json"
            outside_file.write_text("{}", encoding="utf-8")

            loader = ScenarioDatasetLoader(base_dir=base_path)
            # Attempt to traverse up to outside_file
            traversal_path = base_path / ".." / "secret.json"
            with pytest.raises(DatasetLoadingError, match="Security violation"):
                loader.load_scenario_from_file(traversal_path)

    def test_duplicate_scenario_id_detection(self):
        """Duplicate scenario_ids across distinct files raise DuplicateScenarioIdError."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            s1 = _build_test_scenario(scenario_id="SCN-ATO-001")
            (Path(tmp_dir) / "file1.json").write_text(s1.model_dump_json(), encoding="utf-8")
            (Path(tmp_dir) / "file2.json").write_text(s1.model_dump_json(), encoding="utf-8")

            loader = ScenarioDatasetLoader(base_dir=tmp_dir)
            with pytest.raises(DuplicateScenarioIdError, match="Duplicate scenario_id"):
                loader.load_all_scenarios(include_unapproved=True)


class TestMetricsAndValidation:
    """Tests 5, 6, 11, 12, 16: Syntactic JSON, Pydantic Schema, Fallback, Safe Division."""

    def test_05_json_validity_checking(self):
        """5. Measure syntactic JSON validity separately from schema validity."""
        # Valid bare JSON
        ok, data, err = is_syntactic_json('{"key": "value"}')
        assert ok is True and data == {"key": "value"} and err is None

        # Valid markdown fence-wrapped JSON
        ok, data, err = is_syntactic_json('```json\n{"key": "value"}\n```')
        assert ok is True and data == {"key": "value"}

        # Malformed JSON
        ok, data, err = is_syntactic_json('{"key": "value",}')
        assert ok is False and data is None and "JSONDecodeError" in err

    def test_06_schema_validity_checking(self):
        """6. Measure Pydantic schema validity separately from JSON validity."""
        # Valid schema payload
        valid_payload = {
            "investigation_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_identifier": "llama3.1:8b",
            "investigation_summary": "Test summary indicating suspicious execution of processes on endpoint host.",
            "claims": [],
            "mitre_attack_hypotheses": [],
            "alternative_explanations": [],
            "recommended_analyst_actions": ["Review"],
            "uncertainty_and_data_gaps": [],
            "overall_grounding_score": 0.0,
        }
        ok, model, err = is_schema_valid_output(valid_payload)
        assert ok is True and model is not None and err is None

        # Missing required field 'investigation_summary'
        invalid_payload = valid_payload.copy()
        del invalid_payload["investigation_summary"]
        ok, model, err = is_schema_valid_output(invalid_payload)
        assert ok is False and model is None and "ValidationError" in err

    def test_11_fallback_categorization(self):
        """11. Categorize genuine model output vs deterministic fallback vs parser error."""
        # Genuine output
        model = _build_test_investigation_output(model_identifier="llama3.1:8b")
        cat = categorize_fallback(raw_text="{}", parsed_json={}, validated_model=model)
        assert cat == FallbackReasonCategory.GENUINE_MODEL_OUTPUT

        # Deterministic fallback
        fb_model = _build_test_investigation_output(model_identifier="deterministic_fallback")
        cat = categorize_fallback(raw_text="{}", parsed_json={}, validated_model=fb_model)
        assert cat == FallbackReasonCategory.DETERMINISTIC_FALLBACK

        # Parser rejection (malformed JSON)
        cat = categorize_fallback(raw_text="bad json", parsed_json=None, validated_model=None)
        assert cat == FallbackReasonCategory.PARSER_REJECTION

    def test_12_missing_metric_safe_division(self):
        """12. Never fabricate zeroes; safe_division returns None when denominator is zero."""
        assert safe_division(10.0, 0.0) is None
        assert safe_division(0.0, 10.0) == 0.0
        assert safe_division(5.0, 10.0) == 0.5

        prec, rec, f1 = compute_precision_recall_f1(tp=0, fp=0, fn=0)
        assert prec is None and rec is None and f1 is None

    def test_16_malformed_input_handling(self):
        """16. Empty, None, or whitespace inputs handle gracefully without uncaught exceptions."""
        ok, data, err = is_syntactic_json("")
        assert ok is False and "Empty" in err

        ok, model, err = is_schema_valid_output(None)
        assert ok is False and "Expected dictionary" in err

        norm = normalize_ioc("  ", "domain")
        assert norm == ""


class TestGroundingAndMitreEvaluation:
    """Tests 7, 8, 9, 10: Evidence grounding, unsupported claims, IOCs, MITRE."""

    def test_07_evidence_reference_validation(self):
        """7. A claim citing valid evidence UUID present in context is syntactically grounded."""
        scenario = _build_test_scenario()
        ev_id = uuid.uuid4()
        claim_id = uuid.uuid4()
        claim = FactualClaimItem(
            claim_id=claim_id,
            claim_text="powershell.exe was launched with encoded arguments by victim_user",
            category=ClaimCategory.OBSERVED_FACT,
            confidence=0.9,
            supporting_evidence_ids=[ev_id],
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        )
        output = _build_test_investigation_output(claims=[claim])

        adjudication = HumanClaimAdjudication(
            claim_id=claim_id,
            review_status=GroundingEvaluationCategory.SUPPORTED,
            reviewer_id="DEF-SOC-LEAD-01",
            reviewed_at_utc=datetime.now(timezone.utc),
        )

        evaluator = GroundingEvaluator()
        evals, prec, unsupp, detailed = evaluator.evaluate_claims(
            scenario=scenario,
            investigation_output=output,
            context_event_uuids={str(ev_id)},
            adjudication_registry={str(claim_id): adjudication},
        )
        assert len(evals) == 1
        assert evals[0].is_syntactically_grounded is True
        assert evals[0].category == GroundingEvaluationCategory.SUPPORTED
        assert prec == 1.0
        assert unsupp == 0.0
        assert detailed["reference_validity_rate"] == 1.0

        # Without explicit human verification, lexical overlap is diagnostic only; precision is None
        claim_unreviewed = FactualClaimItem(
            claim_id=uuid.uuid4(),
            claim_text="powershell.exe was launched with encoded arguments by victim_user",
            category=ClaimCategory.OBSERVED_FACT,
            confidence=0.9,
            supporting_evidence_ids=[ev_id],
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        )
        output_unreviewed = _build_test_investigation_output(claims=[claim_unreviewed])
        evals2, prec2, unsupp2, detailed2 = evaluator.evaluate_claims(
            scenario=scenario,
            investigation_output=output_unreviewed,
            context_event_uuids={str(ev_id)},
        )
        assert evals2[0].category == GroundingEvaluationCategory.LEXICAL_HEURISTIC_MATCH
        assert prec2 is None  # Semantic support unverified without human adjudication
        assert detailed2["lexical_diagnostic_overlap_rate"] == 1.0
        assert detailed2["claims_requiring_human_adjudication"] == 1

    def test_08_unsupported_and_contradicted_claims(self):
        """8. Missing evidence references or assertions violating prohibited claims are detected."""
        scenario = _build_test_scenario()
        # Claim violating prohibited assertion PRO-01
        contradicted_claim = FactualClaimItem(
            claim_id=uuid.uuid4(),
            claim_text="This activity is normal corporate system administration routine",
            category=ClaimCategory.OBSERVED_FACT,
            confidence=0.9,
            supporting_evidence_ids=[uuid.uuid4()],
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        )
        # Claim with no evidence references
        unsupported_claim = FactualClaimItem(
            claim_id=uuid.uuid4(),
            claim_text="Attacker dumped Active Directory hashes",
            category=ClaimCategory.INFERENCE,
            confidence=0.9,
            supporting_evidence_ids=[],
            references_exist=False,
            grounding_status=GroundingStatus.UNSUPPORTED,
        )
        output = _build_test_investigation_output(claims=[contradicted_claim, unsupported_claim])

        evaluator = GroundingEvaluator()
        evals, prec, unsupp, detailed = evaluator.evaluate_claims(
            scenario=scenario,
            investigation_output=output,
        )
        assert len(evals) == 2
        categories = {e.category for e in evals}
        assert GroundingEvaluationCategory.CONTRADICTED in categories
        assert GroundingEvaluationCategory.UNSUPPORTED in categories
        assert prec is None  # No verified claims
        assert unsupp == 1.0  # Both are unsupported / contradicted
        assert detailed["contradicted_claim_rate"] == 0.5

    def test_09_ioc_precision_recall(self):
        """9. IOC normalization and extraction metrics calculate correctly."""
        assert normalize_ioc("192.168.1.1", "ipv4") == "192.168.1.1"
        assert normalize_ioc("HTTP://C2.EVIL.COM:443/STAGE1", "domain") == "c2.evil.com"
        assert normalize_ioc("A697368B25A0B7EC9AEBEE3FECE92CE9D0E76F4B84BBDA5701FEA28A6635A33D", "sha256") == (
            "a697368b25a0b7ec9aebee3fece92ce9d0e76f4b84bbda5701fea28a6635a33d"
        )
        assert normalize_ioc("C:\\Windows\\System32\\powershell.exe", "executable") == "powershell.exe"

    def test_10_mitre_evaluation_and_subtechnique_tolerance(self):
        """10. MITRE evaluation handles exact match, parent tolerance, and penalizes hallucinations."""
        scenario = _build_test_scenario()  # expects T1059.001
        evaluator = MitreEvaluator()

        # Exact match
        h_exact = MitreAttackHypothesis(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactics=["Execution"],
            confidence=0.9,
            reasoning="Observed",
            supporting_event_uuids=[],
        )
        out_exact = _build_test_investigation_output(hypotheses=[h_exact])
        res = evaluator.evaluate_mitre_hypotheses(scenario, out_exact)
        assert res.precision == 1.0
        assert res.recall == 1.0
        assert res.f1 == 1.0
        assert "T1059.001" in res.true_positives

        # Parent technique tolerance: scenario expects T1059.001, model predicted T1059
        h_parent = MitreAttackHypothesis(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactics=["Execution"],
            confidence=0.9,
            reasoning="Observed",
            supporting_event_uuids=[],
        )
        out_parent = _build_test_investigation_output(hypotheses=[h_parent])
        res_p = evaluator.evaluate_mitre_hypotheses(scenario, out_parent)
        assert res_p.precision == 1.0  # Tolerated parent match
        assert "T1059" in res_p.true_positives

        # Hallucinated technique
        h_hallucinated = MitreAttackHypothesis(
            technique_id="T1486",  # Data Encrypted for Impact (Ransomware)
            technique_name="Data Encrypted for Impact",
            tactics=["Impact"],
            confidence=0.9,
            reasoning="Hallucinated",
            supporting_event_uuids=[],
        )
        out_fp = _build_test_investigation_output(hypotheses=[h_exact, h_hallucinated])
        res_fp = evaluator.evaluate_mitre_hypotheses(scenario, out_fp)
        assert res_fp.precision == 0.5  # 1 TP / (1 TP + 1 FP)
        assert res_fp.recall == 1.0     # 1 TP / (1 TP + 0 FN)
        assert "T1486" in res_fp.false_positives


class TestRunnerReportAndReproducibility:
    """Tests 13, 15, 18: Reproducibility comparison, report generation, replay runner."""

    def test_13_reproducibility_comparisons(self):
        """13. Multi-run comparator detects claim or hash drift."""
        comp = ReproducibilityComparator()
        out1 = _build_test_investigation_output(summary="Run 1 - Execution of suspicious command line")
        out2 = _build_test_investigation_output(summary="Run 2 - Execution of suspicious command line")

        # Identical claim counts and models
        res = comp.compare_runs([out1, out2], output_hashes=["hashA", "hashA"])
        assert res["is_reproducible"] is True
        assert res["hash_identical"] is True

        # Divergent claim counts
        claim = FactualClaimItem(
            claim_id=uuid.uuid4(),
            claim_text="Extra claim detected in execution logs",
            category=ClaimCategory.INFERENCE,
            confidence=0.9,
            supporting_evidence_ids=[],
            references_exist=False,
            grounding_status=GroundingStatus.UNSUPPORTED,
        )
        out3 = _build_test_investigation_output(claims=[claim])
        res_div = comp.compare_runs([out1, out3], output_hashes=["hashA", "hashB"])
        assert res_div["claim_count_consistent"] is False
        assert res_div["hash_identical"] is False

    def test_15_report_generation(self):
        """15. BenchmarkReportGenerator produces compliant Markdown table without fabricated zeroes."""
        runner = EvaluationReplayRunner()
        scenario = _build_test_scenario()
        output = _build_test_investigation_output()

        summary = runner.run_benchmark(
            scenarios=[scenario],
            fixtures_by_scenario_id={scenario.scenario_id: output.model_dump()},
        )
        generator = BenchmarkReportGenerator()
        report = generator.generate_markdown_report(summary)

        assert "# AISOP AI Investigation Benchmark Report" in report
        assert "JSON Validity Rate" in report
        assert "Unavailable for offline replay" in report
        assert scenario.scenario_id in report

    def test_18_deterministic_replay_runner_behavior(self):
        """18. Offline replay runner executes without network or database dependencies."""
        runner = EvaluationReplayRunner()
        scenario = _build_test_scenario()
        output = _build_test_investigation_output()

        res = runner.evaluate_scenario_output(
            scenario=scenario,
            structured_output_dict=output.model_dump(),
            output_source_type="offline_replay_fixture",
        )
        assert res.scenario_id == scenario.scenario_id
        assert res.is_json_valid is True
        assert res.is_schema_valid is True
        assert res.fallback_category == FallbackReasonCategory.GENUINE_MODEL_OUTPUT


class TestEvaluationIntegrityRemediations:
    """
    Milestone P3-H3A.2 Integrity Remediation Tests:
    - Sibling sub-technique strict rejection (T1059.006 vs T1059.001 -> 1 FP + 1 FN).
    - Sub-technique predicted for parent expected (T1059.001 for T1059 -> 1 TP).
    - Benign scenario false positive penalization (expected=[] with predicted T1486 -> Prec=0.0, F1=0.0).
    - Dataset-level micro MITRE metrics accounting for benign false positives.
    - IOC exact matching and substring collision resistance (10.0.0.1 vs 10.0.0.15 -> TP=0, FP=1, FN=1).
    - IOC negation filtering ("was not observed", "did not execute").
    - Fixture independence and UNMEASURED status for missing model fixtures.
    - Harness self-test mode distinction and explicit labelling.
    """

    def test_sibling_subtechnique_rejection(self):
        """Remediation A: Sibling sub-technique must NOT match parent tolerance (1 FP + 1 FN)."""
        scenario = _build_test_scenario()  # expects T1059.001 (PowerShell)
        evaluator = MitreEvaluator()

        # Model predicts T1059.006 (Python), which shares parent T1059 with T1059.001
        h_sibling = MitreAttackHypothesis(
            technique_id="T1059.006",
            technique_name="Python",
            tactics=["Execution"],
            confidence=0.85,
            reasoning="Observed python script invocation",
            supporting_event_uuids=[],
        )
        output = _build_test_investigation_output(hypotheses=[h_sibling])
        res = evaluator.evaluate_mitre_hypotheses(scenario, output)

        assert res.precision == 0.0, f"Expected 0.0, got {res.precision}"
        assert res.recall == 0.0, f"Expected 0.0, got {res.recall}"
        assert res.f1 == 0.0, f"Expected 0.0, got {res.f1}"
        assert "T1059.006" in res.false_positives
        assert "T1059.001" in res.false_negatives
        assert len(res.true_positives) == 0

    def test_subtechnique_predicted_for_parent_expected(self):
        """Remediation A: If ground truth expects parent T1059, predicting subtechnique T1059.001 is tolerated as TP."""
        scenario = _build_test_scenario(
            expected_mitre_techniques=[
                ExpectedMitreMapping(
                    technique_id="T1059",
                    technique_name="Command and Scripting Interpreter",
                    tactic="Execution",
                    is_mandatory=True,
                )
            ]
        )
        evaluator = MitreEvaluator()

        # Model predicts specific sub-technique T1059.001
        h_sub = MitreAttackHypothesis(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactics=["Execution"],
            confidence=0.9,
            reasoning="Observed PowerShell execution",
            supporting_event_uuids=[],
        )
        output = _build_test_investigation_output(hypotheses=[h_sub])
        res = evaluator.evaluate_mitre_hypotheses(scenario, output)

        assert res.precision == 1.0
        assert res.recall == 1.0
        assert res.f1 == 1.0
        assert "T1059.001" in res.true_positives
        assert "T1059.001" in res.tolerated_matches
        assert any("T1059.001" in m for m in res.subtechnique_matches)

    def test_benign_target_false_positive_penalization(self):
        """Remediation B: Zero-target benign scenarios penalize hallucinated techniques with F1=0.0."""
        scenario = _build_test_scenario(
            scenario_id="SCN-BEN-001",
            category=ScenarioCategory.BENIGN_BASELINE,
            expected_mitre_techniques=[],
            expected_interpretation=ExpectedInterpretation.BENIGN,
        )

        evaluator = MitreEvaluator()

        # Model hallucinates a ransomware technique T1486
        h_hallucinated = MitreAttackHypothesis(
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactics=["Impact"],
            confidence=0.9,
            reasoning="False alarm on file encryption",
            supporting_event_uuids=[],
        )
        output = _build_test_investigation_output(hypotheses=[h_hallucinated])
        res = evaluator.evaluate_mitre_hypotheses(scenario, output)

        # Under zero-target penalty convention:
        # tp=0, fp=1, fn=0 -> precision=0.0, recall=None, f1=0.0
        assert res.precision == 0.0
        assert res.recall is None
        assert res.f1 == 0.0
        assert "T1486" in res.false_positives
        assert len(res.false_negatives) == 0

    def test_dataset_micro_mitre_metrics(self):
        """Remediation B: Dataset-level micro metrics aggregate TP, FP, FN and penalize benign FPs."""
        runner = EvaluationReplayRunner()

        # Scenario 1: Malicious, expects T1059.001, model predicts T1059.001 (TP=1, FP=0, FN=0)
        scen_mal = _build_test_scenario(scenario_id="SCN-ATO-001")
        h_mal = MitreAttackHypothesis(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactics=["Execution"],
            confidence=0.9,
            reasoning="Observed PowerShell execution",
            supporting_event_uuids=[],
        )
        out_mal = _build_test_investigation_output(hypotheses=[h_mal])

        # Scenario 2: Benign, expects [], model predicts T1486 (TP=0, FP=1, FN=0)
        scen_ben = _build_test_scenario(
            scenario_id="SCN-BEN-001",
            category=ScenarioCategory.BENIGN_BASELINE,
            expected_mitre_techniques=[],
            expected_interpretation=ExpectedInterpretation.BENIGN,
        )
        h_ben_fp = MitreAttackHypothesis(
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactics=["Impact"],
            confidence=0.9,
            reasoning="False positive on encryption",
            supporting_event_uuids=[],
        )
        out_ben = _build_test_investigation_output(hypotheses=[h_ben_fp])

        summary = runner.run_benchmark(
            scenarios=[scen_mal, scen_ben],
            fixture_envelopes_by_scenario_id={
                "SCN-ATO-001": _build_test_envelope("SCN-ATO-001", out_mal),
                "SCN-BEN-001": _build_test_envelope("SCN-BEN-001", out_ben),
            },
            benchmark_mode="captured_evaluation",
        )

        # Micro counts: TP=1, FP=1, FN=0
        # Micro precision = 1 / (1 + 1) = 0.5
        # Micro recall = 1 / (1 + 0) = 1.0
        # Micro F1 = 2 * (0.5 * 1.0) / (0.5 + 1.0) = 0.6667
        assert summary.benign_scenarios_evaluated == 1
        assert summary.benign_false_positive_count == 1
        assert summary.benign_false_positive_rate == 1.0
        assert summary.dataset_micro_mitre_precision == pytest.approx(0.5)
        assert summary.dataset_micro_mitre_recall == pytest.approx(1.0)
        assert summary.dataset_micro_mitre_f1 == pytest.approx(0.6667, rel=1e-2)

    def test_ioc_false_positive_and_substring_collision(self):
        """Remediation C: Substring collision (10.0.0.1 vs 10.0.0.15) results in TP=0, FP=1, FN=1."""
        scenario = _build_test_scenario(
            expected_observables=[
                ExpectedObservable(observable_type="ipv4", observable_value="10.0.0.1")
            ]
        )

        # Model mentions 10.0.0.15 but never 10.0.0.1
        output = _build_test_investigation_output(
            summary="Attacker connected from staging host 10.0.0.15 to conduct reconnaissance."
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(
            scenario=scenario,
            structured_output_dict=output.model_dump(),
            output_source_type="offline_replay_fixture",
        )

        assert "ipv4" in res.ioc_evaluations
        ipv4_res = res.ioc_evaluations["ipv4"]
        assert ipv4_res.true_positives == []
        assert "10.0.0.15" in ipv4_res.false_positives
        assert "10.0.0.1" in ipv4_res.false_negatives
        assert ipv4_res.precision == 0.0
        assert ipv4_res.recall == 0.0
        assert ipv4_res.f1 == 0.0

    def test_ioc_negation_filter(self):
        """Remediation C: Negated observables are not extracted as predicted positives."""
        output = _build_test_investigation_output(
            summary="Network analysis confirmed that 192.168.100.5 was not observed in any traffic.",
            claims=[
                FactualClaimItem(
                    claim_id=uuid.uuid4(),
                    claim_text="powershell.exe was not executed by the administrative account",
                    category=ClaimCategory.OBSERVED_FACT,
                    confidence=0.9,
                    supporting_evidence_ids=[],
                    references_exist=False,
                    grounding_status=GroundingStatus.UNSUPPORTED,
                )
            ]
        )

        runner = EvaluationReplayRunner()
        extracted = runner._extract_observables_from_model(output)

        assert "192.168.100.5" not in extracted["ipv4"]
        assert "powershell.exe" not in extracted["executable"]

    def test_fixture_independence_and_unmeasured_scenarios(self):
        """Remediation E: Missing fixtures are marked UNMEASURED and excluded from model performance claims."""
        runner = EvaluationReplayRunner()
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")

        # In captured_evaluation mode without fixture:
        summary = runner.run_benchmark(
            scenarios=[scenario],
            fixtures_by_scenario_id={},  # Missing fixture
            benchmark_mode="captured_evaluation",
        )

        assert summary.total_scenarios_evaluated == 1
        assert summary.unmeasured_scenarios_count == 1
        assert summary.measured_scenarios_count == 0
        assert len(summary.scenario_results) == 1

        scen_res = summary.scenario_results[0]
        assert scen_res.is_measured is False
        assert scen_res.output_source_type == "missing_fixture"
        assert scen_res.fallback_category == FallbackReasonCategory.UNMEASURED_MISSING_FIXTURE

        # Unmeasured scenarios do not contribute to measured macro metrics
        assert summary.overall_mitre_f1 is None

    def test_harness_self_test_mode_distinction(self):
        """Remediation E & F: Self-test mode explicitly flags output as synthetic harness test mock."""
        runner = EvaluationReplayRunner()
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")

        summary = runner.run_benchmark(
            scenarios=[scenario],
            benchmark_mode="harness_self_test",
        )

        assert summary.benchmark_mode == "harness_self_test"
        assert summary.evaluated_model_identifier == "HARNESS_SELF_TEST"
        assert summary.measured_scenarios_count == 1
        assert summary.unmeasured_scenarios_count == 0

        scen_res = summary.scenario_results[0]
        assert scen_res.is_measured is True
        assert scen_res.output_source_type == "harness_self_test_mock"
        assert scen_res.fallback_category == FallbackReasonCategory.HARNESS_SELF_TEST

        generator = BenchmarkReportGenerator()
        report = generator.generate_markdown_report(summary)
        assert "HARNESS SELF-TEST — NOT MODEL PERFORMANCE" in report


class TestBlockingRemediationsP3H3A4:
    """
    Verification suite for Milestone P3-H3A.4 blocking evaluation remediations.

    Guarantees:
    1. BLK-H3A-01: Model-controlled self-certification eliminated; claims require independent human adjudication.
    2. BLK-H3A-02: Cryptographically verifiable CapturedInvestigationFixture envelope enforces scenario binding & SHA-256.
    3. BLK-H3A-03: Zero-prediction failure macro F1 penalization (TP=0, FP=0, FN>0 => F1=0.0).
    4. Negation window clause boundary termination (, ; : . \n and but/however/although/whereas/yet).
    5. Dedicated RFC 5952 IPv6 extraction and scoring.
    6. Descriptive ATT&CK technique string normalization.
    7. SCN-ATO-005 ground-truth contract (T1003 mandatory, T1003.001 uncertain).
    8. Report generator explicit sample size / denominator visibility.
    """

    def test_model_self_certification_rejected(self):
        """BLK-H3A-01: Model analyst notes claiming human verification are ignored without trusted registry."""
        event_id = uuid.uuid4()
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        # Ensure scenario has this event in its telemetry
        scenario = scenario.model_copy(
            update={"raw_telemetry_events": [{"event_uuid": str(event_id)}]}
        )

        # Model attempts to self-certify via analyst_notes
        claim = FactualClaimItem(
            claim_id=uuid.uuid4(),
            claim_text="powershell.exe executed with encoded command",
            category=ClaimCategory.OBSERVED_FACT,
            confidence=0.95,
            supporting_evidence_ids=[str(event_id)],
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
            analyst_notes="human_verified: supported; verified by senior analyst",
        )

        output = _build_test_investigation_output(claims=[claim])
        evaluator = GroundingEvaluator()

        # Without trusted adjudication registry
        claim_evals, grounding_prec, unsupported_rate, metrics = evaluator.evaluate_claims(
            scenario=scenario,
            investigation_output=output,
            context_event_uuids={str(event_id)},
            adjudication_registry=None,
        )

        assert len(claim_evals) == 1
        # Status must never be SUPPORTED without trusted adjudication
        assert claim_evals[0].category in (
            GroundingEvaluationCategory.LEXICAL_HEURISTIC_MATCH,
            GroundingEvaluationCategory.PARTIALLY_SUPPORTED,
        )
        assert claim_evals[0].category != GroundingEvaluationCategory.SUPPORTED
        assert "Confirmed by trusted reviewer" not in claim_evals[0].factual_notes
        # Verified precision is None because no claims have trusted independent review
        assert grounding_prec is None
        assert unsupported_rate == 0.0

    def test_trusted_human_claim_adjudication(self):
        """BLK-H3A-01: Independent human adjudication registry credits SUPPORTED status and precision."""
        event_id = uuid.uuid4()
        claim_id = uuid.uuid4()
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        scenario = scenario.model_copy(
            update={"raw_telemetry_events": [{"event_uuid": str(event_id)}]}
        )

        claim = FactualClaimItem(
            claim_id=claim_id,
            claim_text="powershell.exe executed with encoded command",
            category=ClaimCategory.OBSERVED_FACT,
            confidence=0.95,
            supporting_evidence_ids=[str(event_id)],
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        )

        # Trusted adjudication entry
        adjudication = HumanClaimAdjudication(
            adjudication_record_id=uuid.uuid4(),
            claim_id=claim_id,
            review_status=GroundingEvaluationCategory.SUPPORTED,
            reviewer_id="DEF-SOC-LEAD-01",
            reviewed_at_utc=datetime.now(timezone.utc),
            review_notes="Verified against Sysmon Event ID 1 telemetry",
        )

        output = _build_test_investigation_output(claims=[claim])
        evaluator = GroundingEvaluator()

        claim_evals, grounding_prec, unsupported_rate, metrics = evaluator.evaluate_claims(
            scenario=scenario,
            investigation_output=output,
            context_event_uuids={str(event_id)},
            adjudication_registry={str(claim_id): adjudication},
        )

        assert len(claim_evals) == 1
        assert claim_evals[0].category == GroundingEvaluationCategory.SUPPORTED
        assert "DEF-SOC-LEAD-01" in claim_evals[0].factual_notes
        assert grounding_prec == 1.0

    def test_human_claim_adjudication_contract_validation(self):
        """BLK-H3A-01: Adjudication schema enforces non-empty reviewer identity and UTC timestamps."""
        # Empty reviewer ID rejected
        with pytest.raises(ValidationError):
            HumanClaimAdjudication(
                claim_id=uuid.uuid4(),
                review_status=GroundingEvaluationCategory.SUPPORTED,
                reviewer_id="   ",
                reviewed_at_utc=datetime.now(timezone.utc),
            )

        # Naive datetime rejected
        with pytest.raises(ValidationError):
            HumanClaimAdjudication(
                claim_id=uuid.uuid4(),
                review_status=GroundingEvaluationCategory.SUPPORTED,
                reviewer_id="Analyst-1",
                reviewed_at_utc=datetime.now(),  # naive (no timezone)
            )

    def test_conflicting_adjudication_records_rejected(self):
        """BLK-H3A-01: Passing multiple conflicting adjudication records for the same claim raises ValueError."""
        claim_id = uuid.uuid4()
        adj1 = HumanClaimAdjudication(
            claim_id=claim_id,
            review_status=GroundingEvaluationCategory.SUPPORTED,
            reviewer_id="Analyst-1",
            reviewed_at_utc=datetime.now(timezone.utc),
        )
        adj2 = HumanClaimAdjudication(
            claim_id=claim_id,
            review_status=GroundingEvaluationCategory.UNSUPPORTED,
            reviewer_id="Analyst-2",
            reviewed_at_utc=datetime.now(timezone.utc),
        )

        evaluator = GroundingEvaluator()
        scenario = _build_test_scenario()
        claim = FactualClaimItem(
            claim_id=claim_id,
            claim_text="Process execution detected",
            category=ClaimCategory.OBSERVED_FACT,
            confidence=0.9,
            supporting_evidence_ids=[],
            references_exist=False,
            grounding_status=GroundingStatus.UNSUPPORTED,
        )
        output = _build_test_investigation_output(claims=[claim])

        with pytest.raises(ValueError, match="Conflicting human adjudication records"):
            evaluator.evaluate_claims(
                scenario=scenario,
                investigation_output=output,
                adjudication_registry=[adj1, adj2],
            )

    def test_fixture_envelope_scenario_id_mismatch_rejected(self):
        """BLK-H3A-02: Envelope with mismatched scenario_id is rejected and marked UNMEASURED."""
        raw_resp = '{"test": true}'
        sha = hashlib.sha256(raw_resp.encode("utf-8")).hexdigest()
        envelope = CapturedInvestigationFixture(
            scenario_id="SCN-ATO-002",  # Mismatched scenario ID
            capture_timestamp_utc=datetime.now(timezone.utc),
            model_identifier="llama3.1:8b",
            prompt_sha256="a" * 64,
            raw_response_sha256=sha,
            raw_response=raw_resp,
        )

        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is False
        assert res.output_source_type == "fixture_misbound"
        assert any("FIXTURE MISBINDING" in note for note in res.evaluation_notes)

    def test_fixture_envelope_sha256_mismatch_rejected(self):
        """BLK-H3A-02: Envelope with corrupted or mismatched raw_response SHA-256 is rejected."""
        raw_resp = '{"valid": true}'
        corrupt_sha = "f" * 64
        envelope = CapturedInvestigationFixture(
            scenario_id="SCN-ATO-001",
            capture_timestamp_utc=datetime.now(timezone.utc),
            model_identifier="llama3.1:8b",
            prompt_sha256="a" * 64,
            raw_response_sha256=corrupt_sha,
            raw_response=raw_resp,
        )

        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is False
        assert res.output_source_type == "fixture_hash_mismatch"
        assert any("FIXTURE INTEGRITY COMPROMISED" in note for note in res.evaluation_notes)

    def test_fixture_envelope_valid_execution(self):
        """BLK-H3A-02: Valid envelope passes verification, unpacks response, and records trusted model identifier."""
        output_obj = _build_test_investigation_output(
            summary="Valid execution summary.",
            model_identifier="llama3.1:8b-verified",
        )
        raw_resp = json.dumps(output_obj.model_dump(mode="json"))
        sha = hashlib.sha256(raw_resp.encode("utf-8")).hexdigest()
        prompt_txt = "Test prompt text for scenario SCN-ATO-001"
        prompt_sha = hashlib.sha256(canonicalize_prompt_artifact(prompt_txt)).hexdigest()

        envelope = CapturedInvestigationFixture(
            scenario_id="SCN-ATO-001",
            capture_timestamp_utc=datetime.now(timezone.utc),
            model_identifier="llama3.1:8b-verified",
            prompt_sha256=prompt_sha,
            prompt_artifact=prompt_txt,
            raw_response_sha256=sha,
            raw_response=raw_resp,
            capture_method="captured_verified_envelope",
        )

        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        runner = EvaluationReplayRunner()
        summary = runner.run_benchmark(
            scenarios=[scenario],
            fixture_envelopes_by_scenario_id={"SCN-ATO-001": envelope},
        )

        assert summary.measured_scenarios_count == 1
        assert summary.unmeasured_scenarios_count == 0
        assert summary.evaluated_model_identifier == "llama3.1:8b-verified"
        assert summary.overall_json_validity_rate == 100.0
        assert summary.overall_schema_validity_rate == 100.0

    def test_zero_prediction_failure_macro_f1_penalization(self):
        """BLK-H3A-03: Complete failure on mandatory technique (TP=0, FP=0, FN>0) receives F1=0.0 and penalizes macro F1."""
        # 1. Direct metric contract:
        p, r, f1 = compute_precision_recall_f1(tp=0, fp=0, fn=2, zero_target_penalty=True)
        assert p is None
        assert r == 0.0
        assert f1 == 0.0

        # 2. Integration into benchmark macro F1:
        # Scenario 1: Model achieves F1 = 1.0 (TP=1, FP=0, FN=0)
        scen1 = _build_test_scenario(
            scenario_id="SCN-ATO-001",
            expected_mitre_techniques=[
                ExpectedMitreMapping(technique_id="T1059.001", technique_name="PowerShell", tactic="Execution", is_mandatory=True)
            ]
        )
        out1 = _build_test_investigation_output(
            hypotheses=[
                MitreAttackHypothesis(technique_id="T1059.001", technique_name="PowerShell", tactics=["Execution"], confidence=0.9, reasoning="PowerShell used")
            ]
        ).model_dump(mode="json")

        # Scenario 2: Model completely fails to predict expected technique (TP=0, FP=0, FN=1 => F1=0.0)
        scen2 = _build_test_scenario(
            scenario_id="SCN-ATO-002",
            expected_mitre_techniques=[
                ExpectedMitreMapping(technique_id="T1003", technique_name="Credential Dumping", tactic="Credential Access", is_mandatory=True)
            ]
        )
        out2_empty = _build_test_investigation_output(
            hypotheses=[]  # 0 predictions made
        ).model_dump(mode="json")

        runner = EvaluationReplayRunner()
        summary = runner.run_benchmark(
            scenarios=[scen1, scen2],
            fixture_envelopes_by_scenario_id={
                "SCN-ATO-001": _build_test_envelope("SCN-ATO-001", out1),
                "SCN-ATO-002": _build_test_envelope("SCN-ATO-002", out2_empty),
            }
        )

        assert summary.measured_scenarios_count == 2
        res1 = next(r for r in summary.scenario_results if r.scenario_id == "SCN-ATO-001")
        res2 = next(r for r in summary.scenario_results if r.scenario_id == "SCN-ATO-002")

        assert res1.mitre_eval.f1 == 1.0
        assert res2.mitre_eval.f1 == 0.0
        # Macro F1 is (1.0 + 0.0) / 2 = 0.5000, NOT dropped to 1.0
        assert summary.overall_mitre_f1 == 0.5000

    def test_zero_target_empty_expected_distinction(self):
        """BLK-H3A-03: Scenario with 0 expected techniques and 0 predicted techniques receives F1=None, not penalizing model."""
        p, r, f1 = compute_precision_recall_f1(tp=0, fp=0, fn=0, zero_target_penalty=True)
        assert p is None
        assert r is None
        assert f1 is None

    def test_ioc_negation_clause_boundaries(self):
        """Negation window terminates at clause separators (, ; : . \\n) and contrasting conjunctions."""
        # 1. Comma + 'but' clause boundary: 10.0.0.1 must be extracted because negation belongs to second clause
        out_comma = _build_test_investigation_output(
            summary="10.0.0.1 was active on host-a, but host-b was not observed"
        )
        runner = EvaluationReplayRunner()
        extracted1 = runner._extract_observables_from_model(out_comma)
        assert "10.0.0.1" in extracted1["ipv4"]

        # 2. Leading clause with comma: 10.0.0.1 must be extracted
        out_lead = _build_test_investigation_output(
            summary="No evidence was found on host-b, 10.0.0.1 was observed."
        )
        extracted2 = runner._extract_observables_from_model(out_lead)
        assert "10.0.0.1" in extracted2["ipv4"]

        # 3. Direct unseparated negation: 10.0.0.1 must NOT be extracted
        out_neg = _build_test_investigation_output(
            summary="10.0.0.1 was not observed during the incident."
        )
        extracted3 = runner._extract_observables_from_model(out_neg)
        assert "10.0.0.1" not in extracted3["ipv4"]

        # 4. Executable clause boundary: powershell.exe must be extracted
        out_exe = _build_test_investigation_output(
            summary="powershell.exe executed successfully, however cmd.exe was not executed."
        )
        extracted4 = runner._extract_observables_from_model(out_exe)
        assert "powershell.exe" in extracted4["executable"]
        assert "cmd.exe" not in extracted4["executable"]

    def test_ipv6_observable_extraction_and_scoring(self):
        """Dedicated RFC 5952 IPv6 extraction, canonical normalization, and IOC grading."""
        out = _build_test_investigation_output(
            summary="Observed connection to 2001:0db8:85a3:0000:0000:8a2e:0370:7334 while 2001:db8::2 was not observed."
        )
        runner = EvaluationReplayRunner()
        extracted = runner._extract_observables_from_model(out)

        # Canonical RFC 5952 format
        assert "2001:db8:85a3::8a2e:370:7334" in extracted["ipv6"]
        # Negated IPv6 must not be extracted
        assert "2001:db8::2" not in extracted["ipv6"]

        # Evaluate against expected observables
        scenario = _build_test_scenario(
            expected_observables=[
                ExpectedObservable(observable_type="ipv6", observable_value="2001:db8:85a3::8a2e:370:7334", is_mandatory=True)
            ]
        )
        ioc_results = runner._evaluate_iocs(scenario=scenario, validated_model=out)
        assert "ipv6" in ioc_results
        res6 = ioc_results["ipv6"]
        assert res6.true_positives == ["2001:db8:85a3::8a2e:370:7334"]
        assert res6.false_positives == []
        assert res6.false_negatives == []
        assert res6.f1 == 1.0

    def test_mitre_technique_normalization_descriptive_strings(self):
        """Technique ID normalizer cleanly extracts canonical Txxxx(.yyy)? from descriptive strings."""
        evaluator = MitreEvaluator()
        assert evaluator._normalize_tech_id("T1059: PowerShell") == "T1059"
        assert evaluator._normalize_tech_id("T1059.001 - Command and Scripting Interpreter") == "T1059.001"
        assert evaluator._normalize_tech_id("technique T1003 in credential access") == "T1003"
        assert evaluator._normalize_tech_id("  T1078.003  ") == "T1078.003"
        assert evaluator._normalize_tech_id("InvalidTechnique") == "INVALIDTECHNIQUE"

    def test_scn_ato_005_ground_truth_contract(self):
        """SCN-ATO-005 defines T1003 as mandatory and T1003.001 as uncertain based on Event ID 10 access intent."""
        gt_path = Path(__file__).resolve().parents[3] / "datasets" / "ground_truth" / "atomic" / "SCN-ATO-005.json"
        assert gt_path.exists(), f"Ground truth scenario not found at {gt_path}"

        with open(gt_path, "r", encoding="utf-8") as f:
            sc_data = json.load(f)

        scenario = EvaluationScenario.model_validate(sc_data)
        tech_map = {t.technique_id: t for t in scenario.expected_mitre_techniques}

        assert "T1003" in tech_map
        assert tech_map["T1003"].is_mandatory is True
        assert tech_map["T1003"].is_uncertain is False

        assert "T1003.001" in tech_map
        assert tech_map["T1003.001"].is_mandatory is False
        assert tech_map["T1003.001"].is_uncertain is True

        assert any("PROCESS_VM_READ" in u for u in scenario.known_uncertainty)

    def test_report_generator_explicit_sample_size_formatting(self):
        """Benchmark report renders explicit sample sizes and measured/approved denominators."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        env = _build_test_envelope("SCN-ATO-001", _build_test_investigation_output())
        runner = EvaluationReplayRunner()
        summary = runner.run_benchmark(
            scenarios=[scenario],
            fixture_envelopes_by_scenario_id={"SCN-ATO-001": env},
            benchmark_mode="captured_evaluation",
        )

        generator = BenchmarkReportGenerator()
        report = generator.generate_markdown_report(summary)

        # Explicit count verification in markdown rows
        assert "100.0% (1/1 measured scenarios)" in report
        assert "(1/1 approved scenarios measured)" in report


class TestLegacyExclusionAndProvenanceP3H3A6:
    """
    Dedicated test suite for Milestone P3-H3A.6:
    - Exclusion of legacy un-enveloped fixtures from measured performance.
    - Deterministic prompt artifact canonicalization and cryptographic SHA-256 verification.
    - Model identifier consistency enforcement between fixture envelope and parsed response.
    - Explicit representation of unavailable model digest.
    - Preservation of SCN-ATO-001-replay.json byte-for-byte.
    """

    def test_legacy_fixture_bare_json_excluded_from_measurement(self):
        """Bare un-enveloped JSON fixture is classified as LEGACY_UNVERIFIED and excluded from measured metrics."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        bare_fixture = _build_test_investigation_output().model_dump(mode="json")
        runner = EvaluationReplayRunner()

        summary = runner.run_benchmark(
            scenarios=[scenario],
            fixtures_by_scenario_id={"SCN-ATO-001": bare_fixture},
            benchmark_mode="captured_evaluation",
        )

        assert summary.total_scenarios_evaluated == 1
        assert summary.official_approved_scenarios == 1
        assert summary.measured_scenarios_count == 0
        assert summary.unmeasured_scenarios_count == 1
        assert summary.overall_mitre_f1 is None
        assert summary.evaluated_model_identifier == "unknown"

        res = summary.scenario_results[0]
        assert res.is_measured is False
        assert res.output_source_type == "legacy_unverified_fixture"
        assert res.fallback_category == FallbackReasonCategory.LEGACY_UNVERIFIED_FIXTURE
        assert any("LEGACY_UNVERIFIED" in note for note in res.evaluation_notes)
        assert res.is_json_valid is True
        assert res.is_schema_valid is True

    def test_legacy_fixture_file_bytes_preserved(self):
        """SCN-ATO-001-replay.json is preserved byte-for-byte without unauthorized mutation."""
        fixture_path = Path(__file__).resolve().parents[3] / "datasets" / "ground_truth" / "fixtures" / "SCN-ATO-001-replay.json"
        assert fixture_path.exists(), f"Expected fixture file at {fixture_path}"

        raw_bytes = fixture_path.read_bytes()
        computed_sha = hashlib.sha256(raw_bytes).hexdigest().lower()
        expected_sha = "4a8ef9ad16a6d3f46ffc46a0a249b74a1867684cb9c5594a50083153036c9d2c"

        assert computed_sha == expected_sha, (
            f"Fixture byte-for-byte integrity violated! Expected {expected_sha}, got {computed_sha}"
        )

        # Confirm valid JSON structure
        data = json.loads(raw_bytes.decode("utf-8"))
        assert "investigation_id" in data
        assert "claims" in data
        assert "model_identifier" in data

    def test_canonicalize_prompt_artifact_newline_and_whitespace_invariance(self):
        """Canonicalize function produces byte-identical hashes across CRLF, LF, CR, and whitespace variations."""
        text_lf = "System Prompt:\nYou are an AI SOC analyst.\nInvestigate the following events.\n"
        text_crlf = "System Prompt:\r\nYou are an AI SOC analyst.\r\nInvestigate the following events.\r\n  "
        text_cr = "System Prompt:\rYou are an AI SOC analyst.\rInvestigate the following events.\r"

        bytes_lf = canonicalize_prompt_artifact(text_lf)
        bytes_crlf = canonicalize_prompt_artifact(text_crlf)
        bytes_cr = canonicalize_prompt_artifact(text_cr)

        assert bytes_lf == bytes_crlf
        assert bytes_lf == bytes_cr

        sha_lf = hashlib.sha256(bytes_lf).hexdigest()
        sha_crlf = hashlib.sha256(bytes_crlf).hexdigest()
        sha_cr = hashlib.sha256(bytes_cr).hexdigest()

        assert sha_lf == sha_crlf == sha_cr

    def test_prompt_artifact_sha256_match_verified(self):
        """Cryptographically matching prompt artifact and SHA-256 succeeds with is_measured=True."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        prompt_text = "Canonical prompt for SCN-ATO-001 investigation"
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            prompt_text=prompt_text,
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(
            scenario=scenario,
            fixture_envelope=envelope,
        )

        assert res.is_measured is True
        assert res.output_source_type == "captured_verified_envelope"
        assert res.is_json_valid is True
        assert res.is_schema_valid is True
        assert not any("PROMPT" in note for note in res.evaluation_notes)

    def test_prompt_artifact_sha256_mismatch_rejected(self):
        """Tampered or mismatched prompt artifact fails closed with is_measured=False."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            prompt_text="Original prompt text",
        )

        runner = EvaluationReplayRunner()
        # Pass a conflicting/tampered prompt artifact externally
        res = runner.evaluate_scenario_output(
            scenario=scenario,
            fixture_envelope=envelope,
            prompt_artifact="Tampered or different prompt text",
        )

        assert res.is_measured is False
        assert res.output_source_type == "prompt_hash_mismatch"
        assert res.is_json_valid is False
        assert any("PROMPT INTEGRITY MISMATCH" in note for note in res.evaluation_notes)

    def test_missing_prompt_artifact_fails_closed(self):
        """Envelope missing prompt_artifact and without external companion fails closed."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output()
        raw_str = json.dumps(output_obj.model_dump(mode="json"))
        resp_sha = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

        envelope = CapturedInvestigationFixture(
            scenario_id="SCN-ATO-001",
            capture_timestamp_utc=datetime.now(timezone.utc),
            model_identifier="llama3.1:8b",
            prompt_sha256="a" * 64,
            prompt_artifact=None,  # Missing prompt artifact
            raw_response_sha256=resp_sha,
            raw_response=raw_str,
            capture_method="captured_verified_envelope",
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(
            scenario=scenario,
            fixture_envelope=envelope,
            prompt_artifact=None,
        )

        assert res.is_measured is False
        assert res.output_source_type == "missing_prompt_artifact"
        assert res.is_json_valid is False
        assert any("PROMPT ARTIFACT MISSING" in note for note in res.evaluation_notes)

    def test_model_identifier_consistency_match(self):
        """Consistent model identifier between envelope and response payload passes verification."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(model_identifier="llama3.1:8b")
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is True
        assert not any("MODEL IDENTIFIER MISMATCH" in note for note in res.evaluation_notes)

    def test_model_identifier_consistency_conflict_rejected(self):
        """Content-declared model identity differing from envelope does not cause infrastructure mismatch.

        Content-declared identity is untrusted generated output and is ignored for
        infrastructure binding. With no provider_reported_model_identifier (legacy
        fixture), the requested tag is used as the legacy-consistent value.
        """
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        # Content payload claims gpt-4o, but envelope declares llama3.1:8b.
        # Content identity is ignored for infrastructure binding.
        output_obj = _build_test_investigation_output(model_identifier="gpt-4o")
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",
            provider_reported_model_identifier=None,
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is True
        assert not any("MODEL IDENTIFIER MISMATCH" in note for note in res.evaluation_notes)

    def test_model_identifier_case_insensitive_tolerated(self):
        """Case and whitespace variations in model_identifier do not trigger false conflict rejection."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(model_identifier="  LLAMA3.1:8B  ")
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is True
        assert not any("MODEL IDENTIFIER MISMATCH" in note for note in res.evaluation_notes)

    def test_run_benchmark_model_identifier_mismatch_zero_measured(self):
        """Regression test: when provider-reported identity differs from requested tag,
        the benchmark reports zero measured scenarios.

        With provider-reported identity present and differing from requested tag,
        infrastructure binding fails and the scenario is unmeasured.
        """
        # Envelope declares llama3.1:8b (requested) but provider reports qwen3:4b
        output_obj = _build_test_investigation_output(model_identifier="llama3.1:8b")
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",  # Requested tag
            provider_reported_model_identifier="qwen3:4b",  # Provider-reported differs
        )

        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        runner = EvaluationReplayRunner()
        summary = runner.run_benchmark(
            scenarios=[scenario],
            fixture_envelopes_by_scenario_id={"SCN-ATO-001": envelope},
        )

        # Provider-reported identity mismatch causes zero measured scenarios
        assert summary.measured_scenarios_count == 0
        assert summary.unmeasured_scenarios_count == 1
        assert summary.identity_binding_status == "diverged"
        result = summary.scenario_results[0]
        assert result.is_measured is False
        assert result.output_source_type == "model_identifier_mismatch"
        assert any("MODEL IDENTIFIER MISMATCH" in note for note in result.evaluation_notes)

    def test_model_digest_explicitly_none_when_unavailable(self):
        """Model digest defaults to None when unavailable, maintaining explicit provenance."""
        output_obj = _build_test_investigation_output()
        raw_str = json.dumps(output_obj.model_dump(mode="json"))
        resp_sha = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

        envelope = CapturedInvestigationFixture(
            scenario_id="SCN-ATO-001",
            capture_timestamp_utc=datetime.now(timezone.utc),
            model_identifier="llama3.1:8b",
            model_digest=None,
            prompt_sha256="c" * 64,
            prompt_artifact="Test prompt",
            raw_response_sha256=resp_sha,
            raw_response=raw_str,
        )

        assert envelope.model_digest is None
        data = envelope.model_dump(mode="json")
        assert data["model_digest"] is None

    def test_report_generator_legacy_unverified_fixture_display(self):
        """Benchmark report renders legacy unverified fixtures as unmeasured with explicit provenance label."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        bare_fixture = _build_test_investigation_output().model_dump(mode="json")
        runner = EvaluationReplayRunner()

        summary = runner.run_benchmark(
            scenarios=[scenario],
            fixtures_by_scenario_id={"SCN-ATO-001": bare_fixture},
            benchmark_mode="captured_evaluation",
        )

        generator = BenchmarkReportGenerator()
        report = generator.generate_markdown_report(summary)

        assert "| `SCN-ATO-001` | atomic_technique | approved | **NO** |" in report
        assert "*LEGACY_UNVERIFIED — NO ENVELOPE PROVENANCE*" in report

    def test_report_generator_rejected_provenance_display(self):
        """Benchmark report renders integrity-rejected outputs with clear diagnostic rejected tags.

        Content-declared identity mismatch no longer causes rejection. A digest
        mismatch (not identity mismatch) is now the rejection reason."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(model_identifier="llama3.1:8b")
        raw_str = json.dumps(output_obj.model_dump(mode="json"))
        # Corrupt the hash to trigger digest mismatch rejection
        corrupted_sha = "0" * 64
        envelope = CapturedInvestigationFixture(
            scenario_id="SCN-ATO-001",
            capture_timestamp_utc=datetime.now(timezone.utc),
            model_identifier="llama3.1:8b",
            provider_reported_model_identifier="llama3.1:8b",
            prompt_sha256=hashlib.sha256(b"test prompt").hexdigest(),
            prompt_artifact="test prompt",
            raw_response_sha256=corrupted_sha,
            raw_response=raw_str,
            capture_method="captured_verified_envelope",
        )

        runner = EvaluationReplayRunner()
        summary = runner.run_benchmark(
            scenarios=[scenario],
            fixture_envelopes_by_scenario_id={"SCN-ATO-001": envelope},
            benchmark_mode="captured_evaluation",
        )

        generator = BenchmarkReportGenerator()
        report = generator.generate_markdown_report(summary)

        assert "| `SCN-ATO-001` | atomic_technique | approved | **NO** |" in report
        assert "REJECTED" in report
        assert "FIXTURE_HASH_MISMATCH" in report

class TestModelIdentityProtocolRevision:
    """Tests for the P3-H3B model identity protocol revision.

    Verifies that infrastructure identity binding compares requested model tag
    against provider-reported model identity, and that content-declared model
    identity (untrusted generated output) never causes infrastructure mismatch.
    """

    def test_requested_and_provider_identities_match_measured(self):
        """When requested tag matches provider-reported identity, scenario is measured."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(
            model_identifier="AISOP SOC Assistant"  # Content-declared, ignored for binding
        )
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",  # Requested tag
            provider_reported_model_identifier="llama3.1:8b",  # Provider-reported
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is True
        assert res.output_source_type != "model_identifier_mismatch"
        assert not any("MODEL IDENTIFIER MISMATCH" in note for note in res.evaluation_notes)

    def test_requested_and_provider_identities_mismatch_unmeasured(self):
        """When requested tag differs from provider-reported identity, scenario is unmeasured."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(model_identifier="llama3.1:8b")
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",  # Requested tag
            provider_reported_model_identifier="qwen3:4b",  # Provider-reported differs
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is False
        assert res.output_source_type == "model_identifier_mismatch"
        assert any("MODEL IDENTIFIER MISMATCH" in note for note in res.evaluation_notes)

    def test_content_persona_differs_while_infrastructure_matches_measured(self):
        """Content-declared model identity differing from requested tag does not cause mismatch.

        The model-generated content may declare 'AISOP SOC Assistant' as its model
        name, but infrastructure binding uses requested vs provider-reported identity.
        """
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(
            model_identifier="AISOP SOC Assistant"  # Content-declared, ignored for binding
        )
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",  # Requested tag
            provider_reported_model_identifier="llama3.1:8b",  # Provider-reported matches
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is True
        assert not any("MODEL IDENTIFIER MISMATCH" in note for note in res.evaluation_notes)

    def test_certified_digest_mismatch_still_rejected(self):
        """Certified model digest mismatch remains rejected regardless of identity binding."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(model_identifier="llama3.1:8b")
        raw_str = json.dumps(output_obj.model_dump(mode="json"))
        # Corrupt the hash to trigger digest mismatch rejection (create with wrong hash)
        corrupted_sha = "0" * 64
        envelope = CapturedInvestigationFixture(
            scenario_id="SCN-ATO-001",
            capture_timestamp_utc=datetime.now(timezone.utc),
            model_identifier="llama3.1:8b",
            provider_reported_model_identifier="llama3.1:8b",
            prompt_sha256=hashlib.sha256(b"test prompt").hexdigest(),
            prompt_artifact="test prompt",
            raw_response_sha256=corrupted_sha,
            raw_response=raw_str,
            capture_method="captured_verified_envelope",
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is False
        assert any("FIXTURE INTEGRITY COMPROMISED" in note for note in res.evaluation_notes)

    def test_legacy_fixture_without_provider_reported_identity_measured(self):
        """Legacy fixture lacking provider_reported_model_identifier defaults to requested tag.

        Legacy fixtures are treated as legacy-consistent (not directly observed),
        but are still measurable if the requested tag is present.
        """
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(model_identifier="llama3.1:8b")
        # No provider_reported_model_identifier - legacy fixture
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",
            provider_reported_model_identifier=None,
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is True
        assert not any("MODEL IDENTIFIER MISMATCH" in note for note in res.evaluation_notes)

    def test_missing_provider_identity_with_valid_requested_tag(self):
        """Missing provider identity with valid requested tag uses legacy consistency."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(model_identifier="llama3.1:8b")
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",
            provider_reported_model_identifier=None,
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        # provider_reported_model_identifier is None (legacy), falls back to requested tag
        assert res.is_measured is True
        assert not any("MODEL IDENTIFIER MISMATCH" in note for note in res.evaluation_notes)

    def test_ambiguous_provider_identity_not_treated_as_direct_evidence(self):
        """Ambiguous provider identity (empty string) falls back to legacy handling."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(model_identifier="llama3.1:8b")
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",
            provider_reported_model_identifier="   ",  # Whitespace-only, treated as empty
        )

        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        # Whitespace-only provider identity strips to empty, falls to legacy path
        assert res.is_measured is True
        assert not any("MODEL IDENTIFIER MISMATCH" in note for note in res.evaluation_notes)

    def test_benchmark_reporting_identity_dimensions(self):
        """Benchmark summary reports identity dimensions distinctly."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(model_identifier="llama3.1:8b")
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",
            provider_reported_model_identifier="llama3.1:8b",
        )

        runner = EvaluationReplayRunner()
        summary = runner.run_benchmark(
            scenarios=[scenario],
            fixture_envelopes_by_scenario_id={"SCN-ATO-001": envelope},
            benchmark_mode="captured_evaluation",
        )

        assert summary.measured_scenarios_count == 1
        assert summary.requested_model_tag == "llama3.1:8b"
        assert summary.provider_reported_model_identifier == "llama3.1:8b"
        assert summary.identity_binding_status == "consistent"
        assert summary.identity_evidence_source == "directly_observed"
        assert summary.certified_model_digest is None  # Not set in test envelope

    def test_legacy_fixture_evidence_source_labeling(self):
        """Legacy fixture (no provider_reported_model_identifier) is labeled legacy_derived."""
        scenario = _build_test_scenario(scenario_id="SCN-ATO-001")
        output_obj = _build_test_investigation_output(model_identifier="llama3.1:8b")
        envelope = _build_test_envelope(
            scenario_id="SCN-ATO-001",
            output=output_obj,
            model_identifier="llama3.1:8b",
            provider_reported_model_identifier=None,
        )

        runner = EvaluationReplayRunner()
        summary = runner.run_benchmark(
            scenarios=[scenario],
            fixture_envelopes_by_scenario_id={"SCN-ATO-001": envelope},
            benchmark_mode="captured_evaluation",
        )

        assert summary.measured_scenarios_count == 1
        assert summary.identity_evidence_source == "legacy_derived"

    def test_existing_fixture_integrity_preserved(self):
        """Existing captured fixtures validate and measure under new logic."""
        import os
        fixture_path = Path("datasets/ground_truth/fixtures/SCN-ADV-002-captured.json")
        assert fixture_path.exists(), "Existing fixture must exist"

        with open(fixture_path) as f:
            data = json.load(f)
        envelope = CapturedInvestigationFixture.model_validate(data)

        assert envelope.model_identifier == "llama3.1:8b"
        assert envelope.provider_reported_model_identifier is None  # Legacy, no field
        assert envelope.model_digest == "sha256:667b0c1932bc6ffc593ed1d03f895bf2dc8dc6df21db3042284a6f4416b06a29"

        scenario = _build_test_scenario(scenario_id="SCN-ADV-002")
        runner = EvaluationReplayRunner()
        res = runner.evaluate_scenario_output(scenario=scenario, fixture_envelope=envelope)

        assert res.is_measured is True
        assert not any("MODEL IDENTIFIER MISMATCH" in note for note in res.evaluation_notes)



