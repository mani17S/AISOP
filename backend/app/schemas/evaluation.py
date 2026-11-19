"""
AISOP Evaluation Data Contracts & Schemas.

P3-H3A: Ground-Truth AI Evaluation Framework.
Governing Policy: AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001.

Provides typed, immutable Pydantic V2 models for:
- Ground-truth evaluation scenarios and provenance
- Observable and MITRE ATT&CK expectations
- Factual claim expectations and prohibited assertions
- Scenario-level and aggregate benchmark evaluation results
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
import re
from typing import Any
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ── REGEX PATTERNS ───────────────────────────────────────────────────────────
_SCENARIO_ID_RE = re.compile(r"^SCN-(ATO|CHN|BEN|ADV)-\d{3}$")
_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


# ── ENUMS ────────────────────────────────────────────────────────────────────
class ScenarioCategory(StrEnum):
    """Categorization of ground-truth security evaluation scenarios."""
    ATOMIC_TECHNIQUE = "atomic_technique"
    MULTI_STAGE_CHAIN = "multi_stage_chain"
    BENIGN_BASELINE = "benign_baseline"
    ADVERSARIAL_AMBIGUOUS = "adversarial_ambiguous"


class ReviewerStatus(StrEnum):
    """Forensic approval state of a ground-truth scenario."""
    DRAFT = "draft"
    REVIEWED = "reviewed"
    APPROVED = "approved"
    PENDING_HUMAN_REVIEW = "pending_human_review"


class ExpectedInterpretation(StrEnum):
    """High-level security interpretation expected for a scenario."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"


class GroundingEvaluationCategory(StrEnum):
    """Factual claim grounding evaluation disposition."""
    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"
    UNVERIFIABLE = "unverifiable"
    LEXICAL_HEURISTIC_MATCH = "lexical_heuristic_match"
    REQUIRES_HUMAN_REVIEW = "requires_human_review"


class FactCoverageStatus(StrEnum):
    """Coverage disposition of an expected ground-truth fact."""
    COVERED = "covered"
    OMITTED = "omitted"
    INCORRECT = "incorrect"


class FallbackReasonCategory(StrEnum):
    """Categorization of model synthesis vs fallback disposition."""
    GENUINE_MODEL_OUTPUT = "genuine_model_output"
    DETERMINISTIC_FALLBACK = "deterministic_fallback"
    PARSER_REJECTION = "parser_rejection"
    GUARDRAIL_REJECTION = "guardrail_rejection"
    PROVIDER_FAILURE = "provider_failure"
    TIMEOUT = "timeout"
    INVALID_RESPONSE = "invalid_response"
    UNMEASURED_MISSING_FIXTURE = "unmeasured_missing_fixture"
    LEGACY_UNVERIFIED_FIXTURE = "legacy_unverified_fixture"
    HARNESS_SELF_TEST = "harness_self_test"


# ── SCENARIO EXPECTATION CONTRACTS ───────────────────────────────────────────
class ExpectedObservable(BaseModel):
    """Observable indicator expected to be resolved in investigation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    observable_type: str = Field(
        min_length=1,
        description="Type: ipv4, ipv6, domain, sha256, md5, sha1, executable, command_line, user, host",
    )
    observable_value: str = Field(min_length=1, description="Canonical observable value string")
    is_mandatory: bool = Field(default=True, description="Whether observable must be extracted")


class ExpectedMitreMapping(BaseModel):
    """MITRE ATT&CK technique mapping expected for scenario telemetry."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str = Field(description="Technique ID (e.g. T1059 or T1059.001)")
    technique_name: str = Field(min_length=1, description="Standard MITRE technique name")
    tactic: str | None = Field(default=None, description="ATT&CK tactic (e.g. Execution)")
    is_mandatory: bool = Field(default=True, description="Whether mapping is required for full score")
    is_uncertain: bool = Field(default=False, description="Whether technique mapping is plausible but ambiguous")

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, v: str) -> str:
        clean = v.strip().upper()
        if not _MITRE_TECHNIQUE_RE.match(clean):
            raise ValueError(f"Invalid MITRE technique ID format '{v}'; expected T#### or T####.###")
        return clean


class ExpectedClaim(BaseModel):
    """Atomic factual statement that an accurate investigation should assert."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    claim_id: str = Field(min_length=1, description="Unique identifier for expected claim (e.g. EXP-01)")
    statement: str = Field(min_length=5, description="Expected factual conclusion")
    category: str = Field(default="behavioral", description="Category: behavioral, attribution, impact, timeline")
    required_evidence_indices: list[int] = Field(
        default_factory=list,
        description="0-based indices into raw telemetry events that support this claim",
    )
    is_mandatory: bool = Field(default=True, description="Whether claim is required for factual coverage")


class ProhibitedClaim(BaseModel):
    """Unsupported or hallucinatory claim that must NOT be asserted."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    prohibited_claim_id: str = Field(min_length=1, description="Identifier for prohibited claim (e.g. PRO-01)")
    prohibited_assertion: str = Field(min_length=5, description="Assertion that is contradicted or unsupported")
    reason: str = Field(min_length=5, description="Why this assertion constitutes hallucination or false positive")


class GroundTruthProvenance(BaseModel):
    """Audit provenance and curation metadata for an evaluation scenario."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    author: str = Field(min_length=1, description="Engineer or analyst who created the ground truth")
    dataset_source: str = Field(min_length=1, description="Origin: sample_corpus, atomic_red_team, sysmon_sample")
    creation_timestamp_utc: datetime = Field(description="UTC timestamp when scenario was created")
    review_status: ReviewerStatus = Field(default=ReviewerStatus.DRAFT, description="Approval state")
    reviewer: str | None = Field(default=None, description="Independent reviewer who approved ground truth")
    review_notes: str | None = Field(default=None, description="Review commentary or audit trail")

    @field_validator("creation_timestamp_utc", mode="after")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_approval_invariants(self) -> Self:
        if self.review_status == ReviewerStatus.APPROVED:
            if not self.reviewer or not self.reviewer.strip():
                raise ValueError("Approved scenario must specify an independent reviewer")
        return self


# ── EVALUATION SCENARIO CONTRACT ─────────────────────────────────────────────
class EvaluationScenario(BaseModel):
    """
    Immutable ground-truth scenario for evaluating AISOP investigation quality.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(description="Scenario ID matching SCN-(ATO|CHN|BEN|ADV)-###")
    dataset_version: str = Field(default="1.0.0", description="Semver dataset version")
    category: ScenarioCategory = Field(description="Category of scenario")
    title: str = Field(min_length=3, description="Short descriptive title")
    description: str = Field(min_length=10, description="Detailed security scenario description")
    raw_telemetry_events: list[dict[str, Any]] = Field(
        min_length=1,
        description="Raw security events (e.g. Sysmon JSON) comprising the scenario",
    )
    expected_interpretation: ExpectedInterpretation = Field(
        description="Expected overall security interpretation",
    )
    expected_observables: list[ExpectedObservable] = Field(
        default_factory=list,
        description="Observables expected to be extracted",
    )
    expected_mitre_techniques: list[ExpectedMitreMapping] = Field(
        default_factory=list,
        description="MITRE techniques expected to be identified",
    )
    expected_claims: list[ExpectedClaim] = Field(
        default_factory=list,
        description="Evidence-supported factual claims expected in investigation",
    )
    prohibited_claims: list[ProhibitedClaim] = Field(
        default_factory=list,
        description="Claims that must NOT be asserted",
    )
    known_uncertainty: list[str] = Field(
        default_factory=list,
        description="Known data gaps or unobservable elements in telemetry",
    )
    expected_limitations: list[str] = Field(
        default_factory=list,
        description="Methodological limitations of this scenario",
    )
    provenance: GroundTruthProvenance = Field(
        description="Curation and review provenance record",
    )
    is_synthetic: bool = Field(
        default=False,
        description="True if scenario was artificially constructed rather than captured from real malware",
    )
    synthetic_generation_rationale: str | None = Field(
        default=None,
        description="Explanation of how synthetic telemetry was generated and verified",
    )

    @field_validator("scenario_id")
    @classmethod
    def validate_scenario_id(cls, v: str) -> str:
        clean = v.strip().upper()
        if not _SCENARIO_ID_RE.match(clean):
            raise ValueError(f"Invalid scenario_id '{v}'; must match format SCN-(ATO|CHN|BEN|ADV)-###")
        return clean

    @field_validator("dataset_version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        clean = v.strip()
        if not _SEMVER_RE.match(clean):
            raise ValueError(f"Invalid dataset_version '{v}'; must be semantic version X.Y.Z")
        return clean

    @model_validator(mode="after")
    def validate_synthetic_disclosure(self) -> Self:
        if self.is_synthetic and not self.synthetic_generation_rationale:
            raise ValueError("Synthetic scenarios must provide synthetic_generation_rationale")
        return self


# ── ADJUDICATION & FIXTURE PROVENANCE CONTRACTS ─────────────────────────────
class HumanClaimAdjudication(BaseModel):
    """
    Independent human review record for an asserted investigation claim.
    Provides verifiable, non-model adjudication for epistemic grounding metrics.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    adjudication_record_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Unique identifier of this adjudication record",
    )
    claim_id: uuid.UUID = Field(
        description="UUID of the specific model claim being adjudicated",
    )
    review_status: GroundingEvaluationCategory = Field(
        description="Human verified disposition: SUPPORTED, PARTIALLY_SUPPORTED, UNSUPPORTED, CONTRADICTED, UNVERIFIABLE",
    )
    reviewer_id: str = Field(
        min_length=1,
        description="Identifier of the human reviewer/auditor (trusted application input)",
    )
    reviewed_at_utc: datetime = Field(
        description="UTC timestamp of the human review",
    )
    review_notes: str | None = Field(
        default=None,
        description="Optional justification notes from the human reviewer",
    )

    @field_validator("reviewer_id")
    @classmethod
    def validate_reviewer_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("reviewer_id must be a non-empty string")
        return clean

    @field_validator("reviewed_at_utc")
    @classmethod
    def validate_reviewed_at(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("reviewed_at_utc must be timezone-aware (UTC)")
        return v


class CapturedInvestigationFixture(BaseModel):
    """
    Validated envelope binding an authentic captured model response to an evaluation scenario.
    Provides verified input/output hashes, scenario binding, and capture metadata.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(
        default="1.0.0",
        description="Fixture envelope schema version",
    )
    scenario_id: str = Field(
        description="Target evaluation scenario ID this response was captured for",
    )
    capture_timestamp_utc: datetime = Field(
        description="UTC timestamp when the model response was captured",
    )
    model_identifier: str = Field(
        min_length=1,
        description="Requested model tag (e.g. llama3.1:8b)",
    )
    provider_reported_model_identifier: str | None = Field(
        default=None,
        description="Model identity reported in the provider response envelope",
    )
    model_digest: str | None = Field(
        default=None,
        description="Cryptographic SHA-256 digest of local model weights if available; None if unavailable",
    )
    prompt_sha256: str = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 digest of the exact prompt artifact supplied to the model",
    )
    prompt_artifact: str | None = Field(
        default=None,
        description="Exact canonical prompt text artifact supplied to model at capture time",
    )
    raw_response_sha256: str = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 digest of the raw response payload",
    )
    raw_response: str | dict[str, Any] = Field(
        description="Raw string response or serialized JSON dictionary from the model",
    )
    capture_method: str = Field(
        default="ollama_api_capture",
        description="Method or harness used to capture the response",
    )
    capture_environment: dict[str, Any] = Field(
        default_factory=dict,
        description="Runtime execution environment metadata (OS, hardware, python version)",
    )
    capture_manifest_version: str = Field(
        default="1.0.0",
        description="Capture manifest specification version",
    )
    inference_parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Inference hyper-parameters (temperature, context_window, seed, etc.)",
    )

    @field_validator("scenario_id")
    @classmethod
    def validate_scenario_id(cls, v: str) -> str:
        clean = v.strip()
        if not _SCENARIO_ID_RE.match(clean):
            raise ValueError(f"Invalid scenario_id format: '{v}'")
        return clean

    @field_validator("prompt_sha256", "raw_response_sha256")
    @classmethod
    def validate_hex_digest(cls, v: str) -> str:
        clean = v.strip().lower()
        if not re.match(r"^[a-f0-9]{64}$", clean):
            raise ValueError(f"Must be a 64-character lowercase hex SHA-256 digest: '{v}'")
        return clean

    @field_validator("capture_timestamp_utc")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("capture_timestamp_utc must be timezone-aware (UTC)")
        return v


# ── EVALUATION RESULTS CONTRACTS ─────────────────────────────────────────────
class ClaimEvaluationItem(BaseModel):
    """Detailed evaluation of an asserted factual claim."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    claim_id: str = Field(description="Normalized or original claim ID")
    claim_text: str = Field(description="Asserted claim text")
    category: GroundingEvaluationCategory = Field(description="Grounding categorization")
    cited_evidence_ids: list[str] = Field(default_factory=list, description="Evidence UUIDs cited")
    is_syntactically_grounded: bool = Field(description="True if cited UUIDs exist in context")
    factual_notes: str = Field(default="", description="Adjudication rationale")


class FactCoverageItem(BaseModel):
    """Evaluation of whether an expected ground-truth fact was covered."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    fact_id: str = Field(description="Expected claim ID")
    description: str = Field(description="Fact description")
    status: FactCoverageStatus = Field(description="Coverage status")
    matched_claim_id: str | None = Field(default=None, description="Asserted claim that satisfied fact")


class MitreEvaluationResult(BaseModel):
    """Evaluation metrics for MITRE ATT&CK technique mapping."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    precision: float | None = Field(description="Precision: TP / (TP + FP); None if TP + FP == 0")
    recall: float | None = Field(description="Recall: TP / (TP + FN); None if TP + FN == 0")
    f1: float | None = Field(description="F1 score; None if precision or recall is None")
    true_positives: list[str] = Field(default_factory=list, description="Correctly identified techniques")
    false_positives: list[str] = Field(default_factory=list, description="Incorrect/hallucinated techniques")
    false_negatives: list[str] = Field(default_factory=list, description="Omitted expected techniques")
    uncertain_mappings: list[str] = Field(default_factory=list, description="Mappings marked uncertain")
    exact_matches: list[str] = Field(default_factory=list, description="Techniques matched exactly")
    parent_matches: list[str] = Field(default_factory=list, description="Predicted general parent for specific expected sub-technique")
    subtechnique_matches: list[str] = Field(default_factory=list, description="Predicted specific sub-technique for general expected parent")
    tolerated_matches: list[str] = Field(default_factory=list, description="Combined parent/sub-technique tolerated matches")
    matching_notes: list[str] = Field(default_factory=list, description="Explicit rationale for matches and rejections")


class IocTypeEvaluationResult(BaseModel):
    """Evaluation metrics for an observable/IOC category."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    observable_type: str = Field(description="Observable type (ipv4, domain, etc.)")
    precision: float | None = Field(description="Precision: TP / (TP + FP)")
    recall: float | None = Field(description="Recall: TP / (TP + FN)")
    f1: float | None = Field(description="F1 score")
    true_positives: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    false_negatives: list[str] = Field(default_factory=list)


class ScenarioEvaluationResult(BaseModel):
    """Comprehensive evaluation result for a single scenario."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(description="Scenario ID evaluated")
    category: ScenarioCategory = Field(description="Scenario category")
    review_status: ReviewerStatus = Field(description="Provenance review status")
    is_official_score_eligible: bool = Field(description="True if scenario was approved")
    is_json_valid: bool = Field(description="True if output was syntactically valid JSON")
    is_schema_valid: bool = Field(description="True if output conformed to StructuredInvestigationOutput")
    output_source_type: str = Field(
        description="Source classification: offline_replay_fixture, deterministic_fallback, live_inference, harness_self_test, missing_fixture",
    )
    fallback_category: FallbackReasonCategory = Field(description="Model output vs fallback categorization")
    grounding_precision: float | None = Field(
        default=None,
        description="Verified supported claims / total claims; None if pending human adjudication or 0 claims",
    )
    unsupported_claim_rate: float | None = Field(
        default=None,
        description="Unsupported + Contradicted / total claims; None if 0 claims",
    )
    is_measured: bool = Field(default=True, description="True if evaluated from an authentic captured output")
    claims_requiring_human_review_count: int = Field(default=0, description="Count of claims requiring human adjudication")
    reference_validity_rate: float | None = Field(default=None, description="Proportion of claims citing valid context references")
    lexical_diagnostic_overlap_rate: float | None = Field(default=None, description="Diagnostic lexical match rate against expected claims")
    mitre_eval: MitreEvaluationResult = Field(description="MITRE technique evaluation metrics")
    ioc_evaluations: dict[str, IocTypeEvaluationResult] = Field(
        default_factory=dict,
        description="Per-type IOC evaluation results",
    )
    claim_evaluations: list[ClaimEvaluationItem] = Field(
        default_factory=list,
        description="Individual claim evaluations",
    )
    fact_coverage: list[FactCoverageItem] = Field(
        default_factory=list,
        description="Coverage of expected ground-truth facts",
    )
    execution_latencies_ms: dict[str, float] | None = Field(
        default=None,
        description="Execution latency metrics in ms if available; None for offline replay",
    )
    reproducibility_hash: str | None = Field(
        default=None,
        description="Forensic output SHA-256 digest if available",
    )
    evaluation_notes: list[str] = Field(
        default_factory=list,
        description="Diagnostic and audit notes from evaluator",
    )


class BenchmarkRunSummary(BaseModel):
    """Aggregated evaluation scorecard across an entire scenario corpus."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Evaluation run UUID")
    dataset_version: str = Field(description="Semver dataset version evaluated")
    timestamp_utc: datetime = Field(description="UTC execution timestamp")
    benchmark_mode: str = Field(default="captured_evaluation", description="Execution mode: harness_self_test or captured_evaluation")
    evaluated_model_identifier: str = Field(default="unknown", description="Model identity extracted from evaluated response payloads")
    requested_model_tag: str | None = Field(default=None, description="Requested model tag (e.g. llama3.1:8b)")
    provider_reported_model_identifier: str | None = Field(default=None, description="Model identity reported in the provider response envelope")
    content_declared_model_identifier: str | None = Field(default=None, description="Model identity declared in generated content (untrusted)")
    certified_model_digest: str | None = Field(default=None, description="Certified model artifact digest")
    identity_binding_status: str | None = Field(default=None, description="Infrastructure identity binding status (consistent/diverged/unknown)")
    identity_evidence_source: str | None = Field(default=None, description="Identity evidence source: directly_observed or legacy_derived")
    total_scenarios_evaluated: int = Field(description="Total scenarios processed")
    official_approved_scenarios: int = Field(description="Count of approved scenarios contributing to score")
    draft_excluded_scenarios: int = Field(description="Count of unapproved scenarios excluded from score")
    measured_scenarios_count: int = Field(default=0, description="Count of scenarios with authentic captured outputs")
    unmeasured_scenarios_count: int = Field(default=0, description="Count of scenarios missing captured outputs")
    benign_scenarios_evaluated: int = Field(default=0, description="Count of benign scenarios evaluated")
    benign_false_positive_count: int = Field(default=0, description="Total false-positive technique predictions on benign scenarios")
    benign_false_positive_rate: float | None = Field(default=None, description="Proportion of benign scenarios with >=1 false positive")
    claims_requiring_human_adjudication_count: int = Field(default=0, description="Total claims pending human semantic adjudication")
    overall_json_validity_rate: float = Field(description="Percentage (0-100) of syntactically valid JSON outputs")
    overall_schema_validity_rate: float = Field(description="Percentage (0-100) of valid Pydantic schema outputs")
    overall_evidence_grounding_precision: float | None = Field(
        default=None,
        description="Aggregate verified grounding precision across approved scenarios",
    )
    overall_unsupported_claim_rate: float | None = Field(
        default=None,
        description="Aggregate unsupported claim rate across approved scenarios",
    )
    overall_mitre_precision: float | None = Field(default=None, description="Aggregate MITRE technique precision")
    overall_mitre_recall: float | None = Field(default=None, description="Aggregate MITRE technique recall")
    overall_mitre_f1: float | None = Field(default=None, description="Aggregate MITRE technique F1")
    dataset_micro_mitre_precision: float | None = Field(default=None, description="Dataset-level micro precision (Total TP / (Total TP + Total FP))")
    dataset_micro_mitre_recall: float | None = Field(default=None, description="Dataset-level micro recall (Total TP / (Total TP + Total FN))")
    dataset_micro_mitre_f1: float | None = Field(default=None, description="Dataset-level micro F1")
    overall_ioc_f1: float | None = Field(default=None, description="Aggregate IOC extraction F1")
    fallback_rate: float = Field(description="Percentage (0-100) of outputs resolving to fallback")
    latency_summary: dict[str, Any] = Field(
        default_factory=dict,
        description="Latency metrics (min, max, mean) if available; explicitly marked unavailable if replay",
    )
    reproducibility_summary: dict[str, Any] = Field(
        default_factory=dict,
        description="Reproducibility statistics if multi-run evaluation performed",
    )
    known_limitations: list[str] = Field(
        default_factory=list,
        description="Documented limitations of this benchmark run",
    )
    scenario_results: list[ScenarioEvaluationResult] = Field(
        default_factory=list,
        description="Per-scenario evaluation details",
    )

