# AISOP AI Investigation Model Evaluation Framework Architecture
**Milestone:** P3-H3A (Ground-Truth AI Evaluation Framework — Offline-First)  
**Governing Policy:** `AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001`  
**Classification:** Engineering Specification & Testing Methodology  

---

## 1. Executive Purpose & Scope

The AISOP AI Model Evaluation Framework provides an objective, reproducible, and offline-first testing harness for grading LLM-generated security investigations against curated ground-truth telemetry scenarios.

Prior to P3-H3A, evaluation of AI investigation outputs relied on ad-hoc inspections or subjective review. Under P3-H3A, the system enforces:
1. **Zero-Toxicity & Anti-Fabrication Principles:** Ground truth is strictly segregated from model inference. The framework measures objective factual correspondence, never fabricating zeroes when denominators are undefined.
2. **Deterministic Replay Guarantee:** 100% of benchmark evaluation can execute offline without access to live database instances, GPU runtimes, or external cloud endpoints ($0 cloud cost).
3. **Multi-Tier Degradation Discrimination:** Explicitly distinguishes syntactically valid JSON, Pydantic schema conformance, factual evidence grounding, advisory MITRE ATT&CK attribution, and deterministic fallback responses.
4. **Model-Agnostic Baseline:** Provides an invariant evaluation methodology suitable for comparing `llama3.1:8b`, future quantized models (e.g. Q4_K_M), and future distilled student models under identical scoring rubrics.

---

## 2. System Architecture & Evaluation Pipeline

```
                     +---------------------------------------+
                     |  Ground-Truth Scenarios (JSON files)  |
                     |  - Atomic Techniques (5)              |
                     |  - Multi-Stage Attack Chains (5)      |
                     |  - Benign Baselines (5)               |
                     |  - Adversarial / Ambiguous (5)        |
                     +-------------------+-------------------+
                                         |
                                         v
                     +---------------------------------------+
                     |   ScenarioDatasetLoader               |
                     |   - Path traversal prevention         |
                     |   - Duplicate ID detection            |
                     |   - Review status gating              |
                     +-------------------+-------------------+
                                         |
                                         v
+-------------------------------+        |
| Investigation Output Source   |        |
| - Recorded Replay Fixture     |------->+
| - (Optional) Live Model Output|        |
+-------------------------------+        |
                                         v
                     +---------------------------------------+
                     |   EvaluationReplayRunner              |
                     |   - Tier 1: Syntactic JSON Validity   |
                     |   - Tier 2: Pydantic Schema Check     |
                     |   - Tier 3: Fallback Categorization   |
                     +---+-------------------------------+---+
                         |                               |
                         v                               v
+------------------------------------+   +------------------------------------+
| GroundingEvaluator                 |   | MitreEvaluator                     |
| - Evaluates Factual Claims         |   | - Exact Technique Match            |
| - Detects Prohibited Claims        |   | - Parent Technique Tolerance       |
| - Evidence Reference Validation    |   | - Mandatory vs Uncertain Handling  |
| - Fact Coverage vs Expected        |   | - Precision, Recall, F1 Metrics    |
+------------------+-----------------+   +-----------------+------------------+
                   |                                       |
                   +-------------------+-------------------+
                                       |
                                       v
                     +---------------------------------------+
                     |   BenchmarkReportGenerator            |
                     |   - Aggregates per-scenario results   |
                     |   - Excludes unapproved draft entries |
                     |   - Emits Markdown Benchmark Scorecard|
                     +---------------------------------------+
```

---

## 3. Schemas & Contract Definitions

All evaluation contracts are implemented in `backend/app/schemas/evaluation.py` using Pydantic V2 with `frozen=True` and `extra="forbid"`.

### 3.1 Scenario Metadata & Expectations
- **`EvaluationScenario`**: Top-level model containing `scenario_id` (`SCN-(ATO|CHN|BEN|ADV)-###`), `category`, `title`, `description`, `raw_telemetry_events`, `expected_interpretation` (`malicious`, `benign`, `suspicious_ambiguous`), `expected_observables`, `expected_mitre_techniques`, `expected_claims`, `prohibited_claims`, `known_uncertainty`, and `provenance`.
- **`ExpectedClaim`**: Atomic statement expected to be asserted, linked to required evidence indices.
- **`ProhibitedClaim`**: Contradicted, hallucinatory, or false-positive assertions that must NOT be present in valid investigations.
- **`ExpectedMitreMapping`**: ATT&CK technique expectations distinguishing mandatory techniques from uncertain/ambiguous hypotheses.
- **`GroundTruthProvenance`**: Explicit authorship, creation timestamp, reviewer identity, review notes, and review status (`approved`, `in_review`, `draft`, `rejected`). Only `approved` scenarios contribute to official benchmark scores.

### 3.2 Evaluation Results
- **`ClaimEvaluationItem`**: Individual claim grading categorized into:
  - `SUPPORTED`: Claim is factually aligned with expected conclusions and cites valid context event UUIDs.
  - `PARTIALLY_SUPPORTED`: Claim is plausible but omits key factual qualifiers.
  - `UNSUPPORTED`: Claim cites non-existent UUIDs or asserts unevidenced conclusions.
  - `CONTRADICTED`: Claim violates explicit `prohibited_claims` or contradicts telemetry.
  - `UNVERIFIABLE`: Claim cannot be confirmed or refuted from provided scope.
- **`ScenarioEvaluationResult`**: Comprehensive per-scenario grading record.
- **`BenchmarkRunSummary`**: Multi-scenario aggregated scorecard.

---

## 4. Mathematical Formulation & Safe Division

The framework enforces strict avoidance of fabricated zeroes or arbitrary defaults when sample counts or denominators are zero.

### 4.1 Safe Division
$$\text{safe\_division}(N, D) = \begin{cases} \frac{N}{D} & \text{if } D > 0 \\ \text{None (reported as N/A)} & \text{if } D = 0 \end{cases}$$

### 4.2 Precision, Recall, and F1
$$\text{Precision} = \text{safe\_division}(\text{TP}, \text{TP} + \text{FP})$$
$$\text{Recall} = \text{safe\_division}(\text{TP}, \text{TP} + \text{FN})$$
$$\text{F1} = \text{safe\_division}(2 \times \text{Precision} \times \text{Recall}, \text{Precision} + \text{Recall})$$

When $\text{TP} + \text{FP} = 0$ (e.g. for benign baseline scenarios where zero MITRE techniques are expected and zero are predicted), Precision, Recall, and F1 evaluate to `None` and are formatted as `N/A *(unmeasured / 0 denominator)*` rather than false $0.00$.

### 4.3 Evidence Grounding Metrics
$$\text{Grounding Precision} = \frac{\text{Count}(\text{SUPPORTED Claims})}{\text{Total Asserted Claims}}$$
$$\text{Unsupported Claim Rate} = \frac{\text{Count}(\text{UNSUPPORTED}) + \text{Count}(\text{CONTRADICTED})}{\text{Total Asserted Claims}}$$

---

## 5. Curated Ground-Truth Dataset (20 Scenarios)

The initial dataset comprises 20 JSON scenarios located in `datasets/ground_truth/`:

| Category | Identifier Range | Count | Approved | Purpose |
|:---|:---|:---:|:---:|:---|
| **Atomic Technique** | `SCN-ATO-001` - `005` | 5 | 5 | Focused execution of specific MITRE ATT&CK techniques (PowerShell encoded execution, process injection, scheduled task persistence, LSASS credential dumping, network reconnaissance). |
| **Multi-Stage Chain** | `SCN-CHN-001` - `005` | 5 | 5 | End-to-end attack lifecycles spanning initial execution, persistence, privilege escalation, credential access, lateral movement, and data exfiltration. |
| **Benign Baseline** | `SCN-BEN-001` - `005` | 5 | 4 *(1 Draft)* | High-volume benign administrator workflows, software installation, vulnerability scanning, and routine maintenance designed to test false-positive resistance. |
| **Adversarial / Ambiguous** | `SCN-ADV-001` - `005` | 5 | 5 | Dual-use admin tools (LOLBins), masqueraded binaries, incomplete telemetry scopes, and ambiguous user activity designed to test model epistemic humility. |

### Draft Exclusion Invariant
`SCN-BEN-005` is curated with `review_status: "draft"` and `reviewer: null`. When loaded with `include_unapproved=False`, it is strictly excluded from official benchmark metric calculations, guaranteeing dataset provenance integrity.

---

## 6. Execution Instructions

### Running the Offline Unit Tests
```bash
# Execute evaluation framework unit tests (19 tests)
pytest backend/tests/unit/test_ai_evaluation_framework.py -v

# Execute full offline unit regression suite (886 tests)
pytest backend/tests/unit -m "not postgres and not ollama" -q
```

### Running the Benchmark CLI Runner
```bash
# Execute benchmark in offline replay mode
python backend/scripts/run_ai_benchmark.py --mode replay

# Optional: write report to custom location
python backend/scripts/run_ai_benchmark.py --mode replay --output-report custom_report.md
```
Output report is generated at `docs/04_Testing/AI_Model_Benchmark_Report.md`.

