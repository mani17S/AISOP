# AISOP AI Investigation Benchmark Report

> [!NOTE]
> **CAPTURED MODEL EVALUATION REPORT**
> Target Model: `unknown` | Measured Scenarios: 0 / 19 (Unmeasured: 19)

| Metric / Metadata Field | Value | Classification |
|:---|:---|:---:|
| **Evaluation Run ID** | `f414a5c3-6764-417b-919e-9232c0e3c00f` | Measured |
| **Evaluation Timestamp** | 2026-10-31 12:23:25 UTC | Measured |
| **Benchmark Execution Mode** | `captured_evaluation` | Provenance |
| **Evaluated Model Identifier** | `unknown` | Provenance |
| **Dataset Version** | `1.0.0` | Provenance |
| **Total Scenarios Processed** | 20 | Measured |
| **Official Approved Scenarios** | 19 | Measured |
| **Draft / Excluded Scenarios** | 1 | Provenance |
| **Scenarios with Authentic Output** | 0 | Measured |
| **Missing Fixtures (Unmeasured)** | 19 | Measured |
| **JSON Validity Rate** | 0.0% (0/0 measured scenarios) | Measured |
| **Schema Validity Rate** | 0.0% (0/0 measured scenarios) | Measured |
| **Evidence Grounding Precision** | N/A *(unmeasured / 0 denominator)* | Human Adjudication Required |
| **Claims Pending Human Review** | 0 | Measured |
| **Unsupported Claim Rate** | N/A *(unmeasured / 0 denominator)* | Measured |
| **MITRE Macro Precision** | N/A *(unmeasured / 0 denominator)* | Measured |
| **MITRE Macro Recall** | N/A *(unmeasured / 0 denominator)* | Measured |
| **MITRE Macro F1 Score** | N/A *(unmeasured / 0 denominator)* (0/19 approved scenarios measured) | Measured |
| **Dataset Micro MITRE F1** | N/A *(unmeasured / 0 denominator)* | Measured |
| **Benign Scenarios Evaluated** | 0 | Measured |
| **Benign False Positive Count** | 0 | Measured |
| **Benign False Positive Rate** | N/A *(unmeasured / 0 denominator)* (0 FP / 0 benign scenarios) | Measured |
| **Aggregate IOC Extraction F1** | N/A *(unmeasured / 0 denominator)* | Measured |
| **Fallback Rate** | 0.0% (0/0 measured scenarios) | Measured |
| **Execution Latencies** | *Unavailable for offline replay* | Unavailable |

---

## 1. Executive Summary & Quality Scorecard

- **Evaluation Status:** **0 scenarios possess authentic captured model responses**. All model-performance metrics are reported as `UNMEASURED`.
- **Data Integrity Protection:** The benchmark runner refused to auto-manufacture passing answers from expected ground truth.

---

## 2. Per-Scenario Evaluation Ledger

| Scenario ID | Category | Status | Measured? | JSON Valid | Schema Valid | Fallback State | Grounding Prec. | Unsupported Rate | MITRE F1 | Output Origin / Hash |
|:---|:---|:---:|:---:|:---:|:---:|:---|:---:|:---:|:---:|:---|
| `SCN-ADV-001` | adversarial_ambiguous | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-ADV-002` | adversarial_ambiguous | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-ADV-003` | adversarial_ambiguous | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-ADV-004` | adversarial_ambiguous | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-ADV-005` | adversarial_ambiguous | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-ATO-001` | atomic_technique | approved | **NO** | PASS | PASS | legacy_unverified_fixture | N/A | N/A | N/A | *LEGACY_UNVERIFIED — NO ENVELOPE PROVENANCE* |
| `SCN-ATO-002` | atomic_technique | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-ATO-003` | atomic_technique | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-ATO-004` | atomic_technique | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-ATO-005` | atomic_technique | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-BEN-001` | benign_baseline | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-BEN-002` | benign_baseline | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-BEN-003` | benign_baseline | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-BEN-004` | benign_baseline | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-BEN-005` | benign_baseline | draft | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-CHN-001` | multi_stage_chain | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-CHN-002` | multi_stage_chain | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-CHN-003` | multi_stage_chain | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-CHN-004` | multi_stage_chain | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-CHN-005` | multi_stage_chain | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |

---

## 3. Known Methodological Limitations

- Offline replay engine evaluates recorded fixtures without live Ollama token generation timing.
- Execution latencies are unavailable for static replay runs.
- Unapproved draft scenarios are excluded from official benchmark scores in accordance with P3-H3A.
- Automated semantic entailment is not claimed; claims with valid references require human adjudication.
- Missing authentic fixtures are strictly reported as UNMEASURED and excluded from performance claims.
