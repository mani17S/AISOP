# AISOP AI Investigation Benchmark Report

> [!NOTE]
> **CAPTURED MODEL EVALUATION REPORT**
> Target Model: `llama3.1:8b` | Measured Scenarios: 10 / 19 (Unmeasured: 9)

| Metric / Metadata Field | Value | Classification |
|:---|:---|:---:|
| **Evaluation Run ID** | `76927150-78cd-41b8-84e2-389c36b15a7d` | Measured |
| **Evaluation Timestamp** | 2026-11-09 12:57:16 UTC | Measured |
| **Benchmark Execution Mode** | `captured_evaluation` | Provenance |
| **Evaluated Model Identifier** | `llama3.1:8b` | Provenance |
| **Dataset Version** | `1.0.0` | Provenance |
| **Total Scenarios Processed** | 20 | Measured |
| **Official Approved Scenarios** | 19 | Measured |
| **Draft / Excluded Scenarios** | 1 | Provenance |
| **Scenarios with Authentic Output** | 10 | Measured |
| **Missing Fixtures (Unmeasured)** | 9 | Measured |
| **JSON Validity Rate** | 100.0% (10/10 measured scenarios) | Measured |
| **Schema Validity Rate** | 100.0% (10/10 measured scenarios) | Measured |
| **Evidence Grounding Precision** | N/A *(unmeasured / 0 denominator)* | Human Adjudication Required |
| **Claims Pending Human Review** | 10 | Measured |
| **Unsupported Claim Rate** | 0.0000 | Measured |
| **MITRE Macro Precision** | 0.0000 | Measured |
| **MITRE Macro Recall** | 0.0000 | Measured |
| **MITRE Macro F1 Score** | 0.0000 (10/19 approved scenarios measured) | Measured |
| **Dataset Micro MITRE F1** | 0.0000 | Measured |
| **Benign Scenarios Evaluated** | 2 | Measured |
| **Benign False Positive Count** | 2 | Measured |
| **Benign False Positive Rate** | 1.0% (2 FP / 2 benign scenarios) | Measured |
| **Aggregate IOC Extraction F1** | 0.3148 | Measured |
| **Fallback Rate** | 0.0% (0/10 measured scenarios) | Measured |
| **Execution Latencies** | *Unavailable for offline replay* | Unavailable |

---

## 1. Executive Summary & Quality Scorecard

- **Dataset Evaluation Scope:** Evaluated 20 scenarios (19 approved; 10 measured with authentic outputs).
- **Structural Integrity:** Syntactic JSON validity: **100.0%**; Pydantic V2 schema conformance: **100.0%**.
- **Grounding Integrity:** Verified grounding precision is **N/A *(unmeasured / 0 denominator)*** (10 claims require manual human semantic review). Unsupported claim rate is **0.0000**.
- **MITRE Attribution Quality:** Macro Technique F1 is **0.0000** (Recall: **0.0000**, Precision: **0.0000**). Dataset Micro F1 across all evaluated techniques is **0.0000**.
- **Benign False Alarm Restraint:** Across 2 clean benign scenarios, produced **2 false positive technique predictions** (Benign FP Rate: **1.0%**).

---

## 2. Per-Scenario Evaluation Ledger

| Scenario ID | Category | Status | Measured? | JSON Valid | Schema Valid | Fallback State | Grounding Prec. | Unsupported Rate | MITRE F1 | Output Origin / Hash |
|:---|:---|:---:|:---:|:---:|:---:|:---|:---:|:---:|:---:|:---|
| `SCN-ADV-001` | adversarial_ambiguous | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-ADV-002` | adversarial_ambiguous | approved | YES | PASS | PASS | genuine_model_output | N/A | 0.00 | 0.00 | `dc5e60916f11...` |
| `SCN-ADV-003` | adversarial_ambiguous | approved | YES | PASS | PASS | genuine_model_output | N/A | 0.00 | 0.00 | `4a046f96d999...` |
| `SCN-ADV-004` | adversarial_ambiguous | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-ADV-005` | adversarial_ambiguous | approved | YES | PASS | PASS | genuine_model_output | N/A | 0.00 | 0.00 | `36a2f2f4b5a9...` |
| `SCN-ATO-001` | atomic_technique | approved | YES | PASS | PASS | genuine_model_output | N/A | 0.00 | 0.00 | `6f5366067eb8...` |
| `SCN-ATO-002` | atomic_technique | approved | YES | PASS | PASS | genuine_model_output | N/A | 0.00 | 0.00 | `11a7f6a17a5e...` |
| `SCN-ATO-003` | atomic_technique | approved | YES | PASS | PASS | genuine_model_output | N/A | 0.00 | 0.00 | `e42facad7cbb...` |
| `SCN-ATO-004` | atomic_technique | approved | YES | PASS | PASS | genuine_model_output | N/A | 0.00 | 0.00 | `0bbb08a8b981...` |
| `SCN-ATO-005` | atomic_technique | approved | YES | PASS | PASS | genuine_model_output | N/A | 0.00 | 0.00 | `cbf2567b5d1e...` |
| `SCN-BEN-001` | benign_baseline | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-BEN-002` | benign_baseline | approved | YES | PASS | PASS | genuine_model_output | N/A | 0.00 | 0.00 | `51f1923e6790...` |
| `SCN-BEN-003` | benign_baseline | approved | **NO** | N/A | N/A | missing_fixture | N/A | N/A | N/A | *UNMEASURED — NO CAPTURED MODEL OUTPUT* |
| `SCN-BEN-004` | benign_baseline | approved | YES | PASS | PASS | genuine_model_output | N/A | 0.00 | 0.00 | `5aa844be10dd...` |
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
