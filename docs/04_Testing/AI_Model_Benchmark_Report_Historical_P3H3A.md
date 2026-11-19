# AISOP AI Investigation Benchmark Report

| Metric / Metadata Field | Value | Classification |
|:---|:---|:---:|
| **Evaluation Run ID** | `20c9dc6d-626f-4447-af65-4c4e4e86b868` | Measured |
| **Evaluation Timestamp** | 2026-10-30 14:16:46 UTC | Measured |
| **Dataset Version** | `1.0.0` | Provenance |
| **Total Scenarios Evaluated** | 20 | Measured |
| **Official Approved Scenarios** | 19 | Measured |
| **Draft / Excluded Scenarios** | 1 | Provenance |
| **JSON Validity Rate** | 100.0% | Measured |
| **Schema Validity Rate** | 100.0% | Measured |
| **Evidence Grounding Precision** | 1.0000 | Measured |
| **Unsupported Claim Rate** | 0.0000 | Measured |
| **MITRE ATT&CK Precision** | 1.0000 | Measured |
| **MITRE ATT&CK Recall** | 1.0000 | Measured |
| **MITRE ATT&CK F1 Score** | 1.0000 | Measured |
| **Aggregate IOC Extraction F1** | 0.9524 | Measured |
| **Fallback Rate** | 0.0% | Measured |
| **Execution Latencies** | *Unavailable for offline replay* | Unavailable |

---

## 1. Executive Summary & Quality Scorecard

- **Dataset Evaluation Scope:** Evaluated 20 scenarios (19 contributing to official score).
- **Structural Integrity:** Syntactic JSON validity achieved **100.0%**; Pydantic V2 schema conformance achieved **100.0%**.
- **Grounding Integrity:** Mean grounding precision across evaluated claims is **1.0000**, with an unsupported claim rate of **0.0000**.
- **MITRE Attribution Quality:** Overall technique recall is **1.0000** with precision of **1.0000** (F1: **1.0000**).

---

## 2. Per-Scenario Evaluation Ledger

| Scenario ID | Category | Status | JSON Valid | Schema Valid | Fallback State | Grounding Prec. | Unsupported Rate | MITRE F1 | Output Hash |
|:---|:---|:---:|:---:|:---:|:---|:---:|:---:|:---:|:---|
| `SCN-ADV-001` | adversarial_ambiguous | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `6c6e913639fe...` |
| `SCN-ADV-002` | adversarial_ambiguous | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `62bfdbb10f09...` |
| `SCN-ADV-003` | adversarial_ambiguous | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | N/A | `6a439c1d32d0...` |
| `SCN-ADV-004` | adversarial_ambiguous | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `74f37d1368ec...` |
| `SCN-ADV-005` | adversarial_ambiguous | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `7d15ccad49a4...` |
| `SCN-ATO-001` | atomic_technique | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `d91b272c0d49...` |
| `SCN-ATO-002` | atomic_technique | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `0ca1afd2d1d7...` |
| `SCN-ATO-003` | atomic_technique | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `00d8b5bcb946...` |
| `SCN-ATO-004` | atomic_technique | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `657677217c82...` |
| `SCN-ATO-005` | atomic_technique | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `08556d996f73...` |
| `SCN-BEN-001` | benign_baseline | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | N/A | `f50efc10ce8b...` |
| `SCN-BEN-002` | benign_baseline | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | N/A | `a865525f6932...` |
| `SCN-BEN-003` | benign_baseline | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | N/A | `eeb37ae82a16...` |
| `SCN-BEN-004` | benign_baseline | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | N/A | `cd185ba8047e...` |
| `SCN-BEN-005` | benign_baseline | draft | PASS | PASS | genuine_model_output | 1.00 | 0.00 | N/A | `d0489a94a5c9...` |
| `SCN-CHN-001` | multi_stage_chain | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `6d5c0abe0a92...` |
| `SCN-CHN-002` | multi_stage_chain | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `574150d4aa9c...` |
| `SCN-CHN-003` | multi_stage_chain | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `f017ed6681e6...` |
| `SCN-CHN-004` | multi_stage_chain | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `554c771eae5a...` |
| `SCN-CHN-005` | multi_stage_chain | approved | PASS | PASS | genuine_model_output | 1.00 | 0.00 | 1.00 | `4ecbc8c6ab5b...` |

---

## 3. Known Methodological Limitations

- Offline replay engine evaluates recorded fixtures without live Ollama token generation timing.
- Execution latencies are unavailable for static replay runs.
- Unapproved draft scenarios are excluded from official benchmark scores in accordance with P3-H3A.
