# ADR-017: Vantage-Level Independence for Corroboration

| Field | Value |
|---|---|
| **ID** | ADR-017 |
| **Status** | **PROPOSED, implemented 2026-11-24** on the project owner's instruction to add a defensible research contribution (same convention as ADR-009 and ADR-010). Owner approval of this record is still wanted. |
| **Date** | 2026-11-23 (proposed), 2026-11-24 (implemented) |
| **Relates to** | ADR-008 (sufficiency gate), ADR-013 (contradiction-aware sufficiency), `docs/10_Research/Contribution_Statement.md`, `docs/10_Research/Real_Format_Ingestion_Result.md` |
| **Changes** | One new reason code (`SAME_VANTAGE_ONLY`) and one verdict cap in `ai/guardrails/sufficiency_gate.py`. It can only lower a verdict. |
| **Does not change** | The hash-locked development cases (they carry no vantage), the deterministic fallback, claim verification, or the single gate entry point. |

## Context
Before this change the gate treated two records as independent corroboration when they were different raw records (after duplicate clustering), linked by a specific or strong artefact, and different observations. It did not ask whether they were seen from different vantage points.

Measured evidence (2026-11-23), real public Windows data (OTRF, MIT): one incident reached SUFFICIENT from two Sysmon records on one host, a registry key event and a registry value set by the same `svchost.exe` process, joined by a process-GUID link. Both came from one sensor and the activity was ordinary. The gate behaved as designed; the design was the question. The source-dependence literature in data fusion (Dong, Berti-Equille, Srivastava, read at abstract level only) draws the same line between independent sources and copies.

## Decision (as built)
A **vantage** is the declared source type at a host (for example `sysmon@workstation5`), or an explicit `attributes["vantage"]` if a record carries one. The incident path supplies the source as `attributes["source_type"]` and the case path stores the same fact as `attributes["source_system"]`; the gate reads either.

When the key event is corroborated, the gate takes the **whole chain joined by specific or strong links** around it (not only the key event's direct neighbours: a story can be carried by several vantage points one hop apart, such as file hash, process artefact, public IP, then DNS and firewall records). If every record in that chain has a **known** vantage and it is **one** vantage, the verdict is capped at LIMITED with `SAME_VANTAGE_ONLY`. A record with an unknown vantage never triggers the cap, so contexts that carry no source type behave exactly as before.

## What was measured (`backend/evaluation_tools/vantage_effect.py`, development split, no labels)
| Annotation of the 67 locked cases | SUFFICIENT | Fell | Raised |
|---|---|---|---|
| none (as locked) | 11 | 0 | 0 |
| every record from one vantage | 0 | 11 | 0 |
| key event from A, the rest from B | 11 | 0 | 0 |
| every record from its own vantage | 11 | 0 | 0 |
On the real public data the one SUFFICIENT incident became LIMITED (`SAME_VANTAGE_ONLY`); the three synthetic envelope scenarios (identity and cloud, network and endpoint, e-mail and forensic) stay SUFFICIENT. Tests: `test_vantage_independence.py` (22), the two-path parity test in `test_stage7b_parity.py`, and the unchanged development counts pinned in `test_metamorphic_sufficiency.py` and `test_ablation_sufficiency.py`.

## Alternatives considered
1. Keep record-level independence and state the limit. Rejected once a real-data case showed the cost.
2. Require two vantage points for any SUFFICIENT (this ADR, applied to the corroborating chain).
3. Weight corroboration by vantage (a score). Rejected: an unexplained number, against the deterministic and explainable rule.

## Consequences and limits (stated plainly)
- **The rule table is still labelled `suff-v4`.** The label is pinned in 35 places (stored results, integration tests, report text), so renaming it to `suff-v5` is a separate mechanical change that needs owner approval of this ADR. Until then the cap is recorded in every affected result by the `SAME_VANTAGE_ONLY` reason code, and results without it are identical to before. A result stored before 2026-11-24 for same-vantage-only evidence still says SUFFICIENT until the evidence changes or it is re-run.
- **Vantage is coarse.** Two different sensor instances of one type at one host count as one vantage, and a record forwarded through a second system is merged by duplicate clustering rather than counted as a second vantage.
- **No labelled evidence yet** says the cap is right. It follows the project's own definition of independence; whether analysts agree needs the owner's labels.
- **The development dataset cannot exercise it** (no vantage in the locked cases); the controlled annotations above are the evidence, plus the real public data.
- Verdicts on stored demo investigations that rely on same-vantage corroboration will fall to LIMITED when re-run.

## Decision
Owner approval of the record, and of renaming the rule table to `suff-v5`, is pending.
