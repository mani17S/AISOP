# ADR-017: Vantage-Level Independence for Corroboration

| Field | Value |
|---|---|
| **ID** | ADR-017 |
| **Status** | **PROPOSED.** Not implemented. No code, dataset or rule version was changed. Owner decision required. |
| **Date** | 2026-11-23 |
| **Relates to** | ADR-008 (sufficiency gate), ADR-013 (contradiction-aware sufficiency), `docs/10_Research/Contribution_Statement.md`, `docs/10_Research/Real_Format_Ingestion_Result.md` |
| **Does not change** | Anything today. It describes a possible next version of the gate (`suff-v5`). |

## Context
The gate treats two records as independent corroboration when they are different raw records (after duplicate clustering), are linked by a specific or strong artefact, and are different observations. It does not ask whether they came from different *vantage points*.

Measured evidence (2026-11-23): on a real public Windows dataset (OTRF, MIT) one incident became SUFFICIENT from two Sysmon records on one host, a registry event (event 12) and a registry value set (event 13) by the same `svchost.exe` process instance, joined by a process-GUID link. Both came from one sensor and the activity is ordinary. The gate behaved as designed; the design is what is in question. The source-dependence literature in data fusion (Dong, Berti-Equille, Srivastava, read at abstract level only) makes the same distinction between independent sources and copies.

`ContextEventItem` has no field for the sensor or provider (`source_identifier` is the host or sensor id), so the gate cannot tell vantage points apart today.

## Options
1. **Keep record-level independence** and state the limit (current behaviour).
2. **Add a vantage field and require at least two vantage points for SUFFICIENT**; same-vantage corroboration caps the verdict at LIMITED with a disclosed reason (for example `SAME_VANTAGE_ONLY`). Verdict can only fall, never rise.
3. **Weight corroboration by vantage** (a score). Rejected for now: adds an unexplained number, against the project's deterministic and explainable rule.

## Recommendation (agent's, not a decision)
Option 2, after the defence, as `suff-v5`. It is a one-directional tightening, so it is consistent with the fail-closed principle, and it directly addresses a measured finding. It must not be done before the current labels and the held-out run, because it changes verdicts.

## What implementing it would need (estimate 1.5 to 2 days)
- A `vantage` field (for example the adapter's source type plus the sensor id) on the context event, filled by the context builder from stored events.
- A new dataset version: the current 115 cases are hash-locked and carry no vantage; the generator must emit it, and any labels written against v1 would need re-checking.
- A new rule version `suff-v5`, tests, and a metamorphic relation R6: adding records from the same vantage must not raise the verdict.
- Re-running the ablation and the labelled comparison on the new version, reported beside v4.

## Risks
Verdicts on existing demos fall (more LIMITED); synthetic cases may lack realistic vantage diversity; a sensor id that differs by name only could be mistaken for independence (needs a rule on aliases).

## Decision
Pending. Until decided, the limit is stated in the defence material and nothing is claimed about vantage-level independence.
