# Research Gap

**Read this first.** The gap below is stated by the project. It has **not** been established by a literature review. No search of papers or products was done for this document, and nothing here claims that other tools lack these features. Before it is presented as a research gap, it needs a proper literature and product comparison.

## The working position
Many investigation tools correlate records and many assistants summarise them. The project's position is that two properties are worth making explicit, testable and deterministic in one local-first tool:

1. **Evidence independence.** Duplicates, near-duplicates and records that only share a weak context (a bare host, user or internal address) do not count as corroboration. Analyst notes, threat intelligence and model output never count.
2. **Abstention.** When the independent evidence is not enough, the system says so and does not call a model.

A language model is then an optional layer on top: its output is checked claim by claim against the evidence and labelled as generated.

## What is engineering, what is research, what is unproven
| Layer | Status |
|---|---|
| Building the pipeline (ingest, correlate, timeline, rules, report, UI) | Engineering. Implemented and tested on synthetic data. |
| Several ideas are adapted from public projects (see `docs/10_Research/AiSOC_Adaptation_Register.md`) | Acknowledged. The combination is an applied integration, not a new algorithm. |
| "Independence and abstention rules reduce unsupported conclusions" | A testable hypothesis. **Not yet tested**: no labels, no baseline comparison, no held-out run (see `docs/10_Research/Evaluation.md`). |
| Novelty compared with the literature or other products | **Unknown.** Requires the literature and product review that has not been done. |

## What would close the gap
1. A literature and product review, with sources the student has actually read, comparing how others treat corroboration and abstention.
2. The experiment in `docs/10_Research/Evaluation.md`, reported with its failures.

## Honest limits
The data is synthetic and author-built. The reference deck from phase 1 cites papers that were not verified in this work and must not be repeated as support until they are.
