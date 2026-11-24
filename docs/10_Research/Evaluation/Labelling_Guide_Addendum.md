# Labelling guide addendum (ADOPTED for the owner's labelling, 2026-11-24)

Written 2026-11-24 and adopted the same day on the project owner's "ok go ahead" to the proposal. It applies together with `datasets/sufficiency_eval/labelling_guide.md`, which is covered by the dataset hash manifest and was NOT changed. `backend/evaluation_tools/label_cases.py` prints these four rules at the start of every interactive session and records the guide version in the labels file, so the labels say which rubric they were written under. The owner may reverse this decision before labelling; labels written under the literal guide are a legitimate alternative and should then be reported as such.

## Why this exists
A reference implementation of the guide, written only from the guide's text (`backend/evaluation_tools/rubric_oracle.py`), agrees with the gate on all 65 judged development cases (Cohen's kappa 1.000; the 2 built as contradictory are excluded because the oracle cannot read meaning). It disagrees with the gate on the situations the guide does not mention. Run over the 2,250-case synthetic benchmark (final seed), the literal guide calls the following SUFFICIENT although they were built not to be corroborated:

| Situation | What the guide literally implies | What the gate does | Literal-guide SUFFICIENT out of 250 |
|---|---|---|---|
| A copy of the same observation arrives later, with a new digest (a replay or forwarded copy 3 to 60 s later) | A different raw record sharing a specific artefact corroborates | The same observation (same host, event id, type, action) is a repetition, not independent proof | 250 |
| A second observation sharing an artefact, but seen by the same sensor at the same host (ADR-017) | Silent; counts as corroboration | One vantage is one witness; SUFFICIENT is capped at LIMITED (`SAME_VANTAGE_ONLY`) | 250 |
| The shared artefact is a placeholder (all-zero or repeated-character hash, `localhost`, a private address, a one-word domain) | A shared "file hash" or "domain" corroborates | A placeholder or non-public value is only a weak link | 150 |
| A near-duplicate (re-serialised copy within about 2 s) | "Not a duplicate or near-duplicate", never defined | Same identity and entities within 2 s are one evidence unit | 176 (depends on how near-duplicate is read) |

If the owner labels by the guide alone, these cases will be labelled SUFFICIENT and the gate will be scored as wrong on them, for a reason the guide could have settled. If the owner prefers the literal guide, that is a legitimate choice, but it should be made knowingly.

## Proposed clarifications (for the owner to accept, change or reject)
1. **Repeated observation.** A later record of the same observation (same host or sensor, event id, event type and action) is a repetition, not corroboration, even if its digest differs. Corroboration needs a different observation.
2. **Vantage.** Records seen by the same source type at the same host are one witness. Corroboration needs records from at least two vantage points somewhere in the chain of specific links around the key event. If the source of a record is not stated, do not assume it is the same.
3. **Placeholder artefacts.** An empty, all-zero or repeated-character hash, `localhost`, a loopback, private or link-local address, or a single-label name is not a specific artefact.
4. **Near-duplicate.** Records with the same identity and the same entities within 2 seconds of each other are one record.

## What changes if adopted
Labels written under the addendum describe the rules the project actually claims, so agreement with the gate measures the gate and not the guide's silence. It also makes labelling less independent of the gate (the labeller is told its rules). Report which version of the guide was used and keep the literal-guide labels for the four situations separately if you want both numbers.

## Reproduce
`.venv\Scripts\python.exe backend\evaluation_tools\rubric_oracle.py` (development agreement); the family table comes from running `rubric_label` over `synthetic_benchmark.generate` at seed 20261124 with 250 cases per family.
