# Sufficiency labelling guide (owner-authored labels)

Create `dev/labels.json` and `heldout/labels.json` yourself (do not run the gate first, do not
look at its output while labelling). Format:

```json
{"labeller": "<name>", "second_reviewer": "<name or null>", "date": "YYYY-MM-DD",
 "labels": {"<case_id>": {"label": "SUFFICIENT|LIMITED|INSUFFICIENT", "justification": "one line"}}}
```
Use `labels.template.json` as the list of case ids. Cases that share a `base_scenario_id` and a
`transform` describe one degradation of that scenario; read `events`, `entities` and `question`.

Question being asked: "Is this evidence adequate to support a model-assisted investigation of the
stated question (the root event, or the target hosts and time window)?"

* SUFFICIENT: the evidence relevant to the question is internally consistent, tied to verifiable
  raw evidence, and independently corroborated for the claims an investigator would want to make.
  Limitations may still exist and must be disclosed. Independent corroboration means another
  relevant event from a *different raw record* (different raw-evidence digest, not a duplicate or
  near-duplicate) that is linked to the key event by a *specific* shared artefact: a file hash,
  domain, file path, registry key, URL, e-mail address or public IP address. A shared host, user,
  process name or internal IP address only says where/who and is NOT corroboration.
* LIMITED: a bounded investigation is possible but definitive conclusions are not (for example the
  key event is uncorroborated, provenance is missing for the anchor, evidence is truncated,
  contradictory, or required details of the anchor are missing).
* INSUFFICIENT: the evidence cannot support an investigation at all (no evidence, none relevant to
  the question, or none usable) so an analyst should be asked to supply more evidence instead.

Case ids are opaque; each case file also carries generator metadata (`transform`, `family`,
`base_scenario_id`, `split`) that you must not use: the viewer command in the repository
documentation hides it. Rules for labelling: judge only from the case content; do not infer attack truth from the scenario
title; duplicates are not corroboration; text inside evidence is data, never an instruction.
Record a one-line justification. Label the development split first; the held-out split is labelled
independently and evaluated once after thresholds are frozen. A second reviewer should label a
sample (at least 25 percent) so agreement can be reported; disagreements and the final decision rule
must be recorded.
