# Analyst investigation workflow

## When to use
Use this workflow for any alert that an analyst intends to investigate in AISOP, whatever the source. The workflow does not depend on a particular vendor or event ID.

## Triage
- Read the source, observed time, observables (address, domain, hash, user, process) and the raw digest.
- Severity is the source's judgement. It does not measure how well the evidence is corroborated.
- Two alerts about the same event from different tools are one piece of evidence.
- Promote the alert to a case only if it needs investigation. The promoting analyst becomes case lead.

## Link evidence
- Link related normalized events to the case. Import evidence from other sources into the same case.
- Missing fields stay missing. Never supply a timestamp, source or relationship that the record does not contain.

## Run the deterministic investigation
- Start it from the case. It builds a timeline, correlates records, maps ATT&CK techniques by rule and issues a sufficiency verdict. It needs no language model.
- SUFFICIENT means at least one different, attested record shares a specific artifact with the first, such as a file hash, public address, domain or logon session. It is not a confirmed finding.
- LIMITED means bounded findings only. Read each reason code and either gather what it asks for or state the limit.
- INSUFFICIENT means no conclusion is offered and no AI analysis runs.
- Weak links (same host, user or internal address) are context, not corroboration.

## Optional AI explanation
- Start it only on request. Claims are labelled observed fact or inference. Claims the evidence does not support are shown as unsupported and must not be used.
- An AI statement is never observed evidence and never corroborates anything.
- If the model is disabled or fails, the deterministic result stands.

## Decide and report
- Record one decision: close, escalate to a Tier-2 or admin lead, or request more telemetry. Give a reason.
- The case lead approves or rejects the current result. A report is released only after approval, and only for evidence that has not changed since.
- State every limitation in the report. Do not close a LIMITED case as resolved without saying so.
