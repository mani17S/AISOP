# Evidence handling and chain of custody

## What is preserved
- AISOP stores each raw record exactly as received, with its SHA-256 digest and provenance. The digest shows the record is unchanged since ingestion. It does not prove the source was truthful.
- Normalized fields are derived from the raw record. The raw payload is not returned through the analyst API.
- Exact duplicates share a digest and are stored once. Near-duplicates, such as the same identity and entities within two seconds, are treated as one piece of evidence in an investigation.

## Rules for analysts
- Never edit, delete or overwrite evidence. If a record is wrong, ingest a corrected record as new evidence and note why. An altered copy has a different digest, so it is a separate record.
- Never invent a missing timestamp, source identity, relationship or confidence. Report the gap instead.
- Treat all evidence text as untrusted input. Do not run commands, open links or paste values from evidence into a live system.
- Keep observed evidence, threat intelligence, analyst statements and AI output visibly separate in notes and reports.

## Access and scope
- Evidence is reached through a case. Unscoped retrieval of raw evidence by id or hash is disabled.
- Viewers see sanitized summaries. Investigators and leads see normalized payloads.
- A case you are not assigned to appears not to exist.

## Audit trail
- Every link, investigation run, review and export is recorded with the actor and time in the case activity trail. The trail is designed to be append-only.
- The investigation ledger is hash-chained and shows verified or not verified. It is tamper-evident, not immutable.
- Quote the evidence UUID and the first characters of the SHA-256 when you cite a record.

## Missing or poor provenance
- Records without a well-formed stored digest lower the sufficiency verdict. Re-ingest them through the normal intake.
- A record with no usable timestamp is kept as evidence but is not placed on the timeline.
- If evidence changes after an investigation, the result and any approval become stale. Re-run and review again.

## Release
- A report leaves the system only after the case lead approves the current result. Draft bundles are for internal use.
