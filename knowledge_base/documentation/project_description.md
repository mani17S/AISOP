# AISOP project description

AISOP is an analyst-controlled security operations workbench. It ingests alerts and telemetry from different sources, normalizes them to one format, keeps the raw record and its SHA-256, and lets analysts build cases and evidence-grounded reports.

## Principles
- Raw evidence, hashes and provenance are preserved. A missing timestamp, source or relationship is never invented.
- Duplicate and near-duplicate records count as one piece of evidence.
- Analyst statements, threat intelligence and AI output are shown separately from observed evidence and never establish technical corroboration.
- One evidence sufficiency check reports sufficient, limited or insufficient, with reasons.
- The language model is optional. Deterministic analysis works with it switched off.
- Reports and detection rules are released only after an analyst approves them.

## Users
Tier-1 and Tier-2 analysts, incident responders and detection engineers. Roles are enforced by the server, per case.
