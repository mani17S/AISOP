# AISOP Detection Engineering: Implementation Roadmap

Status: **PROPOSAL, not approved.** No milestone below has started. Companion to `DETECTION_ENGINEERING_ARCHITECTURE.md`. Each milestone is small enough to verify offline, ends with an acceptance gate, and does not deploy anything.

## Preconditions (Owner decisions, all PENDING)
1. Approve ADR-011 and ADR-012 (PROPOSED).
2. Sigma validation approach: in-house subset validator (recommended first) versus `pySigma` (new dependency, needs review).
3. Persistence: new tables (needs a migration the Owner authorises) versus ADR-010-style audit-row storage for the prototype.
4. Approver policy: may the proposer approve their own rule? (recommended: no).
5. Resolve or accept the Stage 6 sufficiency gap (cross-sensor contradictions are not weighed by the gate); detection candidates must not be built from incidents with unresolved contradictions.

## Milestones
| ID | Scope | Depends on | Acceptance gate (all offline) | Status |
|---|---|---|---|---|
| DE-0 | Canonical `endpoint.process_creation` observation (parent image, image, command line, user, host, hashes), adapter tests, correlation integration, and one new rule-based ATT&CK mapping for process lineage (e.g. T1059 with explicit limitation); sysmon-alert bridge for parent image | Stage 6 baseline | Existing 1509 backend tests still pass; new adapter/graph/ATT&CK tests; no change to sufficiency rules | PROPOSED |
| DE-1 | Finding interface and opportunity identification with abstention reason codes; read-only API `GET .../detections/opportunities` | DE-0 | Refuses stale, INSUFFICIENT, analyst-only and single-victim-constant findings (tests); case isolation tests | PROPOSED |
| DE-2 | Rule model, deterministic template generator, Sigma serialisation, round-trip and determinism tests | DE-1 | parse(serialize(rule)) == rule; hostile values cannot change structure; identical bytes on rerun | PROPOSED |
| DE-3 | Schema and log-source validators; field catalogue; unsupported-field reporting | DE-2 | Fixture corpus of valid and invalid rules; every unsupported field flagged | PROPOSED |
| DE-4 | Matcher, positive and negative test generation, FP assessment; optional pySigma cross-check if approved | DE-3 | Web-server-shell example: positives match, benign negatives do not; no benign corpus gives `NOT_ASSESSED` | PROPOSED |
| DE-5 | Versioning, provenance, review state machine, approval and export APIs, audit rows, persistence per Owner decision | DE-4 + persistence decision | Export refuses unapproved or modified rules; audit failure suppresses state change; RBAC and IDOR tests | PROPOSED |
| DE-6 | Frontend: opportunities, rule view, tests, FP risks, approval and export; AI-skipped states | DE-5 | SSR tests, typecheck, build; escapes untrusted text; shows "validation is not effectiveness" | PROPOSED |
| DE-7 | Optional LLM candidate proposer behind `GatedGenerator`; candidate re-validated; prompt-injection tests | DE-6 | LLM disabled: all earlier gates pass; failure produces no candidate; AI output never reaches APPROVED without human action | PROPOSED |
| DE-8 | Evaluation on synthetic scenarios A/B/C plus new endpoint scenarios; report | DE-7 | Honest report: validity, test results, abstentions; no effectiveness claim | PROPOSED |

## Out of scope for the whole track
Automatic deployment; production tuning; querying customer SIEMs or EDR; GRC, compliance, policy and audit workflows; platform-specific export in the first release (later, optional).

## Risks
* Generated rules look authoritative: mitigated by mandatory test and limitation display and a human gate.
* Over-fitting to one victim: abstention rules and constant detection.
* Telemetry mismatch: unsupported-field blocking.
* Scope creep into SIEM behaviour: hard product boundary.
* Dependency risk if pySigma is adopted: review before use; keep in-house validator as the primary check.

## Next implementation milestone
**DE-0**, because the Stage 6 observation model cannot express process lineage, which is the first behaviour the Detection Engineering acceptance example needs. It is also a self-contained extension of verified code, with no new dependency and no migration.
