# ADR-014: Evidence Visibility and Case Linking Scope

| Field | Value |
|---|---|
| **ID** | ADR-014 |
| **Status** | **PROPOSED**. Not approved and not implemented. The owner decides. |
| **Date Proposed** | 2026-11-22 |
| **Raised by** | OWASP API Top 10 review, `docs/07_Security/OWASP_API_Top10_Review.md` (open items on the evidence link endpoint) |
| **Relates to** | ADR-007 (alert ingestion), ADR-010 (case-scoped investigation), the case assignment model in `backend/app/core/rbac.py` |

## Context
Cases are strictly scoped: an unassigned analyst gets the same response for a case that exists and one that does not (verified live, 54 probes, no difference). Evidence events are not scoped the same way. They form one global pool that every Tier-1, Tier-2 and security-admin analyst can list through the alert and evidence triage views, and `POST /api/v1/cases/{case_id}/evidence` lets an investigator or lead of a case link any event id into that case. Two consequences were found:

1. Anyone who holds a case investigator or lead role can attach any event in the system to their own case and then read it through the case-scoped views.
2. The link endpoint answers `EVIDENCE_NOT_FOUND` (404) for an unknown id and `409` or `201` for a known one, so an investigator can test whether an event id exists. The ids are random UUIDs, which makes guessing impractical, but the difference exists.

This is by design for a single-tenant SOC in which triage is a shared queue. It becomes a real exposure if AISOP is ever used by teams that must not see each other's telemetry, or if some sources are sensitive (HR, legal, executive mailboxes).

## Options
A. **Keep the global pool, make linking accountable.** Leave the model as is, document it as single-tenant, and add an audit event on every link that records the actor, the event id and its source. Collapse the 404 versus 409 difference so an unknown id and an already-linked id give the same response to an investigator. Cheapest. Does not stop a determined insider.
B. **Source partitions.** Give each evidence source a sensitivity label and a list of roles or teams that may triage and link it. Linking requires access to the source. Closes the gap for sensitive sources. Needs a migration, an admin interface and tests for every read path.
C. **Link by promotion only.** Evidence enters a case only through the "promote alert" action by someone who can triage that alert, never by raw id. Removes the id-oracle. Changes the analyst workflow, since linking by UUID is used today.

## Recommendation
Adopt A now, because it is small, reversible and honest about the single-tenant assumption, and record B as the path if multi-team use is ever required. Do not adopt C without checking how often analysts link by id.

## Consequences if A is adopted
- The security documentation states that AISOP is single-tenant and that triage is a shared pool.
- Every link is an audited, attributable action.
- The existence test through the link endpoint is closed.
- Cross-team isolation is NOT provided and must not be claimed.

## What this ADR does not decide
Whether AISOP will ever be multi-tenant. The panel is more likely to ask about this than to ask for it to be built, so the answer should be stated plainly: single-tenant by design, with a documented path to partitions.
