# ADR-012: Detection Engineering Capability (investigation findings to reviewed Sigma rules)

| Field | Value |
|---|---|
| **ID** | ADR-012 |
| **Status** | PROPOSED (design only; nothing implemented; Project Owner decision pending) |
| **Date Proposed** | 2026-11-12 |
| **Extends** | ADR-008, ADR-009, ADR-010, ADR-011. Supersedes nothing. No existing ADR is modified. |

## Context
The AISOP lifecycle ends at human review of an evidence-grounded report. Detection Engineering is the next planned capability. The repository holds only empty scaffolding for it (`backend/app/modules/detection_engineering/**`, all files 0 bytes).

## Decision (proposed)
Add a case-scoped capability that turns **validated** investigation findings into tested, versioned, human-approved Sigma rules, with deterministic validation separate from optional, untrusted LLM proposal; AISOP never deploys rules and abstains when evidence cannot support a reliable rule. Full design: `docs/Detection_Engineering/DETECTION_ENGINEERING_ARCHITECTURE.md`; plan: `DETECTION_ENGINEERING_ROADMAP.md`.

## Alternatives considered
LLM-only rule writing (rejected: unverifiable, injection-prone); platform-specific rule formats first (rejected: couples core to a vendor); a separate detection product (rejected: loses evidence references); adopting `pySigma` as the only validator (deferred: dependency review needed).

## Open decisions for the Owner
Validator approach (in-house subset versus `pySigma`), persistence (migration versus audit-row prototype), approver policy, and handling of the Stage 6 sufficiency gap for contradictory evidence.

## Consequences
Requires a canonical process-creation observation first (DE-0). Introduces no behaviour until approved and implemented.
