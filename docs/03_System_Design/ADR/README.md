# AISOP Architectural Decision Records (ADR)

## Purpose

This directory contains formal architectural decision records for the AISOP
project. Each ADR documents a significant technical decision, the alternatives
considered, the trade-offs evaluated, and the final decision made by the
Project Owner.

## Governance

- The **Project Owner** is the final decision maker for all architectural
  decisions.
- No agent, tool, or automated process may silently reinterpret, override, or
  contradict an approved ADR.
- If a future requirement conflicts with an existing ADR, a new ADR must be
  created documenting the proposed change, and the Project Owner must
  explicitly approve the supersession.
- Each ADR is immutable once approved. Amendments are recorded as new ADRs
  that reference the original.

## Format

Each ADR follows a standard structure:

1. **Title & ID** — unique identifier and descriptive title.
2. **Status** — `PROPOSED`, `APPROVED`, `SUPERSEDED`, or `DEPRECATED`.
3. **Date** — date the decision was approved.
4. **Context** — the architectural problem being addressed.
5. **Options Considered** — all alternatives evaluated.
6. **Evaluation** — trade-off analysis against AISOP requirements.
7. **Recommendation** — the agent's recommendation with reasoning.
8. **Decision** — the Project Owner's final decision.
9. **Consequences** — architectural implications of the decision.
10. **Risks** — identified risks and mitigations.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-001](ADR-001_LLM_Layer_Abstraction.md) | AI/LLM Layer Abstraction Strategy | APPROVED | 2026-09-09 |
| [ADR-002](ADR-002_Vector_Database.md) | Vector Database Selection | APPROVED | 2026-09-09 |
| [ADR-003](ADR-003_Python_Version.md) | Python Version Selection | APPROVED | 2026-09-09 |
| [ADR-004](ADR-004_Initial_Ingestion_Scope.md) | Initial Telemetry Ingestion Scope | APPROVED | 2026-09-09 |
| [ADR-005](ADR-005_Frontend_Stack.md) | Frontend Technology Stack | APPROVED | 2026-09-09 |
