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
| [ADR-006](ADR-006_SDLC_and_DevSecOps_Strategy.md) | Software Development Life Cycle (SDLC) & DevSecOps Strategy | APPROVED | 2026-10-16 |
| [ADR-007](ADR-007_Vendor_Neutral_Alert_Ingestion.md) | Vendor-Neutral Security Alert Ingestion Architecture & Adapter Registry | APPROVED | 2026-10-31 |
| [ADR-008](ADR-008_Evidence_Sufficiency_Gate.md) | Deterministic Evidence-Sufficiency Gate before LLM Invocation | PROPOSED (revised 2026-11-12, suff-v3; approval pending) | 2026-11-11 |
| [ADR-009](ADR-009_Multi_Source_Correlation_and_Deterministic_ATTACK_Mapping.md) | Multi-Source Evidence Correlation, Timeline and Deterministic ATT&CK Mapping | PROPOSED (implemented 2026-11-12; approval pending) | 2026-11-12 |
| [ADR-010](ADR-010_Case_Scoped_Multi_Source_Investigation_Integration.md) | Case-Scoped Multi-Source Investigation Integration (API, audit-row persistence, analyst UI) | PROPOSED (implemented 2026-11-12; offline-tested only; approval pending) | 2026-11-12 |
| [ADR-011](ADR-011_Source_Agnostic_Evidence_Domain_Architecture.md) | Source-Agnostic Evidence-Domain Architecture (canonical observations, investigation graph, domain adapters) | PROPOSED (implemented 2026-11-12; offline-tested only; approval pending) | 2026-11-12 |
| [ADR-012](ADR-012_Detection_Engineering_Capability.md) | Detection Engineering Capability (investigation findings to reviewed Sigma rules) | PROPOSED (design only; not implemented) | 2026-11-12 |
| [ADR-013](ADR-013_Contradiction_Aware_Sufficiency.md) | Contradiction-Aware Evidence Sufficiency (revision proposal for the ADR-008 rule table) | APPROVED for implementation 2026-11-12 (Revision 2); implemented: ordering, outcome, identity, temporal (STATE not declared); case_service integrated | 2026-11-12 |
| [ADR-014](ADR-014_Evidence_Visibility_and_Case_Linking_Scope.md) | Evidence Visibility and Case Linking Scope (single-tenant pool, audited linking, closing the id-existence oracle) | APPROVED 2026-11-22 (Option A; audit already implemented, existence test accepted as residual risk) | 2026-11-22 |
| [ADR-015](ADR-015_Human_Authentication_MFA_and_Signed_Approvals.md) | Human Authentication, MFA and Signed Approvals (step-up MFA, HMAC-signed ingestion, signed approvals; threat model for MFA fatigue, evil-proxy session theft and endpoint malware) | PROPOSED (2026-11-22; design only, not implemented) | 2026-11-22 |
| [ADR-016](ADR-016_Opt_In_Hosted_AI_Provider.md) | Opt-In Hosted AI Provider for the Public Demo (Cloudflare Workers AI for generation and embeddings; synthetic data only; daily budget) | PROPOSED (2026-11-23; implemented and offline-tested; owner confirmation wanted) | 2026-11-23 |
| [ADR-017](ADR-017_Vantage_Level_Independence.md) | Vantage-Level Independence for Corroboration (same-sensor corroboration capped at LIMITED; measured on real data) | APPROVED 2026-11-24 (implemented; rule table renamed suff-v5) | 2026-11-23 |
| [ADR-018](ADR-018_Analysis_Worker_Process.md) | Analysis Worker Process for Large Multi-Source Investigations (optional bounded process pool, default off; measured in a spike) | APPROVED 2026-11-26 (implemented; default off; acceptance criteria only partly met, responsiveness issue stays open) | 2026-11-26 |
