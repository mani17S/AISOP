# Architecture Diagrams (drawn from the source, 2026-11-21)

Each component is marked **IMPLEMENTED** (source exists and tests were run), **PARTIAL** (exists but limited or not wired into the path shown) or **PLANNED** (design only). "Implemented" does not mean verified on real data: everything was exercised on synthetic data. Source paths are in brackets.

## 1. Architecture

```mermaid
flowchart TD
  S["Sources: JSON alerts, Sysmon events, evidence envelopes<br/>IMPLEMENTED on synthetic samples only"]
  S --> P["Intake perimeter: auth, roles, size limits, rate limit<br/>IMPLEMENTED [api/, middleware/, core/rbac.py]"]
  P --> A["Parsers: 8 alert adapters, Sysmon parser, 6 domain adapters<br/>IMPLEMENTED, sample-shaped [modules/alerts, evidence, evidence_domains]"]
  A --> E[("Evidence store, PostgreSQL 17<br/>raw payload + SHA-256, events, entities, cases, audit<br/>IMPLEMENTED, 34 PG tests passed")]
  E --> C["Deterministic core: observations, correlation, duplicate collapse,<br/>timeline, 13 ATT&CK rules, ONE sufficiency gate<br/>IMPLEMENTED [modules/correlation, evidence_domains, ai/guardrails]"]
  C --> R["Deterministic report<br/>IMPLEMENTED [ai/reporting/synthesizer.py]"]
  C -->|"only if the gate allows"| L["Optional local model (Ollama, one provider) + claim verification<br/>IMPLEMENTED, small model, on demand [ai/llm, ai/guardrails]"]
  L --> R
  R --> U["Analyst workbench (React)<br/>IMPLEMENTED"]
  K[("pgvector knowledge base (RAG)<br/>PARTIAL: case synthesis with a query filter only, corpus uncommitted")] -.-> L
  T["Threat intelligence (offline feeds, shield)<br/>PARTIAL: not applied in the investigation"] -.-> C
  AP["Lead review record of the investigation<br/>PARTIAL: multi-source export gated on approval; case-synthesis reports not gated"] -.-> U
  D["Detection engineering (Sigma)<br/>PLANNED: empty files"] -.-> U
  N["Native Suricata EVE source<br/>IMPLEMENTED: file conversion, synthetic-tested; alert, dns, flow only"] -.-> A
```

## 2. Trust boundaries

```mermaid
flowchart LR
  subgraph UNTRUSTED["Untrusted input"]
    EV["Evidence text: alerts, events, notes<br/>escaped, bounded, never executed"]
  end
  subgraph CORE["Deterministic core (no model, no network)"]
    ST["Stored raw record + SHA-256"]
    LK["Typed links, duplicate collapse, contradictions"]
    GT["Sufficiency gate: fails closed, abstains"]
  end
  subgraph OPTIONAL["Optional, never a source of truth"]
    LLM["Local model: loopback only, no silent fallback"]
    CV["Claim verifier: checks each claim against evidence"]
  end
  EV --> ST --> LK --> GT
  GT -->|"sufficient or limited"| LLM --> CV
  GT -->|"insufficient: no model call"| OUT
  CV --> OUT["Report labels each statement: observed, inferred, external, analyst, AI"]
  OUT --> AN["Analyst decides"]
```
Rules enforced in code: duplicates count once; analyst notes, threat intelligence and model output never corroborate; missing time stays missing; the model's output is never observed evidence [`correlation/correlator.py`, `evidence/independence.py`, `ai/guardrails/`].

## 3. Investigation sequence

```mermaid
sequenceDiagram
  participant Sn as Sensor (ingest identity)
  participant API as Backend
  participant DB as PostgreSQL
  participant An as Analyst
  participant M as Local model (optional)
  Sn->>API: POST /alerts/ingest (batch)
  API->>DB: raw payload + SHA-256, per-alert errors, duplicates skipped
  An->>API: create case, link evidence
  An->>API: start investigation (model off)
  API->>DB: re-derive from preserved raw evidence, correlate, gate
  API-->>An: deterministic result (timeline, links, ATT&CK, verdict) immediately
  opt Analyst presses Run AI explanation (timer, Cancel, 90 s limit)
    An->>API: start investigation (model on)
    API->>M: only if the gate allows
    M-->>API: answer
    API->>API: claim verification, or deterministic fallback
    API-->>An: result with AI status per incident
  end
  Note over An,API: Timeout or cancel leaves the deterministic result unchanged
```

## Gaps these diagrams make visible
Real vendor formats, an approval step, threat-intelligence use in the investigation, RAG in the deterministic path, detection engineering and a native network source are not implemented. They are drawn dashed on purpose.
