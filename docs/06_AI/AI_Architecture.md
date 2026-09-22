# AISOP AI Subsystem Architecture

| Field | Value |
|---|---|
| **Document ID** | AI-ARCH-001 |
| **Status** | ACTIVE |
| **Governing ADRs** | [ADR-001: AI Layer Abstraction](file:///docs/03_System_Design/ADR/ADR-001_LLM_Layer_Abstraction.md), [ADR-002: Vector Database](file:///docs/03_System_Design/ADR/ADR-002_Vector_Database.md) |
| **Last Updated** | 2026-09-22 |

---

## 1. Executive Summary

The AISOP Artificial Intelligence (AI) Subsystem serves as the core reasoning engine for security investigation assistance. It assists Security Operations Center (SOC) analysts by automating tedious analytical tasks:
- Correlating evidence across process, network, file, and registry artifacts.
- Mapping observed indicators and attacker behaviors to the MITRE ATT&CK knowledge base.
- Generating investigation hypotheses with transparent confidence scoring.
- Formulating actionable, non-destructive next steps for incident responders.
- Generating role-tailored incident reports (Executive, Technical, Detection Engineering).

---

## 2. Core Architectural Principles

1. **Lightweight Protocol Abstraction (ADR-001):**
   AISOP core business logic never couples to proprietary LLM frameworks (e.g. LangChain, LangGraph, LlamaIndex) or vendor SDKs. All AI interactions flow through a runtime checkable `LLMProvider` Protocol.
2. **Local-First Reference Implementation:**
   The reference deployment is fully local and zero-cost, backed by a local Ollama instance running open-weights models (`llama3.1:8b` or `mistral:7b`) with zero telemetry or cloud leakage.
3. **No Autonomous Containment or Destructive Actions:**
   In accordance with the AISOP Charter, the AI subsystem is strictly **advisory and analytical**. It never executes containment actions, process kills, firewall changes, or data deletion.
4. **Deterministic Testing:**
   All AI adapters are verified using deterministic in-memory mock transports (`httpx.MockTransport`), requiring zero live daemon or GPU availability in CI pipelines.
5. **Streaming Deferred to Frontend:**
   Streaming generation is deferred to Phase 4 (Investigation Dashboard). Phase 2 backend pipelines consume complete, validated JSON or text responses.

---

## 3. Subsystem Component Hierarchy

```
AISOP AI Subsystem
├── Provider Layer (P2-H1)
│   ├── Protocol: LLMProvider
│   ├── Data Contracts: LLMRequest, LLMResponse, TokenUsage, ProviderHealthResponse
│   ├── Exceptions: LLMError hierarchy
│   ├── Reference Adapter: OllamaProvider (async httpx + tenacity)
│   └── Manager: get_llm_provider() factory
├── Knowledge & Retrieval Layer (P2-H2 / P2-H3) [Deferred to Next Milestones]
│   ├── MITRE ATT&CK Ingestion
│   └── pgvector Semantic Search (ADR-002)
├── Threat Intelligence Correlation Layer (P2-H4) [Deferred to Next Milestones]
│   └── Cache-backed, opt-in TI enrichment
└── SOC Reasoning & Reporting Engine (P2-H5 / P2-H6 / P2-H7) [Deferred to Next Milestones]
    ├── ContextBuilder & Prompt Engineering
    ├── Investigation Hypothesis Generator
    └── Role-Tailored Report Synthesizer
```

---

## 4. Milestone Implementation Reference

For detailed specifications of the provider contract, schemas, Ollama API mapping, error handling, and health probing, refer to:
* **[LLM Provider Contract Specification](file:///docs/06_AI/LLM_Provider_Contract.md)**
* **[ADR-001: AI/LLM Layer Abstraction Strategy](file:///docs/03_System_Design/ADR/ADR-001_LLM_Layer_Abstraction.md)**
