# ADR-001: AI/LLM Layer Abstraction Strategy

| Field | Value |
|-------|-------|
| **ID** | ADR-001 |
| **Status** | APPROVED |
| **Date Proposed** | 2026-09-09 |
| **Date Approved** | 2026-09-09 |
| **Decision Maker** | Project Owner |

---

## Question

How should AISOP abstract the interface between its application logic and
the underlying LLM provider(s)?

## Context

AISOP's AI layer serves as the intelligence engine behind investigation
assistance — generating hypotheses, mapping MITRE ATT&CK techniques to
evidence, suggesting investigative next steps, and producing role-tailored
reports. This layer is invoked from multiple backend services (case analysis,
evidence correlation, detection engineering, reporting).

The decision determines:

- How tightly coupled the backend becomes to a specific LLM vendor or
  framework.
- How easily a contributor can swap providers (Ollama → OpenAI → custom).
- The debugging, testing, and security boundary between AISOP's evidence
  pipeline and the non-deterministic AI inference layer.
- Memory footprint, cold-start time, and dependency surface area — all
  critical for local-first workstation deployment.

AISOP Master Prompt references:

- §5: *"The AI layer must be replaceable. Do not design the entire application
  around one model, one vendor, or one framework."*
- §26: *"Do not add technology merely because it is popular. Every major
  dependency should answer: Why do we need it?"*
- §11: *"Avoid excessive framework usage."*

## Options Considered

### Option A: Direct Lightweight LLM Abstraction

Define a Python `Protocol` (~50–150 lines) specifying the contract any LLM
provider must fulfill. Each provider (Ollama, OpenAI, Gemini, Anthropic)
implements this protocol by making direct HTTP calls via `httpx`. Prompt
templates managed as Jinja2 or Python string templates. Retry logic via
`tenacity`. Structured output parsing via Pydantic v2.

Removes ~12 direct LangChain/LangGraph packages and dozens of transitive
dependencies from `requirements.txt`.

### Option B: LangChain / LangGraph Framework

Use `langchain-core` as the abstraction layer. LLM calls go through
LangChain's `ChatModel` interface. Prompts are `ChatPromptTemplate` objects.
Multi-step reasoning via `langgraph` state machine graphs.

Retains all 12 LangChain/LangGraph packages currently in `requirements.txt`.

### Option C: Hybrid (Direct now, optional LangGraph later)

Build the direct lightweight abstraction first (Option A). Introduce LangGraph
only if a future requirement genuinely needs complex cyclic multi-agent
orchestration — at that point, as an optional orchestration plugin behind the
existing protocol interface.

## Trade-Off Analysis

| Criterion | Option A: Direct | Option B: LangChain | Option C: Hybrid |
|-----------|-----------------|---------------------|-----------------|
| Local-First Deployment | Strong | Weak | Strong |
| Open-Source Extensibility | Strong | Weak | Strong |
| Modularity | Strong | Adequate | Strong |
| Security | Strong | Weak | Strong |
| Maintainability | Strong | Weak | Strong |
| Scalability | Adequate | Adequate | Adequate |
| Developer Experience | Strong | Weak | Strong |
| Testing | Strong | Adequate | Strong |
| Operational Complexity | Strong | Adequate | Strong |
| Future LLM Flexibility | Strong | Adequate | Strong |

## Recommendation

Option A (Direct Lightweight LLM Abstraction) was recommended. It scores
Strong on 9/10 criteria. LangChain creates dependency, security,
maintainability, and developer experience risks that directly contradict
AISOP's stated master requirements.

## Decision (Project Owner — 2026-09-09)

**APPROVED: Direct lightweight LLM/provider abstraction (Option A).**

AISOP Core must remain independent of LangChain/LangGraph.

The AI layer must expose a provider/interface abstraction so that local LLMs,
cloud LLMs, OpenAI-compatible APIs, or custom providers can be plugged in
without modifying AISOP Core.

LangChain/LangGraph shall not be added to the core architecture unless a
future requirement demonstrates a specific need and the Project Owner
explicitly approves it.

## Architectural Consequences

1. `requirements.txt` will be trimmed by ~12 direct LangChain packages and
   their transitive dependencies, significantly reducing the dependency
   surface and install size.
2. Every LLM interaction in AISOP will flow through a single, team-owned
   protocol interface that the project fully controls.
3. Prompt engineering becomes explicit: templates are files in `prompts/`,
   rendered with Jinja2 or Python string formatting, passed as plain strings
   to the HTTP API. No framework DSL.
4. Multi-step reasoning (analyze → correlate → suggest) is implemented as
   explicit Python async function composition, not as a LangGraph state
   machine.
5. If LangGraph is ever genuinely needed later, it can be added as an optional
   orchestration layer behind the existing protocol interface without
   rewriting core code.

## Risks

1. **Risk (Low): Complex Autonomous Agent Loops.** If a future feature
   requires genuinely complex autonomous multi-agent orchestration,
   implementing this from scratch without LangGraph would require more
   engineering effort. **Mitigation:** Add LangGraph surgically at that
   point, behind the existing protocol interface.
2. **Risk (Low): Community Provider Adapters.** Some community LLM providers
   may only offer LangChain adapters. **Mitigation:** Any provider with a
   LangChain adapter necessarily has an underlying REST API; the adapter
   source code documents the API contract.
