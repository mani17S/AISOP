# ADR-006: Software Development Life Cycle (SDLC) & DevSecOps Strategy

| Field | Value |
|---|---|
| **ID** | ADR-006 |
| **Status** | APPROVED |
| **Date Proposed** | 2026-10-16 |
| **Date Approved** | 2026-10-16 |
| **Decision Maker** | Project Owner |
| **Governing Documents** | [ADR-001](ADR-001_LLM_Layer_Abstraction.md), [ADR-002](ADR-002_Vector_Database.md), [ADR-003](ADR-003_Python_Version.md), [ADR-004](ADR-004_Initial_Ingestion_Scope.md), [ADR-005](ADR-005_Frontend_Stack.md), [ARCH-001](../Architecture.md) |

---

## 1. Context & Problem Statement

AISOP (AI-Assisted Security Operations Platform) is designed as a local-first, analyst-centric security operations platform operating at the intersection of raw telemetry ingestion, canonical data normalization, deterministic investigation retrieval, vector semantic search, and AI-assisted hypothesis generation.

Developing an enterprise-grade security operations tool in an academic capstone setting introduces distinct engineering challenges:
1. **Academic Milestone Alignment:** Progress must align with scheduled project reviews, thesis evaluations, and milestone audits without sacrificing architectural coherence.
2. **AI & RAG Experimentation:** AI prompt engineering, knowledge base chunking, and similarity retrieval require rapid experimentation and fast feedback cycles.
3. **High-Assurance Security Constraints:** Telemetry parsers process untrusted endpoint data, vector databases are susceptible to retrieval poisoning, and LLM reasoning engines face prompt injection. Security cannot be treated as an afterthought or deferred to a final pre-release checklist.
4. **Prototype Drift Prevention:** Code developed during fast exploratory prototyping must not bypass type checking, boundary enforcement, or database integrity guarantees into production builds.

A formal software development life cycle (SDLC) methodology is required to govern how features are prototyped, hardened, verified, and released.

---

## 2. Options Considered

### Option A: Traditional Waterfall / V-Model
Sequential phase execution: Requirements $\rightarrow$ Design $\rightarrow$ Implementation $\rightarrow$ Verification $\rightarrow$ Maintenance.
* *Advantages:* Predictable scheduling; comprehensive upfront documentation.
* *Disadvantages:* Highly rigid; incompatible with prompt engineering and vector tuning; defects discovered late in integration require costly rework.

### Option B: Pure Rapid Application Development (RAD)
Emphasis on rapid iterative prototyping, interface mockups, and minimal formal documentation.
* *Advantages:* Maximum early velocity; immediate visual feedback.
* *Disadvantages:* High risk of architectural decay; weak security verification; prototype shortcuts often persist into production; inadequate for security-critical telemetry pipelines.

### Option C: Standard Scrum / Agile Sprints
Timeboxed sprints (e.g., 2 weeks) with sprint planning, daily standups, sprint reviews, and retrospectives.
* *Advantages:* Adaptable to changing priorities; steady cadence of deliverables.
* *Disadvantages:* Generic Scrum focuses on feature delivery rather than security gating; does not inherently mandate multi-tier test isolation or threat modeling at design time.

### Option D: Hybrid Agile + RAD Prototyping within Bounded Increments + DevSecOps (Selected)
Combines Agile milestone governance, RAD-style exploratory prototyping within strictly bounded increments, and continuous DevSecOps automated testing and security verification gates.
* *Advantages:* Preserves established project milestones; facilitates rapid AI experimentation; enforces non-negotiable security and database gates before merging; ensures complete traceability for academic defense.
* *Disadvantages:* Requires maintaining multiple automated test tiers (offline mocks vs live containerized services) and disciplined enforcement of prototype-to-production promotion criteria.

---

## 3. Evaluation & Trade-Off Analysis

| Evaluation Criteria | Option A: Waterfall | Option B: Pure RAD | Option C: Standard Scrum | Option D: Hybrid (Agile + RAD + DevSecOps) |
|:---|:---:|:---:|:---:|:---:|
| **Milestone Predictability** | High | Low | Moderate | **Optimal** (Preserves Phase structure) |
| **Exploratory Velocity (AI/RAG)** | Poor | Very High | Moderate | **High** (Bounded spike prototyping) |
| **Security & Defect Containment** | Late | Inadequate | Inconsistent | **Continuous** (Multi-tier DevSecOps gates) |
| **Architectural Integrity** | High | Low | Moderate | **Strict** (Enforced by ADR contracts) |
| **Prototype Promotion Governance** | N/A | Deficient | Moderate | **Strict** (Formal promotion criteria) |
| **Academic Audit Traceability** | High | Low | Moderate | **Exemplary** (Empirical test dossiers) |

---

## 4. Decision & Implementation Framework

Adopt **Option D: Hybrid Agile + RAD Prototyping + DevSecOps Strategy**. The methodology is governed by the following core architectural rules:

### 4.1 Milestone Organization & Rhythm
1. The development roadmap is structured into fixed architectural Phases and Milestones (Phase 1 Ingestion, Phase 2 AI & Threat Intel, Phase 3 Case Management, Phase 4 Frontend Workspace).
2. Existing milestone identifiers (`P1-H1` through `P4-H*`) are immutable. Milestones are never renumbered or reordered to match process ceremonies.
3. Each milestone operates as a self-contained increment: design review $\rightarrow$ prototyping spike $\rightarrow$ production hardening $\rightarrow$ multi-tier test verification $\rightarrow$ documentation synchronization $\rightarrow$ owner acceptance checkpoint.

### 4.2 Prototype vs. Hardened Production Code Separation
To prevent experimental prototype debt from leaking into production, code is classified into two distinct states:

* **Spike / Prototype Code:**
  * Permitted only in experimental test branches, scratch directories, or behind explicit development feature toggles.
  * May utilize in-memory mock transports (`httpx.MockTransport`) and synthetic data fixtures.
  * Must **never** be merged into the `main` branch or included in a release baseline.
* **Hardened Production Code:**
  * Must satisfy 100% strict type hints and Pydantic v2 input validation models.
  * Must enforce strict perimeter bounds (batch sizes, payload byte ceilings, pagination limits).
  * Must include Loguru structured logging with automated credential redaction.
  * Must utilize parameterized SQLAlchemy 2.0 expressions; dynamic raw SQL concatenation is prohibited.
  * Must be verified against live PostgreSQL 17 / pgvector containerized instances with zero SQLite dialect fallback.

### 4.3 Interface Contracts & Module Isolation
1. Module boundaries must be defined via Python `Protocol` classes (e.g., `LLMProvider`, `EvidenceParser`) or immutable Pydantic schemas.
2. In accordance with [ADR-001](ADR-001_LLM_Layer_Abstraction.md), internal business logic must remain decoupled from vendor SDKs and framework orchestrators (LangChain, LangGraph, LlamaIndex are prohibited).
3. Data transfer objects between modules must be immutable (`frozen=True`) to eliminate accidental mutation side-effects across asynchronous execution flows.

### 4.4 Continuous DevSecOps Gating & Test Execution Semantics
All commits and milestone baselines must pass through four explicit, separated verification tiers:

```
Automated Test Verification Matrix
├── Tier 1: Fast Offline Unit & Mock Suite:
│   command: uv run pytest -m "not postgres and not ollama"
│   scope: In-memory SQLite, parser logic, chunking algorithms, mock HTTP transports, schema validation.
│   guarantee: Fast execution (< 20s), zero external daemon dependencies.
├── Tier 2: Live Local AI Daemon Integration Suite:
│   command: uv run pytest -m ollama
│   scope: Live Ollama HTTP client communication, embedding generation (nomic-embed-text), timeout recovery.
│   guarantee: Verifies real model tokenization and 768-dim vector assertions against localhost:11434.
├── Tier 3: Live PostgreSQL 17 + pgvector Container Integration Suite:
│   command: uv run pytest -m postgres
│   scope: Isolated containerized PostgreSQL on port 5433 (aisop_test), DDL migrations, JSONB, pgvector (<=>).
│   guarantee: Prohibits SQLite fallback; certifies real transactional savepoint rollbacks and HNSW indexing.
└── Tier 4: Comprehensive Release Regression Suite:
    command: uv run pytest
    scope: Full integration across all modules, schemas, databases, and adapters.
```

### 4.5 Security Requirements & Design-Time Threat Modeling
1. Security controls are established at design time using OWASP Top 10:2025, OWASP API Security Top 10 (2023), and OWASP GenAI LLM Top 10 (2026).
2. Every external boundary (REST ingress, file loader, LLM provider response, threat intel client) must incorporate input validation and payload bounds before processing.
3. Security dependencies must be scanned continuously using `pip-audit`.

### 4.6 Deployment, Staging, Rollback & Observability
1. **Zero Runtime Schema Alterations:** Application startup (`lifespan`) must never perform automated schema modifications or run DDL statements. All migrations are executed explicitly via Alembic revisions.
2. **Rollback Verification:** Downward migrations (`alembic downgrade base`) must be validated against a disposable test database (`aisop_test`) to verify clean schema reversal.
3. **Traceability & Correlation:** Every incoming HTTP request is assigned a unique `X-Request-ID` via correlation middleware, bound into the Loguru logger context, and returned in the HTTP response headers.
4. **Sensitive Data Redaction:** Recursive dictionary key filtering and regular expression masks sanitize passwords, tokens, API keys, and sensitive payload fragments prior to log emission.

### 4.7 Findings & User Feedback Loop
1. Any security vulnerability, regression defect, or review finding identified during testing or review must be logged as a reproducible test case.
2. The failing test must be added to the regression test suite prior to implementing the fix.
3. A milestone cannot be marked complete until all associated defect test cases pass.

---

## 5. Consequences & Architectural Implications

### Positive Consequences
* **Deterministic Quality:** Clear separation of prototype experimentation from production code prevents fragile code from entering the main branch.
* **Security Resilience:** Continuous DevSecOps gating prevents common security regressions (unbounded batches, credential exposure, vector corruption) early in development.
* **Audit Readiness:** Milestone-specific test dossiers provide complete empirical evidence for capstone evaluation and technical audits.
* **Zero Vendor Lock-in:** Protocol-based boundaries preserve autonomy from changing third-party cloud APIs.

### Negative Consequences / Trade-offs
* **Harness Maintenance Overhead:** Developers must maintain separate test tiers (offline mocks, live containerized PostgreSQL, live Ollama) and ensure fixtures remain synchronized.
* **Disciplined Execution:** Fast prototypes cannot be committed directly; they must undergo formal refactoring, typing, and testing before milestone acceptance.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation Strategy |
|:---|:---:|:---|
| **Prototype Bleed:** Experimental spike code committed directly to main without production hardening. | High | Automated Gate 1 checks fail on missing type annotations, unhandled boundaries, or missing unit tests. |
| **False Assurance from Mocks:** Suite passes offline while failing against real PostgreSQL or Ollama engines. | Critical | Separate pytest markers (`postgres`, `ollama`) ensure live integration tests are explicitly tracked and executed. |
| **Dependency Vulnerability Introduction:** Introduction of vulnerable third-party packages during rapid prototyping. | High | DevSecOps Gate 3 mandates `pip-audit` execution with zero High or Critical CVE tolerance. |
| **Scope Creep in Milestones:** Adding unplanned features during iterative prototyping loops. | Medium | Scope bounded strictly to deliverables codified in [Milestones.md](../../00_Project_Management/Milestones.md). |
