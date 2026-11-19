# AISOP Canonical Agent Handover & Architecture Ledger
**Document Reference:** `AISOP-AGENT-HANDOVER-001`  
**Last Updated:** 2026-10-24  
**Status:** CANONICAL / AUTHORITATIVE (Supersedes all previous ad-hoc handovers)  
**Primary Workspace:** `D:\AISOP`  
**Secondary IDE Path:** `c:\Users\sarik\Documents\GO\02_COLLEGE\SEM_Projects\MINOR\SEM7\AISOP`  
**Git Baseline:** Branch `main` | Commit `c4e877cf06056bce32f5a3f893a82261b850ff85`

---

> [!IMPORTANT]
> **MANDATORY INSTRUCTION FOR NEW AGENTS:**  
> Before performing ANY edit or proposing any next phase:  
> 1. You MUST independently inspect repository status (`git status --short`, HEAD, active files).  
> 2. You MUST NOT blindly trust this handover or any previous conversation summary without verifying disk reality.  
> 3. You MUST adhere to all operating rules in Section 14.

---

## 1. Project Purpose & Intended Users

The **AI-assisted Security Operations Platform (AISOP)** is a cognitive, local-first security telemetry correlation and investigation assistant designed for **Tier-1 and Tier-2 Security Operations Center (SOC) analysts**.

### Foundational Pillars:
1. **Local-First & Privacy-Preserving:** Operates on local workstations or air-gapped on-premises servers. Telemetry, usernames, internal IPs, and file hashes **never leave the host**. Zero third-party cloud LLM APIs are used.
2. **Human-in-the-Loop Authority (Anti-Autonomous):** AISOP is strictly an advisory cognitive assistant. It parses logs, aggregates IOCs, maps MITRE ATT&CK techniques, searches internal playbooks, and drafts structured briefs. It is **strictly prohibited from executing autonomous containment actions** (e.g. killing processes, blocking firewall IPs, or modifying endpoint state).
3. **Evidence-First Invariant:** Every conclusion, claim, and hypothesis must cite immutable, verified database evidence UUIDs. Assertions without evidence references are rejected as hallucinations.
4. **Radical Dependency Minimalism:** Heavy, opaque agent frameworks (LangChain, LangGraph, LlamaIndex, AutoGen, ChromaDB) are banned. Core logic is pure Python 3.12, Pydantic V2, and direct HTTP/SQL protocols.
5. **Deterministic Precedence:** Deterministic normalization, schema validation, entity extraction, and cryptographic hashing always precede non-deterministic AI inference.

---

## 2. Current Architecture & Actual Repository Paths

```
D:\AISOP\
├── backend\
│   ├── app\
│   │   ├── api\v1\endpoints\          # REST endpoints (evidence, ingest, query, threatintel, investigation)
│   │   ├── core\config.py             # Pydantic v2 application settings
│   │   ├── db\                        # Async SQLAlchemy engine & session factories
│   │   │   └── migrations\versions\   # Alembic async migration scripts (0001, 0002, 0003)
│   │   ├── models\                    # SQLAlchemy ORM models (evidence, knowledge)
│   │   ├── modules\
│   │   │   ├── ai\
│   │   │   │   ├── context_builder\   # Investigation context formatting & budgeting
│   │   │   │   ├── embeddings\        # Ollama 768d embedding adapter & exceptions
│   │   │   │   ├── knowledge\         # pgvector sliding-window chunker, loader, & retriever
│   │   │   │   └── llm\providers\     # Async Ollama HTTP client with Tenacity retries
│   │   │   ├── entity_extraction\     # Deterministic regex extraction (IPs, hashes, domains, paths)
│   │   │   ├── normalization\         # Sysmon Event ID normalizers to CanonicalEvent
│   │   │   └── threatintel\           # Local feed cache, RFC1918 PrivateNetworkShield, Orchestrator
│   │   ├── schemas\                   # Immutable Pydantic V2 contracts:
│   │   │   ├── investigation.py       # P2-H4 InvestigationContext, BudgetMetrics, Claims, Output
│   │   │   ├── threatintel.py         # Observable, ThreatVerdict, ThreatIntelFindingItem
│   │   │   ├── knowledge.py           # SourceSection, ChunkRecord, RetrievalResult
│   │   │   ├── ai.py                  # LLMMessage, LLMRequest, LLMResponse, TokenUsage
│   │   │   ├── entities.py            # ProcessEntity, NetworkEntity, HostEntity, UserEntity
│   │   │   ├── normalized_event.py    # CanonicalEvent schema
│   │   │   ├── query.py               # NormalizedEventDetail, ExtractedEntityItem
│   │   │   └── ingest.py              # IngestRequest, IngestResponse
│   │   └── services\                  # IngestionService, InvestigationQueryService
│   └── tests\
│       ├── unit\                      # 24 test modules (493 passing unit tests)
│       └── integration\               # 6 test modules (36 passing live database/Ollama tests)
├── docs\                              # ADRs, Project Management reports, Security threat models
└── pyproject.toml                     # Python 3.12 project configuration (ruff, pytest, dependencies)
```

---

## 3. Approved Architecture Decisions (ADRs)

| ADR Identifier | Title | Core Decision & Rationale |
|---|---|---|
| **ADR-001** | LLM Layer Abstraction | Direct lightweight protocol; local Ollama adapter via httpx; banned LangChain/LlamaIndex. |
| **ADR-002** | Vector Database | PostgreSQL with `pgvector` and HNSW cosine index; eliminated separate vector DB infrastructure. |
| **ADR-003** | Python Version | Python 3.12 with strict typing, `typing.Self`, and Pydantic V2. |
| **ADR-004** | Initial Ingestion Scope | Windows Sysmon Event IDs (1, 3, 7, 8, 10, 11, 15, 22, 23) normalized to `CanonicalEvent`. |
| **ADR-005** | Frontend Stack | FastAPI REST API backend; local-first web UI deferred to Phase 4. |
| **ADR-006** | SDLC & DevSecOps Strategy | Multi-tier test verification, offline-first, $0 budget, Docker PostgreSQL 17 on port 5433. |

---

## 4. Verified Milestones & Authoritative Evidence

| Milestone | Scope & Deliverables | Status | Authoritative Verification Report |
|---|---|:---:|---|
| **P1-H1 to P1-H10** | Ingestion pipeline, deduplication, batch queries, Sysmon parser, Alembic migrations, logging, live PostgreSQL harness. | **COMPLETE** | `docs/00_Project_Management/Phase_1_Closeout_Report.md` (114 passing tests) |
| **P2-H1** | LLM Provider Protocol, Pydantic V2 contracts, async OllamaProvider with Tenacity backoff. | **COMPLETE** | `backend/tests/unit/test_llm_provider.py` |
| **P2-H2** | pgvector schema foundation, Alembic `0002`, `KnowledgeEmbedding` ORM, HNSW cosine index. | **COMPLETE** | `backend/tests/integration/test_postgres_lifecycle.py` |
| **P2-H3** | Knowledge chunker, loader, `OllamaEmbedder` (768d), `KnowledgeRetriever`, Option A-Prime source-scoped chunk provenance. | **COMPLETE** | `docs/00_Project_Management/P2-H3_Final_Acceptance_Report.md` |
| **TI-2, TI-3A, TI-3B** | Threat intelligence protocol, RFC1918 `PrivateNetworkShield`, local feed engine, resilient orchestrator. | **COMPLETE** | `docs/00_Project_Management/TI-3B_Phase1.3_Closeout_Report.md` |
| **P2-H4 (Curr.) / P2-H5 (Hist.)** | Tasks 2.1–2.5: Context Assembly, Defensive Prompts, Parser, 3-Tier Guardrails, InvestigationPipelineService, POST /synthesize endpoint. | **COMPLETE** | Working tree baseline (571 unit + 18 integration tests passed) |
| **P2-H6 — Role-Tailored Structured Investigation Reporting** | Schemas (`report.py`), deterministic synthesizer (`synthesizer.py`), formatter (`formatter.py`), endpoints (`reports.py`). Historical alias: P2-H5 Candidate. Remediated SEC-AUDIT-001 to 005. | **COMPLETE** | Working tree baseline (596 unit + 11 reporting integration tests passed) |
| **P2-H7 — Phase 2 Capstone Review, Security Hardening & Full Pipeline Consolidation** | End-to-end integration harness (`test_phase2_capstone.py`), live PostgreSQL 17/pgvector Tier 3 verification (port 5433), dependency audit, Phase 2 closeout report (`Phase_2_Closeout_Report.md`). | **COMPLETE** | Working tree baseline (682 total passing tests: 611 unit + 71 integration) |
| **P3-H1 — API Ingress Authentication & Security Perimeter** | Centralized `verify_api_key` dependency on protected routes, `API_AUTH_KEYS` configuration, Bearer and X-API-Key schemes, constant-time validation, 19 auth tests (`test_api_auth.py`), OWASP A07 / API2:2023 mitigation. | **COMPLETE** | Working tree baseline (701 total passing tests: 630 unit + 71 integration) |

> [!NOTE]
> **Roadmap Numbering Reconciliation:** In the 19 October 7-Milestone roadmap (`AISOP_Historical_Handover.md`), Threat Intelligence was labeled P2-H4, and LLM Investigation Reasoning & Grounding was labeled P2-H5. In the 23 October design gate (`AISOP-P2-H4-DESIGN-GATE-002`), Context Assembly and Pipeline Synthesis were grouped under the milestone label `P2-H4`. Therefore, Tasks 2.1–2.5 fully deliver the reasoning, context assembly, and grounding scope originally planned under P2-H5.

---

## 5. Claims Reported by Antigravity Requiring Context

1. **Recorded Test Baselines:**  
   Following completion and certification of Milestone P3-H1 (`test_api_auth.py`), the verified test results across the repository are:
   - **630 Backend Unit Tests Passed** (`pytest backend/tests/unit` in ~18.0s).
   - **71 Backend Integration Tests Passed** (`pytest backend/tests/integration` in ~12.9s, including live PostgreSQL 17 container on port 5433 and `test_phase2_capstone.py`).
   - **701 Total Passing Backend Tests** (`pytest backend/tests` in ~29.7s, 0 failures, 4 warnings).
   - **Recorded Warnings:** 2 upstream `StarletteDeprecationWarning` notices regarding `httpx` in Starlette `TestClient` and 2 FastAPI routing deprecation warnings regarding `HTTP_422_UNPROCESSABLE_ENTITY`.

   - **Live Infrastructure Verification:** Live Docker PostgreSQL 17 + pgvector container (port 5433) fully executed and certified (`test_postgres_lifecycle.py`, `test_postgres_vector_retrieval.py`). Live Ollama embedding client verified (`test_ollama_live_embedding.py`). Zero paid external network egress ($0 budget).
2. **P2-H4 Tasks 2.1 through 2.5 State:**  
   Tasks 2.1 through 2.5 are **implemented and verified in the working tree baseline** (uncommitted). This includes the canonical serializer/hasher (`hasher.py`), multi-event context builder (`context_builder.py`), defensive prompt builder (`builder.py`), structured response parser (`parser.py`), output guardrails validator (`validator.py`), orchestration service (`investigation_service.py`), and endpoint (`investigations.py`).
3. **P2-H6 Reporting Implementation State:**  
   Role-Tailored Structured Investigation Reporting is **implemented and verified in the working tree baseline** (uncommitted), pending formal owner acceptance. Includes schemas (`report.py`), deterministic synthesizer (`synthesizer.py`), formatter (`formatter.py`), endpoints (`reports.py`), and verified remediation of findings SEC-AUDIT-001 through SEC-AUDIT-005. Under the implemented reporting policy, detached-context and applicable budget-truncation conditions produce an INCONCLUSIVE assessment, with explicit uncertainty disclosures; this assessment must not be represented as an independently established incident severity.
4. **API Endpoints Registered:**  
   - `POST /api/v1/investigations/synthesize` (`investigations.py`).
   - `POST /api/v1/reports/synthesize` and `POST /api/v1/reports/format` (`reports.py`).

---

## 6. Git Branch, HEAD, and Worktree Preservation Rules

- **Active Branch:** `main`
- **Current HEAD Commit:** `c4e877cf06056bce32f5a3f893a82261b850ff85`
- **Worktree Invariants:**
  - Zero commits without explicit user instruction.
  - Zero staging (`git add`).
  - Zero branch switching or checkouts.
  - Zero resets (`git reset --hard` or `git reset`).
  - Zero clean operations (`git clean -fd`).
  - All pre-existing modified files (`.vscode/settings.json`, `README.md`, etc.) and untracked files must remain strictly preserved.

---

## 7. Database Identities & Protected-Database Rules

PostgreSQL runs via Docker on host port `5433` (container port `5432`):

| Database Name | Status | Protection Rule |
|---|---|---|
| `aisop_dev` | Development Target | **PROTECTED:** 0 public tables. Do not migrate, write, or truncate. |
| `aisop_test` | Staging Target | **PROTECTED:** 5 tables (`alembic_version` at `0003_source_scoped_chunks`). Do not truncate or modify outside formal integration test harnesses. |
| `aisop_p2h3_disposable` | Test Harness Sandbox | **DISPOSABLE:** Dedicated integration sandbox. Can be migrated and truncated by authorized integration tests. |

- **Current Alembic Version:** `0003_source_scoped_chunks` (26 characters). Do not modify or exceed 32 characters (`VARCHAR(32)` column constraint on `alembic_version`).

---

## 8. Local Tooling & AI Runtime Setup

- **Python Runtime:** Python 3.12.0 in `D:\AISOP\.venv\Scripts\python.exe`.
- **Package Manager:** `uv` / `pip` within virtual environment.
- **Local Ollama Daemon:** Running on `http://localhost:11434`.
  - **Reasoning Model:** `qwen3:4b` (for SOC triage and structured output).
  - **Embedding Model:** `nomic-embed-text:latest` (768-dimensional cosine vector embeddings).
- **PostgreSQL pgvector:** Docker container `aisop-postgres` on port `5433`.

---

## 9. Current P2-H4 Design & Implementation Boundary

- **Reference Design:** `docs/00_Project_Management/P2-H4_Design_and_Readiness_Report.md`.
- **Approved & Implemented Tasks (Tasks 2.1–2.5):**
  - Schema module: `backend/app/schemas/investigation.py` (Phase 1 / Task 1.1).
  - Canonical serializer & hasher: `backend/app/modules/ai/context_builder/hasher.py` (Task 2.1).
  - Multi-event context assembly & pruning: `backend/app/modules/ai/context_builder/context_builder.py` (Task 2.2).
  - Defensive prompt builder: `backend/app/modules/ai/prompt_builder/builder.py` (Task 2.3).
  - Structured response parser: `backend/app/modules/ai/response_parser/parser.py` (Task 2.3).
  - Output guardrails & 3-tier claim grounding: `backend/app/modules/ai/guardrails/validator.py` (Task 2.4).
  - Investigation orchestration service: `backend/app/services/investigation_service.py` (Task 2.5).
   - Investigation endpoint: `backend/app/api/v1/endpoints/investigations.py` (Task 2.5).
- **Approved & Implemented Reporting Scope (Milestone P2-H6):**
  - Schemas: `backend/app/schemas/report.py` (P2-H6).
  - Deterministic synthesizer & injection defense: `backend/app/modules/ai/reporting/synthesizer.py` (P2-H6).
  - Deterministic Markdown formatter: `backend/app/modules/ai/reporting/formatter.py` (P2-H6).
  - Reporting endpoints: `backend/app/api/v1/endpoints/reports.py` (P2-H6).
- **Implementation Boundary:** Both investigation reasoning (P2-H4) and role-tailored reporting (P2-H6) are implemented and tested in the working tree baseline, pending formal owner acceptance. Milestone P2-H7 implementation is explicitly unauthorized.

---

## 10. Next Authorized Roadmap Phase: Phase 3 (Case Management & RBAC)

Phase 2 is formally **CLOSED** with the certification of Milestone P2-H7 (`Phase_2_Closeout_Report.md`).
Milestone **P3-H1 (API Ingress Authentication & Security Perimeter)** is **COMPLETE** and verified.

### Phase 3 Roadmap & Status:
1. **P3-H1: API Ingress Authentication & Security Perimeter:** **COMPLETE** (Central `verify_api_key` dependency on protected `/api/v1/*` routes, constant-time validation, multi-client, fail-closed, OWASP A07 / API2 mitigated).
2. **P3-H2: Role-Based Access Control (RBAC):** *NEXT AUTHORIZED MILESTONE* (Tier-1 vs Tier-2 analyst role definitions, tenant scoping, and authorization checks closing OWASP A01 / API1 / API5 gaps).
3. **P3-H3: Investigation Workflow & Case Dossiers:** Case status state machine (`open`, `triage`, `investigating`, `contained`, `closed`), analyst notes, immutable evidence bindings, and audit logging.
4. **P3-H4: Rate Limiting & Abuse Prevention:** Ingress connection throttling and payload defense.

---

## 11. Test Commands & Environmental Baseline

### Unit Test Suite (Offline, zero infrastructure required):
```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/unit
```
- **Current Baseline:** **630 passed**, 2 warnings in ~18.0 seconds.


### Focused Reporting Synthesizer Unit Subset:
```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/unit/test_deterministic_report_synthesizer.py
```
- **Current Baseline:** **25 passed** in ~0.96 seconds (subset overlapping with the 596 unit suite).

### Focused Reporting Pipeline Integration Suite:
```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/integration/test_reporting_pipeline.py -v
```
- **Current Baseline:** **11 passed**, 4 warnings in ~1.8 seconds.

### Focused Investigation Pipeline Integration Suite:
```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/integration/test_investigation_pipeline.py -v
```
- **Current Baseline:** **18 passed**, 2 warnings in ~1.4 seconds.

### Live PostgreSQL Integration Suite (Requires Docker PostgreSQL on port 5433):
```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/integration/test_postgres_lifecycle.py
```
- **Verification Limit Note:** Live PostgreSQL integration tests were not executed during Milestone P2-H4 Task 2.5 because the Docker PostgreSQL container was offline. Live PostgreSQL integration coverage is not claimed as verified for this run.

---

## 12. Security Requirements & Local-First Invariants

1. **Untrusted Data Axiom:** All raw telemetry attributes, command lines, filenames, registry values, and retrieved knowledge chunks are categorized as **UNTRUSTED DATA**. Delimiters (XML tags) provide structure, not complete injection immunity.
2. **Zero Tool Execution:** The LLM receives zero tools, zero shell access, and zero API execution permissions. It is strictly read-only and advisory.
3. **Egress Shielding:** Internal IPs (RFC1918, Loopback, Bogons) are shielded by `PrivateNetworkShield` and never queried against external threat feeds.
4. **$0 Budget Policy:** Zero paid cloud APIs (OpenAI, Anthropic, VirusTotal premium) are permitted.
5. **Auth/RBAC Blocker:** Absence of authentication and RBAC is a formal deployment blocker for untrusted network exposure. AISOP is restricted to `localhost`.

---

## 13. Mandatory Pre-Flight Verification Rule for Future Agents

Every agent starting a session MUST execute the following pre-flight verification sequence before writing code:

```powershell
# 1. Verify working directory and git state
git status --short
git rev-parse HEAD

# 2. Verify Python runtime and unit test baseline
.\.venv\Scripts\python.exe -m pytest backend/tests/unit
```

If the baseline fails or differs from 596 passed unit tests, the agent must report the anomaly immediately before proceeding.

---

## 14. Future Agent Operating Rules

1. **Inspect Repository First:** Always inspect the actual working tree and handover document before taking action.
2. **Inspect Antigravity Timing & Logs:** Antigravity timestamps represent turn-start time, not delivery time. In multi-step turns, interpret relative ages accordingly.
3. **Tailored Prompts Only:** Generate specific, evidence-backed implementation prompts; do not propose generic project plans.
4. **Small, Independently Tested Phases:** Keep implementation units small (e.g. Phase 1 schemas, Phase 2 context builder). Test each unit thoroughly before proceeding.
5. **Explicit Gate Approval:** Never proceed to the next phase without explicit user sign-off.
6. **Zero Unauthorized Git Mutations:** Never run `git reset`, `git clean`, `git add`, or `git commit` without explicit authorization.
7. **Protect Authoritative Databases:** Never run migrations, writes, or schema alterations against `aisop_dev` or `aisop_test`.
8. **Preserve $0 Budget:** Never install new dependencies, cloud SDKs, or download large remote models without authorization.
9. **Never Fabricate Test Claims:** Report actual executed test numbers; never cite historical claims as newly executed runs without rerunning them.
10. **Keep Handover Living:** Update this canonical handover document upon the completion of every authorized milestone phase.
