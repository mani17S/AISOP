# AISOP — Canonical Historical Handover & Architecture Continuity Record

**Document ID:** `AISOP-HANDOVER-CANONICAL-001`  
**Creation Date:** 2026-10-21  
**Project:** AISOP — AI-Assisted Security Operations Platform  
**Target Repository:** `D:\\AISOP` (Mirrored in `C:\\Users\\sarik\\Documents\\GO\\02_COLLEGE\\SEM_Projects\\MINOR\\SEM7\\AISOP`)  
**Status:** CANONICAL REFERENCE — AWAITING OWNER DESIGN DECISION ON P2-H3  

---

## A. Original Project Vision and Requirements

### A.1 Academic & Operational Context
AISOP (**AI-Assisted Security Operations Platform**) is an ongoing undergraduate cybersecurity capstone project (Semester 7 Minor Project, Department of Computer Science & Engineering). 

> [!NOTE]
> **Historical Naming Nuance:** While the canonical system name established across ADRs, configuration, and documentation is **AI-Assisted Security Operations Platform**, one early academic planning log recorded it as *AI-Assisted Investigation Support Operations Platform*. Both refer to the identical codebase and mission.

### A.2 Core Mission & Positioning
AISOP is designed to bridge the operational gap between raw security telemetry/SIEM alerts and human Tier-1/Tier-2 Security Operations Center (SOC) analysts. The platform operates on five foundational pillars:
1. **Local-First & Privacy-Preserving:** The platform must be fully deployable on local analyst workstations or isolated on-premises infrastructure. Sensitive endpoint telemetry, internal network topology, user accounts, and proprietary IOCs must never be transmitted to external, third-party cloud LLM APIs.
2. **Human-in-the-Loop Authority (Anti-Autonomous):** AISOP is strictly an analyst-assistive cognitive tool. It assists analysts by automating tedious parsing, extracting entities, identifying MITRE ATT&CK techniques, retrieving relevant SOP playbooks, and drafting structured investigation briefs. AISOP is **NOT an autonomous SOAR platform**; it is strictly prohibited from triggering unapproved automated containment actions (e.g., firewall rule insertion, host network isolation, process termination).
3. **Evidence-First Invariant:** All security conclusions and generated hypotheses must cite specific, immutable telemetry records persisted in PostgreSQL. An AI finding that does not cite a valid evidence UUID is treated as hallucination and rejected.
4. **Radical Dependency Minimalism:** High-overhead, fragile, multi-layered agent frameworks (such as LangChain, LangGraph, LlamaIndex, ChromaDB) are banned from core application logic to prevent supply-chain vulnerabilities, API churn, and obscure runtime failures.
5. **Deterministic Precedence:** Deterministic validation, canonical parsing, cryptographic hashing, and relational extraction must always precede non-deterministic AI inference. Untrusted log data and retrieved context are treated strictly as data payloads, never as executable instructions.

---

## B. Original Roadmap versus Revised Roadmap

### B.1 Phase 1 Baseline (Ingestion & Canonical Data Modeling)
Phase 1 maintained a steady, 10-milestone sequence (P1-H1 through P1-H10), culminating in the certified closeout report on 2026-09-17 with 114 automated tests passing.

### B.2 Phase 2 Divergence & Reconciliation Analysis
An audit of historical planning artifacts reveals a structural divergence between the **7 October Master Record** and the **19 October Planning Tracker (`README.md`)**:

| Phase 2 Milestone | 7 October Master Planning Baseline | 19 October Execution Tracker (`README.md`) | Reconciled Architecture Status |
|:---|:---|:---|:---|
| **P2-H1** | LLM Provider Protocol & Local Ollama Adapter | LLM Provider Abstraction | **Complete & Committed** (`7f27d69`) |
| **P2-H2** | pgvector Knowledge Schema & Health Readiness | PostgreSQL + pgvector Schema Foundation | **Complete & Committed** (`32c3903`) |
| **P2-H3** | Knowledge Ingestion & Semantic Retrieval | Knowledge Ingestion & Retrieval | **Implemented, Blocked & Unaccepted** |
| **P2-H4** | MITRE ATT&CK Knowledge & Mapping | Threat-Intelligence Enrichment | **Divergence Point** (See Note Below) |
| **P2-H5** | Threat Intelligence Enrichment | LLM Investigation Reasoning & Grounding | **Divergence Point** |
| **P2-H6** | InvestigationContext Assembly | Structured Investigation Reporting | **Divergence Point** |
| **P2-H7** | Structured LLM Output & Evidence Grounding | Phase 2 Capstone Review & Consolidation | Reconciled Capstone Gate |

> [!IMPORTANT]
> **Roadmap Reconciliation Recommendation:**
> In the 19 October revision, MITRE ATT&CK mapping was recognized as a subset of the Knowledge Base (ingested via P2-H3) and the Investigation Context Builder (P2-H5), rather than requiring a dedicated standalone milestone. Similarly, `InvestigationContext` assembly and structured LLM generation were consolidated into P2-H5 and P2-H6 to establish a direct vertical demonstration slice.
> **Recommendation:** Formally adopt the **19 October 7-Milestone Structure** for Phase 2, pending explicit Project Owner sign-off.

### B.3 Beyond Phase 2 Roadmap
* **Phase 3 — Investigation Workflow & Case Management:** REST APIs for alert triage, case status state machines (`open`, `investigating`, `contained`, `closed`), analyst notes, and audit trails.
* **Phase 4 — Analyst Investigation Workspace:** Interactive web UI for timeline navigation, IOC graph exploration, hypothesis confirmation/rejection, and report export.
* **Extension — Detection Engineering Pipeline:** Candidate Sigma/YARA rule generation, automated AST validation, rule syntax linting, and sample test matching.

---

## C. Complete Phase-Wise Milestone Ledger

| Milestone | Checkpoint / Baseline | Scope & Key Deliverables | Status | Test & Verification Evidence |
|:---|:---:|:---|:---:|:---|
| **P1-H1** | `63bee0b` | Git safety checkpoint, initial FastAPI application, Pydantic canonical schemas, in-memory SQLite harness. | COMPLETE | Baseline unit suite |
| **P1-H2** | `e1af0c9` | Option A deduplication contract: skips duplicates, no duplicate child rows, nested savepoint race handling. | COMPLETE | Unit tests in `test_ingestion_service.py` |
| **P1-H3** | `e1af0c9` | Batch query optimization: chunked existence queries (`IN (...)` in 1000-item chunks) replacing O(N) sequential scans. | COMPLETE | Unit tests in `test_ingestion_service.py` |
| **P1-H4** | `2cbe6a8` | Ingestion security & bounds: MAX_BATCH_SIZE=2000, MAX_PAYLOAD=64KB, 128MB batch ceiling, per-event savepoint isolation. | COMPLETE | Unit tests in `test_ingestion_service.py` |
| **P1-H5** | `2228764` | SOC query API: deterministic ordering (`event_timestamp DESC, id DESC`), bounded pagination, timeline & entity filters. | COMPLETE | Unit tests in `test_investigation_query_service.py` |
| **P1-H6** | `bbc34dd` | Structured observability: Loguru JSON/text logging, X-Request-ID correlation middleware, sensitive credential masking. | COMPLETE | Unit tests in `test_logging.py` |
| **P1-H7** | `164a65e` | Database schema lifecycle: Alembic async migrations setup, initial revision `0001_initial_evidence_schema`. | COMPLETE | Unit tests in `test_migrations.py` |
| **P1-H8** | `e5ffff8` | Sysmon parser expansion: Event IDs 8, 10, 15, and 23 added with full entity role extraction (12 Event IDs total). | COMPLETE | Unit tests in `test_sysmon_parser.py` |
| **P1-H9** | `7998be8` | Live PostgreSQL integration harness: real PostgreSQL 17 container on port 5433 with dedicated `aisop_test` database. | COMPLETE | 6 integration tests in `test_postgres_lifecycle.py` |
| **P1-H10** | `0764ea4` | Phase 1 Hardening Capstone: consolidated `Architecture.md`, `Milestones.md`, certified 114-test regression suite. | COMPLETE | `docs/00_Project_Management/Phase_1_Closeout_Report.md` |
| **P2-H1** | `7f27d69` | Team-owned LLMProvider Protocol, Pydantic v2 schemas, async OllamaProvider via httpx with tenacity retry backoff. | COMPLETE | 19 unit tests in `test_llm_provider.py` |
| **P2-H2** | `32c3903` | pgvector knowledge foundation: Alembic migration `0002`, KnowledgeEmbedding ORM, HNSW cosine index, health probe. | COMPLETE | 4 unit tests, 7 integration tests |
| **P2-H3** | *Uncommitted* | Knowledge ingestion pipeline, document chunker, OllamaEmbedder (768-dim), semantic retriever. | BLOCKED | 8 unit tests in `test_knowledge_ingestion_and_retrieval.py` |
| **P2-H4** | *Pending* | Threat Intelligence enrichment: mock-first provider protocol, caching, optional live VirusTotal/AbuseIPDB adapters. | BLOCKED | Dependent on P2-H3 acceptance |
| **P2-H5** | *Pending* | LLM investigation reasoning: context token budgeting, prompt templates, evidence citation verification. | BLOCKED | Dependent on P2-H4 acceptance |
| **P2-H6** | *Pending* | Structured investigation reporting: role-tailored report generator (SOC, IR, Exec), confidence scoring. | BLOCKED | Dependent on P2-H5 acceptance |
| **P2-H7** | *Pending* | Phase 2 Capstone: end-to-end event-to-report integration certification, architecture ledger synchronization. | BLOCKED | Dependent on P2-H6 acceptance |

---

## D. Architecture Decisions and Alternatives

### ADR-001: AI/LLM Layer Abstraction Strategy
* **Status:** `APPROVED` (2026-09-09)
* **Approved Decision:** Direct lightweight team-owned Python `Protocol` with `httpx` and `tenacity` retry logic.
* **Alternatives Evaluated & Rejected:**
  - *LangChain / LangGraph Framework:* Rejected due to severe dependency bloat (~12 direct packages), high vulnerability attack surface, frequent breaking API changes, and unnecessary abstraction layers.
  - *Hybrid Framework:* Rejected to keep core architecture pure.
* **Key Invariant:** Core AISOP code must remain completely independent of LangChain.

### ADR-002: Vector Database Selection
* **Status:** `APPROVED` (2026-09-09)
* **Approved Decision:** PostgreSQL 17 with `pgvector` extension (HNSW index, cosine distance `<=>`).
* **Alternatives Evaluated & Rejected:**
  - *Embedded ChromaDB:* Rejected due to heavy transitive dependencies (`onnxruntime`, `flatbuffers`) and fragmented data persistence (SQLite + parquet alongside PostgreSQL).
  - *Standalone ChromaDB / Milvus / Qdrant Server:* Rejected to avoid adding a third operational daemon to a local workstation deployment.
* **Key Invariant:** Relational investigation telemetry and vector embeddings reside in the identical PostgreSQL database, enabling single-transaction integrity and joint relational-vector queries.

### ADR-003: Python Version Selection
* **Status:** `APPROVED` (2026-09-09)
* **Approved Decision:** Python 3.12 (`>=3.12`).
* **Alternatives Evaluated & Rejected:**
  - *Python 3.14:* Rejected due to lack of stable ecosystem pre-compiled binary wheels (e.g., PyTorch, sentence-transformers, psycopg).
  - *Python 3.11:* Rejected in favor of the current stable LTS standard.
* **Key Invariant:** `pyproject.toml` enforces `requires-python = ">=3.12"`.

### ADR-004: Initial Telemetry Ingestion Scope
* **Status:** `APPROVED` (2026-09-09)
* **Approved Decision:** Internal Canonical Normalized Event Schema first, implemented via Sysmon JSON parser (Event IDs 1, 3, 7, 8, 10, 11, 12, 13, 14, 15, 22, 23).
* **Alternatives Evaluated & Rejected:**
  - *Network Telemetry (Zeek / Suricata):* Deferred. Zeek provides excellent network flow context but is blind to endpoint execution and process hierarchies.
  - *Raw Unnormalized Ingestion:* Rejected. AI inference must never operate directly on unparsed logs.

### ADR-005: Frontend Technology Stack
* **Status:** `APPROVED` (2026-09-09)
* **Approved Decision:** React 19 + Vite + Vanilla CSS single-page application (SPA).
* **Alternatives Evaluated & Rejected:**
  - *Next.js (App Router):* Rejected. SSR adds operational complexity (Node.js runtime server) and architectural confusion without benefit for an internal, authenticated SOC tool.
* **Subsequent Proposed Recommendation:** Streamlit proposed in 19 October `README.md` for rapid academic MVP demonstration. **Status: Awaiting Owner Decision.**

### ADR-006: SDLC and DevSecOps Strategy
* **Status:** `APPROVED` (2026-10-16)
* **Approved Decision:** Hybrid Agile + RAD Prototyping within bounded increments + 4-tier DevSecOps automated testing gates.
* **Testing Matrix:**
  - *Tier 1:* Fast Offline Unit & Mock Suite (`uv run pytest -m "not postgres and not ollama"`).
  - *Tier 2:* Live Local AI Daemon Integration (`uv run pytest -m ollama`).
  - *Tier 3:* Live PostgreSQL 17 + pgvector Container (`uv run pytest -m postgres`).
  - *Tier 4:* Release Regression & End-to-End Workflow Suite.

---

## E. Chronological Decision and Change Log

* **2026-07-26:** Repository initialized (`fb42fe9`). Baseline folder structure and initial Markdown shells established.
* **2026-09-09:** Master Architecture Review with ChatGPT. ADR-001 through ADR-005 formally authored and approved by Project Owner.
* **2026-09-10:** P1-H1 through P1-H5 implemented:
  - Commit `63bee0b` (P1-H1): FastAPI foundation, Pydantic canonical schemas, in-memory SQLite harness.
  - Commit `e1af0c9` (P1-H2 & P1-H3): Option A deduplication, SHA-256 canonical hashing, chunked existence queries.
  - Commit `2cbe6a8` (P1-H4): Ingestion bounds hardening (`MAX_BATCH_SIZE=2000`, payload $\le 64\text{ KB}$, 128MB budget).
  - Commit `2228764` (P1-H5): SOC investigation query API (`/events`, `/entities`, `/by-hash`, deterministic ordering).
* **2026-09-17:** P1-H6 through P1-H10 implemented:
  - Commit `bbc34dd` (P1-H6): Loguru structured logging, `X-Request-ID` correlation middleware, sensitive data redaction.
  - Commit `164a65e` (P1-H7): Alembic async migration lifecycle, initial revision `0001_initial_evidence_schema`.
  - Commit `e5ffff8` (P1-H8): Sysmon parser expansion covering Event IDs 8, 10, 15, and 23.
  - Commit `7998be8` (P1-H9): PostgreSQL 17 automated integration test suite on port 5433 with zero SQLite fallback.
  - Commit `0764ea4` (P1-H10): Capstone consolidation; `Phase_1_Closeout_Report.md` certified with 114 passing tests.
* **2026-09-22:** Commit `7f27d69` (P2-H1): Team-owned `LLMProvider` Protocol, `OllamaProvider`, and MockTransport unit tests.
* **2026-10-05:** Alembic migration `0002_add_pgvector_and_knowledge_schema.py` authored.
* **2026-10-10:** Commit `32c3903` (P2-H2): pgvector knowledge schema foundation, `KnowledgeEmbedding` ORM model, HNSW index. Commit `c4e877c`: documentation baseline synchronization.
* **2026-10-16:** ADR-006 (SDLC and DevSecOps Strategy) authored and approved.
* **2026-10-19:** Comprehensive status tracker authored in `README.md`. Identification of P2-H3 chunk provenance and retrieval baseline blockers.
* **2026-10-21:** Comprehensive continuity recovery and audit (`AISOP-CONTINUITY-RECOVERY-001` and `AISOP-GATE-VERIFY-002`).

---

## F. ChatGPT–Antigravity Working Agreement

To maintain continuity, avoid architectural drift, and prevent accidental regression, the division of responsibilities is formally codified:

### F.1 Division of Responsibilities
* **ChatGPT:**
  - Primary Role: Lead Architect, Planning Partner, Decision Recorder, and Academic Mentor.
  - Responsibilities: Authoring and approving ADRs, defining milestone acceptance criteria, resolving design trade-offs, reviewing roadmaps, and providing conceptual guidance.
* **Antigravity:**
  - Primary Role: Implementation Engineer, Code Inspector, Test Harness Builder, and System Auditor.
  - Responsibilities: Executing code modifications strictly within approved ADR parameters, building automated test harnesses, running test regressions, auditing file parity, and capturing empirical test output.
* **Project Owner (Student Engineer):**
  - Final decision maker for all architectural approvals, milestone sign-offs, and Git commits.

### F.2 Operating Invariants
1. **Never Assume — Always Inspect:** Historical reports are records of past execution, not proof of current working-tree reality. Verify code and tests in the live repository before stating completion.
2. **Never Silently Rewrite ADRs or Milestones:** If a conflict arises between an existing ADR and a new proposal, document the conflict, record trade-offs, and request explicit Project Owner approval.
3. **Strict Separation of Spikes and Production Code:** Prototype code must never be merged into `main` without strict typing, Pydantic validation, bounded limits, Loguru logging, and passing automated test suites.
4. **Non-Destructive Git & DB Policy:** Never use destructive Git commands (`clean`, `reset --hard`, `stash drop`) or destructive database drops without explicit authorization.

---

## G. Important Prompts and Handover Instructions

### G.1 Protocol for Starting a New ChatGPT Session
When starting a new conversation with ChatGPT for architecture review or milestone planning:
1. Copy and paste the **Canonical Handover Brief** from **Section J** of this document.
2. Specify the exact decision or review task required.
3. Instruct ChatGPT to maintain consistency with approved ADR-001 through ADR-006.

### G.2 Protocol for Starting an Antigravity Implementation Session
When initiating an implementation session with Antigravity:
1. Provide the specific approved Milestone ID (e.g., `P2-H3`).
2. Attach the approved design decision and required file changes.
3. Enforce the pre-flight verification checklist:
   - Verify active branch (`main`) and working-tree status.
   - Run Tier 1 offline regression tests to establish a clean starting baseline.
   - Execute implementation changes.
   - Author corresponding unit and integration tests.
   - Run applicable test tiers (Tier 1, Tier 2, Tier 3) and record output.
   - Present verification report to the Project Owner for review before staging or committing.

---

## H. Current Project Status and Latest Blockers

### H.1 Current State Summary
The repository stands at Milestone **P2-H3** (*Knowledge Ingestion Pipeline & Semantic Retrieval*). The feature is functionally implemented across `backend/app/modules/ai/knowledge/` and tested via offline SQLite mocks (167 passing tests). However, it is **BLOCKED and NOT ACCEPTED** due to two unresolved technical defects:

### H.2 Blocker A: Knowledge Chunk Ownership & Provenance Defect
* **The Defect:** Migration `0002` established a global unique index on `KnowledgeEmbedding.content_hash`:
  ```python
  op.create_index("ix_knowledge_embeddings_content_hash", "knowledge_embeddings", ["content_hash"], unique=True)
  ```
* **Failure Modes:**
  1. *Cross-Document Provenance Loss:* If `playbook_a.md` and `playbook_b.md` contain an identical paragraph, `ingestion_service.py` skips the chunk for `playbook_b.md`. Queries filtering on `source_document = 'playbook_b.md'` fail to return the chunk.
  2. *Orphan Deletion Risk:* If `playbook_a.md` is updated or deleted, the shared chunk row is deleted, leaving `playbook_b.md` completely without representation in the database.
  3. *Intra-Document Positional Collapse:* The proposed patch `UNIQUE(source_document, content_hash)` fails if a single document repeats a paragraph or table header across multiple sections. It collapses multiple distinct positional chunks into one or triggers a database constraint error.
* **Recommended Resolution (Positional Uniqueness):**
  - Add top-level column `chunk_index: Mapped[int]` representing sequential 0-based index across the document.
  - Establish composite unique constraint: `UNIQUE(source_document, chunk_index)`.
  - Make `content_hash` a non-unique B-tree index for fast hash lookups.
  - Implement via forward migration: `0003_source_scoped_knowledge_chunks.py`.

### H.3 Blocker B: Missing Exact-Search Ground Truth Baseline
* **The Defect:** Successful execution of an HNSW index query does not prove semantic retrieval accuracy. Approximate Nearest Neighbor (ANN) algorithms can suffer recall loss under restrictive query filters.
* **Required Resolution:**
  - Create a deterministic test dataset of $\ge 50$ curated security chunks.
  - Implement an automated test that executes queries with `SET LOCAL enable_indexscan = off;` to calculate Exact Nearest Neighbor (ENN) cosine ranking.
  - Execute the identical query with HNSW enabled (ANN).
  - Assert that HNSW recall $R = \frac{|\text{ANN} \cap \text{ENN}|}{k} \ge 95\%$ for $k=5$.

---

## I. Unresolved Questions and Missing Historical Evidence

1. **Chunk Ownership Design Approval:** Project Owner must formally approve the Positional Uniqueness design (`UNIQUE(source_document, chunk_index)`) over the content-deduplicated design (`UNIQUE(source_document, content_hash)`).
2. **Forward Migration Approval:** Project Owner must formally authorize authoring Alembic migration `0003_source_scoped_knowledge_chunks.py`.
3. **Frontend Architecture Alignment:** Project Owner must formally decide whether to proceed with React 19 ([ADR-005](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-005_Frontend_Stack.md)) or author an amendment adopting Streamlit for the academic MVP.
4. **Threat Intelligence Strategy:** Confirm whether P2-H4 should implement a mock-first deterministic provider by default, keeping live API keys (VirusTotal, AbuseIPDB) strictly opt-in.
5. **Non-MVP Feature Deferral:** Confirm formal deferral of multi-user RBAC, Redis rate limiting, and immutable forensic WORM storage beyond the single-user local MVP.

---

## J. Canonical Project Handover Brief for a New ChatGPT Conversation

*Copy and paste the exact text block below into a new ChatGPT session to establish full historical continuity:*

```markdown
### AISOP Canonical Engineering Handover Brief

**Project:** AISOP (AI-Assisted Security Operations Platform)
**Repository Working Directory:** D:\AISOP (Mirrored in C:\Users\sarik\Documents\GO\02_COLLEGE\SEM_Projects\MINOR\SEM7\AISOP)
**Current Milestone:** P2-H3 (Knowledge Ingestion & Semantic Retrieval) — BLOCKED / UNACCEPTED
**Git State:** Branch 'main', commit c4e877c (12 commits ahead of origin/main). 12 modified files, 33 untracked items.

#### 1. System Identity & Mission
AISOP is an evidence-first, local-first, human-in-the-loop security investigation platform designed to assist SOC analysts in alert triage, canonical normalization, entity/IOC correlation, MITRE ATT&CK mapping, vector knowledge retrieval, and structured report generation.
Anti-autonomous invariant: The human analyst remains the sole decision-maker. AISOP is strictly prohibited from executing automated destructive SOAR responses.

#### 2. Immutable Architecture Invariants (Do Not Drift)
- Python 3.12 runtime baseline (ADR-003).
- PostgreSQL 17 with pgvector for unified relational and vector persistence (ADR-002; standalone vector DBs prohibited).
- Direct lightweight Python Protocol for LLM abstraction (ADR-001; LangChain/LangGraph prohibited).
- 768-dimensional embedding space (nomic-embed-text via local Ollama).
- Canonical event schema + Sysmon JSON parser (12 Event IDs) as initial telemetry baseline (ADR-004).
- Deterministic parsing precedes probabilistic AI reasoning.
- Approved Frontend Stack: React 19 + Vite static SPA (ADR-005). (Note: Streamlit has been proposed for academic MVP velocity; awaiting explicit owner approval).
- SDLC & DevSecOps Strategy: Strict 4-tier automated test matrix (ADR-006).

#### 3. Current Active Gate: Milestone P2-H3 Blockers
Milestone P2-H3 is implemented in the working tree but blocked from owner acceptance by two issues:
1. **Provenance Defect:** Migration 0002 established a global UNIQUE index on `content_hash`. Chunks shared across documents or repeated within a document lose attribution or trigger constraint violations.
   - *Recommended Fix:* Promote `chunk_index` to a top-level column; establish composite uniqueness `UNIQUE(source_document, chunk_index)`; keep `content_hash` as a non-unique lookup index; deliver via forward migration `0003_source_scoped_knowledge_chunks.py`. (Migration 0002 must remain immutable).
2. **Exact-Search Retrieval Baseline:** Retrieval quality has not yet been validated against an exact sequential scan (`SET LOCAL enable_indexscan = off;`) to prove >=95% HNSW recall on a curated dataset.

#### 4. Test Suite Baseline
- Tier 1 (Offline / SQLite / Mock): 167 tests executed and 100% PASSING in 14.73s.
- Tier 2 (PostgreSQL Integration): 11 tests exist; currently blocked because Docker test container on port 5433 is stopped.
- Tier 3 (Ollama Live Integration): 2 tests exist; host Ollama is active on port 11434.

#### 5. Immediate Decisions Required from Project Owner
1. Formally approve Positional Uniqueness `UNIQUE(source_document, chunk_index)` and authoring of forward migration 0003.
2. Formally decide frontend stack: React 19 (ADR-005) vs. Streamlit MVP.
3. Formally approve mock-first strategy for P2-H4 Threat Intelligence.

#### 6. Safest Next Action
Do not modify code or migrations yet. Start the PostgreSQL test container (`docker compose up -d postgres`) and review the P2-H3 positional uniqueness proposal.
```
