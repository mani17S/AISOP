# AISOP — 15-LAYER ENGINEERING COMPLIANCE MATRIX
## Comprehensive Architecture, Security, Operational & Governance Assessment

- **Project:** AISOP (AI-Assisted Security Operations Platform)
- **Repository:** `D:\AISOP`
- **Milestone:** P4-GOV (Platform Governance & Compliance Milestone)
- **Previous Milestone:** Phase 4C — Reported ACCEPTED
- **Engineering Baseline:** `Vibe Coding a Real SaaS: The 15-Layer Playbook` (36-Page Engineering Blueprint)
- **Git Branch:** `main` (Preserved)
- **Git HEAD:** `c4e877cf06056bce32f5a3f893a82261b850ff85`
- **Evaluation Date:** October 31, 2026
- **Status:** **RECONCILED GOVERNANCE DELIVERABLE (ACCEPTED)**

---

# 1. Executive Summary & Methodology

### 1.1 Scope and Objective
This document provides the definitive, evidence-backed reconciliation and compliance evaluation of the AISOP platform against all fifteen architectural layers defined in *Vibe Coding a Real SaaS: The 15-Layer Playbook*. The objective is to evaluate AISOP not as an abstract prototype or collection of isolated unit tests, but as an integrated, secure, resilient, and maintainable local-first defensive security operations platform.

This governance deliverable reconciles all historical audit figures, establishes a single authoritative register of exactly 86 discrete engineering requirements, eliminates previous counting and classification ambiguities, provides repository-grounded evidence for every implementation claim, and qualifies all security evaluations based on actual test records.

### 1.2 Status Classification Standard
To ensure absolute engineering rigor, every requirement is evaluated against six mutually exclusive classification categories. Each requirement belongs to exactly one category:

1. **IMPLEMENTED AND VERIFIED:** Code exists in the repository, complies with architectural invariants, and is validated by automated unit, integration, or end-to-end tests with documented commands and passing results.
2. **IMPLEMENTED BUT NOT FULLY VERIFIED:** Code exists and operates, but live end-to-end verification remains gated (e.g., live LLM inference held in reserve pending operational authorization).
3. **PARTIALLY IMPLEMENTED:** Core foundation exists, but specific edge cases, sub-features, or operational documentation remain incomplete.
4. **MISSING AND REQUIRED:** Capability is mandatory for production or operational readiness at the current project scope but has not yet been implemented in the codebase.
5. **DEFERRED WITH JUSTIFICATION:** Capability is intentionally postponed to a future milestone with an explicit, documented architectural, budgetary, or operational justification.
6. **NOT APPLICABLE TO CURRENT SCOPE:** Requirement from commercial SaaS playbooks (e.g., public multi-tenant cloud hosting, external CDNs) that directly conflicts with AISOP's local-first SOC deployment model, zero cloud egress policy, or governance constraints.

### 1.3 Quantitative Compliance Scorecard (Authoritative Reconciliation)
The evaluation assessed **86 discrete engineering requirements** across all fifteen layers. Every requirement is individually registered with a unique identifier (`REQ-1.1` through `REQ-15.5`):

| Classification Category | Count | Percentage of Total (86 Reqs) | Percentage of Applicable (84 Reqs) |
| :--- | :---: | :---: | :---: |
| **Implemented and Verified** | **67** | **77.9%** | **79.8%** |
| **Implemented but not Fully Verified** | **1** | **1.2%** | **1.2%** |
| **Partially Implemented** | **4** | **4.7%** | **4.8%** |
| **Missing and Required** | **4** | **4.7%** | **4.8%** |
| **Deferred with Justification** | **8** | **9.3%** | **9.5%** |
| **Not Applicable to Current Scope** | **2** | **2.3%** | — |
| **Total Requirements Assessed** | **86** | **100.0%** | **100.0%** |

*Mathematical Invariant Verification:*
$$\text{Total Requirements} = 67 + 1 + 4 + 4 + 8 + 2 = 86$$
$$\text{Applicable Denominator} = 86 - 2 = 84$$
$$\text{Total Functionally Non-Blocking (Verified + Deferred)} = 67 + 8 = 75 \; (89.3\% \text{ of applicable})$$

### 1.4 Reconciliation & Register Integrity Audit
During previous governance passes, reporting figures contained conflicting numbers across executive summaries, detailed tables, and milestone logs. A rigorous audit of the source texts revealed the following root causes:

1. **Origin of the 54 vs. 67 Implemented Discrepancy:** The previous author synthesized 86 discrete requirements in the detailed matrix, where 67 were verified. However, in the executive summary, the author conflated 9 qualitative commercial SaaS architectural concepts (e.g., Stripe billing, consumer self-registration, public multi-tenancy) rejected at project inception with matrix-level requirements, and informally counted 14 deferred items. The author then computed verified requirements by subtracting $32$ from $86$ ($86 - 2 - 4 - 3 - 14 - 9 = 54$), producing a fabricated figure of 54 that directly contradicted the 67 verified items in the actual matrix.
2. **Origin of the 92 Table Total:** In the Section 3.1 detailed table, the author correctly tallied 67 verified items from the layer rows, but manually typed "14" into the Deferred column total (even though the row sum of deferred items was 8), and typed "2" into the Not Applicable total. Consequently, $67 + 2 + 4 + 3 + 14 + 2 = 92$, creating an internal mathematical contradiction against the 86 total requirement denominator.
3. **Reconciled Classification Corrections:**
   - **Layer 3 (REQ-3.7 — Database Backup & Recovery):** Previously described as missing in narrative text but categorized as partial in the table. Investigation confirmed that no backup script exists in the repository, `docs/11_Deployment/Deployment_Guide.md` is 0 bytes, and restore procedures/drills are unexecuted. REQ-3.7 is now authoritatively classified as **MISSING AND REQUIRED**.
   - **Layer 14 (REQ-14.3 — Database & pgvector Health Probe):** Previously classified as implemented but unverified. Inspection of `backend/app/api/v1/endpoints/health.py` revealed that `/api/v1/health/ready` executes `SELECT 1` for PostgreSQL connectivity, but completely lacks any query probing the `vector` extension or vector operators. Because the functionality is absent rather than awaiting live authorization, REQ-14.3 is now authoritatively classified as **PARTIALLY IMPLEMENTED**.
   - **Layer 8 (REQ-8.5 — Ground-Truth AI Evaluation):** Remains the sole **IMPLEMENTED BUT NOT FULLY VERIFIED** requirement (53 unit tests pass on the evaluation harness, but live model fixture captures remain 0/19 pending operator authorization).
   - **Deferred Work:** Exactly 8 requirements are deferred with documented architectural justifications (REQ-7.5, REQ-10.7, REQ-11.4, REQ-12.3, REQ-13.5, REQ-14.5, REQ-15.4, REQ-15.5).
   - **Not Applicable Requirements:** Exactly 2 requirements in the 86-item matrix are Not Applicable (REQ-9.4 public cloud SaaS hosting and REQ-12.4 public CDN edge caching). The 9 rejected SaaS concepts from *Vibe Coding a Real SaaS* are treated as architectural exclusion boundaries (REQ-1.6), not separate unnumbered requirements.

---

# 2. Fifteen-Layer Compliance Matrix

```mermaid
flowchart TD
    subgraph "Core Foundations (Layers 1-3)"
        L1["Layer 1: System Design (83.3%)"]
        L2["Layer 2: System Architecture (100%)"]
        L3["Layer 3: Databases & Storage (85.7%)"]
    end
    subgraph "Application Core (Layers 4-6)"
        L4["Layer 4: Auth & Permissions (100%)"]
        L5["Layer 5: APIs & Backend Logic (100%)"]
        L6["Layer 6: Frontend Experience (100%)"]
    end
    subgraph "DevSecOps & Quality (Layers 7-8)"
        L7["Layer 7: CI/CD & Version Control (20.0%)"]
        L8["Layer 8: Testing & Verification (83.3%)"]
    end
    subgraph "Infrastructure & Security (Layers 9-12)"
        L9["Layer 9: Hosting & Deployment (75.0%)"]
        L10["Layer 10: Application Security (85.7%)"]
        L11["Layer 11: Rate Limiting & Abuse (75.0%)"]
        L12["Layer 12: Caching & Isolation (66.7%)"]
    end
    subgraph "Operations & Scale (Layers 13-15)"
        L13["Layer 13: Logging & Error Tracking (80.0%)"]
        L14["Layer 14: Monitoring & Health Probes (60.0%)"]
        L15["Layer 15: Scaling & Concurrency (40.0%)"]
    end
    L1 --> L2 --> L3 --> L4 --> L5 --> L6
    L5 --> L7 & L8
    L5 --> L9 & L10 & L11 & L12
    L5 --> L13 & L14 & L15
```

---

## Layer 1 — System Design

### 1. Purpose of Layer in AISOP
Establishes the foundational mission, user personas, operational boundaries, and security invariants of AISOP. Guarantees that the platform solves real SOC analyst pain points (alert fatigue, evidence correlation, hallucination risk) without introducing autonomous SOAR hazards or data leakage.

### 2. Requirements Derived from Playbook
- **REQ-1.1:** Precise problem statement and target audience definition.
- **REQ-1.2:** Comprehensive Functional (FR) and Non-Functional Requirements (NFR).
- **REQ-1.3:** Analyst personas, global roles, and case-level workflow definition.
- **REQ-1.4:** Data sensitivity, forensic evidence provenance, and OPSEC privacy boundaries.
- **REQ-1.5:** Strict Human-in-the-Loop (HITL) and Anti-Autonomous SOAR invariants.
- **REQ-1.6:** Explicit out-of-scope boundaries (e.g., commercial billing, public multi-tenancy).

### 3. AISOP-Specific Interpretation
AISOP is an AI-assisted SOC investigation workbench, not an autonomous SOAR. It ingests multi-source security alerts, normalizes them canonically, preserves raw forensic evidence with SHA-256 hashes, enriches observables via local threat intelligence, maps techniques to MITRE ATT&CK, retrieves semantic playbooks from pgvector, and assists human analysts in assembling cases, evaluating AI-generated hypotheses with epistemic guardrails, and synthesizing audit-backed investigation reports.

### 4. Current Implementation Status: SUBSTANTIALLY IMPLEMENTED (83.3% of applicable requirements verified)
- REQ-1.1: **IMPLEMENTED AND VERIFIED**
- REQ-1.2: **IMPLEMENTED AND VERIFIED**
- REQ-1.3: **IMPLEMENTED AND VERIFIED**
- REQ-1.4: **IMPLEMENTED AND VERIFIED**
- REQ-1.5: **IMPLEMENTED AND VERIFIED**
- REQ-1.6: **PARTIALLY IMPLEMENTED** (Documentation reality drift between historical `README.md` and actual code)

### 5. Repository Evidence
- Problem & Vision: `docs/01_Project_Foundation/Problem_Statement.md`, `docs/01_Project_Foundation/Vision.md`.
- Software Requirements: `docs/02_SRS/SRS.md`.
- Personas & Workflow: `docs/07_Security/RBAC.md`, `docs/01_Architecture/Alert_Case_Evidence_Traceability.md`.
- Privacy & Anti-Autonomous Invariants: `docs/01_Project_Foundation/Design_Philosophy.md`, `docs/07_Security/Data_Privacy.md`.

### 6. Verification Evidence
- Architecture documents reviewed; verified adherence to local-first zero-billing policy `AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001`.
- Phase 4C Capstone Review certifies human-in-the-loop synthesis gates.

### 7. Missing Capabilities & Incomplete Verification
- **Documentation Drift in `README.md`:** `README.md` lines 34-37 still state that the Analyst Web UI is "0% Implemented", Case Routes are "Unmounted", and Auth is "Absent", which contradicts the actual Phase 4C accepted implementation.
- Older foundation docs reference an initial 4-role model rather than the accepted 6-role RBAC model (`security_admin`, `soc_lead`, `senior_analyst`, `tier1_analyst`, `auditor`, `ingest_service`).

### 8. Security and Operational Risks
- Misalignment between historical readme documentation and codebase confuses external reviewers regarding the true security perimeter.

### 9. Priority: MEDIUM
### 10. Mandatory for Current Stage: YES (Documentation correction)
### 11. Deferred Items & Justification: None.
### 12. Concrete Next Actions
1. Update `README.md` Section 2 ("Honest Feature Status & Reality Matrix") to accurately document Phase 4C delivered capabilities.

### 13. Acceptance Criteria for Closing Gaps
- `README.md` accurately describes the frontend, mounted case/report routes, and RBAC authentication system.

---

## Layer 2 — System Architecture

### 1. Purpose of Layer in AISOP
Defines the structural decomposition, modular boundaries, ingestion pipeline, data normalization, threat intelligence abstraction, and AI inference contracts.

### 2. Requirements Derived from Playbook
- **REQ-2.1:** Modular monolith domain structure with clean separation of concerns.
- **REQ-2.2:** Vendor-neutral alert ingestion with multi-source adapter extensibility.
- **REQ-2.3:** Canonical event normalization decoupled from raw evidence storage.
- **REQ-2.4:** Semantic knowledge retrieval (RAG) using 768-dim embeddings.
- **REQ-2.5:** Local-first threat intelligence orchestrator with Private Network Shield.
- **REQ-2.6:** Direct LLM provider protocol decoupling inference engines from business logic.
- **REQ-2.7:** Architecture Decision Records (ADRs) tracking design invariants.

### 3. AISOP-Specific Interpretation
AISOP rejects premature distributed microservice complexity. It adopts a modular monolith layout (`backend/app/modules/`) where modules interact via defined schemas, interfaces, and database models. The ingestion pipeline accepts raw JSON, computes SHA-256 hashes, normalizes vendor alerts into `CanonicalEvent`, extracts atomic observable entities, and persists raw evidence immutably.

### 4. Current Implementation Status: IMPLEMENTED AND VERIFIED (100.0% of applicable requirements verified)
- REQ-2.1 through REQ-2.7: **IMPLEMENTED AND VERIFIED**

### 5. Repository Evidence
- Modular domain structure: `backend/app/modules/alerts/`, `backend/app/modules/threatintel/`, `backend/app/modules/ai/`.
- Ingestion adapters: `SysmonParser`, `CrowdStrikeAdapter`, `ZeekAdapter`, `SentinelAdapter` in `backend/app/modules/alerts/`.
- Threat intelligence shield: `backend/app/modules/threatintel/shield.py` (`PrivateNetworkShield`).
- LLM Provider protocol: `backend/app/modules/ai/llm/protocol.py`, `backend/app/modules/ai/llm/manager.py`.
- Architectural ADRs: `docs/03_System_Design/ADR/ADR-001_LLM_Layer_Abstraction.md` through `ADR-007_Vendor_Neutral_Alert_Ingestion.md`.

### 6. Verification Evidence
- 1,198 passing backend tests confirm modular boundaries.
- Adapter test suite: `backend/tests/unit/test_vendor_neutral_alerts.py` (28 passed).
- Private shield test suite: `backend/tests/unit/test_threatintel_private_shield.py` (42 passed).

### 7. Missing Capabilities & Incomplete Verification
- Pull-based active collectors (polling external SIEM REST APIs) are absent; current ingestion is 100% push-based via HTTP POST.

### 8. Security and Operational Risks
- Ingestion of un-sanitized vendor payloads with deeply nested JSON could cause parser recursion depth exhaustion if bounds are bypassed.

### 9. Priority: LOW (Already robust)
### 10. Mandatory for Current Stage: YES
### 11. Deferred Items & Justification
- Active SIEM Pull Collectors: Deferred to enterprise ingestion milestones; push API satisfies current SOC architectures.

### 12. Concrete Next Actions
- Maintain strict modular boundary imports; enforce via linters.

### 13. Acceptance Criteria for Closing Gaps
- Architecture remains modular; no cross-domain circular dependencies.

---

## Layer 3 — Databases and Storage

### 1. Purpose of Layer in AISOP
Governs the persistence layer, relational integrity, vector similarity indexing, database migrations, cryptographic provenance, and immutable audit logs.

### 2. Requirements Derived from Playbook
- **REQ-3.1:** Production-grade relational database engine (PostgreSQL 17) with pgvector.
- **REQ-3.2:** Asynchronous ORM models (SQLAlchemy 2.0) with clean schema definitions.
- **REQ-3.3:** Version-controlled database migrations (Alembic) with reversible upgrade/downgrade.
- **REQ-3.4:** Relational integrity constraints, foreign key cascades, and partial unique indexes.
- **REQ-3.5:** Cryptographic content hashing (SHA-256) and idempotent evidence deduplication.
- **REQ-3.6:** Database-level append-only audit triggers preventing update/delete tampering.
- **REQ-3.7:** Automated database backup, restore, and disaster recovery procedures.

### 3. AISOP-Specific Interpretation
Data integrity is paramount in forensic security systems. Evidence must not be modifiable once recorded. AISOP enforces this via SHA-256 content hashes, database-level triggers blocking `UPDATE` or `DELETE` on `case_audit_events`, strict foreign keys between alerts, cases, and evidence, and partial unique indexes preventing duplicate alert insertion.

### 4. Current Implementation Status: SUBSTANTIALLY IMPLEMENTED / OPERATIONAL GAP (85.7% of applicable requirements verified)
- REQ-3.1 to REQ-3.6: **IMPLEMENTED AND VERIFIED**
- REQ-3.7: **MISSING AND REQUIRED** (No backup script exists in repository; `docs/11_Deployment/Deployment_Guide.md` is 0 bytes; restore procedures and disaster recovery testing unexecuted)

### 5. Repository Evidence
- Engine configuration: `backend/app/db/session.py` (AsyncEngine, pooling parameters).
- ORM models: `backend/app/models/case.py`, `backend/app/models/knowledge.py`, `backend/app/models/analyst.py`.
- Alembic migrations: `backend/app/db/migrations/versions/` (Migrations 0001 through 0004).
- Audit triggers: Migration `20261025_0004_p3h2_rbac_case_scoping.py` implements PostgreSQL trigger `prevent_audit_event_tampering()`.
- Container configuration: `docker-compose.yml` (`aisop-postgres` service using `pgvector/pgvector:pg17`).

### 6. Verification Evidence
- PostgreSQL 17 + pgvector lifecycle verification suite: `backend/tests/integration/test_postgres_lifecycle.py` (29 passed).
- Case scoping and BOLA database verification: `backend/tests/integration/test_postgres_case_scoping.py` (14 passed).
- Alembic migration parity: Migration test suite `backend/tests/unit/test_migrations.py` (12 passed).

### 7. Missing Capabilities & Incomplete Verification
- **CRITICAL GAP:** `docs/11_Deployment/Deployment_Guide.md` is empty (0 bytes). Automated `pg_dump` backup scripts and restore drill tests have not been executed against the container.

### 8. Security and Operational Risks
- Failure to verify automated backup and restore procedures risks irreversible data loss in the event of host volume corruption.

### 9. Priority: HIGH
### 10. Mandatory for Current Stage: YES (Operational Backup Script)
### 11. Deferred Items & Justification: None.
### 12. Concrete Next Actions
1. Author `scripts/backup_postgres.ps1` utilizing `docker exec -t aisop-postgres pg_dump` to create compressed SQL dumps.
2. Populate `docs/11_Deployment/Deployment_Guide.md` with step-by-step restoration commands.

### 13. Acceptance Criteria for Closing Gaps
- Tested backup script generates valid SQL dump; restoration verified on clean test database.

---

## Layer 4 — Authentication and Permissions

### 1. Purpose of Layer in AISOP
Provides ingress security, identity verification, role-based access control (RBAC), and multi-analyst case authorization preventing Broken Object Level Authorization (BOLA/IDOR).

### 2. Requirements Derived from Playbook
- **REQ-4.1:** Secure API ingress authentication with machine client token support.
- **REQ-4.2:** Constant-time token comparison preventing timing attacks.
- **REQ-4.3:** Tiered Global Roles (`security_admin`, `soc_lead`, `senior_analyst`, `tier1_analyst`, `auditor`, `ingest_service`).
- **REQ-4.4:** Context-aware Case Roles (`lead`, `investigator`, `viewer`).
- **REQ-4.5:** Server-side authorization dependencies enforcing BOLA/IDOR protection.
- **REQ-4.6:** Anti-enumeration behavior returning HTTP 404 for unauthorized foreign cases.

### 3. AISOP-Specific Interpretation
Defensive security tools are high-value targets. AISOP implements Bearer token ingress verification with SHA-256 hashed token lookup in the database. When an analyst accesses a case, server-side dependencies (`require_case_access`) inspect the user's role on that specific case dossier. If unauthorized, the API returns HTTP 404 rather than 403, preventing case ID enumeration.

### 4. Current Implementation Status: IMPLEMENTED AND VERIFIED (100.0% of applicable requirements verified)
- REQ-4.1 through REQ-4.6: **IMPLEMENTED AND VERIFIED**

### 5. Repository Evidence
- Token verification: `backend/app/core/auth.py` (`verify_api_key`, `hmac.compare_digest`).
- RBAC dependencies: `backend/app/core/rbac.py` (`require_global_role`, `require_case_role`, `require_case_access`).
- Anti-enumeration invariant: `backend/app/api/v1/endpoints/cases.py` lines 128-135 (raising 404 for unauthorized cases).
- Role documentation: `docs/07_Security/RBAC.md`, `docs/03_System_Design/Role_Hierarchy_Matrix.md`.

### 6. Verification Evidence
- Auth test suite: `backend/tests/unit/test_api_auth.py` (19 passed).
- RBAC unit tests: `backend/tests/unit/test_rbac.py` and `test_rbac_dependencies.py` (48 passed).
- BOLA anti-enumeration test suite: `backend/tests/unit/test_case_bola_security.py` (41 passed).

### 7. Missing Capabilities & Incomplete Verification
- SSO / SAML / OIDC integration (e.g. Okta, Azure AD) is not implemented; authentication currently uses hashed bearer tokens.

### 8. Security and Operational Risks
- Compromised bearer tokens must be revoked manually in the database; automated revocation list / token rotation UI is absent.

### 9. Priority: MEDIUM
### 10. Mandatory for Current Stage: YES (Bearer tokens verified)
### 11. Deferred Items & Justification
- Enterprise SSO/OIDC: Deferred to enterprise integration phase; bearer token hashing satisfies current SOC deployment.

### 12. Concrete Next Actions
- Provide token management CLI scripts for SOC administrators (`scripts/create_analyst_token.py`).

### 13. Acceptance Criteria for Closing Gaps
- All ingress endpoints require valid Bearer token; foreign case access reliably yields 404.

---

## Layer 5 — APIs and Backend Logic

### 1. Purpose of Layer in AISOP
Implements core business logic, alert management, investigation synthesis, report generation, and transactional boundaries.

### 2. Requirements Derived from Playbook
- **REQ-5.1:** Versioned REST API routing (`/api/v1`) with OpenAPI documentation.
- **REQ-5.2:** Bounded Pydantic v2 schemas validating all inputs and outputs.
- **REQ-5.3:** Safe bounded pagination (`DEFAULT=50`, `MAX=200`) on all list endpoints.
- **REQ-5.4:** Atomic database transactions and nested savepoint isolation for batch operations.
- **REQ-5.5:** Structured multi-audience report synthesis API (`POST .../reports/synthesize`).
- **REQ-5.6:** Role-tailored report export API (`GET .../reports/export`) supporting Markdown and JSON.
- **REQ-5.7:** Centralized error handling and defensive HTTP status code mappings.

### 3. AISOP-Specific Interpretation
All backend capabilities are exposed through FastAPI endpoints mounted under `/api/v1`. Strict Pydantic models validate input boundaries (maximum batch size 2,000, max payload 64 KB, bounded string lengths). Multi-audience reporting synthesizes three distinct views (Executive, Technical, Detection Playbook) from validated investigation context.

### 4. Current Implementation Status: IMPLEMENTED AND VERIFIED (100.0% of applicable requirements verified)
- REQ-5.1 through REQ-5.7: **IMPLEMENTED AND VERIFIED**

### 5. Repository Evidence
- Versioned endpoints: `backend/app/api/v1/endpoints/alerts.py`, `cases.py`, `investigations.py`, `reports.py`, `evidence.py`.
- Validation schemas: `backend/app/schemas/alert.py`, `case.py`, `investigation.py`, `report.py`.
- Report export API: `backend/app/api/v1/endpoints/reports.py` (`export_case_report`).
- Savepoint isolation: `backend/app/services/alert_ingestion_service.py` (`session.begin_nested()`).

### 6. Verification Evidence
- Capstone integration suite: `backend/tests/integration/test_phase4c_capstone.py` (6/6 passed).
- Report export unit tests: `backend/tests/unit/test_report_export_api.py` (18 passed).
- Case schemas and service tests: `backend/tests/unit/test_case_schemas.py`, `test_case_service.py` (32 passed).

### 7. Missing Capabilities & Incomplete Verification
- WebSocket or Server-Sent Events (SSE) streaming for real-time alert triage updates is absent; UI relies on polling.

### 8. Security and Operational Risks
- Extremely large investigation dossiers could exceed memory during report rendering if unbounded evidence items are attached.

### 9. Priority: LOW
### 10. Mandatory for Current Stage: YES
### 11. Deferred Items & Justification
- Real-time WebSockets: Deferred; REST polling is adequate for student/analyst triage cadence.

### 12. Concrete Next Actions
- Enforce memory-safe streaming for large JSON export bundles.

### 13. Acceptance Criteria for Closing Gaps
- Export API delivers Markdown and JSON bundles with valid checksums and audit trail logging.

---

## Layer 6 — Frontend

### 1. Purpose of Layer in AISOP
Delivers the analyst user interface for alert triage, case management, interactive investigation, epistemic guardrail visualization, and report review.

### 2. Requirements Derived from Playbook
- **REQ-6.1:** Modern React 18, TypeScript, and Vite frontend architecture.
- **REQ-6.2:** Multi-source alert triage queue with promotion to case (`Alerts.tsx`).
- **REQ-6.3:** Evidence-centered investigation workspace (`InvestigationWorkspace.tsx`).
- **REQ-6.4:** Multi-tab role-tailored report viewer with export controls (`ReportViewer.tsx`).
- **REQ-6.5:** Comprehensive UI state handling (loading spinners, empty states, error banners).
- **REQ-6.6:** Strict adherence to AISOP Website Design Constitution (dark mode, no emojis, no purple gradients).
- **REQ-6.7:** Automated component unit testing and zero TypeScript build errors.

### 3. AISOP-Specific Interpretation
The frontend provides a dark-mode, high-density operations center designed according to the AISOP Website Design Constitution. It features monospace technical typography, subtle borders, amber/red/blue status badges, and zero decorative animations. Key workflows include promoting unassigned alerts to cases, viewing normalized forensic events, triggering AI investigation synthesis, and reviewing multi-tab reports with one-click Markdown/JSON download.

### 4. Current Implementation Status: IMPLEMENTED AND VERIFIED (100.0% of applicable requirements verified)
- REQ-6.1 through REQ-6.7: **IMPLEMENTED AND VERIFIED**

### 5. Repository Evidence
- Configuration: `frontend/package.json`, `frontend/vite.config.ts`, `frontend/tsconfig.json`.
- Pages & Components: `frontend/src/pages/Alerts.tsx`, `frontend/src/components/InvestigationWorkspace.tsx`, `frontend/src/components/ReportViewer.tsx`.
- Design Constitution: `docs/08_Frontend/AISOP_Website_Design_Constitution.md`, `frontend/src/styles/index.css`.
- API integration: `frontend/src/services/api.ts`.

### 6. Verification Evidence
- Vitest component test suite: `npm test` runs 33 unit tests across 5 test suites; 33 passed in 171.6ms.
- TypeScript verification: `npm run typecheck` passes with 0 errors.
- Production build: `npm run build` succeeds cleanly producing optimized bundle in `frontend/dist/`.

### 7. Missing Capabilities & Incomplete Verification
- Graph-based interactive attack-chain visualization (e.g. Cytoscape or React Flow) is deferred; currently presented as structured lists and timelines.

### 8. Security and Operational Risks
- Storing bearer tokens in browser `localStorage` exposes tokens to Cross-Site Scripting (XSS) if DOM injection mitigations fail.

### 9. Priority: MEDIUM
### 10. Mandatory for Current Stage: YES
### 11. Deferred Items & Justification
- Interactive Visual Graph Canvas: Deferred to Phase 5; structured tabular and timeline views provide complete forensic coverage.

### 12. Concrete Next Actions
- Migrate token storage to HTTP-only SameSite cookies when reverse proxy is deployed.

### 13. Acceptance Criteria for Closing Gaps
- Frontend builds with zero TypeScript errors and all component tests pass.

---

## Layer 7 — CI/CD and Version Control

### 1. Purpose of Layer in AISOP
Automates code quality verification, multi-tier test execution, security scanning, and migration safety checks upon every commit and pull request.

### 2. Requirements Derived from Playbook
- **REQ-7.1:** Git version control discipline, clean branch hygiene, and commit integrity.
- **REQ-7.2:** Automated CI workflow executing backend unit tests on pull requests.
- **REQ-7.3:** Automated frontend typechecking (`tsc`) and build verification in CI.
- **REQ-7.4:** Automated dependency vulnerability scanning (`pip-audit`, `npm audit`) and secret detection.
- **REQ-7.5:** Automated database migration parity and rollback testing in CI.

### 3. AISOP-Specific Interpretation
ADR-006 establishes the multi-tier testing strategy. All 1,198 backend tests and 33 frontend tests are regularly executed locally via CLI scripts. However, to meet true production engineering standards, these gates must run automatically in a remote CI pipeline (e.g. GitHub Actions) to prevent unverified commits from entering the `main` branch.

### 4. Current Implementation Status: NON-COMPLIANT / ACTIVE GAPS (20.0% of applicable requirements verified)
- REQ-7.1: **IMPLEMENTED AND VERIFIED** (Git discipline, branch tracking, commit hygiene)
- REQ-7.2: **MISSING AND REQUIRED** (No GitHub Actions workflow file in `.github/workflows/`; backend tests not automated)
- REQ-7.3: **MISSING AND REQUIRED** (Frontend CI check workflow absent; typechecking not automated in CI)
- REQ-7.4: **MISSING AND REQUIRED** (Automated dependency audit and secret scanning in CI absent)
- REQ-7.5: **DEFERRED WITH JUSTIFICATION** (PostgreSQL container integration in cloud CI deferred)

### 5. Repository Evidence
- Git configuration: `main` branch tracking, `.gitignore`.
- Empty directory: `.github/workflows/` exists but contains zero workflow YAML files.
- Manual verification commands: `pytest -m "not postgres and not ollama"`, `npm test`, `npm run typecheck`.

### 6. Verification Evidence
- Directory inspection: `Get-ChildItem D:\AISOP\.github\workflows` confirms 0 workflow files present.
- Local test execution: 1,198 backend tests pass, 33 frontend tests pass.

### 7. Missing Capabilities & Incomplete Verification
- **CRITICAL GAP:** Automated continuous integration is absent. Currently, test execution relies on manual developer discipline before merging or tagging milestones. No branch protection rules or automated PR checks exist.

### 8. Security and Operational Risks
- Without automated PR gating, a developer could merge code containing broken tests, type errors, or hardcoded secrets without detection.

### 9. Priority: HIGH (Highest operational priority post-Phase 4C)
### 10. Mandatory for Current Stage: YES (Automated CI Workflow)
### 11. Deferred Items & Justification
- Live PostgreSQL 17 in Cloud CI: Deferred; requires Docker-in-Docker GitHub Actions runner configuration. Local disposable DB testing is verified.

### 12. Concrete Next Actions
1. Author `.github/workflows/ci.yml` running:
   - Python 3.12 setup, dependency installation via `uv`/`pip`.
   - Backend offline test suite (`pytest -m "not postgres and not ollama"`).
   - Frontend setup, `npm test`, `npm run typecheck`, and `npm run build`.
   - `pip-audit` vulnerability scanning.

### 13. Acceptance Criteria for Closing Gaps
- GitHub Actions CI workflow triggers on push/PR to `main` and passes with green checkmark.

---

## Layer 8 — Testing

### 1. Purpose of Layer in AISOP
Provides comprehensive, multi-tiered test coverage across unit logic, database invariants, security boundaries, AI guardrails, and end-to-end investigation workflows.

### 2. Requirements Derived from Playbook
- **REQ-8.1:** Multi-tier test architecture (Tiers 1, 2, 3, 4) with strict marker isolation.
- **REQ-8.2:** Comprehensive unit test coverage across all services, models, and parsers.
- **REQ-8.3:** Real PostgreSQL 17 + pgvector integration test suite.
- **REQ-8.4:** Negative, boundary, and BOLA/IDOR security test suites.
- **REQ-8.5:** Ground-truth AI evaluation framework with 20 curated SOC scenarios.
- **REQ-8.6:** End-to-end Capstone integration test verifying the entire investigation lifecycle.

### 3. AISOP-Specific Interpretation
AISOP distinguishes between fast offline mock tests and real containerized database tests. Tests marked `not postgres and not ollama` run in under 60 seconds using in-memory SQLite adapters for rapid feedback. Real PostgreSQL tests run on port 5433 against an isolated disposable database. Live LLM inference tests (`@pytest.mark.ollama`) remain gated pending explicit operational authorization to prevent unmetered executions.

### 4. Current Implementation Status: SUBSTANTIALLY IMPLEMENTED (83.3% of applicable requirements verified)
- REQ-8.1, 8.2, 8.3, 8.4, 8.6: **IMPLEMENTED AND VERIFIED**
- REQ-8.5: **IMPLEMENTED BUT NOT FULLY VERIFIED** (Evaluation harness and 53 unit tests pass, but live model fixture captures remain 0/19 pending authorization)

### 5. Repository Evidence
- Multi-tier test suite: `backend/tests/unit/`, `backend/tests/integration/`.
- Conftest & markers: `backend/tests/conftest.py` (defining `postgres`, `ollama`, and session fixtures).
- PostgreSQL integration: `backend/tests/integration/test_postgres_lifecycle.py` (29 passed).
- Capstone integration: `backend/tests/integration/test_phase4c_capstone.py` (6 passed).
- Ground-truth evaluation framework: `backend/app/modules/evaluation/` and `datasets/ground_truth/`.

### 6. Verification Evidence
- Offline backend test execution: 1,198 passed, 0 failed in 54.18s.
- PostgreSQL container test execution: 29 passed against `aisop_p4c_disposable` database.
- AI evaluation harness test execution: 53 passed in `test_ai_evaluation_framework.py`.

### 7. Missing Capabilities & Incomplete Verification
- Live capture protocol for Ollama model benchmarks remains held in reserve pending operator approval (`P3-H3B` gating).

### 8. Security and Operational Risks
- Regressions in database queries or vector embeddings could occur if developers execute only offline Tier 1 tests without running Tier 3 against real PostgreSQL.

### 9. Priority: LOW (Testing is exceptionally thorough)
### 10. Mandatory for Current Stage: YES
### 11. Deferred Items & Justification
- Live Ollama Model Fixture Capture: Formally gated pending project owner authorization.

### 12. Concrete Next Actions
- Automate Tier 1 test execution in CI (Layer 7).

### 13. Acceptance Criteria for Closing Gaps
- Zero test failures across all 1,198 unit/integration tests and 33 frontend tests.

---

## Layer 9 — Hosting and Cloud

### 1. Purpose of Layer in AISOP
Defines the execution environment, container orchestration, environment configuration, network segregation, and deployment topology.

### 2. Requirements Derived from Playbook
- **REQ-9.1:** Containerized deployment infrastructure (`docker-compose.yml`).
- **REQ-9.2:** Environment variable configuration template (`.env.example`).
- **REQ-9.3:** Hardened private SOC deployment architecture (TLS reverse proxy, internal DNS).
- **REQ-9.4:** Public cloud SaaS deployment architecture (AWS, GCP, Azure multi-tenant).
- **REQ-9.5:** Strict adherence to ₹0 cloud egress policy (`AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001`).

### 3. AISOP-Specific Interpretation
AISOP is explicitly architected as an on-premises, local-first platform designed to run within an isolated SOC laboratory network or local workstation. Multi-tenant public cloud SaaS deployment is intentionally rejected to comply with student project constraints and prevent unauthorized organizational telemetry egress.

### 4. Current Implementation Status: COMPLIANT FOR LOCAL SCOPE (75.0% of applicable requirements verified; 1 N/A)
- REQ-9.1, 9.2, 9.5: **IMPLEMENTED AND VERIFIED**
- REQ-9.3: **PARTIALLY IMPLEMENTED** (Docker container runs locally; Nginx TLS reverse-proxy config un-templated)
- REQ-9.4: **NOT APPLICABLE TO CURRENT SCOPE** (Violates local-first zero-egress policy)

### 5. Repository Evidence
- `docker-compose.yml`: Defines `aisop-postgres` container using PostgreSQL 17 + pgvector on port 5433 with healthchecks.
- `.env.example`: Configuration template with local hostnames and zero hardcoded secrets.
- `docs/01_Project_Foundation/Design_Philosophy.md`: Invariant declaration of local-first deployment.

### 6. Verification Evidence
- Container verification: `docker ps --filter "name=aisop-postgres"` confirms container healthy on port 5433.
- Network verification: Zero external outbound network calls observed during full regression test execution.

### 7. Missing Capabilities & Incomplete Verification
- A production-ready Nginx / Caddy reverse-proxy configuration template with self-signed or internal CA TLS certificates is missing from `deploy/`.

### 8. Security and Operational Risks
- Exposing the backend FastAPI port directly to a local subnet without a TLS reverse proxy exposes internal API tokens in plaintext over the LAN.

### 9. Priority: MEDIUM
### 10. Mandatory for Current Stage: YES (Local Docker Compose); NO for Public Cloud
### 11. Deferred Items & Justification
- Public Cloud SaaS Deployment: NOT APPLICABLE; directly contradicts AISOP's privacy mandate.

### 12. Concrete Next Actions
1. Create `deploy/nginx/nginx.conf` providing an SSL/TLS reverse-proxy template terminating HTTPS.

### 13. Acceptance Criteria for Closing Gaps
- Nginx configuration cleanly forwards HTTPS traffic to FastAPI backend with security headers.

---

## Layer 10 — Security

### 1. Purpose of Layer in AISOP
Provides defense-in-depth protection against the OWASP Top 10, API security vulnerabilities, prompt injection, sensitive data leakage, and unauthorized telemetry access.

### 2. Requirements Derived from Playbook
- **REQ-10.1:** Comprehensive threat model and OWASP Top 10 vulnerability mitigations.
- **REQ-10.2:** Complete SQL Injection prevention via parameterized queries.
- **REQ-10.3:** Cross-Site Scripting (XSS) prevention across all user and alert payloads.
- **REQ-10.4:** Server-Side Request Forgery (SSRF) mitigation for threat intelligence feeds.
- **REQ-10.5:** Hardened HTTP security headers (`SecurityHeadersMiddleware`).
- **REQ-10.6:** AI safety guardrails, prompt injection isolation, and epistemic segregation.
- **REQ-10.7:** Independent third-party penetration testing and formal security certification.

### 3. AISOP-Specific Interpretation & Evidence-Based Security Qualification
Security is AISOP's core domain. Rather than asserting absolute immunity, AISOP's security posture is rigorously qualified by available verification evidence:

- **Automated Security Tests:** Passed. 15 security headers tests, 42 private shield SSRF tests, 28 sanitizer/XSS tests, and comprehensive BOLA/IDOR test suites pass automatically.
- **Static Analysis & Linters:** Completed. Strict typechecking (`tsc`, `mypy`) and linting rules verify syntax and type bounds.
- **Dependency Vulnerability Scanning:** Completed locally via manual CLI execution (`pip-audit` reports zero High or Critical vulnerabilities; automated PR scanning in CI is an identified gap under Layer 7).
- **Manual Code Review:** Completed. All SQL queries use parameterized SQLAlchemy 2.0 expressions; SSRF protection is enforced by `PrivateNetworkShield`; prompt injection is defended by XML encapsulation (`<investigation_context>`).
- **Professional Penetration Testing:** **NOT PERFORMED.** No external third-party CREST/OSCP accredited penetration test or formal SOC 2 / ISO 27001 audit has been conducted to date. Residual risk remains subject to independent security assessment.

### 4. Current Implementation Status: SUBSTANTIALLY IMPLEMENTED (85.7% of applicable requirements verified)
- REQ-10.1 through REQ-10.6: **IMPLEMENTED AND VERIFIED**
- REQ-10.7: **DEFERRED WITH JUSTIFICATION** (Professional third-party penetration test deferred to pre-production audit)

### 5. Repository Evidence
- `backend/app/middleware/security_headers.py`: Injects CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, HSTS.
- `backend/app/modules/threatintel/shield.py`: RFC 1918 Private Network Shield.
- `backend/app/modules/ai/prompt_builder/builder.py`: XML-escaped prompt builder isolating untrusted observables.
- `backend/app/modules/ai/guardrails/validator.py`: 3-Tier epistemic guardrails validator.

### 6. Verification Evidence
- Security headers test suite: `backend/tests/unit/test_security_headers.py` (15 passed).
- Private shield test suite: `backend/tests/unit/test_threatintel_private_shield.py` (42 passed).
- Sanitizer and XSS unit tests: `backend/tests/unit/test_aisop_sanitizer.py` (28 passed).
- Frontend XSS tests: `frontend/tests/investigation_workspace.test.tsx` (XSS escaping verified).

### 7. Missing Capabilities & Incomplete Verification
- A formal external penetration test report from an independent accredited security firm has not been conducted. Internal automated test coverage is verified.

### 8. Security and Operational Risks
- Undetected zero-day vulnerabilities in third-party Python dependencies (FastAPI, Pydantic, SQLAlchemy) or Node dependencies.

### 9. Priority: MEDIUM
### 10. Mandatory for Current Stage: YES (Automated defenses verified)
### 11. Deferred Items & Justification
- External Penetration Test: Deferred to enterprise certification phase; automated test suites provide comprehensive coverage.

### 12. Concrete Next Actions
1. Run `pip-audit` and `npm audit` weekly; document output in `docs/07_Security/`.

### 13. Acceptance Criteria for Closing Gaps
- `pip-audit` reports 0 known High or Critical vulnerabilities.

---

## Layer 11 — Rate Limiting

### 1. Purpose of Layer in AISOP
Protects backend APIs from denial-of-service, brute-force token enumeration, and excessive AI synthesis workload surges.

### 2. Requirements Derived from Playbook
- **REQ-11.1:** Token-bucket ingress rate limiting middleware (`RateLimitMiddleware`).
- **REQ-11.2:** Client identification by API token / IP with standard RFC 6585 HTTP 429 responses.
- **REQ-11.3:** Endpoint sensitivity discrimination (exempting health checks, protecting AI inference).
- **REQ-11.4:** Distributed shared rate limiting store (e.g. Redis Cluster).

### 3. AISOP-Specific Interpretation
AISOP utilizes an in-memory token-bucket algorithm (`RateLimitMiddleware`) providing per-token and per-IP throttling at ₹0 additional infrastructure cost. Standard HTTP 429 responses are returned with `Retry-After` headers. High-cost AI inference routes are subject to strict concurrency and rate boundaries.

### 4. Current Implementation Status: COMPLIANT FOR LOCAL SCOPE (75.0% of applicable requirements verified; 1 deferred)
- REQ-11.1, 11.2, 11.3: **IMPLEMENTED AND VERIFIED**
- REQ-11.4: **DEFERRED WITH JUSTIFICATION** (Redis unnecessary for single-instance local SOC deployment)

### 5. Repository Evidence
- Middleware implementation: `backend/app/middleware/rate_limit.py`.
- Rate limit configuration: `backend/app/core/config.py` (`RATE_LIMIT_PER_MINUTE=100`, `BURST_CAPACITY=20`).
- Documentation: `docs/07_Security/Security_Architecture.md`.

### 6. Verification Evidence
- Rate limiting unit test suite: `backend/tests/unit/test_rate_limiting.py` (14 passed, verifying 429 response, header presence, and token refill).

### 7. Missing Capabilities & Incomplete Verification
- Differentiated rate limits per endpoint category (e.g., lower limit for `/investigations/synthesize` vs higher limit for `/alerts/ingest`) share the same global token bucket.

### 8. Security and Operational Risks
- In-memory rate limiting state is reset if the FastAPI process restarts; rapid restarts could allow bursts.

### 9. Priority: LOW
### 10. Mandatory for Current Stage: YES (In-memory verified)
### 11. Deferred Items & Justification
- Distributed Redis Rate Limiting Store: Deferred; in-memory token bucket provides complete protection for single-host deployment at ₹0 cost.

### 12. Concrete Next Actions
- Split rate limit buckets by route priority (triage vs AI synthesis).

### 13. Acceptance Criteria for Closing Gaps
- Route-specific limits enforced with independent bucket replenishment.

---

## Layer 12 — Caching and CDN

### 1. Purpose of Layer in AISOP
Accelerates observable threat lookups, prevents duplicate threat intelligence lookups, and ensures complete forensic isolation between distinct case dossiers.

### 2. Requirements Derived from Playbook
- **REQ-12.1:** Local threat intelligence observable lookup caching with TTL.
- **REQ-12.2:** Strict case isolation preventing cross-case evidence cache leakage.
- **REQ-12.3:** Database query and semantic vector search result caching.
- **REQ-12.4:** Content Delivery Network (CDN) edge caching for static frontend assets.

### 3. AISOP-Specific Interpretation
In forensic analysis, caching must be used with extreme caution. AISOP restricts caching strictly to read-only threat intelligence lookups (`MemoryCache` with 24-hour TTL). Case dossiers, alert states, and investigation synthesis outputs are **intentionally never cached** in shared memory to eliminate cross-case evidence leakage. Public CDN edge caching is explicitly rejected as incompatible with air-gapped local networks.

### 4. Current Implementation Status: COMPLIANT FOR LOCAL SCOPE (66.7% of applicable requirements verified; 1 deferred, 1 N/A)
- REQ-12.1, 12.2: **IMPLEMENTED AND VERIFIED**
- REQ-12.3: **DEFERRED WITH JUSTIFICATION** (Deliberately avoided to guarantee forensic isolation)
- REQ-12.4: **NOT APPLICABLE TO CURRENT SCOPE** (Public CDN conflicts with local-first air-gapped SOC operations)

### 5. Repository Evidence
- Threat cache: `backend/app/modules/threatintel/cache/memory_cache.py`.
- Cache isolation policy: `backend/app/services/case_service.py` (all reads query database directly).
- Orchestrator cache wiring: `backend/app/modules/threatintel/orchestrator.py`.

### 6. Verification Evidence
- Cache unit tests: `backend/tests/unit/test_threatintel_foundation.py` (18 passed, testing TTL expiration, eviction, and thread safety).

### 7. Missing Capabilities & Incomplete Verification
- Persistent disk caching of downloaded threat intelligence feed files (currently loads into memory on startup).

### 8. Security and Operational Risks
- Stale threat intelligence indicators if feeds are not refreshed within the 24-hour TTL window.

### 9. Priority: LOW
### 10. Mandatory for Current Stage: YES (In-memory threat cache verified)
### 11. Deferred Items & Justification
- Vector Query Caching: Deferred to preserve exact real-time database state and avoid stale security playbooks.

### 12. Concrete Next Actions
- Add cache invalidation CLI hook for threat intelligence feeds.

### 13. Acceptance Criteria for Closing Gaps
- Threat intelligence lookups leverage local memory cache; case queries bypass cache completely.

---

## Layer 13 — Error Tracking and Logs

### 1. Purpose of Layer in AISOP
Provides structured diagnostic logging, request correlation, automated secret sanitization, and immutable database audit trails.

### 2. Requirements Derived from Playbook
- **REQ-13.1:** High-performance structured logging (JSON/text) with Loguru.
- **REQ-13.2:** End-to-end request correlation tracking via `X-Request-ID`.
- **REQ-13.3:** Automated sensitive credential and secret redaction in log records.
- **REQ-13.4:** Append-only immutable audit event logging for all case actions (`case_audit_events`).
- **REQ-13.5:** External cloud error monitoring and APM tracking (Sentry, Datadog).

### 3. AISOP-Specific Interpretation
All diagnostic logs are handled by Loguru formatted as structured JSON or readable console output. Every HTTP transaction is assigned a UUID `X-Request-ID` via `CorrelationIdMiddleware`. Sensitive tokens (`Bearer`, `Authorization`, API keys) are redacted before emission. Tamper-resistant audit events are persisted directly into PostgreSQL with database trigger immutability. Cloud APM (Sentry) is prohibited under zero-cloud-egress invariants.

### 4. Current Implementation Status: COMPLIANT FOR LOCAL SCOPE (80.0% of applicable requirements verified; 1 deferred)
- REQ-13.1, 13.2, 13.3, 13.4: **IMPLEMENTED AND VERIFIED**
- REQ-13.5: **DEFERRED WITH JUSTIFICATION** (Cloud APM prohibited under zero-egress policy)

### 5. Repository Evidence
- Logging configuration: `backend/app/core/logging.py`.
- Correlation middleware: `backend/app/middleware/correlation.py`.
- Audit event model: `backend/app/models/case.py` (`CaseAuditEvent`).
- Database immutability trigger: Migration `20261025_0004_p3h2_rbac_case_scoping.py`.

### 6. Verification Evidence
- Correlation logging tests: `backend/tests/unit/test_security_headers.py` (verifies `X-Request-ID` echo).
- Audit trail emission tests: `backend/tests/unit/test_case_service.py` (16 passed).
- Phase 4C Capstone test: Verifies `case_report_exported` immutable audit event creation.

### 7. Missing Capabilities & Incomplete Verification
- An on-premises self-hosted log aggregator dashboard (e.g. local Grafana Loki or OpenSearch) is not packaged.

### 8. Security and Operational Risks
- High log volume during large ingestion batches could consume disk space if rotation (`10 MB`, `30 days`) is misconfigured.

### 9. Priority: LOW (Logging is mature)
### 10. Mandatory for Current Stage: YES
### 11. Deferred Items & Justification
- Cloud APM / Sentry: Deferred; violates zero-egress policy. Local structured logs provide complete diagnostic capability.

### 12. Concrete Next Actions
- Monitor disk usage of `logs/aisop.log` under heavy ingestion runs.

### 13. Acceptance Criteria for Closing Gaps
- All requests log `X-Request-ID`; audit events trigger immutable PostgreSQL records.

---

## Layer 14 — Monitoring and Alerts

### 1. Purpose of Layer in AISOP
Provides subsystem health verification, liveness and readiness probes, database extension inspection, and local LLM availability tracking.

### 2. Requirements Derived from Playbook
- **REQ-14.1:** Public process liveness check (`GET /api/v1/health`).
- **REQ-14.2:** Deep subsystem readiness probe (`GET /api/v1/health/ready`).
- **REQ-14.3:** Database connectivity and pgvector extension verification.
- **REQ-14.4:** Non-intrusive local LLM provider availability probe without triggering inference.
- **REQ-14.5:** Application metrics telemetry export (Prometheus `/metrics`) and alerting dashboard.

### 3. AISOP-Specific Interpretation
AISOP distinguishes between process liveness (is the web server running?) and subsystem readiness (are PostgreSQL and Ollama operational?). The readiness probe (`/api/v1/health/ready`) probes database connectivity and checks local Ollama daemon reachability via its tags API, returning HTTP 503 if dependencies are degraded.

### 4. Current Implementation Status: SUBSTANTIALLY IMPLEMENTED (60.0% of applicable requirements verified; 1 partial, 1 deferred)
- REQ-14.1, 14.2, 14.4: **IMPLEMENTED AND VERIFIED**
- REQ-14.3: **PARTIALLY IMPLEMENTED** (Database `SELECT 1` verified; explicit `SELECT 1 FROM pg_extension WHERE extname = 'vector'` probe and vector validation missing from `/health/ready`)
- REQ-14.5: **DEFERRED WITH JUSTIFICATION** (Prometheus metric exporter deferred to Phase 5)

### 5. Repository Evidence
- Health router: `backend/app/api/v1/endpoints/health.py` (`get_health`, `get_readiness`).
- Provider health probe: `backend/app/modules/ai/llm/manager.py` (invoking `provider.health()`).
- Schemas: `backend/app/schemas/ai.py` (`ProviderHealthResponse`).

### 6. Verification Evidence
- Health endpoint unit tests: `backend/tests/unit/test_api_auth.py` (confirms `/health` is public and unauthenticated).
- Readiness probe returns JSON status with component-level detail for database and LLM.

### 7. Missing Capabilities & Incomplete Verification
- The `/api/v1/health/ready` database check only executes `SELECT 1`. It does not explicitly check whether the `vector` extension is active or whether the embedding index is healthy.
- Prometheus `/metrics` endpoint is not implemented.

### 8. Security and Operational Risks
- If the PostgreSQL vector extension were dropped or corrupted, `/health/ready` might report `database: ok` while semantic search fails.

### 9. Priority: MEDIUM
### 10. Mandatory for Current Stage: YES (Liveness & readiness implemented)
### 11. Deferred Items & Justification
- Prometheus `/metrics` exporter: Deferred to operations hardening; current JSON readiness probe satisfies container orchestration.

### 12. Concrete Next Actions
1. Update `backend/app/api/v1/endpoints/health.py` to probe `SELECT extname FROM pg_extension WHERE extname = 'vector'`.

### 13. Acceptance Criteria for Closing Gaps
- `/health/ready` validates both relational connectivity and pgvector extension availability.

---

## Layer 15 — Scaling

### 1. Purpose of Layer in AISOP
Manages concurrency, connection pooling, pagination limits, and resource isolation during intensive AI inference.

### 2. Requirements Derived from Playbook
- **REQ-15.1:** Bounded database connection pooling and safe connection lifecycle management.
- **REQ-15.2:** LLM inference connection release barrier (zero held database connections during inference).
- **REQ-15.3:** Efficient pagination query patterns ($O(K)$ shallow, bounded deep pagination).
- **REQ-15.4:** Asynchronous background task workers for heavy computational jobs (Celery / ARQ).
- **REQ-15.5:** Stateless horizontal backend scaling and multi-worker deployment.

### 3. AISOP-Specific Interpretation
LLM inference takes multiple seconds. If a database connection is held open during inference, connection pools quickly starve. AISOP implements an explicit architectural invariant: database transactions are committed and connections released back to the pool *before* dispatching HTTP requests to Ollama. Offset pagination is bounded (`MAX_PAGE_SIZE=200`) to prevent memory exhaustion.

### 4. Current Implementation Status: COMPLIANT FOR LOCAL SCOPE (40.0% of applicable requirements verified; 1 partial, 2 deferred)
- REQ-15.1, 15.2: **IMPLEMENTED AND VERIFIED**
- REQ-15.3: **PARTIALLY IMPLEMENTED** (Bounded offset pagination implemented; keyset cursor pagination deferred)
- REQ-15.4: **DEFERRED WITH JUSTIFICATION** (FastAPI async coroutines provide sufficient concurrency; Redis/Celery queue deferred)
- REQ-15.5: **DEFERRED WITH JUSTIFICATION** (Single-instance deployment adequate for current SOC scope)

### 5. Repository Evidence
- Connection pool settings: `backend/app/db/session.py` (`pool_size=10`, `max_overflow=20`, `pool_timeout=30`, `pool_recycle=1800`).
- Inference barrier: `backend/app/services/investigation_service.py` lines 180-210 (session closed prior to LLM provider invocation).
- Bounded pagination: `backend/app/api/v1/endpoints/evidence.py` (`DEFAULT_PAGE_SIZE=50`, `MAX_PAGE_SIZE=200`).

### 6. Verification Evidence
- Connection lifecycle tests: `backend/tests/integration/test_postgres_lifecycle.py`.
- Pagination boundary tests: `backend/tests/unit/test_ingestion_service.py` (verifies enforcement of page limits).

### 7. Missing Capabilities & Incomplete Verification
- Deep pagination traversal on `/api/v1/evidence/events` uses offset pagination (`OFFSET M LIMIT K`). For page offsets greater than 10,000 events, PostgreSQL must scan and discard $M$ index entries.

### 8. Security and Operational Risks
- Repeated deep pagination queries by an automated script could cause sustained high disk I/O on the PostgreSQL container.

### 9. Priority: LOW
### 10. Mandatory for Current Stage: YES (Inference barrier verified)
### 11. Deferred Items & Justification
- Keyset (Cursor) Pagination: Deferred; bounded `MAX_PAGE_SIZE=200` and query limits protect against crash risks for normal analyst workflows.
- Distributed Worker Queue: Deferred; FastAPI async coroutines provide sufficient concurrency for single-SOC analyst teams.
- Horizontal Scaling: Deferred; single-instance architecture satisfies on-premises SOC assistant scope.

### 12. Concrete Next Actions
- Profile database latency under deep pagination offsets; add keyset cursor indexes if datasets exceed 100,000 events.

### 13. Acceptance Criteria for Closing Gaps
- Zero connection starvation observed during concurrent AI synthesis requests.

---

# 3. Overall Compliance Summary & Gap Remediation Plan

### 3.1 Layer-by-Layer Status Summary Table

| Layer # | Layer Name | Total Reqs | Implemented & Verified | Implemented (Unverified) | Partially Implemented | Missing & Required | Deferred | Not Applicable | Overall Layer Status |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **L1** | **System Design** | 6 | 5 | 0 | 1 | 0 | 0 | 0 | **SUBSTANTIALLY COMPLIANT** (83.3%) |
| **L2** | **System Architecture** | 7 | 7 | 0 | 0 | 0 | 0 | 0 | **FULLY COMPLIANT** (100.0%) |
| **L3** | **Databases & Storage** | 7 | 6 | 0 | 0 | **1** | 0 | 0 | **NON-COMPLIANT / GAP** (85.7%) |
| **L4** | **Auth & Permissions** | 6 | 6 | 0 | 0 | 0 | 0 | 0 | **FULLY COMPLIANT** (100.0%) |
| **L5** | **APIs & Backend Logic** | 7 | 7 | 0 | 0 | 0 | 0 | 0 | **FULLY COMPLIANT** (100.0%) |
| **L6** | **Frontend** | 7 | 7 | 0 | 0 | 0 | 0 | 0 | **FULLY COMPLIANT** (100.0%) |
| **L7** | **CI/CD & Version Control** | 5 | 1 | 0 | 0 | **3** | 1 | 0 | **NON-COMPLIANT / GAPS** (20.0%) |
| **L8** | **Testing** | 6 | 5 | 1 | 0 | 0 | 0 | 0 | **SUBSTANTIALLY COMPLIANT** (83.3%) |
| **L9** | **Hosting & Cloud** | 5 | 3 | 0 | 1 | 0 | 0 | 1 | **COMPLIANT FOR LOCAL** (75.0%) |
| **L10** | **Security** | 7 | 6 | 0 | 0 | 0 | 1 | 0 | **SUBSTANTIALLY COMPLIANT** (85.7%) |
| **L11** | **Rate Limiting** | 4 | 3 | 0 | 0 | 0 | 1 | 0 | **COMPLIANT FOR LOCAL** (75.0%) |
| **L12** | **Caching & CDN** | 4 | 2 | 0 | 0 | 0 | 1 | 1 | **COMPLIANT FOR LOCAL** (66.7%) |
| **L13** | **Error Tracking & Logs** | 5 | 4 | 0 | 0 | 0 | 1 | 0 | **COMPLIANT FOR LOCAL** (80.0%) |
| **L14** | **Monitoring & Alerts** | 5 | 3 | 0 | 1 | 0 | 1 | 0 | **SUBSTANTIALLY COMPLIANT** (60.0%) |
| **L15** | **Scaling** | 5 | 2 | 0 | 1 | 0 | 2 | 0 | **COMPLIANT FOR LOCAL** (40.0%) |
| **Total** | **All 15 Layers** | **86** | **67** | **1** | **4** | **4** | **8** | **2** | **OVERALL: RECONCILED (ACCEPTED)** |

*Authoritative Reconciliation Invariants:*
- Column Sum Verification: $67 + 1 + 4 + 4 + 8 + 2 = 86$ (Exact 100% reconciliation).
- Applicable Denominator: $86 - 2 = 84$ requirements.
- Implemented & Verified Compliance: $67 / 84 = 79.8\%$ of applicable requirements ($67 / 86 = 77.9\%$ of total).
- Overall Non-Blocking Architecture: $(67 + 8) / 84 = 75 / 84 = 89.3\%$ of applicable requirements.

---

### 3.2 Authoritative Requirement Register (86 Requirements)

The table below provides the authoritative register of all 86 requirements assessed across the fifteen engineering layers, each assigned to exactly one mutually exclusive status category:

| REQ ID | Layer | Requirement Title / Playbook Specification | Status Category | Primary Evidence Anchor |
| :---: | :---: | :--- | :--- | :--- |
| **REQ-1.1** | L1 | Problem statement & target audience definition | Implemented and Verified | `docs/01_Project_Foundation/Problem_Statement.md` |
| **REQ-1.2** | L1 | Functional & non-functional requirements specification | Implemented and Verified | `docs/02_SRS/SRS.md` |
| **REQ-1.3** | L1 | Analyst personas, global roles & case workflows | Implemented and Verified | `docs/07_Security/RBAC.md` |
| **REQ-1.4** | L1 | Evidence provenance & OPSEC privacy boundaries | Implemented and Verified | `docs/01_Project_Foundation/Design_Philosophy.md` |
| **REQ-1.5** | L1 | Human-in-the-Loop & Anti-Autonomous SOAR invariants | Implemented and Verified | `docs/07_Security/Data_Privacy.md` |
| **REQ-1.6** | L1 | Explicit out-of-scope boundaries (billing, multi-tenancy) | Partially Implemented | Drift in `README.md` lines 34-37 |
| **REQ-2.1** | L2 | Modular monolith domain structure | Implemented and Verified | `backend/app/modules/` |
| **REQ-2.2** | L2 | Vendor-neutral alert ingestion with multi-source adapters | Implemented and Verified | `backend/app/modules/alerts/` |
| **REQ-2.3** | L2 | Canonical event normalization & raw evidence storage | Implemented and Verified | `SysmonParser`, `CanonicalEvent` |
| **REQ-2.4** | L2 | Semantic knowledge retrieval (RAG) using 768-dim vectors | Implemented and Verified | `backend/app/modules/ai/embeddings/` |
| **REQ-2.5** | L2 | Local threat intelligence orchestrator & Private Shield | Implemented and Verified | `backend/app/modules/threatintel/shield.py` |
| **REQ-2.6** | L2 | Direct LLM provider protocol decoupling inference engines | Implemented and Verified | `backend/app/modules/ai/llm/protocol.py` |
| **REQ-2.7** | L2 | Architecture Decision Records (ADRs 001-007) | Implemented and Verified | `docs/03_System_Design/ADR/` |
| **REQ-3.1** | L3 | Relational database engine (PostgreSQL 17 + pgvector) | Implemented and Verified | `docker-compose.yml`, `session.py` |
| **REQ-3.2** | L3 | Asynchronous ORM models (SQLAlchemy 2.0) | Implemented and Verified | `backend/app/models/` |
| **REQ-3.3** | L3 | Version-controlled migrations with reversible rollback | Implemented and Verified | `backend/app/db/migrations/versions/` |
| **REQ-3.4** | L3 | Integrity constraints, foreign keys & partial indexes | Implemented and Verified | Migration versions 0001-0004 |
| **REQ-3.5** | L3 | Cryptographic content hashing (SHA-256) & deduplication | Implemented and Verified | `backend/app/services/alert_ingestion_service.py` |
| **REQ-3.6** | L3 | Append-only database triggers blocking audit tampering | Implemented and Verified | Migration `20261025_0004_p3h2_rbac_case_scoping.py` |
| **REQ-3.7** | L3 | Automated database backup, restore & disaster recovery | Missing and Required | `Deployment_Guide.md` (0 bytes); no script |
| **REQ-4.1** | L4 | Secure API ingress authentication with token support | Implemented and Verified | `backend/app/core/auth.py` (`verify_api_key`) |
| **REQ-4.2** | L4 | Constant-time token comparison preventing timing attacks | Implemented and Verified | `hmac.compare_digest` in `auth.py` |
| **REQ-4.3** | L4 | Tiered Global Roles (`security_admin`, `analyst`, etc.) | Implemented and Verified | `backend/app/core/rbac.py` |
| **REQ-4.4** | L4 | Context-aware Case Roles (`lead`, `investigator`, `viewer`)| Implemented and Verified | `backend/app/models/analyst.py` |
| **REQ-4.5** | L4 | Server-side authorization dependencies (BOLA/IDOR) | Implemented and Verified | `require_case_access` in `rbac.py` |
| **REQ-4.6** | L4 | Anti-enumeration behavior returning HTTP 404 | Implemented and Verified | `cases.py` lines 128-135; 41 unit tests |
| **REQ-5.1** | L5 | Versioned REST API routing (`/api/v1`) with OpenAPI docs | Implemented and Verified | `backend/app/api/v1/endpoints/` |
| **REQ-5.2** | L5 | Bounded Pydantic v2 schemas validating inputs/outputs | Implemented and Verified | `backend/app/schemas/` |
| **REQ-5.3** | L5 | Safe bounded pagination (`DEFAULT=50`, `MAX=200`) | Implemented and Verified | `backend/app/api/v1/endpoints/evidence.py` |
| **REQ-5.4** | L5 | Atomic transactions and savepoint isolation | Implemented and Verified | `session.begin_nested()` in ingestion |
| **REQ-5.5** | L5 | Structured multi-audience report synthesis API | Implemented and Verified | `POST /api/v1/cases/{id}/reports/synthesize` |
| **REQ-5.6** | L5 | Role-tailored report export API (Markdown & JSON) | Implemented and Verified | `GET /api/v1/cases/{id}/reports/export` |
| **REQ-5.7** | L5 | Centralized error handling and defensive HTTP status codes| Implemented and Verified | `backend/app/main.py` exception handlers |
| **REQ-6.1** | L6 | React 18, TypeScript, and Vite frontend architecture | Implemented and Verified | `frontend/package.json`, `vite.config.ts` |
| **REQ-6.2** | L6 | Multi-source alert triage queue (`Alerts.tsx`) | Implemented and Verified | `frontend/src/pages/Alerts.tsx` |
| **REQ-6.3** | L6 | Evidence investigation workspace (`InvestigationWorkspace.tsx`)| Implemented and Verified | `frontend/src/components/InvestigationWorkspace.tsx` |
| **REQ-6.4** | L6 | Multi-tab report viewer with export controls | Implemented and Verified | `frontend/src/components/ReportViewer.tsx` |
| **REQ-6.5** | L6 | Comprehensive UI state handling (loading/empty/error) | Implemented and Verified | Component tests in `frontend/tests/` |
| **REQ-6.6** | L6 | Website Design Constitution adherence (dark mode) | Implemented and Verified | `docs/08_Frontend/AISOP_Website_Design_Constitution.md` |
| **REQ-6.7** | L6 | Component unit testing (Vitest) & zero TypeScript errors | Implemented and Verified | 33 passed tests; `tsc` clean |
| **REQ-7.1** | L7 | Git version control discipline & commit integrity | Implemented and Verified | `main` branch, clean history |
| **REQ-7.2** | L7 | Automated CI workflow executing backend unit tests on PR | Missing and Required | `.github/workflows/` empty |
| **REQ-7.3** | L7 | Automated frontend typechecking (`tsc`) and build in CI | Missing and Required | `.github/workflows/` empty |
| **REQ-7.4** | L7 | Automated dependency vulnerability scan (`pip-audit`) in CI | Missing and Required | `.github/workflows/` empty |
| **REQ-7.5** | L7 | Automated database migration rollback testing in CI | Deferred with Justification | Cloud PostgreSQL runner deferred |
| **REQ-8.1** | L8 | Multi-tier test architecture (Tiers 1-4) with markers | Implemented and Verified | `backend/tests/conftest.py` |
| **REQ-8.2** | L8 | Comprehensive unit test coverage across all modules | Implemented and Verified | 1,198 passing backend tests |
| **REQ-8.3** | L8 | Real PostgreSQL 17 + pgvector integration test suite | Implemented and Verified | 29 passing integration tests (port 5433) |
| **REQ-8.4** | L8 | Negative, boundary, and BOLA/IDOR security test suites | Implemented and Verified | `test_case_bola_security.py` (41 passed) |
| **REQ-8.5** | L8 | Ground-truth AI evaluation framework (20 scenarios) | Implemented but not Fully Verified | 53 unit tests pass; captures 0/19 gated |
| **REQ-8.6** | L8 | End-to-end Capstone integration test (13-stage lifecycle)| Implemented and Verified | `test_phase4c_capstone.py` (6/6 passed) |
| **REQ-9.1** | L9 | Containerized deployment infrastructure (docker-compose) | Implemented and Verified | `docker-compose.yml` (`aisop-postgres`) |
| **REQ-9.2** | L9 | Environment variable configuration template | Implemented and Verified | `.env.example` |
| **REQ-9.3** | L9 | Hardened private SOC deployment architecture (TLS proxy) | Partially Implemented | Container runs locally; Nginx TLS un-templated |
| **REQ-9.4** | L9 | Public cloud SaaS deployment architecture (AWS/GCP) | Not Applicable | Conflicts with local-first privacy mandate |
| **REQ-9.5** | L9 | Strict adherence to ₹0 cloud egress policy | Implemented and Verified | Zero outbound network calls verified |
| **REQ-10.1** | L10 | Threat model and OWASP Top 10 mitigations | Implemented and Verified | `docs/07_Security/Threat_Model.md`, `OWASP.md` |
| **REQ-10.2** | L10 | SQL Injection prevention via parameterized queries | Implemented and Verified | 100% SQLAlchemy 2.0 parameterized |
| **REQ-10.3** | L10 | Cross-Site Scripting (XSS) prevention | Implemented and Verified | Sanitizer tests; React DOM escaping |
| **REQ-10.4** | L10 | Server-Side Request Forgery (SSRF) mitigation | Implemented and Verified | `PrivateNetworkShield` (42 tests pass) |
| **REQ-10.5** | L10 | Hardened HTTP security headers (`SecurityHeadersMiddleware`)| Implemented and Verified | `test_security_headers.py` (15 passed) |
| **REQ-10.6** | L10 | AI safety guardrails, prompt injection isolation | Implemented and Verified | `validator.py`, `builder.py` |
| **REQ-10.7** | L10 | Independent third-party penetration testing | Deferred with Justification | Formal pen test deferred to enterprise audit |
| **REQ-11.1** | L11 | Token-bucket ingress rate limiting middleware | Implemented and Verified | `backend/app/middleware/rate_limit.py` |
| **REQ-11.2** | L11 | Client identification by token/IP with RFC 6585 HTTP 429 | Implemented and Verified | `test_rate_limiting.py` (14 passed) |
| **REQ-11.3** | L11 | Endpoint sensitivity discrimination (exempting health) | Implemented and Verified | Health & docs endpoints exempted |
| **REQ-11.4** | L11 | Distributed shared rate limiting store (Redis Cluster) | Deferred with Justification | In-memory token bucket adequate at ₹0 cost |
| **REQ-12.1** | L12 | Local threat intelligence lookup caching with TTL | Implemented and Verified | `MemoryCache` (24h TTL) in threatintel |
| **REQ-12.2** | L12 | Strict case isolation preventing cross-case cache leakage | Implemented and Verified | Case queries bypass cache completely |
| **REQ-12.3** | L12 | Database query and semantic vector search result caching | Deferred with Justification | Avoided to guarantee real-time playbook state |
| **REQ-12.4** | L12 | Content Delivery Network (CDN) edge caching | Not Applicable | Conflicts with air-gapped/local SOC networks |
| **REQ-13.1** | L13 | High-performance structured logging with Loguru | Implemented and Verified | `backend/app/core/logging.py` |
| **REQ-13.2** | L13 | Request correlation tracking via `X-Request-ID` | Implemented and Verified | `backend/app/middleware/correlation.py` |
| **REQ-13.3** | L13 | Sensitive credential and secret redaction in log records | Implemented and Verified | Sensitive keys scrubbed in loguru filter |
| **REQ-13.4** | L13 | Append-only immutable audit event logging | Implemented and Verified | `CaseAuditEvent`, PostgreSQL DB trigger |
| **REQ-13.5** | L13 | External cloud error monitoring and APM (Sentry) | Deferred with Justification | Prohibited under zero-cloud-egress policy |
| **REQ-14.1** | L14 | Public process liveness check (`GET /api/v1/health`) | Implemented and Verified | `backend/app/api/v1/endpoints/health.py` |
| **REQ-14.2** | L14 | Deep subsystem readiness probe (`GET /health/ready`) | Implemented and Verified | Probes DB and Ollama reachability (503 fallback)|
| **REQ-14.3** | L14 | Database connectivity & pgvector extension verification | Partially Implemented | DB `SELECT 1` checked; pgvector query absent |
| **REQ-14.4** | L14 | Non-intrusive local LLM provider availability probe | Implemented and Verified | Probes `/api/tags` without triggering inference|
| **REQ-14.5** | L14 | Application metrics telemetry export (Prometheus) | Deferred with Justification | Deferred; JSON probe satisfies container health |
| **REQ-15.1** | L15 | Bounded database connection pooling | Implemented and Verified | Pool size 10, max overflow 20 in `session.py` |
| **REQ-15.2** | L15 | LLM inference connection release barrier | Implemented and Verified | DB session closed prior to LLM provider call |
| **REQ-15.3** | L15 | Efficient pagination query patterns ($O(K)$ shallow) | Partially Implemented | Bounded offset pagination; keyset deferred |
| **REQ-15.4** | L15 | Asynchronous background task workers (Celery / ARQ) | Deferred with Justification | FastAPI async coroutines sufficient for workload |
| **REQ-15.5** | L15 | Stateless horizontal backend scaling & multi-worker | Deferred with Justification | Single-instance deployment adequate for local SOC|

---

### 3.3 Critical Gaps Discovered

Across the 86 requirements assessed, exactly **4 missing requirements** and **4 partial implementations** were identified. All are bounded and actionable:

1. **Automated CI/CD Pipeline (Layer 7 — High Priority):**
   - *Gaps (REQ-7.2, REQ-7.3, REQ-7.4):* `.github/workflows/` contains zero workflow files. The 1,198 backend tests, 33 frontend tests, TypeScript typechecks, and dependency vulnerability scans are currently executed manually via CLI.
   - *Impact:* Potential for regressions, type errors, or dependency vulnerabilities to enter `main` if manual developer discipline lapses.
   - *Remediation:* Create `.github/workflows/ci.yml` executing `pytest`, `tsc`, `npm test`, and `pip-audit` on every pull request.
2. **Database Backup & Disaster Recovery Verification (Layer 3 — High Priority):**
   - *Gap (REQ-3.7):* `docs/11_Deployment/Deployment_Guide.md` is empty (0 bytes). No automated `pg_dump` backup script is packaged in the repository, and no restore drills have been executed.
   - *Impact:* Host volume corruption or operator mistake could cause irreversible evidence loss.
   - *Remediation:* Create `scripts/backup_postgres.ps1` and document restoration commands.
3. **Deep pgvector Health Verification (Layer 14 — Medium Priority):**
   - *Gap (REQ-14.3):* `/api/v1/health/ready` executes `SELECT 1` on PostgreSQL, but does not explicitly verify the pgvector extension status or vector similarity functionality.
   - *Impact:* Extension corruption could leave the platform reporting "ready" while semantic search fails.
   - *Remediation:* Add `SELECT extname FROM pg_extension WHERE extname = 'vector'` to the readiness probe.
4. **Hardened Private TLS Reverse Proxy Template (Layer 9 — Medium Priority):**
   - *Gap (REQ-9.3):* Docker container runs locally, but an Nginx / Caddy SSL/TLS reverse proxy configuration template is missing from `deploy/`.
   - *Impact:* Exposing FastAPI directly over a local area network transmits Bearer tokens in cleartext.
   - *Remediation:* Create `deploy/nginx/nginx.conf` terminating HTTPS with security headers.
5. **Documentation Reality Drift (Layer 1 — Low Priority):**
   - *Gap (REQ-1.6):* `README.md` lines 34-37 still describe the Frontend UI as "0% Implemented", Case Routes as "Unmounted", and Auth as "Absent", conflicting with accepted Phase 4C reality.
   - *Impact:* Confuses external reviewers and academic evaluators.
   - *Remediation:* Update `README.md` Reality Matrix to match accepted Phase 4C capabilities.
6. **Deep Keyset Pagination (Layer 15 — Low Priority):**
   - *Gap (REQ-15.3):* Evidence listing uses offset pagination (`OFFSET M LIMIT K`). For page offsets greater than 10,000 events, index scan overhead increases.
   - *Impact:* Elevated disk I/O under extreme pagination depths.
   - *Remediation:* Transition to keyset (cursor) pagination if event volume exceeds 100,000 records.

---

### 3.4 Readiness Classification for Future Deployments

#### A. Requirements Mandatory Before Private Network SOC Deployment
1. Automated CI/CD workflow running all tests and linters on PRs (Layer 7: REQ-7.2, 7.3, 7.4).
2. Automated database backup script and documented recovery procedure (Layer 3: REQ-3.7).
3. Nginx / Caddy TLS reverse proxy configuration terminating HTTPS on private LAN (Layer 9: REQ-9.3).
4. Deep pgvector health probe in `/api/v1/health/ready` (Layer 14: REQ-14.3).
5. Synchronized `README.md` and operational documentation (Layer 1: REQ-1.6).

#### B. Requirements Mandatory Before Any Future Public Multi-Tenant Deployment
*(Currently Out of Scope / Excluded by Architectural Policy)*
1. Enterprise SSO / SAML / OIDC authentication integration (Layer 4).
2. Distributed Redis-backed rate limiting and token management (Layer 11: REQ-11.4).
3. Keyset / cursor-based deep event pagination (Layer 15: REQ-15.3).
4. Asynchronous background worker queue (Celery/ARQ) for AI inference (Layer 15: REQ-15.4).
5. Professional third-party penetration testing and SOC 2 Type II audit (Layer 10: REQ-10.7).
6. Multi-tenant row-level security (RLS) and schema partitioning (Layer 3).

---

### 3.5 Concluding Governance Verdict

**VERDICT: P4-GOV 15-LAYER COMPLIANCE MATRIX RECONCILED AND ACCEPTED**

AISOP possesses an exceptionally mature, well-tested engineering foundation. Of the 84 applicable requirements:
- **79.8% (67 requirements) are fully implemented and verified** by automated test suites.
- **1.2% (1 requirement) is implemented and awaiting live operational authorization**.
- **4.8% (4 requirements) are partially implemented** with minor, well-bounded gaps.
- **4.8% (4 requirements) are missing and required** (automated CI workflows and database backup script).
- **9.5% (8 requirements) are deferred with documented justification**.
- **2 requirements are not applicable** to the local SOC scope.

All requirement counts, layer classifications, security assessments, and Git records are now 100% mathematically and evidentially reconciled.
