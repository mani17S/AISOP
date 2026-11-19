# AISOP Project Milestones

## Phase 1: Ingestion Pipeline & Canonical Data Model Hardening

| Milestone | Title | Status | Checkpoint / Baseline | Key Deliverables |
|:---|:---|:---:|:---|:---|
| **P1-H1** | Git Safety Checkpoint | COMPLETE | `63bee0b` | Clean local git baseline establishing Phase 0 architecture & initial ingestion pipeline. |
| **P1-H2** | Ingestion Deduplication | COMPLETE | `e1af0c9` | Option A contract: skips duplicates, no duplicate child rows, nested savepoint race handling. |
| **P1-H3** | Batch Query Optimization | COMPLETE | `e1af0c9` | Replaced $O(N)$ sequential lookups with batched chunked existence queries (`IN (...)`) and in-memory classification map. |
| **P1-H4** | Ingestion Security & Bounds Hardening | COMPLETE | `2cbe6a8` | Enforced `MAX_BATCH_SIZE=2000`, `MAX_EVENT_PAYLOAD_BYTES=65536`, `source_type`/`identifier` bounds, per-event atomic savepoint isolation, safe sample serialization. |
| **P1-H5** | SOC Investigation Query API Expansion | COMPLETE | `2228764` | Deterministic SOC investigation retrieval layer: normalized events, entity/IOC queries, time bounding, raw evidence retrieval, and bounded pagination. |
| **P1-H6** | Structured Logging & Observability | COMPLETE | `bbc34dd` | Loguru structured JSON/text logging, request correlation IDs (`X-Request-ID`), sensitive data redaction, and ingestion/query telemetry. |
| **P1-H7** | Database Migrations & Schema Lifecycle | COMPLETE | `164a65e` | Alembic async migrations setup, initial revision (`0001_initial_evidence_schema`), deterministic DDL, schema parity verification, and migration lifecycle tests. |
| **P1-H8** | Sysmon Parser & Dataset Expansion | COMPLETE | `e5ffff8` | Expanded deterministic Sysmon parser for Event IDs 8 (CreateRemoteThread), 10 (ProcessAccess), 15 (FileCreateStreamHash), and 23 (FileDelete) with entity extraction and zero schema migrations. |
| **P1-H9** | PostgreSQL Integration Test Suite | COMPLETE | `7998be8` | Real PostgreSQL 17 automated integration testing harness with zero SQLite fallback and isolated test database. |
| **P1-H10** | Phase 1 Hardening Capstone & Closeout | COMPLETE | `0764ea4` | Phase 1 architecture consolidation, milestone synchronization, test baseline certification (114 tests), and Phase 1 closeout report. |


## Phase 2: AI Layer Abstraction, Semantic Retrieval & Threat Intelligence

| Milestone | Title | Status | Checkpoint / Baseline | Key Deliverables |
|:---|:---|:---:|:---|:---|
| **P2-H1** | LLM Provider Protocol & Local Ollama Adapter | COMPLETE | `7f27d69` | Team-owned LLMProvider Protocol, Pydantic v2 schemas, async OllamaProvider via httpx with tenacity retry backoff, provider factory, and deterministic MockTransport unit tests. |
| **P2-H2** | pgvector Knowledge Schema & Health Readiness Foundation | COMPLETE | `32c3903` | pgvector knowledge foundation: Alembic migration 0002_add_pgvector_and_knowledge_schema, KnowledgeEmbedding ORM (768-dim vector, JSONB metadata, content_hash deduplication), HNSW cosine index, and health readiness integration. |
| **P2-H3** | Knowledge Base Ingestion Pipeline & Semantic Retrieval | COMPLETE | `c4e877c` | Direct OllamaEmbedder (768-dim), KnowledgeSourceLoader, DocumentChunker, KnowledgeIngestionService with atomic document replacement lifecycle, and KnowledgeRetriever with threshold-bounded cosine similarity search. Verified via 4-tier acceptance gate (510 passing tests). |
| **P2-H4 (Hist.) / TI-2/3B** | Threat Intelligence Foundation & Resilient Orchestrator | COMPLETE | Working Tree Baseline | RFC1918 PrivateNetworkShield, local feed cache, local lookup engine, and resilient orchestrator (185 unit tests). |
| **P2-H4 (Curr.) / P2-H5 (Hist.)** | Investigation Pipeline Integration & Evidence Grounding | COMPLETE | Working Tree Baseline (Uncommitted) | Tasks 2.1–2.5: Canonical CJSON-1.0 serializer/hasher, multi-event context assembly with deterministic pruning, defensive prompt builder with untrusted data isolation, structured response parser with length truncation check, 3-tier guardrails validator, investigation pipeline service, and POST /api/v1/investigations/synthesize endpoint. Verified via 571 unit tests and 18 integration tests. |
| **P2-H6** | Role-Tailored Structured Investigation Reporting (Historical Alias: P2-H5 Candidate) | COMPLETE | Working Tree Baseline | Deterministic multi-audience reporting engine (Executive Brief, SOC Incident Response Brief, Detection Engineering Playbook) synthesized from validated investigation outputs. Verified via 25 focused synthesizer unit tests and 11 pipeline integration tests; remediated SEC-AUDIT-001 through 005. |
| **P2-H7** | Phase 2 Capstone Review, Security Hardening & Full Pipeline Consolidation | COMPLETE | Working Tree Baseline | Comprehensive end-to-end telemetry-to-report integration certification (`test_phase2_capstone.py`), live PostgreSQL 17/pgvector Tier 3 container verification (port 5433), security boundary audit, Phase 2 closeout report (682 passing tests). |


## Phase 3: Case Management, Security Perimeter & Ground-Truth AI Evaluation

| Milestone | Title | Status | Checkpoint / Baseline | Key Deliverables |
|:---|:---|:---:|:---|:---|
| **P3-H1** | API Ingress Authentication & Security Perimeter | COMPLETE | Working Tree Baseline | Centralized `verify_api_key` dependency, fail-closed production invariants, constant-time secret comparison, 19 dedicated auth tests, 701 regression tests. |
| **P3-H2** | Case Management, Scoping & RBAC | COMPLETE | Working Tree Baseline | Case dossier models, source-scoped knowledge partitions, 4-tier RBAC (`admin`, `lead`, `analyst`, `read_only`), 422 validation guards. |
| **P3-H3A** | Ground-Truth AI Evaluation Framework | COMPLETE | Working Tree Baseline | Offline-first evaluation framework, 20 curated telemetry scenarios, JSON/schema validation, parent/sub-technique tolerance, Markdown report generation. |
| **P3-H3A.1** | Independent Evaluation Framework Integrity Audit | COMPLETE | Working Tree Baseline | Independent audit gate identifying sibling sub-technique tolerance defects, benign false positive omissions, observable extraction substring collisions, and tautological fixture dependencies. |
| **P3-H3A.2** | Evaluation Integrity Remediation | COMPLETE | Working Tree Baseline | Remediation of all P3-H3A.1 audit findings: strict rejection of sibling sub-techniques, zero-target F1 penalization, exact observable extraction with bi-directional negation filtering, lexical diagnostic disclosure, explicit self-test vs captured replay decoupling, dataset refinements (SCN-CHN-003, SCN-ATO-005), 27 dedicated evaluation tests, 894 full unit regression tests. |
| **P3-H3A.3** | Independent Evaluation Integrity Acceptance Audit | PARTIAL | Working Tree Baseline | Independent audit gate identifying 3 blocking defects: model-controlled self-certification (BLK-H3A-01), fixture envelope & provenance decoupling (BLK-H3A-02), and zero-prediction failure macro F1 penalization (BLK-H3A-03). |
| **P3-H3A.4** | Blocking Evaluation Integrity Remediation | COMPLETE | Working Tree Baseline | Resolved all 3 blocking audit defects and secondary findings: independent HumanClaimAdjudication registry, CapturedInvestigationFixture envelope with scenario binding & raw SHA-256 validation, zero-prediction F1=0.0 penalization, clause-bounded IOC negation, dedicated RFC 5952 IPv6 extraction/scoring, ATT&CK technique normalization, SCN-ATO-005 ground truth contract, and explicit report denominators. Verified via 41 evaluation tests and 908 full regression tests. |
| **P3-H3A.5** | Independent Remediation Acceptance & Provenance Audit | PARTIAL | Working Tree Baseline | Independent audit gate verifying BLK-H3A-01..03 fixes; identified residual provenance limitations: un-enveloped legacy fixture inclusion, prompt hash unverified during replay, and response/envelope model ID conflict tolerance. |
| **P3-H3A.6** | Legacy Fixture Exclusion & Provenance Enforcement | COMPLETE | Working Tree Baseline | Excluded legacy un-enveloped fixtures (SCN-ATO-001-replay.json) from measured performance (is_measured=False, byte-for-byte preserved); deterministic prompt canonicalization and cryptographic SHA-256 verification; fail-closed model identifier consistency; restored historical audit dispositions. Verified via 53 evaluation tests and 920 full regression tests. |
| **P3-H3B** | Live Ollama Capture Protocol & Harness Hardening | PARTIAL | Working Tree Baseline | Dedicated loopback capture harness (`capture_live_fixtures.py`), presence-based credential check, bounded timeout (0-120s), retry filtering (4xx fail-fast vs 5xx retry), zero-pull preflight verification, 19 scenario dry-run certified, 93 dedicated regression tests. Live Ollama model capture execution gated pending Project Owner authorization. |
| **P3-H4** | Ingress Rate Limiting & Abuse Prevention | BLOCKED | Working Tree Baseline | RateLimitMiddleware and SecurityHeadersMiddleware implemented and tested offline (15 unit tests, 1,089 regression baseline). Milestone advancement formally blocked pending P3-H3B live capture execution and acceptance. |


## Phase 4: Analyst Workspace, Multi-Source Alert Triage & Capstone Evaluation

| Milestone | Title | Status | Checkpoint / Baseline | Key Deliverables |
|:---|:---|:---:|:---|:---|
| **P4A** | Multi-Source Alert Ingestion, Retrieval, Triage UI & Postgres Integration | COMPLETE | Working Tree Baseline | Vendor-neutral ingestion adapters (Sysmon, CrowdStrike, Zeek, Sentinel), paginated alert retrieval API, atomic initial_evidence_ids case linking, Alerts.tsx triage UI, PostgreSQL 17 verification (aisop_p4a_disposable). |
| **P4B** | Evidence-Centered Investigation Workspace | COMPLETE | Working Tree Baseline | 6-area investigation workspace (InvestigationWorkspace.tsx), human-invoked AI synthesis trigger, 3-tier epistemic guardrails display, activity audit trail, BOLA anti-enumeration (404), PostgreSQL 17 verification. |
| **P4C** | Capstone Evaluation, Multi-Analyst Security & Report Export | COMPLETE | Working Tree Baseline | 13-stage reproducible investigation lifecycle (test_phase4c_capstone.py: 6/6 passed), 6-role RBAC authorization matrix, role-tailored report export API (GET /reports/export), full regression certification (1,198 passed, 33 frontend passed). |


## Post-Phase 4C: Platform Governance & Production Readiness

| Milestone | Title | Status | Checkpoint / Baseline | Key Deliverables |
|:---|:---|:---:|:---|:---|
| **P4-GOV** | 15-Layer Engineering Compliance Matrix & SaaS Readiness Audit | COMPLETE (ACCEPTED) | Working Tree Baseline | Authoritative 86-requirement compliance audit against the 15-Layer Engineering Playbook (`AISOP_15_Layer_Engineering_Compliance_Matrix.md`), Executive Readiness Summary, reconciled register (67 verified, 1 unverified, 4 partial, 4 missing, 8 deferred, 2 N/A). |
| **P4-HARDENING-01** | CI/CD Automation Foundation | COMPLETE | Working Tree Baseline | Minimal, reliable GitHub Actions CI workflow (`.github/workflows/ci.yml`) covering offline backend suite, frontend build/test/typecheck, and Python dependency security auditing (`pip-audit`). Resolves REQ-7.2, REQ-7.3, REQ-7.4. |
| **P4-HARDENING-02** | Database Backup, Restore & Disaster Recovery Foundation | COMPLETE | Working Tree Baseline | Automated PostgreSQL custom archive backup script (`scripts/backup_postgres.ps1`) with SHA-256 sidecars and JSON metadata; 3-tier recovery checklist in `docs/11_Deployment/Deployment_Guide.md`; 12 unit tests in `tests/test_backup_postgres.ps1`. Resolves REQ-3.7. |
| **P4-HARDENING-03** | Deep PostgreSQL & pgvector Readiness Verification | COMPLETE | Working Tree Baseline | Enhanced `/api/v1/health/ready` probe checking relational connectivity, `pgvector` extension catalog registration, `knowledge_embeddings` schema, and 768d dimension compatibility; sanitized secret reporting; 17 integration tests in `test_health_api.py`. Upgrades REQ-14.3 to Implemented & Verified. |
| **P4-HARDENING-04** | Private LAN TLS Reverse Proxy Preparation | COMPLETE | Working Tree Baseline | Hardened Nginx TLS 1.2/1.3 reverse proxy configuration template (`deploy/nginx/nginx.conf`), host header spoofing drop (444), client IP sanitization, and operational guide (`docs/11_Deployment/TLS_Reverse_Proxy_Guide.md`). Establishes REQ-9.3 deliverable. |
| **P4-HARDENING-05** | Project Reality, README & Documentation Synchronization | COMPLETE | Working Tree Baseline | Synchronized `README.md` reality matrix (remediated 0% UI, unmounted routes, absent auth outdated claims), updated quickstart with frontend and head migration (`0004_p3h2_rbac_case_scoping`), documented 1,270 passing offline tests, validated all internal documentation links. Resolves REQ-1.6. |



## Phase 5: Evidence-Sufficiency Gating & Analyst Abstention

| Milestone | Title | Status | Checkpoint / Baseline | Key Deliverables |
|:---|:---|:---:|:---|:---|
| **P5-S3C** | Deterministic Evidence-Sufficiency Gate with Analyst Abstention (ADR-008) | IMPLEMENTED; revised by P5-S3C-R (owner labels and held-out evaluation pending) | Working Tree Baseline | Pure pre-model gate (`modules/ai/guardrails/sufficiency_gate.py`, rule table `suff-v1`) returning SUFFICIENT / LIMITED / INSUFFICIENT with fixed-vocabulary reason codes and event references; fail-closed; single `GatedGenerator` choke point at both production model-invocation sites; audited abstention in the existing audit schema (no migration); hash-locked derived evaluation cases (99) with owner-authored labels pending; gate-on/gate-off ablation harness; capture harness gate-on by default. |
| **P5-S3C-R** | Evidence Independence, LIMITED Disclosure and Multi-Source Investigation Workflow (ADR-008 rev. 2, ADR-009) | IMPLEMENTED (offline; PostgreSQL audit test, owner labels, real-model run pending) | Working Tree Baseline | Shared independence primitives (`modules/evidence/independence.py`: evidence clusters, strong/specific/weak links); gate `suff-v2`; validator counts independent clusters; LIMITED disclosure in final output; stratified opaque-id evaluation set (115 cases); per-class/macro-F1/coverage-risk/kappa metrics; `modules/correlation/` (normalize, correlate, timeline, deterministic ATT&CK rules, hash-chained ledger, workflow, report); six synthetic multi-source scenarios and demo script; AiSOC adaptation register; panel walkthrough. |
| **P5-S4** | Case-Scoped Multi-Source Investigation Integration (ADR-010) | IMPLEMENTED (offline: SQLite, scripted LLM); PostgreSQL validation of the stored document, real-model run and owner labels pending | Working Tree Baseline | `POST/GET /cases/{id}/investigations/multisource[/{section}]` (`cases.py`), `services/multisource_investigation_service.py` (re-normalizes preserved raw payloads, fingerprint idempotency, stale-evidence flag, evidence-race 409, fail-closed audit write; result stored as a `case_audit_events` row, no migration), `schemas/multisource.py`, frontend `MultiSourcePanel` tab, `scripts/run_integrated_demo.py`, 23 API tests + 9 frontend tests; regression unit 1324 / offline 1409 passed. Persistence is PARTIAL (size-capped, one row per run, synchronous). |
| **P5-S5** | Validation, Security Hardening, Reliability and Evaluation Integrity (ADR-008 rev. 3, ADR-010 amendments) | IMPLEMENTED (offline); PostgreSQL validation BLOCKED; real-model run, owner labels, browser-level testing UNVERIFIED | Working Tree Baseline | 89 adversarial/reliability tests (`test_stage5_adversarial.py`); defects D1-D9 and U1 fixed (replayed observations and placeholder values no longer corroborate, `suff-v3`; invented timestamps, over-deep/over-large records, ledger robustness, 1,000-evidence cap, stored-result and activity-feed bounds, per-case lock, 5-call LLM bound); dataset integrity report; label-independent dev evaluation; benchmarks; PostgreSQL launcher copy and persistence tests prepared, not run; security, evaluation, reliability, LLM, performance and PostgreSQL-readiness reports. |

---

### Milestone Details & Invariants

#### P1-H4: Ingestion Security & Bounds Hardening
* **Validation Semantics (Two-Tier Discrimination):**
  1. *Perimeter / Security Violations:* Requests violating system boundaries (e.g. batch size $> 2000$, individual event $> 64\text{ KB}$, invalid/empty `source_type`, malformed JSON) fail fast at the API/Pydantic boundary with HTTP 422 Unprocessable Entity, preventing resource allocation or database transaction acquisition.
  2. *Pipeline / Processing Errors:* Ordinary parser, normalization, or extraction errors on well-formed payloads preserve best-effort per-event semantics (HTTP 200 with structured `errors` list), allowing valid events in the batch to commit.
* **Memory & Payload Budget:**
  * Maximum aggregate serialized event-payload budget: $\text{MAX\_BATCH\_SIZE} \times \text{MAX\_EVENT\_PAYLOAD\_BYTES} = 2000 \times 64\text{ KB} = 128\text{ MB}$.
  * *Note on Process Memory:* Actual process memory during ingestion can exceed 128 MB due to Python object graph representation, Pydantic model validation structures, SQLAlchemy ORM instance tracking, and intermediate JSON dictionaries.
* **Atomicity & Invariant Preservation:**
  * Complete per-event lifecycle (raw evidence, normalized events, extracted entities) is enclosed in nested savepoints (`session.begin_nested()`).
  * If child normalization or entity extraction fails, the savepoint rolls back the entire event, preventing orphaned raw evidence rows.
  * Preserves all P1-H2 duplicate idempotency, savepoint race handling, and P1-H3 $O(\lceil U / 1000 \rceil)$ batched existence lookup guarantees.

#### P1-H5: SOC Investigation Query API Expansion
* **Objective:**
  * Transform AISOP's telemetry storage layer into a high-performance, deterministic SOC investigation query API layer for rapid security incident triage, timeline assembly, and IOC correlation.
* **Implemented API Capabilities:**
  1. `GET /api/v1/evidence/events`: Paginated query of canonical normalized events supporting multi-field filtering (`start_time`, `end_time`, `event_type`, `source_type`, `source_identifier`, `severity`, `outcome`, `entity_type`, `entity_value`, `page`, `limit`).
  2. `GET /api/v1/evidence/events/{event_id}`: Detailed retrieval of a single normalized event, including its parent raw evidence provenance and associated atomic extracted entities.
  3. `GET /api/v1/evidence/entities`: Paginated IOC/entity exploration (`entity_type`, `entity_value`, `role`, `page`, `limit`).
  4. `GET /api/v1/evidence/by-hash/{sha256_hash}`: Direct lookup of raw evidence records and their child normalized events by cryptographic SHA-256 digest.
  5. `GET /api/v1/evidence/{evidence_id}`: Fetch raw evidence and child normalized events by UUID in a single eager round-trip.
* **Query Semantics & Bounds:**
  * Safe default page size: `DEFAULT_PAGE_SIZE = 50`.
  * Hard upper bound: `MAX_PAGE_SIZE = 200` (enforced via FastAPI/Pydantic validation, returning HTTP 422 if exceeded).
  * Strict time-range validation: `start_time` and `end_time` are normalized to UTC; if `start_time > end_time`, requests are rejected with HTTP 400 Bad Request. Malformed timestamps fail with HTTP 422.
  * Unbounded result set protection: Every query path enforces explicit `LIMIT` and `OFFSET` clauses.
* **Deterministic Ordering:**
  * Normalized events: `ORDER BY event_timestamp DESC, id DESC`. Ensures recent telemetry appears first while using the unique UUID primary key as an immutable tie-breaker to prevent pagination drift.
  * Extracted entities: `ORDER BY entity_type ASC, entity_value ASC, id DESC`.
  * Raw evidence: `ORDER BY ingested_at DESC, id DESC`.
* **Database Indexes Added & Trade-Off Analysis:**
  * Added `ix_normalized_events_time_id` on `(event_timestamp DESC, id DESC)`.
    * *Benefit:* Allows PostgreSQL to satisfy both timeline window range scans and deterministic tie-breaker sorting directly from the index tree without requiring an in-memory or on-disk `SORT` node.
    * *Trade-off:* Adds minor index write latency per event during high-throughput ingestion, but the 24-byte composite index footprint is heavily outweighed by the performance gain for SOC analysts querying large event volumes.
  * Existing indexes utilized: `ix_normalized_events_type_time`, `ix_extracted_entities_type_value`, `RawEvidence.sha256_hash` (unique), and foreign key indexes on `raw_evidence_id` and `event_id`.
* **Performance & Complexity:**
  * Hash lookup (`GET /by-hash/{sha256_hash}`): Theoretical B-tree index search complexity is $O(\log N)$, where $N$ is the number of raw evidence records. In practice, the high branch factor of PostgreSQL B-trees, page caching in memory, and the perfect uniqueness of SHA-256 digests make point retrieval practically efficient.
  * Timeline range and ordering (`GET /events`): Bounded pagination leverages composite index `ix_normalized_events_time_id` on `(event_timestamp DESC, id DESC)`. For shallow pages, retrieval is $O(K)$ where $K = \text{limit} \le 200$.
  * Pagination traversal cost: Because offset-based pagination (`LIMIT K OFFSET M`) is utilized, deep page queries require the database to traverse and discard $M$ preceding rows ($O(K + M)$ traversal cost). While safe and bounded for typical SOC analyst workflows, this traversal overhead is why keyset/cursor pagination is recognized as a future optimization for high-depth navigation.
  * Entity-based event filtering: Uses `NormalizedEventModel.id.in_(select(ExtractedEntityModel.event_id)...)` subqueries to leverage indexes on `ExtractedEntityModel` without producing Cartesian duplicate rows.
  * Eager loading: Uses `joinedload` on relationships, eliminating N+1 sequential queries when retrieving events with raw evidence metadata or evidence with child normalized events.
* **Security Review:**
  * Prevention of query abuse / DoS via hard ceiling `MAX_PAGE_SIZE = 200`.
  * Input validation: Strict regex pattern `^[a-fA-F0-9]{64}$` for SHA-256 paths; standard UUID parsing for all entity/event identifiers.
  * Zero SQL injection: All queries constructed via parameterized SQLAlchemy 2.0 expressions.
  * Sensitive data exposure: Internal database implementation details and connection strings remain completely unexposed.
* **Deferred Items:**
  * Keyset / cursor-based pagination for ultra-deep timeline navigation (deferred).
  * Threat Intelligence reputation scoring (Phase 2).
  * Graph visualization and entity traversal APIs (Phase 2).
  * Full-text search engine integration (Elasticsearch/OpenSearch/Meilisearch).

#### P1-H6: Structured Logging & Observability
* **Objective:**
  * Establish a unified, security-conscious structured logging foundation using Loguru across all backend operations (startup, HTTP request correlation, ingestion batch lifecycle, parser failures, query execution, and database error handling) without exposing sensitive telemetry or credentials.
* **Architecture & Standards:**
  * **Core Library:** Utilizes existing `loguru==0.7.3` dependency configured in `backend/app/core/logging.py`.
  * **Interception:** `InterceptHandler` redirects all standard library logging (Uvicorn, FastAPI, SQLAlchemy) into Loguru's sink pipeline.
  * **Dual Format Modes:**
    1. *Machine-Readable JSON (`LOG_FORMAT="json"`):* Emits structured NDJSON containing `timestamp` (ISO 8601 UTC), `level`, `logger`, `message`, `context` (extra bound metadata), and structured `exception`.
    2. *Developer Formatted Text (`LOG_FORMAT="text"`):* Colorized, human-readable terminal output.
  * **Request Correlation:** `RequestCorrelationMiddleware` extracts or generates `X-Request-ID` (UUID or safe client token) for every HTTP request, binding it into the logger context for end-to-end trace correlation.
* **Logging Hierarchy & Levels:**
  * `INFO`: High-level operational events (app startup/shutdown, HTTP request completions, ingestion batch start and summary completion).
  * `DEBUG`: Detailed diagnostic events (batched existence lookup counts, individual entity queries, health probe completions).
  * `WARNING`: Non-fatal application anomalies (malformed event payloads, unsupported source types, query parameter validation rejections, savepoint rollbacks).
  * `ERROR`: Unhandled exceptions, unexpected database execution failures, and internal server faults.
* **Security & Sensitive Data Redaction:**
  * **Dictionary Key Redaction:** Recursively redacts values for known sensitive keys (`password`, `token`, `secret`, `api_key`, `authorization`, `cookie`, `access_token`, `private_key`, `client_secret`).
  * **Regex Pattern Masking:** Automatically sanitizes Bearer tokens, Basic auth credentials, and key-value credential pairs in freeform string log messages.
  * **Payload Protection:** Full raw telemetry payloads are never logged. Error samples are truncated via `_safe_sample()` with sensitive fields sanitized before logging.
* **Performance & Loop Safety:**
  * **No per-event INFO logging overhead:** Ingestion intentionally emits batch-level lifecycle summaries rather than one INFO record per event (e.g. 2,000 events emit 1 batch-start log and 1 batch-completion log, with failures emitted at WARNING/ERROR). This prevents per-event logging overhead in ingestion loops without claiming literal zero runtime overhead.
  * **Lazy Context Evaluation:** Evaluates structured context dictionaries only when log levels are enabled, avoiding expensive serialization overhead during high-throughput operations.
  * **Regression Baseline:** The current test suite completes in 2.43s with structured logging enabled. This provides a basic regression signal but does not constitute a production throughput benchmark.

#### P1-H7: Database Migrations & Schema Lifecycle
* **Objective:**
  * Establish a reproducible, version-controlled database schema lifecycle using Alembic for the canonical AISOP ORM schema without manual schema mutations, unversioned DDL, or production startup alterations.
* **Architecture & Standards:**
  * **Core Tooling:** `alembic>=1.13,<2.0` with `Mako` configured in root `alembic.ini` and `backend/alembic.ini`.
  * **Async Execution:** `env.py` coordinates async migration execution via SQLAlchemy 2.0 AsyncEngine and dynamic database connection resolution from `app.core.config.get_settings().DATABASE_URL`.
  * **Initial Schema Revision (`0001_initial_evidence_schema`):**
    * Encapsulates all Phase 1 data models: `raw_evidence`, `normalized_events`, `extracted_entities`.
    * Codifies primary keys (UUID), foreign keys with cascading delete (`ON DELETE CASCADE`), indexes, and compound indexes (`ix_normalized_events_type_time`, `ix_normalized_events_time_id`, `ix_extracted_entities_type_value`).
    * Full bidirectional reversibility (`upgrade()` and `downgrade()`).
  * **PostgreSQL / pgvector Policy:**
    * No current model utilizes vector columns; hence `CREATE EXTENSION IF NOT EXISTS vector;` is omitted from the initial migration. Extension handling is strictly deferred until vector models (ADR-002 / Phase 2) are introduced.
  * **Safety Guarantees:**
    * Application startup (`lifespan` in `app/main.py`) performs zero automatic schema mutations.
    * All generated migrations execute inside explicit database transactions (`BEGIN ... COMMIT`).
* **Verification & Testing Scope:**
  * Added `backend/tests/unit/test_migrations.py` validating Alembic script discovery, exact target metadata parity (`diffs == []`), offline PostgreSQL SQL DDL generation, and isolated migration lifecycle (upgrade/downgrade) on in-memory SQLite test engines.
  * Live PostgreSQL containerized integration testing is strictly scoped and deferred to Milestone P1-H9.

#### P1-H8: Sysmon Parser Coverage Expansion
* **Objective:**
  * Expand the deterministic Sysmon JSON parser and entity extraction engine to support advanced endpoint attack techniques:
    * Event ID 8: `CreateRemoteThread` (Process Injection / Thread Injection)
    * Event ID 10: `ProcessAccess` (Credential Dumping / Process Inspection / LSASS access)
    * Event ID 15: `FileCreateStreamHash` (Alternate Data Streams / Web Downloads / Zone.Identifier)
    * Event ID 23: `FileDelete` (Anti-Forensics / Dropper Cleanup / Ransomware file removal)
* **Canonical Schema & Architecture Integration:**
  * **Zero Schema Alterations:** Adheres strictly to the existing `CanonicalEvent` contract and relational schema. No database migrations, ORM column changes, or Alembic revisions required.
  * **Event Mapping & Action Verbs:**
    * Event 8: `event_type="create_remote_thread"`, `action="created"`, `severity="informational"`.
    * Event 10: `event_type="process_access"`, `action="accessed"`, `severity="informational"`.
    * Event 15: `event_type="file_create_stream_hash"`, `action="created"`, `severity="informational"`.
    * Event 23: `event_type="file_delete"`, `action="deleted"`, `severity="informational"`.
* **Field Normalization & Preservation:**
  * **Source vs. Target Process Separation (Events 8 & 10):**
    * The acting/initiating process populates `CanonicalEvent.process` (`ProcessEntity`) with `pid`, `process_name`, `image_path`, `process_guid`, and `user`.
    * Target process attributes are stored in `custom_fields` with normalized keys: `target_process_id`, `target_image`, `target_process_name`, and `target_process_guid`.
    * Injection and memory access attributes are preserved in `custom_fields`:
      * Event 8: `new_thread_id`, `start_address`, `start_module`, `start_function`.
      * Event 10: `source_thread_id`, `granted_access`, `call_trace`.
  * **GrantedAccess & CallTrace Handling:**
    * `GrantedAccess` is preserved verbatim as an exact string (e.g. `"0x1010"`), avoiding error-prone or lossy bitmask reinterpretation.
    * `CallTrace` is preserved verbatim as a string stack trace without unsafe heuristics.
  * **Filesystem & Alternate Data Stream Handling (Events 15 & 23):**
    * `TargetFilename` is normalized into `FileEntity.path`, with file basename extracted to `FileEntity.filename`. For Event 15 ADS streams (`invoice.pdf:Zone.Identifier`), stream naming syntax is preserved.
    * Event 15 `CreationUtcTime` is captured in `custom_fields["creation_utc_time"]`.
  * **Hash Normalization (`_parse_hashes`):**
    * Supports standard Sysmon key-value format (`"SHA256=...,MD5=..."`), case-insensitive key discovery (`Hashes`, `Hash`), and bare hex digests (detecting algorithm by digest length: 32 -> MD5, 40 -> SHA1, 64 -> SHA256, 128 -> SHA512).
  * **Boolean Field Normalization (`_parse_bool`):**
    * Normalizes boolean-like representations (`"true"`, `"1"`, `"yes"`, `True` -> `True`; `"false"`, `"0"`, `"no"`, `False` -> `False`; others -> `None`) for `IsExecutable` and `Archived` in Event 23.
  * **Secondary Process Context:**
    * Updated `_parse_process_context` to capture `process_guid` and `user` alongside `pid`, `image_path`, and `command_line` across secondary events.
* **Atomic Entity & Graph Extraction:**
  * **Process Role Differentiation:**
    * Initiating process in Events 8 and 10 is extracted with `role="source"`.
    * Target process in Events 8 and 10 is extracted with `role="target"` including attributes for `pid`, `image_path`, `process_guid`, `granted_access`, and thread info.
  * **File & Hash Extraction:**
    * Target filenames extracted with `role="target"`.
    * Hashes extracted with `role="file_hash"`.
* **Security & Non-Destructive Principles:**
  * Parsed data is treated strictly as untrusted evidence. No commands are executed, no paths evaluated, and no network/threat-intel queries initiated.
  * File deletion (Event 23) is preserved as neutral telemetry without assuming maliciousness or triggering automated containment or file-deletion actions.
  * Binary EVTX parsing is intentionally out of scope; telemetry must be supplied in JSON representation.
* **Fixtures & Testing Coverage:**
  * Added 4 realistic synthetic fixtures in `datasets/samples/sysmon/`:
    * `sysmon_create_remote_thread.json`
    * `sysmon_process_access.json`
    * `sysmon_file_create_stream_hash.json`
    * `sysmon_file_delete.json`
  * Added 14 unit and integration tests across `test_sysmon_parser.py`, `test_entity_extractor.py`, and `test_sample_dataset_ingestion.py`.
  * Full test suite verification: 108/108 tests passing.

#### P1-H9: PostgreSQL Integration Test Suite
* **Objective:**
  * Introduce a reliable, automated PostgreSQL integration-test layer for AISOP's existing persistence lifecycle, validating real PostgreSQL behavior (SQLAlchemy 2.0 async engine, ORM models, Alembic migrations) without regression or silent fallback.
* **Architecture & Environment Strategy:**
  * **Zero SQLite Fallback:** Enforces strict dialect validation (`dialect == "postgresql"`). If PostgreSQL is unreachable or non-PostgreSQL dialect is used, tests fail immediately with actionable diagnostic errors.
  * **Port & Database Isolation:**
    * Operates strictly against isolated containerized PostgreSQL on host port `5433` (`pgvector/pgvector:pg17`), completely avoiding and isolating the host's native PostgreSQL service on port `5432`.
    * Uses a dedicated `aisop_test` database (auto-provisioned by session fixtures) to prevent any contamination of development data (`aisop_dev`).
  * **Windows Event Loop Compatibility:**
    * Configured `WindowsSelectorEventLoopPolicy` in both `env.py` and `conftest.py` to resolve psycopg 3 async compatibility with Windows asyncio event loops.
  * **Dual Engine Architecture:**
    * `postgres_sync_engine` (synchronous `create_engine`): Coordinates schema provisioning, Alembic migrations, and SQLAlchemy inspection (`inspect()`).
    * `postgres_engine` (asynchronous `create_async_engine`): Coordinates `AsyncSession` interactions, data persistence, and pipeline testing.
* **Test Suite Verification (`backend/tests/integration/test_postgres_lifecycle.py`):**
  * `test_postgres_connectivity_and_dialect`: Confirms live TCP connection, dialect validation (`postgresql`), and server version check (`SELECT version()`).
  * `test_postgres_alembic_upgrade_lifecycle`: Runs online `alembic upgrade head`, inspects native table creation, UUID primary keys, JSON payloads, TIMESTAMPTZ columns, unique indices, cascading foreign keys, and metadata parity (`diffs == []`).
  * `test_postgres_orm_crud_and_datatype_fidelity`: Inserts and retrieves `RawEvidence`, `NormalizedEventModel`, and `ExtractedEntityModel`. Validates native UUID object preservation, complex nested JSON preservation, and timezone offset instant equality.
  * `test_postgres_ingestion_service_deduplication`: Validates idempotent deduplication, `UniqueViolation` constraint enforcement on `raw_evidence.sha256_hash`, nested `SAVEPOINT` rollback recovery, and session reuse after rollback.
  * `test_postgres_foreign_key_cascades`: Validates `ON DELETE CASCADE` semantics by deleting parent `RawEvidence` and confirming automatic deletion of children `NormalizedEventModel` and `ExtractedEntityModel`.
  * `test_postgres_alembic_downgrade_lifecycle`: Runs online `alembic downgrade base`, verifies removal of all application tables and revision records, then re-applies `head` to preserve clean canonical schema state.
* **Documentation & Governance:**
  * Created `docs/04_Database/Database_Testing.md` specifying setup, port isolation, environment variables, and execution commands.
  * Test suite execution:
    * PostgreSQL integration tests: `pytest -v -m postgres` (6 passed in ~1.8s)
    * Fast unit tests: `pytest -v -m "not postgres"` (108 passed in ~3.1s)
    * Complete test suite: `pytest -v` (114 passed in ~4.0s)

#### P1-H10: Phase 1 Hardening Capstone, Documentation Consolidation & Baseline Closeout
* **Objective:**
  * Formally close and consolidate Phase 1 (Ingestion Pipeline & Canonical Data Model Hardening) following completion of P1-H1 through P1-H9.
  * Ensure the implemented system architecture, milestone records, test baseline, and known operational boundaries are consistent, auditable, and certified for a controlled transition to Phase 2.
* **Scope of Deliverables:**
  * Synchronized milestone table with exact commit hashes for all completed Phase 1 milestones.
  * Populated `docs/03_System_Design/Architecture.md` reflecting the code-verified technical architecture of the Phase 1 implementation (Hasher, SysmonParser, EntityExtractor, IngestionService, InvestigationQueryService, SQLAlchemy 2.0 Async, Alembic migrations, and PostgreSQL integration suite).
  * Authored `docs/00_Project_Management/Phase_1_Closeout_Report.md` providing formal audit records, test baseline metrics, and explicit Phase 2 boundaries.
  * Regression verification confirming full suite pass rate (114 tests) with zero failures and zero regressions.
* **Strictly Out-of-Scope Items:**
  * Zero new application features, zero schema modifications, zero new dependencies, and zero changes to existing application behavior.
  * AI/LLM integrations, RAG, pgvector vector search, and embeddings deferred to Phase 2 (ADR-001, ADR-002).
  * Frontend, UI, and dashboard development deferred to Phase 4 (ADR-005).
  * Alternate telemetry parsers (EVTX, Windows Security Events, Zeek, Suricata) deferred to future milestones (ADR-004).
* **Verification Criteria & Baseline:**
  * Unit test suite: 108 passed.
  * PostgreSQL integration test suite: 6 passed.
  * Combined regression suite: 114 passed.
  * Formatting & linting: Black and isort checks pass on all codebase components.
  * Architectural documentation parity: 100% verified against source code and ADRs.

#### P2-H1: LLM Provider Protocol & Local Ollama Adapter
* **Objective:**
  * Establish the foundational AI provider abstraction layer for AISOP in strict accordance with ADR-001 (Direct Lightweight LLM Abstraction).
  * Decouple all downstream AI services (SOC hypothesis generation, MITRE mapping, reporting) from specific model vendors and frameworks (prohibiting LangChain/LangGraph).
* **Delivered Capabilities:**
  * **AI Schemas & Data Contracts (`app/schemas/ai.py`):** Pydantic v2 models for `MessageRole`, `LLMMessage`, `LLMRequest`, `LLMResponse`, `TokenUsage`, and `ProviderHealthResponse`.
  * **Domain Exception Hierarchy (`app/modules/ai/llm/exceptions.py`):** Typed exceptions for `LLMError`, `LLMConnectionError`, `LLMTimeoutError`, `LLMModelNotFoundError`, and `LLMResponseError`.
  * **Runtime Protocol (`app/modules/ai/llm/protocol.py`):** `LLMProvider` Protocol defining `generate()`, `health()`, and `model_name`.
  * **Ollama Provider Adapter (`app/modules/ai/providers/ollama/provider.py`):** Asynchronous HTTP client communicating directly with Ollama's `/api/chat` and `/api/tags` endpoints via `httpx`.
  * **Resilience & Retries:** Integrated `tenacity` exponential backoff retry loop for transient connection failures and HTTP 502/503/504 errors; immediate fail-fast on non-retryable 4xx client errors.
  * **Structured JSON Enforcement:** Automatically passes `"format": "json"` when `request.json_mode=True`.
  * **Documentation:** Authored comprehensive provider contract specification in `docs/06_AI/LLM_Provider_Contract.md` and AI subsystem architecture in `docs/06_AI/AI_Architecture.md`.
* **Testing & Verification:**
  * Added 19 unit tests in `backend/tests/unit/test_llm_provider.py` using `httpx.MockTransport` covering success, parameter overrides, JSON mode, token usage parsing, fast-fail on 4xx/timeouts, transient 503 recovery, persistent 503 exhaustion, malformed JSON, missing message keys, and full health probe lifecycle (healthy, degraded, timeout, 500).
  * Full test suite regression verification: 133 tests passing (112 unit + 21 integration).
  * Code formatting & linting: 100% compliant with Black and isort.
* **Preserved Invariants:**
  * Zero database schema modifications, zero new ORM models, zero Alembic migrations.
  * Zero new runtime dependencies (uses existing httpx, tenacity, pydantic).
  * Streaming explicitly deferred to Phase 4 (Frontend Investigation Dashboard).

#### P2-H2: pgvector Knowledge Schema & Health Readiness Foundation
* **Objective:**
  * Establish the foundational pgvector vector storage schema and health readiness probing for AISOP in strict accordance with ADR-002 (PostgreSQL/pgvector as Primary Vector Store).
  * Enable persistent, indexable storage of 768-dimensional text embeddings alongside structured chunk metadata without introducing secondary vector databases (Chroma, Pinecone, Qdrant).
* **Delivered Capabilities:**
  * **Knowledge Embedding ORM Model (`app/models/knowledge.py`):** `KnowledgeEmbedding` model with UUID PK, `source_document`, `section_title`, `content` (untrusted reference text), `content_hash` (unique SHA-256 digest), `embedding` (`Vector(768)`), and `chunk_metadata` (`JSONB` with SQLite JSON variant fallback).
  * **Alembic Migration (`20261005_0002_add_pgvector_and_knowledge_schema.py`):**
    * Enables `vector` extension idempotently (`CREATE EXTENSION IF NOT EXISTS vector`).
    * Creates `knowledge_embeddings` table with UUID primary key, content hash uniqueness constraint, and source document index.
    * Provisions HNSW cosine distance index `ix_knowledge_embeddings_embedding_hnsw` (`vector_cosine_ops`, `m=16`, `ef_construction=64`).
    * Implements fully reversible `downgrade()` removing table and extension.
  * **Health Readiness Integration (`app/api/v1/endpoints/health.py`):**
    * Refactored `/health/ready` probe to evaluate both database connectivity and LLM provider readiness.
    * Returns HTTP 200 `status="ready"` when both components pass; HTTP 503 `status="unready"` with structured diagnostic dictionary if either component is unhealthy.
* **Testing & Verification:**
  * Added 12 new tests (145 total passing across unit and integration suites):
    * Unit tests (`test_knowledge_models.py`, `test_migrations.py`): Validates model instantiation, exact content hash computation, JSON fallback, Alembic migration discovery, and target metadata parity (`diffs == []`).
    * Integration tests (`test_postgres_lifecycle.py`, `test_health_api.py`): Real PostgreSQL 17 + pgvector integration verifying vector insertion, exact round-trip retrieval, cosine distance ordering (`<=>`), HNSW index usage, UniqueViolation on duplicate hashes, and `/health/ready` probe semantics.
* **Preserved Invariants:**
  * Fixed 768-dimensional vector contract matching `nomic-embed-text`.
  * Zero third-party vector databases or wrapper frameworks (LangChain, LangGraph prohibited).

#### P2-H4: Investigation Pipeline Integration & Evidence Grounding (Tasks 2.1–2.5)
* **Roadmap Divergence & Numbering Reconciliation:**
  * In the 19 October 7-Milestone baseline (`AISOP_Historical_Handover.md`), Threat Intelligence was labeled P2-H4, and LLM Investigation Reasoning & Grounding was labeled P2-H5.
  * In the 23 October design gate (`AISOP-P2-H4-DESIGN-GATE-002`), Context Assembly and Pipeline Synthesis were grouped under the milestone label `P2-H4`.
  * Therefore, the completed Tasks 2.1–2.5 fully deliver the reasoning, context assembly, and grounding scope originally planned under P2-H5. The historical divergence is preserved and documented rather than silently rewritten.
* **Delivered Pipeline Architecture (Tasks 2.1–2.5):**
  1. *Task 1.1 / Phase 1:* Typed immutable Pydantic V2 schemas (`investigation.py`) for `InvestigationContext`, `BudgetMetrics`, `ReproducibilityRecord`, `FactualClaimItem`, and `StructuredInvestigationOutput`.
  2. *Task 2.1:* Canonical serializer and forensic hasher (`hasher.py`) enforcing `AISOP-CJSON-1.0` and collision-resistant dictionary key normalization.
  3. *Task 2.2:* Multi-event context assembly and deterministic pruning (`context_builder.py`) enforcing `MAX_CONTEXT_CHARS=8750` on evidence and mandatory root-evidence retention (`IncompleteContextOverflowError`).
  4. *Task 2.3:* Defensive prompt construction (`prompt_builder.py`) enforcing XML untrusted data isolation and role separation; structured response parser (`parser.py`) with truncation detection (`finish_reason='length'`).
  5. *Task 2.4:* Three-tier evidence grounding and output guardrails validator (`validator.py`) enforcing reference existence (Tier 1), information containment (Tier 2), and human analyst advisory review (Tier 3).
  6. *Task 2.5:* Authoritative `InvestigationPipelineService` orchestration (`investigation_service.py`), FastAPI endpoint `POST /api/v1/investigations/synthesize` (`investigations.py`), and 18 end-to-end integration tests (`test_investigation_pipeline.py`).
* **Failure, Fallback & Epistemic Invariants:**
  * Fallbacks are strictly deterministic and generated via `InvestigationResponseParser.build_deterministic_fallback`.
  * Fallback outputs are evaluated through the guardrail validator and explicitly classified with `decision=GuardrailDecision.REJECT_TO_FALLBACK` and `is_valid=False`.
  * Fallback results are **never** labeled or encoded as successful AI investigations (`is_valid=True` or `GuardrailDecision.PASS`).
  * Incomplete telemetry or missing threat intelligence never justifies benign conclusions (`"benign"` claims on partial telemetry are strictly prevented).
  * System prompts and untrusted evidence are isolated; model recommendations are strictly advisory with zero autonomous tool/shell execution.
* **Test Verification & Reported Metrics:**
  * **Recorded Backend Unit Test Baseline:** **571 passed**, 0 failed, 2 warnings in 15.88s (`pytest backend/tests/unit`).
  * **Recorded Pipeline Integration Test Baseline:** **18 passed**, 0 failed, 2 warnings in 1.15s (`pytest backend/tests/integration/test_investigation_pipeline.py`).
  * **Verification Limits & Infrastructure Clarification:**
    * The PostgreSQL live container integration harness (`test_postgres_lifecycle.py`) was not executed during Task 2.5 because the Docker daemon/container on port 5433 was offline. Live PostgreSQL integration coverage is not claimed as verified for this baseline run.
    * Recorded warnings: 2 `StarletteDeprecationWarning` notices regarding `httpx` in Starlette `TestClient`.
* **Preserved Invariants & Policy Compliance:**
  * Strict adherence to `AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001` ($0 budget, local Ollama only, zero cloud LLMs, zero external network egress).
  * Zero database migrations or persistent database mutations.

#### P2-H6: Role-Tailored Structured Investigation Reporting (Historical Alias: P2-H5 Candidate)
* **Status:** Implemented and tested in Working Tree Baseline — Pending Formal Owner Acceptance.
* **Objective:**
  * Deliver a 100% deterministic, multi-audience reporting engine translating validated `InvestigationValidationResult` contracts and authentic bound `InvestigationContext` into role-tailored Markdown reports (Executive Brief, SOC Technical IR Report, Detection Engineering Report).
* **Delivered Capabilities & Implementation Scope:**
  1. *Immutable Pydantic V2 Schemas (`app/schemas/report.py`):* `ExecutiveBrief`, `TechnicalIncidentReport`, `DetectionEngineeringReport`, `InvestigationReportBundle`, and `ReportFormatRequest` enforcing `frozen=True`, `extra="forbid"`, and timezone-aware UTC timestamps.
  2. *Deterministic Report Synthesizer (`app/modules/ai/reporting/synthesizer.py`):* Pure Python transformation; zero secondary LLM calls; cryptographic context-hash binding (`AISOP-CJSON-1.0`); detached-mode fallback with safe disclosures; and defensive command sanitization.
  3. *Deterministic Markdown Formatter (`app/modules/ai/reporting/formatter.py`):* Escaped, tabular rendering with guaranteed Unix newlines and trailing newline.
  4. *REST Endpoints (`app/api/v1/endpoints/reports.py`):* `POST /api/v1/reports/synthesize` and `POST /api/v1/reports/format` (with context-hash integrity verification).
  5. *Orchestration Integration (`app/services/investigation_service.py`):* `synthesize_investigation_with_context` provides authentic bound context preserving telemetry, threat intelligence, and budget metrics.
* **Remediated Security Findings (Independent Audit SEC-AUDIT-001 through SEC-AUDIT-005):**
  * `SEC-AUDIT-001`: Removed ungrounded claim string matching for incident severity; severity evaluated strictly from structured event `outcome` and `action`.
  * `SEC-AUDIT-002`: Under the implemented reporting policy, detached-context and applicable budget-truncation conditions produce an INCONCLUSIVE assessment, with explicit uncertainty disclosures. This assessment must not be represented as an independently established incident severity.
  * `SEC-AUDIT-003`: Replaced synthetic context reconstruction in endpoint with authentic pipeline context exposure.
  * `SEC-AUDIT-004`: Hardened Markdown table generation with `html.escape`, dangerous URL neutralization (`javascript:`, `data:`, `vbscript:`), and line-start control token escaping.
  * `SEC-AUDIT-005`: Removed unused threat intel engine import in `reports.py`.
* **Test Accounting & Execution Baselines (Overlap Clarification):**
  * **Backend Unit Suite Total:** **596 passed**, 0 failed, 2 warnings in 22.17s (`pytest backend/tests/unit`).
  * **Reporting Synthesizer Unit Tests (Subset):** **25 passed**, 0 failed in 0.96s (`pytest backend/tests/unit/test_deterministic_report_synthesizer.py`). These 25 tests are a focused subset of, and overlap entirely with, the 596-test unit suite (they do not represent additional unique tests).
  * **Reporting Pipeline Integration Suite:** **11 passed**, 0 failed, 4 warnings in 1.76s (`pytest backend/tests/integration/test_reporting_pipeline.py`).
  * **Investigation Pipeline Integration Suite:** **18 passed**, 0 failed, 2 warnings in 1.37s (`pytest backend/tests/integration/test_investigation_pipeline.py`).
  * **Reported Passing Test Executions Aggregate:** 625 aggregate passing test executions reported across the three suites (596 unit + 11 reporting integration + 18 investigation integration). This is strictly an aggregate of reported suite runs and is not a verified count of distinct tests across suites. It must not be described as 625 unique tests.
  * **Recorded Warnings:**
    * 2 upstream `StarletteDeprecationWarning` notices regarding `httpx` in Starlette `TestClient`.
    * 2 FastAPI routing deprecation warnings regarding `HTTP_422_UNPROCESSABLE_ENTITY`.
* **Outstanding Infrastructure & Environmental Verification:**
  * **Live PostgreSQL 17 Container (Port 5433):** Not executed during this baseline run; Docker daemon/container was offline. Live PostgreSQL persistence and vector indexing remain unverified.
  * **Live Local Ollama Daemon (Port 11434):** Not executed against live running models during this baseline run; tested strictly via deterministic mock transports (`httpx.MockTransport`).
  * **Perimeter Assertions:** Passing mocked unit/integration tests does not constitute proof of zero network egress, a completed dependency vulnerability audit, or full end-to-end production certification.
* **Preserved Invariants & Policy Compliance:**
  * Designed for zero paid cloud APIs and zero external network egress (`AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001`).
  * Zero database migrations or persistent database mutations.
  * Anti-autonomous invariant: All report recommendations are strictly advisory with zero automated tool execution.
* **Subsequent Milestone Transition:**
  * Phase 2 is formally **CLOSED** with the certification of Milestone P2-H7 (`Phase_2_Closeout_Report.md`). The project advances to **Phase 3: Case Management, Authentication & RBAC**.

#### P3-H1: API Ingress Authentication & Security Perimeter
* **Status:** COMPLETE
* **Objective:**
  * Establish a verified, testable authentication perimeter for all applicable `/api/v1/*` routes in accordance with `AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001`, OWASP A07, and API2:2023 without breaking existing offline testing, investigation, evidence, or reporting workflows.
* **Delivered Architecture & Implementation:**
  1. *Settings Integration (`app/core/config.py`):* Added `API_AUTH_ENABLED: bool = True` and `API_AUTH_KEYS: list[str] = Field(default_factory=list)`. Configured field validators supporting comma-separated strings and JSON lists, plus a model validator prohibiting `API_AUTH_ENABLED=False` in `ENVIRONMENT="production"`.
  2. *Central Authentication Dependency (`app/core/auth.py`):* Implemented `verify_api_key` supporting both `Authorization: Bearer <token>` and `X-API-Key: <token>`. Constant-time secret comparison via `secrets.compare_digest`. Fails closed with generic HTTP 401 Unauthorized (`WWW-Authenticate: Bearer`) on missing, invalid, malformed, or conflicting credentials, revealing zero secrets or verification diagnostics.
  3. *Re-export & Dependency Registry (`app/api/dependencies.py`):* Re-exported `AuthenticatedClient` and `verify_api_key`.
  4. *Centralized Perimeter Route Wiring (`app/api/v1/__init__.py`):* Mounted all functional routers (`evidence_router`, `investigations_router`, `reports_router`) under `protected_v1_router = APIRouter(dependencies=[Depends(verify_api_key)])`. Health probes (`/api/v1/health`, `/api/v1/health/ready`) and root/OpenAPI routes (`/`, `/docs`, `/redoc`, `/api/v1/openapi.json`) remain explicitly permitted public routes.
* **Test Verification & Empirical Evidence:**
  * Added 19 dedicated unit/integration tests in `backend/tests/unit/test_api_auth.py` verifying missing credentials, invalid bearer/API keys, malformed headers, conflicting headers, fail-closed empty keys, secret non-leakage, multi-client acceptance, public route access, exhaustive route rejection for all 9 protected endpoints, production security invariant, and dependency override test isolation.
  * Updated existing integration fixtures across `test_ingest_api.py`, `test_investigation_api.py`, `test_threatintel_http_integration.py`, `test_investigation_pipeline.py`, `test_phase2_capstone.py`, and `test_reporting_pipeline.py` using explicit test authentication dependency overrides (`AuthenticatedClient`).
  * **Test Metrics:**
    * **Backend Unit Suite:** 630 passed in ~18.0s (0 failures).
    * **Backend Integration Suite:** 71 passed in ~12.9s (0 failures).
    * **Complete Suite Regression:** 701 passed in ~29.7s (0 failures, 4 warnings).
* **Security & Non-Destructive Invariants:**
  * Zero external cloud services, $0 cost (`AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001`).
  * Zero database migrations or schema alterations.
  * Constant-time comparisons eliminate timing side-channels.
  * Secret tokens automatically scrubbed from logs via Loguru `SENSITIVE_KEYS` and `REDACTION_PATTERNS`.
  * RBAC and case dossiers deferred to P3-H2 and subsequent Phase 3 milestones.

#### P3-H3A: Ground-Truth AI Evaluation Framework (Offline-First)
* **Status:** COMPLETE
* **Objective:**
  * Implement an objective, reproducible, offline-first evaluation framework for assessing AISOP AI investigation synthesis outputs against curated ground-truth telemetry scenarios without manufacturing ground truth or depending on live inference runtimes.
* **Delivered Architecture & Implementation:**
  1. *Pydantic V2 Evaluation Contracts (`backend/app/schemas/evaluation.py`):* `EvaluationScenario`, `ExpectedClaim`, `ExpectedMitreMapping`, `ExpectedObservable`, `ProhibitedClaim`, `GroundTruthProvenance`, `ClaimEvaluationItem`, `MitreEvaluationResult`, `ScenarioEvaluationResult`, and `BenchmarkRunSummary` with strict `frozen=True` and `extra="forbid"`.
  2. *Core Evaluation Subsystem (`backend/app/modules/evaluation/`):*
     - `metrics.py`: Mathematical metrics with division-by-zero safety (`safe_division`, `compute_precision_recall_f1`), syntactic JSON validity checking, schema conformance validation, IOC normalization, and deterministic fallback categorization (`genuine_model_output`, `deterministic_fallback`, `parser_rejection`, `invalid_response`).
     - `dataset_loader.py`: Path traversal protected loader, Pydantic V2 validation, duplicate `scenario_id` detection, and provenance/review status gating.
     - `grounding_evaluator.py`: Factual claim grounding evaluation (`SUPPORTED`, `PARTIALLY_SUPPORTED`, `UNSUPPORTED`, `CONTRADICTED`, `UNVERIFIABLE`), prohibited assertion detection, and expected fact coverage.
     - `mitre_evaluator.py`: Technique ID normalization, parent/sub-technique tolerance (e.g. `T1059` vs `T1059.001`), mandatory vs uncertain technique discrimination, and Precision/Recall/F1 calculation.
     - `reproducibility.py`: Multi-run structural consistency, output hash stability, claim count stability, and evidence reference set overlap comparator.
     - `evaluation_runner.py`: Offline replay engine, per-scenario evaluation, and multi-scenario benchmark aggregator.
     - `report_generator.py`: Clean Markdown scorecard generator strictly formatting unmeasured metrics as `N/A *(unmeasured / 0 denominator)*`.
  3. *Ground-Truth Dataset (`datasets/ground_truth/`):* 20 curated scenarios across Atomic Techniques (5: `SCN-ATO-001`–`005`), Multi-Stage Attack Chains (5: `SCN-CHN-001`–`005`), Benign Baselines (5: `SCN-BEN-001`–`005`), and Adversarial/Ambiguous (5: `SCN-ADV-001`–`005`). `SCN-BEN-005` curated in `draft` status to test provenance gating.
  4. *Benchmark CLI Runner (`backend/scripts/run_ai_benchmark.py`):* CLI utility executing 100% offline replay benchmarks and emitting scorecards to `docs/04_Testing/AI_Model_Benchmark_Report.md`.
  5. *Architecture Documentation (`docs/04_Testing/AI_Model_Evaluation_Architecture.md`):* Complete technical specification and mathematical formulas.
* **Test Verification & Empirical Evidence:**
  * Dedicated evaluation unit test suite (`backend/tests/unit/test_ai_evaluation_framework.py`): **19 passed**, 0 failed in 0.26s covering all 18 milestone requirements.
  * Full offline unit regression suite (`backend/tests/unit -m "not postgres and not ollama"`): **886 passed**, 0 failed, 6 warnings in 31.00s.
  * Benchmark CLI runner executed cleanly in offline replay mode with 0 DB queries, 0 Ollama calls, and 0 external egress.
* **Security & Non-Destructive Invariants:**
  * Strict adherence to `AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001` ($0 budget, 0 external cloud network egress).
  * Zero database migrations or schema alterations.
  * Anti-autonomous invariant: Ground-truth evaluation is purely analytical and advisory.

#### P3-H3A.2: Evaluation Integrity Remediation
* **Status:** COMPLETE
* **Objective:**
  * Correct methodological and mathematical limitations identified during independent audit Gate P3-H3A.1 to guarantee that AISOP's AI investigation evaluation framework is mathematically rigorous, un-inflatable, transparent, and completely decoupled from ground-truth answer synthesis.
* **Delivered Architecture & Remediation Scope:**
  1. *Remediation A (MITRE Sibling Sub-Technique Strict Rejection):*
     - Fixed over-tolerant sub-technique matching in `mitre_evaluator.py`. Strict parent-child matching is preserved (`pred == exp_parent` or `exp == pred_parent`), but sibling sub-techniques sharing a common parent (e.g. `T1059.006` Python vs expected `T1059.001` PowerShell) are strictly rejected as 1 False Positive and 1 False Negative.
     - Documented explicit rationale in `MitreEvaluationResult.matching_notes`.
  2. *Remediation B (Benign Scenario False Positive Penalization & Micro-Averaging):*
     - Corrected `compute_precision_recall_f1` in `metrics.py`: Under the zero-target penalty convention, when expected targets are empty ($FN = 0$) and the model hallucinates techniques ($FP > 0$), Precision is $0.0$, Recall is undefined (`None`), and $F_1$ is penalized with $0.0$.
     - Introduced `dataset_micro_mitre_precision`, `dataset_micro_mitre_recall`, and `dataset_micro_mitre_f1` to aggregate raw True Positives, False Positives, and False Negatives across all scenarios, ensuring benign false alarms penalize dataset-level performance.
     - Added explicit tracking for `benign_scenarios_evaluated`, `benign_false_positive_count`, and `benign_false_positive_rate`.
  3. *Remediation C (Observable / IOC Exact Matching & Bi-Directional Negation Filtering):*
     - Replaced substring containment checks and hardcoded `fp=0` with structured entity extraction (`_extract_observables_from_model`) and exact set difference (`pred_set - exp_set`).
     - Added bi-directional regex negation filtering (`neg_pat_before` and `neg_pat_after`) covering phrases such as `"was not observed"`, `"no evidence of"`, `"did not execute"`, preventing negated observables from being counted as positive detections.
     - Substring collisions (e.g. `10.0.0.1` vs `10.0.0.15`) are strictly resolved to $TP = 0, FP = 1, FN = 1$.
  4. *Remediation D (Grounding Transparency & Diagnostic Lexical Matching):*
     - Disclosed in schemas, reports, and code that token/word-overlap is a diagnostic heuristic, not semantic entailment.
     - Partitioned claim dispositions into verified ground truth (`SUPPORTED`, `PARTIALLY_SUPPORTED`), diagnostic heuristic match (`LEXICAL_HEURISTIC_MATCH`), unverified assertion (`UNVERIFIABLE`), and contradicted claims (`CONTRADICTED`).
     - Unreviewed claims citing valid context evidence require human semantic adjudication (`claims_requiring_human_review_count`); `overall_evidence_grounding_precision` remains `None` (`N/A`) until human review is completed.
  5. *Remediation E (Decoupling Replay from Ground-Truth Answer Synthesis):*
     - Removed automatic answer fabrication in `run_ai_benchmark.py`.
     - Introduced distinct benchmark execution modes:
       - `captured` (alias `replay`): Strictly evaluates authentic captured outputs from `datasets/ground_truth/fixtures/`. Scenarios lacking authentic fixtures are reported as `UNMEASURED` ($F_1 = \text{None}$) and excluded from performance scores.
       - `self-test`: Evaluates static diagnostic mock payloads to validate evaluator harness mechanisms, explicitly labeled with `[!WARNING] HARNESS SELF-TEST — NOT MODEL PERFORMANCE`.
  6. *Remediation F (Benchmark Report Transparency & Historical Preservation):*
     - Preserved historical P3-H3A benchmark report as `docs/04_Testing/AI_Model_Benchmark_Report_Historical_P3H3A.md`.
     - Updated active report `docs/04_Testing/AI_Model_Benchmark_Report.md` to clearly reflect authentic captured evaluation (1 measured scenario, 18 unmeasured) without manufactured 100% metrics.
  7. *Remediation G (Ground-Truth Dataset Refinement):*
     - Refined `SCN-CHN-003` (Process Injection): Set parent `T1055` as mandatory ground truth, with `T1055.001` and `T1055.002` marked `is_uncertain: true` due to Sysmon Event ID 8 telemetry ambiguities.
     - Refined `SCN-ATO-005` (LSASS ProcessAccess): Clarified that memory access handle acquisition (`0x1010`) establishes intent/attempt rather than completed dumping (`T1003.001`), adding parent `T1003` with `is_uncertain: true`.
  8. *Remediation H (Unit Testing & Full Regression Certification):*
     - Added 8 dedicated unit tests in `TestEvaluationIntegrityRemediations` covering sibling rejection, sub-technique tolerance, zero-target F1 penalization, dataset micro-metrics, IOC collision resistance, negation filtering, missing fixture handling, and self-test mode labeling.
     - Evaluation test suite: **27 passed**, 0 failed in 0.30s.
     - Full offline unit regression suite: **894 passed**, 0 failed, 6 warnings in 31.36s.
* **Security & Non-Destructive Invariants:**
  * Strict adherence to `AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001` ($0 budget, 0 external network calls).
  * Zero database migrations, zero database mutations.
  * Anti-autonomous invariant: Purely analytical evaluation and advisory reporting.

#### P3-H3A.4: Blocking Evaluation Integrity Remediation
* **Status:** COMPLETE
* **Objective:**
  * Resolve all three blocking evaluation defects identified by independent audit Gate P3-H3A.3 (model self-certification, fixture envelope & provenance decoupling, zero-prediction failure macro F1 penalization) along with explicit secondary findings covering negation clause boundaries, IPv6 observable extraction, ATT&CK technique string normalization, ground-truth LSASS uncertainty, and report denominator visibility.
* **Delivered Architecture & Remediation Scope:**
  1. *Decoupled Independent Adjudication Contract (BLK-H3A-01):*
     - Replaced model-controlled `claim.analyst_notes` inspection in `GroundingEvaluator.evaluate_claims` with an independent `HumanClaimAdjudication` schema (`adjudication_record_id`, `claim_id`, `review_status`, `reviewer_id`, `reviewed_at_utc`, `review_notes`) and external `adjudication_registry`.
     - Validates non-empty `reviewer_id` and timezone-aware UTC timestamps; rejects conflicting adjudication records with `ValueError`.
     - Only independent trusted adjudications credit `SUPPORTED` and increment `verified_supported_count`. Claims without adjudication default strictly to `LEXICAL_HEURISTIC_MATCH`, `PARTIALLY_SUPPORTED`, or `UNVERIFIABLE`. `overall_evidence_grounding_precision` remains `None` (`N/A`) until human adjudication is performed.
  2. *Cryptographically Bound Fixture Envelope & Provenance (BLK-H3A-02):*
     - Introduced `CapturedInvestigationFixture` envelope (`schema_version`, `scenario_id`, `capture_timestamp_utc`, `model_identifier`, `prompt_sha256`, `raw_response_sha256`, `raw_response`, `capture_method`, `capture_environment`, `capture_manifest_version`, `inference_parameters`).
     - In `EvaluationReplayRunner.evaluate_scenario_output`, validates scenario ID binding (`envelope.scenario_id == scenario.scenario_id`) and computes raw response SHA-256 (`hashlib.sha256(raw_response.encode()).hexdigest() == envelope.raw_response_sha256`).
     - Mismatched scenario IDs are rejected with `FIXTURE MISBINDING` and marked `is_measured=False`. Tampered/mismatched payloads are rejected with `FIXTURE INTEGRITY COMPROMISED` and marked `is_measured=False`.
     - Supports legacy un-enveloped fixtures explicitly labeled as unverified; prevents fallback to synthetic answers in captured mode.
  3. *Zero-Prediction Failure Macro F1 Penalization (BLK-H3A-03):*
     - Corrected `compute_precision_recall_f1` in `metrics.py`: When a scenario expects mandatory techniques ($FN > 0$) and the model produces zero predictions ($TP = 0, FP = 0$), the zero-prediction penalty convention assigns $F_1 = 0.0$ while honestly returning Precision as undefined (`None`).
     - Ensures complete failure scenarios remain in macro $F_1$ aggregation (`[r.f1 for r in scoring_set if r.f1 is not None]`) and penalize overall macro performance rather than dropping out of the average.
     - Preserves $F_1 = \text{None}$ for clean scenarios with zero expected techniques and zero model predictions ($TP=0, FP=0, FN=0$).
  4. *Negation Window Clause Boundary Isolation:*
     - Updated observable negation regex lookaheads in `_extract_observables_from_model` to terminate strictly at clause separators (`,`, `;`, `:`, `.`, `\n`) and contrasting conjunctions (`but`, `however`, `although`, `whereas`, `yet`).
     - Prevents sentences like `"10.0.0.1 was active on host-a, but host-b was not observed"` from negating `10.0.0.1`.
  5. *Dedicated RFC 5952 IPv6 Observable Extraction & Scoring:*
     - Implemented token-based RFC 5952 IPv6 candidate extraction and validation using `ipaddress.IPv6Address` in `_extract_observables_from_model`.
     - Updated `_evaluate_iocs` to map `obs_type == "ipv6"` to dedicated `norm_type = "ipv6"` (separated from `ipv4`), supporting exact set comparison and F1 scoring for IPv6 observables.
  6. *ATT&CK Technique String Normalization:*
     - Updated `_normalize_tech_id` in `mitre_evaluator.py` with regex extraction `r"\b(T\d{4}(?:\.\d{3})?)\b"`.
     - Normalizes descriptive technique strings (e.g. `"T1059: PowerShell" -> "T1059"`, `"T1059.001 - Command and Scripting Interpreter" -> "T1059.001"`).
  7. *Ground-Truth LSASS Uncertainty Contract Refinement:*
     - Refined `datasets/ground_truth/atomic/SCN-ATO-005.json`: Set parent `T1003` to `is_mandatory: true, is_uncertain: false` and sub-technique `T1003.001` to `is_mandatory: false, is_uncertain: true`.
     - Ground-truth documentation notes that Sysmon Event ID 10 records handle acquisition with `PROCESS_VM_READ` access mask, establishing intent but not confirmed memory dumping.
  8. *Explicit Report Sample Size & Denominator Visibility:*
     - Updated `BenchmarkReportGenerator` to explicitly display sample sizes and denominators in scorecard rows (e.g. `100.0% (1/1 measured scenarios)`, `1.0000 (1/19 approved scenarios measured)`).
  9. *Unit Testing & Full Regression Certification:*
     - Added 14 new dedicated unit tests in `TestBlockingRemediationsP3H3A4` inside `backend/tests/unit/test_ai_evaluation_framework.py`.
     - Evaluation test suite: **41 passed**, 0 failed in 0.47s.
     - Full offline unit regression suite: **908 passed**, 0 failed, 6 warnings in 32.52s.
* **Security & Non-Destructive Invariants:**
  * Strict adherence to `AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001` ($0 budget, 0 external cloud calls).
  * Zero database migrations, zero database mutations.
  * Preserved historical benchmark reports immutable (`AI_Model_Benchmark_Report_Historical_P3H3A.md`).
  * P3-H3B remains conditionally gated pending live testing protocol authorization.

#### P3-H3A.6: Legacy Fixture Exclusion & Provenance Enforcement
* **Status:** COMPLETE
* **Objective:**
  * Remediate findings from independent audit Gate P3-H3A.5: exclude un-enveloped legacy fixtures from official measured benchmarks without file mutation, cryptographically verify scenario prompt artifacts and hashes, enforce fail-closed model identifier consistency between fixture envelopes and parsed investigation outputs, and restore historical milestone ledger audit dispositions.
* **Delivered Architecture & Remediation Scope:**
  1. *Exclusion of Legacy Unverified Fixtures (Remediation A):*
     - Bare un-enveloped fixtures (such as `datasets/ground_truth/fixtures/SCN-ATO-001-replay.json`) lacking cryptographic `CapturedInvestigationFixture` envelopes are classified as `output_source_type="legacy_unverified_fixture"` and assigned `is_measured=False`.
     - In `EvaluationReplayRunner.run_benchmark`, unmeasured scenarios are excluded from the official scoring set (`measured_official`), preventing unverified legacy fixtures from contributing to measured denominators or macro/micro metrics.
     - Preserved `SCN-ATO-001-replay.json` byte-for-byte unmodified (`SHA256: 4a8ef9ad16a6d3f46ffc46a0a249b74a1867684cb9c5594a50083153036c9d2c`).
  2. *Deterministic Prompt Canonicalization & Cryptographic Verification (Remediation B):*
     - Implemented `canonicalize_prompt_artifact(prompt: str | bytes) -> bytes` in `backend/app/modules/evaluation/metrics.py`, normalizing Windows/POSIX newline conventions (`\r\n` -> `\n`, `\r` -> `\n`) and trimming whitespace before UTF-8 encoding.
     - Extended `CapturedInvestigationFixture` with `prompt_artifact: str | None = None`.
     - In `EvaluationReplayRunner.evaluate_scenario_output`, computes `hashlib.sha256(canonicalize_prompt_artifact(candidate_prompt)).hexdigest()` and verifies exact match against `envelope.prompt_sha256`. Missing prompt artifacts fail closed (`is_measured=False`, `output_source_type="missing_prompt_artifact"`). Mismatches fail closed (`is_measured=False`, `output_source_type="prompt_hash_mismatch"`).
     - Added optional `--prompts-dir` CLI support in `backend/scripts/run_ai_benchmark.py` to ingest canonical prompt text artifacts.
  3. *Fail-Closed Model Identifier Consistency Enforcement (Remediation C):*
     - In `EvaluationReplayRunner.evaluate_scenario_output`, compares envelope `model_identifier` against parsed `validated_model.model_identifier` (case- and whitespace-insensitive). Disagreement fails closed (`is_measured=False`, `output_source_type="model_identifier_mismatch"`).
     - Never allows unverified model responses to override envelope model identity in benchmark summaries.
     - Model weight digests remain explicitly `None` when unavailable (`CapturedInvestigationFixture.model_digest: str | None = None`).
  4. *Scorecard & Provenance Reporting Transparency:*
     - Updated `BenchmarkReportGenerator` to render distinct Per-Scenario ledger entries:
       - Missing fixtures: `*UNMEASURED — NO CAPTURED MODEL OUTPUT*`
       - Legacy unverified fixtures: `*LEGACY_UNVERIFIED — NO ENVELOPE PROVENANCE*`
       - Integrity rejected fixtures: `*REJECTED — {REASON}*`
  5. *Historical Milestone Ledger Correction (Remediation D):*
     - Restored historically accurate audit disposition for `P3-H3A.3` in the milestone ledger as `PARTIAL` (independent audit gate: 3 blocking defects identified).
     - Preserved `P3-H3A.4` as `COMPLETE` (blocking remediations implemented).
     - Recorded `P3-H3A.5` as `PARTIAL` (independent audit gate: residual provenance and legacy fixture limitations identified).
     - Recorded `P3-H3A.6` as `COMPLETE` (legacy exclusion, prompt hash verification, model consistency, ledger correction).
  6. *Unit Testing & Full Regression Certification:*
     - Added 12 new dedicated unit tests in `TestLegacyExclusionAndProvenanceP3H3A6` inside `backend/tests/unit/test_ai_evaluation_framework.py`.
     - Evaluation test suite: **53 passed**, 0 failed in 0.36s.
     - Full offline unit regression suite: **920 passed**, 0 failed, 6 warnings in 29.38s.
* **Security & Non-Destructive Invariants:**
  * Strict adherence to `AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001` ($0 budget, 0 external cloud calls).
  * Zero database migrations, zero database mutations.
  * Preserved historical benchmark reports immutable (`AI_Model_Benchmark_Report_Historical_P3H3A.md`).
  * P3-H3B remains conditionally gated pending live testing protocol authorization.

#### P4C: Capstone Evaluation & Production-Readiness Hardening
* **Status:** COMPLETE
* **Objective:** Verify AISOP as an integrated security investigation platform across all architectural layers, including the 13-stage reproducible investigation lifecycle, 6-role collaboration & authorization matrix, role-tailored report export API, PostgreSQL 17 live integration, and full regression certification.
* **Delivered Architecture & Results:**
  1. *Report Export API:* Implemented `GET /api/v1/cases/{case_id}/reports/export` supporting role-tailored Markdown (Executive, Technical, Detection) and JSON bundle formats, emitting immutable `case_report_exported` audit events.
  2. *Capstone Integration Suite (`test_phase4c_capstone.py`):* 6/6 tests passed in 1.83s covering 13-stage lifecycle, 6-role RBAC, duplicate alert idempotency, vendor field preservation, and deterministic fallback.
  3. *Full Offline Backend Regression:* 1,198 passed, 0 failed in 54.18s.
  4. *PostgreSQL 17.11 + pgvector 0.8.6 Verification:* 29/29 tests passed against isolated disposable database `aisop_p4c_disposable` on port 5433 (database dropped cleanly).
  5. *Frontend Verification:* 33/33 tests passed in 171.6ms, 0 type errors, production build verified.
  6. *Governance Verdict:* Capstone Ready (Accepted). Documented in `docs/00_Project_Management/Phase_4C_Capstone_Evaluation_Report.md`.

#### P4-GOV: 15-Layer Engineering Compliance Matrix & SaaS Readiness Audit
* **Status:** COMPLETE (ACCEPTED — RECONCILED)
* **Objective:** Comprehensive, evidence-backed evaluation of AISOP against all 15 layers of the production engineering playbook (*Vibe Coding a Real SaaS: The 15-Layer Playbook*).
* **Delivered Architecture & Results:**
  1. *Authoritative 15-Layer Assessment & Reconciliation:* Assessed 86 discrete requirements across all 15 architectural layers:
     - **67 Implemented & Verified** (77.9% of total 86; 79.8% of 84 applicable requirements).
     - **1 Implemented awaiting live authorization** (1.2% — REQ-8.5 AI benchmark live capture).
     - **4 Partially Implemented** (4.8% of applicable — REQ-1.6 README drift, REQ-9.3 TLS proxy template, REQ-14.3 pgvector probe, REQ-15.3 keyset pagination).
     - **4 Missing and Required** (4.8% of applicable — REQ-3.7 backup script/procedure, REQ-7.2 backend CI workflow, REQ-7.3 frontend CI workflow, REQ-7.4 dependency audit in CI).
     - **8 Deferred with documented justification** (9.5% of applicable — REQ-7.5 cloud DB in CI, REQ-10.7 external pen test, REQ-11.4 Redis, REQ-12.3 query cache, REQ-13.5 cloud APM, REQ-14.5 Prometheus, REQ-15.4 worker queue, REQ-15.5 horizontal scaling).
     - **2 Not Applicable in matrix** (2.3% of total — REQ-9.4 public cloud SaaS, REQ-12.4 public CDN).
  2. *Reconciliation Resolution:* Corrected historical count discrepancies (54 vs 67, 14 vs 8, 9 vs 2), verified exact mathematical invariant ($67 + 1 + 4 + 4 + 8 + 2 = 86$), reclassified REQ-3.7 as missing and REQ-14.3 as partial based on repository reality, and qualified security claims.
  3. *Identified Gaps:* Automated CI/CD workflow (`.github/workflows/`), database backup/restore script (`Deployment_Guide.md`), and pgvector deep health probe in `/health/ready`.
  4. *Primary Deliverables:* Published reconciled `docs/00_Project_Management/AISOP_15_Layer_Engineering_Compliance_Matrix.md` and `docs/00_Project_Management/AISOP_Engineering_Readiness_Summary.md`.

#### Post-P4-GOV Engineering Hardening Milestones (P4-HARDENING-01 through 05)

* **P4-HARDENING-01: CI/CD Foundation (REQ-7.2, REQ-7.3, REQ-7.4)**
  - *Objective:* Establish a minimal, reliable, self-contained GitHub Actions CI workflow verifying backend, frontend, and dependencies without external cloud or paid services.
  - *Deliverable:* `.github/workflows/ci.yml` (multi-job pipeline: `backend` running offline suite `pytest -m "not postgres and not ollama"`, `frontend` running `npm ci`, typecheck, Vitest, and production build, and `dependency-audit` running `pip-audit`).
  - *Status:* COMPLETE.

* **P4-HARDENING-02: Database Backup, Restore & Disaster Recovery Foundation (REQ-3.7)**
  - *Objective:* Establish an automated, deterministic PostgreSQL backup utility and comprehensive disaster recovery runbook.
  - *Deliverables:* `scripts/backup_postgres.ps1` (container-side `pg_dump -Fc` custom archive, `docker cp` binary safety, overwrite collision guard, 0-byte detection/cleanup, SHA-256 checksum sidecar, JSON audit metadata), `docs/11_Deployment/Deployment_Guide.md` (3-tier validation checklist: file integrity, SQL schema/trigger/vector integrity, application health probe; emergency host recovery runbook), and `tests/test_backup_postgres.ps1` (12 unit tests passing).
  - *Status:* COMPLETE (Partially Implemented in compliance matrix pending operator live container restore drill).

* **P4-HARDENING-03: Deep PostgreSQL & pgvector Readiness Verification (REQ-14.3)**
  - *Objective:* Upgrade `/api/v1/health/ready` from a simple `SELECT 1` ping to a deep, non-destructive probe validating relational connectivity, `pgvector` extension catalog registration, `knowledge_embeddings` schema, and 768d vector dimension compatibility.
  - *Deliverables:* `backend/app/api/v1/endpoints/health.py` (read-only queries, sanitized secret reporting preventing credential leakage, explicit SQLite test fallback), `docs/03_System_Design/Health_and_Readiness_Architecture.md`, and 10 deep readiness test cases in `backend/tests/integration/test_health_api.py` (17 tests passing).
  - *Status:* COMPLETE (Upgraded to Implemented & Verified in compliance matrix).

* **P4-HARDENING-04: Private LAN TLS Reverse Proxy Preparation (REQ-9.3)**
  - *Objective:* Prepare a hardened Nginx TLS reverse proxy configuration template and operational runbook for private LAN deployment.
  - *Deliverables:* `deploy/nginx/nginx.conf` (TLS 1.2/1.3, AEAD ciphers, PFS, canonical port 80->443 redirect, HTTP 444 drop for untrusted Host/SNI scans, 50M body size for evidence ingestion, sanitized `X-Forwarded-For` against client IP spoofing, header deduplication via `proxy_hide_header`), and `docs/11_Deployment/TLS_Reverse_Proxy_Guide.md`.
  - *Status:* COMPLETE (Template deliverable; inactive pending operator PKI certificate issuance and port binding).

* **P4-HARDENING-05: Project Reality, README & Documentation Synchronization (REQ-1.6)**
  - *Objective:* Reconcile project-facing documentation with actual repository evidence, eliminating outdated claims of 0% UI, unmounted routes, and absent authentication.
  - *Deliverables:* Synchronized `README.md` (updated Reality Matrix, human-in-the-loop governance disclosures, quick start with frontend and head migration `0004_p3h2_rbac_case_scoping`, verified 1,270 passing offline tests, updated limitations), and updated `docs/00_Project_Management/Milestones.md`.
  - *Status:* COMPLETE (Upgraded to Implemented & Verified).

---

### SDLC Methodology & DevSecOps Verification Framework (ADR-006)

* **Adopted Development Methodology:** Agile core governance with RAD-style exploratory prototyping within bounded increments, reinforced by continuous DevSecOps testing and security verification gates ([ADR-006](../03_System_Design/ADR/ADR-006_SDLC_and_DevSecOps_Strategy.md)).
* **Multi-Tier Test Verification Matrix:**
  * **Tier 1 (Offline Unit & Mock Suite):** `uv run pytest -m "not postgres and not ollama"` (In-memory SQLite, parsers, chunkers, MockTransport).
  * **Tier 2 (Live Local Ollama AI Daemon):** `uv run pytest -m ollama` (Real HTTP client against localhost:11434 with `nomic-embed-text`).
  * **Tier 3 (Live PostgreSQL 17 + pgvector Container):** `uv run pytest -m postgres` (Docker container on port 5433, `aisop_test` DB, zero SQLite fallback).
  * **Tier 4 (Comprehensive Regression Suite):** `uv run pytest` (All integration tiers executed simultaneously).
* **Continuous DevSecOps Gating Rules:**
  * **Gate 1 (Pre-Commit / PR):** 100% Black/isort formatting, strict typing, Tier 1 unit tests passing, zero hardcoded credentials.
  * **Gate 2 (Persistence & Parity):** Tier 3 PostgreSQL tests passing, Alembic parity verified (`diffs == []`), reversible downgrade tested on disposable database (`aisop_test`).
  * **Gate 3 (Boundary & Dependency):** `uv run pip-audit` reports zero High/Critical CVEs; perimeter bounds enforced (`MAX_BATCH_SIZE=2000`, `MAX_PAYLOAD=64KB`, `MAX_PAGE_SIZE=200`).
  * **Gate 4 (AI Safety & Non-Destructive Guardrails):** Strict vector dimension assertion (768-dim); advisory-only architecture with zero autonomous containment or destructive tools.

