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
| **P1-H8** | Sysmon Parser & Dataset Expansion | COMPLETE | Ready for Checkpoint | Expanded deterministic Sysmon parser for Event IDs 8 (CreateRemoteThread), 10 (ProcessAccess), 15 (FileCreateStreamHash), and 23 (FileDelete) with entity extraction and zero schema migrations. |
| **P1-H9** | PostgreSQL Integration Test Suite | PENDING | — | Real PostgreSQL automated testing harness. |


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
  * Full test suite verification: 106/106 tests passing.



