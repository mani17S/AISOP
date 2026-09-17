# AISOP Project Milestones

## Phase 1: Ingestion Pipeline & Canonical Data Model Hardening

| Milestone | Title | Status | Checkpoint / Baseline | Key Deliverables |
|:---|:---|:---:|:---|:---|
| **P1-H1** | Git Safety Checkpoint | COMPLETE | `63bee0b` | Clean local git baseline establishing Phase 0 architecture & initial ingestion pipeline. |
| **P1-H2** | Ingestion Deduplication | COMPLETE | `e1af0c9` | Option A contract: skips duplicates, no duplicate child rows, nested savepoint race handling. |
| **P1-H3** | Batch Query Optimization | COMPLETE | `e1af0c9` | Replaced $O(N)$ sequential lookups with batched chunked existence queries (`IN (...)`) and in-memory classification map. |
| **P1-H4** | Ingestion Security & Bounds Hardening | COMPLETE | `2cbe6a8` | Enforced `MAX_BATCH_SIZE=2000`, `MAX_EVENT_PAYLOAD_BYTES=65536`, `source_type`/`identifier` bounds, per-event atomic savepoint isolation, safe sample serialization. |
| **P1-H5** | SOC Investigation Query API Expansion | COMPLETE | `2228764` | Deterministic SOC investigation retrieval layer: normalized events, entity/IOC queries, time bounding, raw evidence retrieval, and bounded pagination. |
| **P1-H6** | Structured Logging & Observability | COMPLETE | Ready for Checkpoint | Loguru structured JSON/text logging, request correlation IDs (`X-Request-ID`), sensitive data redaction, and ingestion/query telemetry. |
| **P1-H7** | Sysmon Parser & Dataset Expansion | PENDING | — | Event IDs 8 (RemoteThread), 10 (ProcessAccess), 15 (ADS), 23 (FileDelete). |
| **P1-H8** | Database Migrations (Alembic Setup) | PENDING | — | Versioned schema migration management. |
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



