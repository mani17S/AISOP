# AISOP Phase 1 Technical Architecture: Ingestion Pipeline & Canonical Data Model

| Field | Value |
|---|---|
| **Document ID** | ARCH-001 |
| **Status** | ACTIVE / BASELINE CERTIFIED |
| **Phase Scope** | Phase 1 (Milestones P1-H1 through P1-H10) |
| **Last Updated** | 2026-11-25 (sections 8.1, 8.2 and 9 status and rule counts, IOC wording) |
| **Primary Authors** | Implementation Engineer & Project Owner |
| **Related Documents** | [ADR-001](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-001_LLM_Layer_Abstraction.md), [ADR-002](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-002_Vector_Database.md), [ADR-003](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-003_Python_Version.md), [ADR-004](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-004_Initial_Ingestion_Scope.md), [ADR-005](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-005_Frontend_Stack.md), [Database Design](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/04_Database/Database_Design.md), [Migration Strategy](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/04_Database/Migration_Strategy.md), [Database Testing](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/04_Database/Database_Testing.md) |

---

## 1. System Overview & Architectural Principles

AISOP (AI-Assisted Security Operations Platform) is designed as a local-first, analyst-centric security operations platform operating at the intersection of raw telemetry ingestion, canonical data normalization, deterministic investigation retrieval, and (in Phase 2) AI-assisted hypothesis generation.

Phase 1 establishes the deterministic foundational core of the platform: a reliable, bounded telemetry ingestion pipeline, a strict relational data model, an asynchronous query API for SOC incident triage, structured observability, and a verified migration/persistence lifecycle.

```
+-----------------------------------------------------------------------------------------+
|                                    AISOP Phase 1 System                                 |
|                                                                                         |
|  [ Raw Telemetry ] ---> [ Ingestion Boundary ] ---> [ Cryptographic Canonicalization ]  |
|  (Sysmon JSON)          (Pydantic Validation,       (SHA-256 Digest over Compact JSON)  |
|                         Bounds Enforcement)                                             |
|                                                                   |                     |
|                                                                   v                     |
|  [ Extracted Entities ] <--- [ Atomic Parser Engine ] <--- [ Deduplication Engine ]     |
|  (Host, Process, User,       (Sysmon Event Parser,         (Option A Batch Lookup       |
|   IP, File, Registry...)      12 Event IDs Supported)       IN (...) with Chunking)     |
|                                                                   |                     |
|                                                                   v                     |
|  [ SOC Investigation API ] <--- [ Persistence Layer ] <--- [ Transaction Isolation ]    |
|  (Filtered Timeline Scans,      (SQLAlchemy 2.0 Async,      (Per-Event Savepoint        |
|   Deterministic Ordering,        PostgreSQL 17 / Alembic)    Rollback & Race Safety)    |
|   Bounded Pagination)                                                                   |
+-----------------------------------------------------------------------------------------+
```

### 1.1 Architectural Principles
1. **Local-First Deployment:** The platform must run completely and reliably on local analyst workstations and isolated infrastructure without compulsory external cloud dependencies.
2. **Determinism over Heuristics:** Ingestion, canonical normalization, entity extraction, deduplication, and query retrieval operate strictly through deterministic code without non-deterministic LLM processing in the ingestion critical path.
3. **Zero Silent Data Loss:** Duplicate evidence is explicitly identified and safely skipped under the Option A contract. Parsing or entity extraction errors on well-formed payloads preserve best-effort per-event isolation via nested savepoints.
4. **Strict Boundary Enforcement:** Request payloads, batch sizes, page limits, and timestamp windows are strictly validated and bounded at ingress to prevent denial-of-service, unbounded memory consumption, and slow queries.
5. **Separation of Concerns:** Evidence parsing depends only on Pydantic schemas; persistence depends only on SQLAlchemy ORM models and Alembic migrations; downstream consumers depend only on canonical interfaces.

### 1.2 Technology Stack
* **Runtime:** Python 3.12+ ([ADR-003](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-003_Python_Version.md))
* **Application Framework:** FastAPI 0.115+, Uvicorn 0.34+, Pydantic v2
* **Persistence & ORM:** SQLAlchemy 2.0 (AsyncIO), Alembic 1.14+
* **Database Engine:** PostgreSQL 17 with `pgvector` container ([ADR-002](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-002_Vector_Database.md))
* **Database Drivers:** `psycopg` 3.2+ (binary async driver for PostgreSQL), `aiosqlite` (for in-memory unit testing)
* **Observability:** Loguru 0.7+ structured JSON/text logging

---

## 2. Canonical Telemetry Ingestion Pipeline

### 2.1 Ingestion Ingress & Bounds Enforcement
Telemetry ingestion is exposed via the HTTP endpoint:
```http
POST /api/v1/evidence/ingest
```
Request bodies are validated against `IngestRequest` containing an array of `RawEvidencePayload` objects. The ingress boundary enforces two distinct tiers of validation:

1. **Perimeter / Security Violations (Fail Fast):**
   * Batch size limit: `MAX_BATCH_SIZE = 2000` items. Requests exceeding 2000 events are rejected immediately with `HTTP 422 Unprocessable Entity`.
   * Event payload size limit: `MAX_EVENT_PAYLOAD_BYTES = 65536` bytes (64 KB). Any individual raw payload exceeding 64 KB fails fast with `HTTP 422`.
   * Metadata constraints: `source_type` and `source_identifier` are constrained to bounded string lengths ($1 \le \text{length} \le 128$) with whitespace stripping. Empty or missing values fail fast with `HTTP 422`.
   * Total serialized payload budget: $\text{MAX\_BATCH\_SIZE} \times \text{MAX\_EVENT\_PAYLOAD\_BYTES} = 2000 \times 64\text{ KB} = 128\text{ MB}$.
2. **Pipeline / Processing Errors (Best-Effort Isolation):**
   * Malformed event payloads or unparseable event structures within an otherwise valid batch are handled gracefully on a per-event basis.
   * Processing errors are captured in a structured `errors` list in the response (`HTTP 200 OK`), allowing valid events in the batch to commit successfully.

### 2.2 Cryptographic Canonicalization
To guarantee deterministic deduplication across distributed ingest sources, [hasher.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/modules/evidence/hasher.py) computes a SHA-256 digest over the canonical representation of the raw payload:
```python
def compute_sha256(payload: Any) -> str:
    canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
```
* **Key Sorting:** `sort_keys=True` ensures JSON key order variations do not alter the cryptographic hash.
* **Whitespace Normalization:** `separators=(',', ':')` eliminates insignificant whitespace differences.
* **Encoding:** UTF-8 byte serialization guarantees platform-independent hashing.

### 2.3 Extensible Parser Architecture
In accordance with [ADR-004](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-004_Initial_Ingestion_Scope.md), the parser layer decouples raw evidence ingestion from downstream consumption using a protocol-driven adapter pattern:
* [parser_protocol.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/modules/evidence/parser_protocol.py): Defines the `EvidenceParser` runtime protocol requiring `parse(raw_payload: dict[str, Any]) -> list[NormalizedEvent]`.
* [parser_registry.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/modules/evidence/parser_registry.py): Maintains an in-memory mapping of `source_type` string identifiers to parser implementations.

### 2.4 Deterministic Sysmon JSON Parser
[sysmon_parser.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/modules/evidence/sysmon_parser.py) implements full deterministic normalization for **12 Sysmon Event IDs**:

| Sysmon Event ID | Event Name | Normalized Event Type | Extracted Context & Attributes |
|:---:|:---|:---|:---|
| **1** | Process Creation | `process_create` | Image path, command line, PID, parent PID, user, current directory, process GUID, hashes (SHA256, MD5, SHA1). |
| **3** | Network Connection | `network_connect` | Source IP, source port, destination IP, destination port, protocol, direction, image path, PID, user. |
| **7** | Image Loaded | `image_load` | Image loaded path, loading process image, PID, hashes, signature status, signed, valid. |
| **8** | CreateRemoteThread | `remote_thread_create` | Source process (PID, image, GUID), target process (PID, image, GUID), new thread ID, start address, start module/function. |
| **10** | ProcessAccess | `process_access` | Source process (PID, image, GUID), target process (PID, image, GUID), granted access mask, call trace. |
| **11** | File Creation | `file_create` | Target filename, creation time, process image, PID, user. |
| **12** | Registry Create/Delete | `registry_create` | Target object path, event type, process image, PID, user. |
| **13** | Registry Value Set | `registry_set` | Target object path, details (value data), event type, process image, PID, user. |
| **14** | Registry Renamed | `registry_rename` | Target object path, new name, process image, PID, user. |
| **15** | FileCreateStreamHash | `file_create_stream_hash` | Target filename with Alternate Data Stream (ADS) syntax (`file:Zone.Identifier`), stream hash, creation time, process image, PID. |
| **22** | DNS Query | `dns_query` | Query name (domain), query status, query results, process image, PID, user. |
| **23** | File Delete | `file_delete` | Target filename, hashes, is_executable boolean, archived boolean, process image, PID, user. |

### 2.5 Atomic Entity Extraction
[entity_extractor.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/modules/evidence/entity_extractor.py) extracts observables (items seen in events, such as hosts, users, IPs, domains, files and hashes) from normalized events, mapping them into canonical entity representations across **8 entity types**. An observable is an indicator of compromise (IOC) only if it has been assessed as indicative of compromise; the extractor makes no such judgement, so a host or user seen in a log is an observable, not an IOC:
1. `host`: Hostname, domain, FQDN.
2. `user`: Username, domain user, security identifier (SID).
3. `process`: Process name, PID, image path, process GUID (with contextual roles: `source`, `target`, `parent`).
4. `ip`: IPv4/IPv6 addresses (with roles: `source`, `destination`).
5. `domain`: DNS query names, network hostnames.
6. `file`: Target files, loaded images, alternate data streams (role: `target`).
7. `file_hash`: SHA256, SHA1, MD5, SHA512 cryptographic digests (role: `file_hash`).
8. `registry`: Registry keys, values, and paths.

### 2.6 Ingestion Service & Option A Deduplication
[ingestion_service.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/modules/evidence/ingestion_service.py) coordinates the complete batch persistence workflow under the **Option A Deduplication Contract**:

```
[ Ingest Batch (N <= 2000) ]
              |
              v
[ Compute Canonical SHA-256 for all items ]
              |
              v
[ Query DB in chunks of 1000: SELECT sha256_hash WHERE sha256_hash IN (...) ]
              |
              +-------------------------------+
              |                               |
       [ Existing Hash ]               [ New Hash ]
              |                               |
              v                               v
    [ Skip Event Entirely ]        [ session.begin_nested() (SAVEPOINT) ]
    [ Increment skipped_count ]               |
                                              +---> [ Insert RawEvidence ]
                                              +---> [ Parse NormalizedEvents ]
                                              +---> [ Extract Entities ]
                                              +---> [ Flush & Commit SAVEPOINT ]
                                              |
                                      (On Error / Race)
                                              |
                                              +---> [ Rollback SAVEPOINT ]
                                              +---> [ Capture Structured Error ]
```

* **Batch Existence Optimization:** Rather than executing $N$ round-trip queries, hashes are queried in bulk using `IN (...)` in chunks of `DEFAULT_CHUNK_SIZE = 1000`, reducing database round trips to $\lceil U / 1000 \rceil$ (where $U$ is the number of unique hashes in the batch).
* **In-Memory Classification:** An in-memory hash map categorizes events into duplicates (skipped) and novel records (processed).
* **Savepoint Isolation:** Each novel event is enclosed within `async with session.begin_nested():`. If an error occurs during parsing, model instantiation, or child entity insertion, the savepoint rolls back only that specific event's changes without rolling back the surrounding transaction.
* **Concurrent Race Safety:** If two concurrent transactions attempt to insert the same raw evidence record simultaneously, the unique constraint on `raw_evidence.sha256_hash` raises an `IntegrityError` / `UniqueViolation`. The nested savepoint absorbs the exception, rolls back the subtransaction, and records the conflict without aborting the parent transaction.

---

## 3. Canonical Data Model & Persistence Architecture

### 3.1 Relational Schema & ORM Entities
The database schema is defined using SQLAlchemy 2.0 mapped declarative models in [backend/app/models/evidence.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/models/evidence.py):

```
+-------------------------------------------------------------+
|                         raw_evidence                        |
+-------------------------------------------------------------+
| id            : UUID (PK)                                   |
| sha256_hash   : VARCHAR(64) UNIQUE NOT NULL (Index)         |
| payload       : JSON / JSONB NOT NULL                       |
| source_type   : VARCHAR(64) NOT NULL                        |
| received_at   : TIMESTAMPTZ NOT NULL                        |
| created_at    : TIMESTAMPTZ NOT NULL                        |
+-------------------------------------------------------------+
                               | 1
                               |
                               | ON DELETE CASCADE
                               v 0..*
+-------------------------------------------------------------+
|                      normalized_events                      |
+-------------------------------------------------------------+
| id                : UUID (PK)                               |
| raw_evidence_id   : UUID (FK -> raw_evidence.id) NOT NULL   |
| event_timestamp   : TIMESTAMPTZ NOT NULL                    |
| event_type        : VARCHAR(64) NOT NULL                    |
| severity          : VARCHAR(32) NOT NULL                    |
| source_type       : VARCHAR(64) NOT NULL                    |
| source_identifier : VARCHAR(128) NOT NULL                   |
| outcome           : VARCHAR(32) NOT NULL                    |
| action            : VARCHAR(64) NULL                        |
| custom_fields     : JSON / JSONB NULL                       |
+-------------------------------------------------------------+
| Indexes:                                                    |
| - ix_normalized_events_time_id (event_timestamp DESC, id DESC)
| - ix_normalized_events_type_time (event_type, event_timestamp)
+-------------------------------------------------------------+
                               | 1
                               |
                               | ON DELETE CASCADE
                               v 0..*
+-------------------------------------------------------------+
|                      extracted_entities                     |
+-------------------------------------------------------------+
| id            : UUID (PK)                                   |
| event_id      : UUID (FK -> normalized_events.id) NOT NULL  |
| entity_type   : VARCHAR(64) NOT NULL                        |
| entity_value  : VARCHAR(512) NOT NULL                       |
| role          : VARCHAR(64) NULL                            |
| attributes    : JSON / JSONB NULL                           |
+-------------------------------------------------------------+
| Indexes:                                                    |
| - ix_extracted_entities_type_value (entity_type, entity_value)
+-------------------------------------------------------------+
```

### 3.2 Key Constraints & Relational Invariants
1. **Primary Keys:** Every table uses UUID primary keys generated in application space or via database defaults.
2. **Cryptographic Uniqueness:** `raw_evidence.sha256_hash` enforces a hard database-level unique constraint (`uq_raw_evidence_sha256`), guaranteeing that no two duplicate evidence records can ever coexist.
3. **Referential Integrity & Cascading Deletes:**
   * `normalized_events.raw_evidence_id` references `raw_evidence.id` with `ON DELETE CASCADE`.
   * `extracted_entities.event_id` references `normalized_events.id` with `ON DELETE CASCADE`.
   * Deleting a parent `raw_evidence` record automatically and atomically removes all child normalized events and extracted entities, preventing orphaned records.
4. **Timezone Fidelity:** All timestamp columns (`event_timestamp`, `received_at`, `created_at`) use `TIMESTAMPTZ` (SQLAlchemy `DateTime(timezone=True)`). Timestamps are strictly normalized to UTC instants.
5. **JSON/JSONB Handling:** Raw payloads, custom fields, and entity attributes use JSON/JSONB data types, ensuring lossless preservation of vendor-specific telemetry attributes.

### 3.3 Indexing Strategy & Performance Trade-offs
* **Timeline Query Index (`ix_normalized_events_time_id`):** Composite index on `(event_timestamp DESC, id DESC)`. This index enables PostgreSQL to fulfill investigation timeline scans and deterministic tie-breaker sorting directly from the index tree without requiring an expensive in-memory or on-disk `SORT` node.
* **Type-Time Index (`ix_normalized_events_type_time`):** Composite index on `(event_type, event_timestamp)` for rapid retrieval of specific event categories over time windows.
* **Entity Lookup Index (`ix_extracted_entities_type_value`):** Composite index on `(entity_type, entity_value)` for high-speed observable exploration and cross-event correlation.

---

## 4. SOC Investigation Query & Retrieval API

### 4.1 Investigation Query Service
[query_service.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/services/query_service.py) provides a high-performance, deterministic query layer for SOC incident triage, timeline assembly, and indicator correlation.

### 4.2 Endpoint Specifications

| HTTP Method & Path | Description | Key Parameters | Ordering Semantics |
|:---|:---|:---|:---|
| `GET /api/v1/evidence/events` | Paginated timeline query of normalized events with multi-field filtering. | `start_time`, `end_time`, `event_type`, `source_type`, `source_identifier`, `severity`, `outcome`, `entity_type`, `entity_value`, `page`, `limit` | `ORDER BY event_timestamp DESC, id DESC` |
| `GET /api/v1/evidence/events/{event_id}` | Detailed single-event retrieval. | `event_id` (UUID) | Eagerly loads parent `raw_evidence` and child `extracted_entities`. |
| `GET /api/v1/evidence/entities` | Paginated observable/entity exploration. | `entity_type`, `entity_value`, `role`, `page`, `limit` | `ORDER BY entity_type ASC, entity_value ASC, id DESC` |
| `GET /api/v1/evidence/by-hash/{sha256_hash}` | Direct point lookup by cryptographic digest. | `sha256_hash` (64-char hex) | Direct B-tree index point lookup. |
| `GET /api/v1/evidence/{evidence_id}` | Direct point lookup of raw evidence record. | `evidence_id` (UUID) | Single eager round-trip with child events. |
| `GET /api/v1/health` | Process liveness endpoint. | None | Verifies service availability (zero-dependency). |
| `GET /api/v1/health/ready` | Deep subsystem readiness endpoint. | None | Verifies PostgreSQL connectivity, `pgvector` extension, schema presence, and LLM daemon availability (see [Health_and_Readiness_Architecture.md](Health_and_Readiness_Architecture.md)). |

### 4.3 Deterministic Pagination & Ordering Rules
* **Safe Defaults:** `DEFAULT_PAGE_SIZE = 50`.
* **Upper Bounds:** `MAX_PAGE_SIZE = 200` (enforced via Pydantic/FastAPI validation; requests exceeding 200 fail fast with `HTTP 422`).
* **Deterministic Tie-Breaking:** Queries order by primary sorting columns and append the unique UUID `id DESC` as an immutable tie-breaker. This prevents "pagination drift" (duplicate or skipped rows across page boundaries) when multiple events share identical timestamps.
* **Time Range Validation:** If `start_time > end_time`, the request is immediately rejected with `HTTP 400 Bad Request`. Malformed timestamp formats fail with `HTTP 422`.

### 4.4 Pagination Complexity & Traversal Cost
The query API utilizes standard SQL `LIMIT K OFFSET M` pagination.
* **Shallow Pages ($M \le 1000$):** Retrieval is satisfied in $O(K)$ time via index scans on `ix_normalized_events_time_id`.
* **Deep Pages ($M \gg 1000$):** Traversal requires scanning and discarding $M$ preceding rows ($O(K + M)$ traversal cost). This is an accepted and documented trade-off for Phase 1; keyset/cursor-based pagination is scheduled for Phase 2/3 high-depth optimization.

---

## 5. Observability, Telemetry & Request Correlation

### 5.1 Structured Logging Architecture
Structured logging is centralized in [backend/app/core/logging.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/core/logging.py) powered by Loguru:
* **JSON Output Sink:** Production environments serialize log events to structured JSON lines containing timestamp, log level, module, function name, line number, message, correlation ID, and execution duration.
* **Standard Output Console Sink:** Development environments output colorized, readable terminal logs.
* **Intercept Handler:** Standard Python `logging` calls from third-party libraries (SQLAlchemy, Uvicorn, FastAPI) are intercepted and routed through Loguru sinks to maintain unified log formatting.

### 5.2 Distributed Request Tracing
The `RequestCorrelationMiddleware` automatically inspects incoming HTTP requests for the `X-Request-ID` header:
* If present, the correlation ID is validated and attached to the request context.
* If absent, a cryptographically random UUIDv4 is generated.
* The correlation ID is bound to the Loguru execution context (`logger.bind(correlation_id=...)`) and injected into the outgoing response headers as `X-Request-ID`.

### 5.3 Sensitive Data Sanitization
The `redact_sensitive_data` filter recursively sanitizes dictionary structures before logging. Fields matching sensitive key patterns (`password`, `token`, `secret`, `authorization`, `api_key`, `credential`) are masked (`***REDACTED***`), preventing credential leakage into application logs.

---

## 6. Database Migration Lifecycle & Schema Versioning

### 6.1 Alembic Migration Framework
Database schema migrations are managed via Alembic using an asynchronous configuration in [backend/app/db/migrations/env.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/db/migrations/env.py):
* **Async Engine Bridge:** Utilizes `async_engine.connect()` with `connection.run_sync(do_run_migrations)` to bridge SQLAlchemy 2.0 async connections with Alembic's synchronous DDL operations.
* **Offline Migration Support:** Supports `--sql` generation without an active database connection for auditable migration scripting.
* **Zero Automatic Startup Migrations:** In accordance with [ADR-004](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-004_Initial_Ingestion_Scope.md) and production safety standards, migrations are never run automatically on application startup. Schema evolution is strictly an intentional, auditable operational command (`alembic upgrade head`).

### 6.2 Schema Version Baseline
* **Baseline Revision:** [20260917_0001_initial_evidence_schema.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/app/db/migrations/versions/20260917_0001_initial_evidence_schema.py).
* **Deterministic DDL:** Replaces non-deterministic autogenerated naming with explicit constraint and index identifiers (`pk_raw_evidence`, `uq_raw_evidence_sha256`, `fk_normalized_events_raw_evidence_id`, `ix_normalized_events_time_id`).
* **Bidirectional Lifecycle:** Implements complete `upgrade()` and `downgrade()` logic. Downgrading cleanly drops tables in reverse topological order (`extracted_entities` -> `normalized_events` -> `raw_evidence`).

---

## 7. Dual-Tier Testing & Verification Architecture

To guarantee both high developer velocity and absolute database fidelity, AISOP enforces a dual-tier testing architecture:

```
+-----------------------------------------------------------------------------------------+
|                                Dual-Tier Test Baseline                                  |
|                                                                                         |
|  [ Tier 1: In-Memory Unit Suite ]                  [ Tier 2: PostgreSQL Integration ]   |
|  - Engine: SQLite (:memory:) via aiosqlite         - Engine: PostgreSQL 17 via psycopg  |
|  - Scope: Parsers, extractors, bounds, API, mocks  - Scope: DDL, types, migrations, FKs |
|  - Count: 108 tests                                - Count: 6 tests                     |
|  - Speed: ~3.1 seconds                             - Speed: ~1.8 seconds                |
|  - Execution: pytest -m "not postgres"            - Execution: pytest -m postgres      |
|                                                                                         |
|                    Total Combined Baseline: 114 Tests Passing (100%)                    |
+-----------------------------------------------------------------------------------------+
```

### 7.1 Tier 1: Fast In-Memory Unit Suite
* **Execution:** `pytest -v -m "not postgres"`
* **Volume:** 108 automated tests executing in ~3.1 seconds.
* **Characteristics:** Uses in-memory SQLite with `AsyncSessionAdapter`. Exercises parser corner cases, entity extraction accuracy, Pydantic validation bounds, query service filters, and error handlers with zero external infrastructure dependencies.

### 7.2 Tier 2: Real PostgreSQL 17 Integration Suite
* **Execution:** `pytest -v -m postgres`
* **Volume:** 6 comprehensive integration tests executing in ~1.8 seconds.
* **Test Suite:** [backend/tests/integration/test_postgres_lifecycle.py](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/backend/tests/integration/test_postgres_lifecycle.py).
* **Dialect Validation:** Enforces strict dialect checks (`dialect == "postgresql"`). If PostgreSQL is unreachable or an incorrect dialect is provided, tests fail immediately without silent fallback to SQLite.
* **Environment & Port Isolation:** Operates against the containerized PostgreSQL 17 instance on host port `5433` (`pgvector/pgvector:pg17`), isolating the native PostgreSQL service on port `5432`. Tests execute against a dedicated, auto-provisioned `aisop_test` database.
* **Windows Event Loop Accommodation:** Injects `WindowsSelectorEventLoopPolicy` on Windows systems to resolve psycopg 3 async driver compatibility with Windows asyncio event loops.
* **Verified Behaviors:** Live TCP connectivity, Alembic upgrade/downgrade cycles, metadata parity (`diffs == []`), native UUID object preservation, complex JSON preservation, timezone offset instant equality, savepoint deduplication recovery, and cascading deletes (`ON DELETE CASCADE`).

---

## 8. Operational Boundaries, Security Posture & Known Limitations

### 8.1 Supported vs Deferred Telemetry
* **Supported in Phase 1:** Sysmon JSON event logs conforming to Event IDs 1, 3, 7, 8, 10, 11, 12, 13, 14, 15, 22, and 23.
* **Listed as deferred in Phase 1; status checked against the code on 2026-11-25:**
  * Binary EVTX log ingestion (requires external binary parsers): **PLANNED**. Not implemented; `sysmon_parser.py` states binary EVTX is out of scope and telemetry must be JSON.
  * Windows Security Event Logs (Event IDs 4624, 4625, 4688, etc.): **IMPLEMENTED for JSON only**. `alerts/adapters/windows_security_adapter.py` normalises the JSON form, and ATT&CK rules read Windows Security fields (for example failed and successful logons by outcome, and event ids 4688 process creation, 4719 audit policy changed, 1102 log cleared). Validated on synthetic samples and the public datasets in `docs/10_Research/Real_Format_Ingestion_Result.md`, not on vendor-certified exports.
  * Zeek connection logs: **PLANNED**. No Zeek parser was found; `firewall_ids_adapter.py` accepts the label `zeek` as a source type, and `evidence_domains/adapters.py` lists native Zeek as PROPOSED.
  * Suricata EVE JSON: **PARTIAL**. `evidence_domains/suricata_eve.py` translates EVE `alert`, `dns` and `flow` records into evidence envelopes (other types are counted as skipped), driven by `backend/scripts/eve_to_envelopes.py`; the alert adapter also accepts the label `suricata` in a vendor-neutral alert shape. No route that uploads a raw EVE file was found.
  * Cloud audit logs (AWS CloudTrail, Azure Activity Logs, GCP Audit): **PARTIAL**. `alerts/adapters/cloud_audit_adapter.py` handles records labelled CloudTrail, GuardDuty, Entra ID and GCP audit, and cloud evidence enters through `POST /api/v1/cases/{id}/evidence/domain`; `evidence_domains/adapters.py` lists native CloudTrail and Entra formats as PROPOSED. Fidelity to real vendor exports is unverified.

### 8.2 Deferred AI & Advanced Analytics Capabilities
In accordance with [ADR-001](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-001_LLM_Layer_Abstraction.md) and [ADR-002](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-002_Vector_Database.md), the following capabilities were deferred to Phase 2. Status checked against the code on 2026-11-25 (code and routes were read; nothing was run):
* AI/LLM integration (Ollama, OpenAI, Claude, LangChain, prompt templates): **PARTIAL**. Ollama is the default local provider (`modules/ai/providers/ollama/provider.py`, selected in `modules/ai/llm/manager.py`) and Cloudflare Workers AI is an opt-in external provider (ADR-016); prompts are built in `modules/ai/prompt_builder/builder.py`. The `openai`, `anthropic` and `gemini` provider files are empty (0 bytes) and no LangChain use was found. The model is optional (`LLM_ENABLED=false`) and sits behind the sufficiency gate (section 9). Live-model behaviour is unverified.
* Retrieval-Augmented Generation (RAG) and semantic vector search: **PARTIAL**. `modules/ai/knowledge/retriever.py` and `modules/ai/embeddings/` exist. Retrieval runs only inside the AI synthesis paths (`services/investigation_service.py` and `services/case_service.py`), and only when the request carries a query filter of at least 3 characters and a retriever was initialised; otherwise it is skipped and an uncertainty flag is recorded. The multi-source investigation workflow does not use it. What the knowledge base contains on a given installation was not checked.
* pgvector vector embeddings and similarity indexing (`vector(N)` columns): **IMPLEMENTED in code**. `models/knowledge.py` defines a 768-dimension `Vector` column, with migrations `20261005_0002` and `20261021_0003`; the retriever uses pgvector cosine distance. PostgreSQL behaviour was not verified in this review.
* Automated MITRE ATT&CK technique mapping: **IMPLEMENTED, narrow**. 52 evidence-backed rules in three tables (see section 9); recall is low (`docs/10_Research/Evaluation.md`).
* Sigma rule and YARA rule generation: **PLANNED**. ADR-012 is PROPOSED and nothing is implemented; the knowledge loader only reads Sigma YAML as reference text.
* Web-based frontend investigation dashboard ([ADR-005](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-005_Frontend_Stack.md), deferred to Phase 4): **IMPLEMENTED**. `frontend/src/pages/` holds Dashboard, Alerts, Evidence, Cases, Reports and Security pages, and `InvestigationWorkspace` carries the multi-source panel.
* Threat intelligence (not on the original list): **PARTIAL**. Two small local feed files in `data/feeds/` (`feodo_tracker.csv`, `tor_exit_nodes.txt`) are loaded at start-up through `LocalThreatIntelEngine`. The AbuseIPDB provider code exists, but nothing in the application instantiates it or `ThreatIntelOrchestrator`, so it is not connected. Threat intelligence is context and never corroborates.

### 8.3 Operational Boundaries & Resource Limits
* **Ingestion Throughput:** Ingestion operates synchronously within worker tasks. High-throughput distributed ingestion pipelines (Kafka, Celery, Redis queues) are not implemented in Phase 1.
* **Single-Worker Concurrency:** Ingestion is bounded by database connection pool size and SQLite/PostgreSQL transaction serialization.
* **Offset Pagination Overhead:** Deep page navigation exhibits $O(K + M)$ traversal latency. Keyset/cursor pagination will replace offset pagination for large-scale export workflows.
* **Untrusted Data Isolation:** Telemetry payloads are treated as untrusted input. Parsers do not execute code, spawn child processes, evaluate paths, or perform active network queries.

---

## 9. Evidence-Sufficiency Gate and Multi-Source Investigation Workflow (Stage 3C / 3C-R)

> This section describes code that exists (2026-11-12). Sections 1-8 describe the Phase 1 pipeline; where section 8.2 lists "Automated MITRE ATT&CK technique mapping" and similar items as out of scope, a limited, deterministic implementation now exists (IMPLEMENTED, 52 rules in three tables: 6 `attack-map-v1` in `correlation/mitre.py`, 7 `domain-attack-v1` in `evidence_domains/domain_attack.py`, 39 `endpoint-attack-v1` in `correlation/mitre_endpoint.py`, all run by `correlation/workflow.py`; see below). Authoritative detail: [Multi_Source_Investigation_Workflow.md](../05_Backend/Multi_Source_Investigation_Workflow.md), ADR-008 and ADR-009.

* **Pre-model evidence-sufficiency gate (IMPLEMENTED, ADR-008 `suff-v2`)** - `backend/app/modules/ai/guardrails/sufficiency_gate.py: evaluate_sufficiency` runs before every production model invocation in `investigation_service.py` and `case_service.py`; INSUFFICIENT means no model call; exceptions fail closed; `GatedGenerator.generate` is the only production caller of `provider.generate`. The verdict is audited in `case_audit_events.details` (no migration) and disclosed in the final output.
* **Independence (IMPLEMENTED)** - `backend/app/modules/evidence/independence.py`: evidence clusters (duplicates, same raw record, near-duplicates) and link strengths shared by the gate, the claim validator and the correlator.
* **Multi-source workflow (IMPLEMENTED; integrated into the case workflow by Stage 4, see next bullet)** - `backend/app/modules/correlation/`: normalization through the ADR-007 adapters with raw-record digests, explainable correlation, timeline, deterministic ATT&CK mapping, hash-chained ledger, analyst report, optional gated LLM investigation. Not yet exposed through an API route or persisted in the database.
* **Trust boundaries** - raw records are untrusted data; everything before the gate is deterministic; the model is optional, untrusted and reachable only through the gate; reports and ledgers carry hashes for tamper evidence.
* **Integrated into the product (IMPLEMENTED offline, Stage 4, ADR-010)** - `POST /api/v1/cases/{case_id}/investigations/multisource` and `GET .../multisource/{section}` (`api/v1/endpoints/cases.py`) call `services/multisource_investigation_service.py`, which loads only the case's linked evidence, re-normalizes preserved raw payloads through the ADR-007 adapters (stored SHA-256 kept as provenance, persisted evidence id kept as `event_key`), runs `correlation.workflow.run_workflow`, and stores one `case_audit_events` row (`case_multisource_investigation`; PARTIAL persistence, no migration). Idempotent by evidence fingerprint; `stale_evidence` flag on reads; 409 on closed case or evidence changed mid-run; an audit failure returns no result. Frontend: `MultiSourcePanel` tab in `InvestigationWorkspace`. API: `docs/05_Backend/Multi_Source_Investigation_API.md`.
* **Not implemented / unverified** - live-model behaviour, accuracy of sufficiency classification (development labels written 2026-11-25: 49.3 % agreement, labels not shown reliable; held-out unlabelled), PostgreSQL validation of the new audit test, additional adapters/rules, streaming operation.

## 10. Source-Agnostic Evidence Domains and Investigation Graph (Stage 6, ADR-011)

Vendor, source and event ids are inputs, not architecture. Evidence enters as `aisop.evidence/1` envelopes (identity, cloud audit, network, e-mail, forensic artefacts, analyst statements; unknown but valid types are preserved as unclassified), is validated by per-domain adapters (`backend/app/modules/evidence_domains/adapters.py`) into canonical `Observation`s (`model.py`), and is projected (`bridge.py`) onto the existing correlation engine (Section 9), so the sufficiency gate, gated LLM step, claim verifier and report are the same code for SIEM/Sysmon alerts and for source-agnostic evidence.

Data flow: `POST /api/v1/cases/{id}/evidence/domain` (validate, quarantine, store raw unchanged + SHA-256, dedupe, link, audit) -> `POST /api/v1/cases/{id}/investigations/multisource` -> `normalize_records` (domain records bypass the alert adapters) -> `correlate` -> per incident: `build_timeline`, `map_techniques` + `map_domain_techniques`, `build_graph`, `enrich` (TI context), `evaluate_sufficiency` -> optional `GatedGenerator` -> report. Sections `graph` and `evidence` expose the graph, correlation rationale, TI context, analyst statements and per-record classification and provenance. No migration; no graph database. Limits and known gaps: ADR-011 Section 3.
