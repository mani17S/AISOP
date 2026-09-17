# AISOP Database Testing Architecture & PostgreSQL Integration Guide

**Milestone:** P1-H9 — PostgreSQL Integration Test Suite  
**Status:** Implemented & Verified  
**Canonical Test Suite:** `backend/tests/integration/test_postgres_lifecycle.py`  
**Configuration & Fixtures:** `backend/tests/conftest.py`

---

## 1. Executive Summary

AISOP enforces a tiered database testing strategy:
1. **Tier 1 (Unit & Endpoint Tests):** Fast, in-memory SQLite testing utilizing an asynchronous session adapter (`AsyncSessionAdapter`) to validate API endpoints, query services, log redactions, and parsing pipelines without requiring external services.
2. **Tier 2 (PostgreSQL Integration Tests):** Comprehensive lifecycle and persistence verification against a live PostgreSQL 17 instance with `pgvector` to validate production-fidelity behavior that SQLite cannot accurately represent.

### Zero Silent Fallback Policy
When PostgreSQL integration tests are invoked (`pytest -m postgres`), the test suite **strictly forbids silent fallback to SQLite or mock drivers**. If PostgreSQL is unreachable, the engine dialect does not evaluate to `postgresql`, or migration parity drifts, the test suite aborts immediately with explicit diagnostic errors.

---

## 2. Infrastructure & Prerequisites

### 2.1 Containerized PostgreSQL Environment
AISOP provides a dedicated Docker Compose configuration in the project root:
- **Image:** `pgvector/pgvector:pg17`
- **Host Port:** `5433` (Container Port: `5432`)
- **Default User / Password:** `aisop` / `aisop`
- **Default Dev DB:** `aisop_dev`
- **Dedicated Test DB:** `aisop_test`

> [!IMPORTANT]
> **Port Isolation Guarantee:**  
> The host port `5433` is strictly mapped to avoid any interference or conflict with native PostgreSQL installations (which typically occupy host port `5432`). Native services on port 5432 are never queried, altered, or accessed.

### 2.2 Starting the Test Database
To launch the isolated PostgreSQL container:

```powershell
docker compose up -d postgres
```

Verify container readiness:

```powershell
docker compose exec postgres pg_isready -U aisop -d aisop_dev
```

---

## 3. Configuration & Environment Variables

| Variable | Default Value | Purpose |
| :--- | :--- | :--- |
| `TEST_DATABASE_URL` | `postgresql+psycopg://aisop:aisop@localhost:5433/aisop_test` | Connection URL for integration test suite. |

If `TEST_DATABASE_URL` is omitted, the test fixtures automatically connect to `localhost:5433/aisop_test`.

### 3.1 Automatic Test Database Provisioning
The session-level test fixture `postgres_sync_engine` checks for the existence of `aisop_test` on startup. If missing, it connects to the maintenance database `postgres` and creates `aisop_test` automatically before running tests.

### 3.2 Windows Event Loop Compatibility
On Windows platforms, Python 3.8+ defaults to `ProactorEventLoop`. `psycopg` 3 async mode requires socket polling via `SelectorEventLoop`. Both `backend/app/db/migrations/env.py` and `backend/tests/conftest.py` automatically configure:

```python
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
```

This guarantees seamless async database driver execution across Windows, Linux, and macOS environments.

---

## 4. Test Suite Architecture

The PostgreSQL integration suite is located at `backend/tests/integration/test_postgres_lifecycle.py` and is tagged with the `@pytest.mark.postgres` marker.

```mermaid
graph TD
    A[pytest -m postgres] --> B[Verify Live Connectivity & postgresql Dialect]
    B --> C[Alembic Migration: upgrade head]
    C --> D[Inspect Tables, UUID, JSON, TIMESTAMPTZ, Indices, FKs]
    D --> E[ORM CRUD & Data Type Fidelity Test]
    E --> F[Ingestion Service Deduplication & SAVEPOINT Recovery Test]
    F --> G[Foreign Key ON DELETE CASCADE Integrity Test]
    G --> H[Alembic Migration: downgrade base & re-upgrade head]
```

### 4.1 Test Cases & Verifications

| Test Function | Verification Target |
| :--- | :--- |
| `test_postgres_connectivity_and_dialect` | Validates active TCP connection to PostgreSQL, verifies dialect is `postgresql`, and queries `SELECT version()`. |
| `test_postgres_alembic_upgrade_lifecycle` | Runs `alembic upgrade head` online, inspects table existence, native PostgreSQL types (`UUID`, `JSON`, `TIMESTAMPTZ`), indices, and validates schema parity against `Base.metadata`. |
| `test_postgres_orm_crud_and_datatype_fidelity` | Inserts and reads `RawEvidence`, `NormalizedEventModel`, and `ExtractedEntityModel`. Asserts UUID preservation, JSON payload nesting fidelity, and timezone offset preservation. |
| `test_postgres_ingestion_service_deduplication` | Executes batch ingestion with `IngestionService`. Verifies idempotent deduplication, `UniqueViolation` constraint enforcement on `raw_evidence.sha256_hash`, nested `SAVEPOINT` rollback, and session recovery. |
| `test_postgres_foreign_key_cascades` | Inserts a parent `RawEvidence` with child `NormalizedEventModel` and `ExtractedEntityModel`. Deletes the parent and asserts child records are automatically cascade-deleted. |
| `test_postgres_alembic_downgrade_lifecycle` | Runs `alembic downgrade base` online, asserts complete table and revision removal, then re-applies `head` to preserve canonical schema state. |

---

## 5. Execution Guide

### 5.1 Running Only PostgreSQL Integration Tests
```powershell
.venv\Scripts\pytest -v -m postgres
```

### 5.2 Running Fast Unit Tests (Excluding PostgreSQL)
```powershell
.venv\Scripts\pytest -v -m "not postgres"
```

### 5.3 Running the Full Suite (Unit + PostgreSQL Integration)
```powershell
.venv\Scripts\pytest -v
```

---

## 6. Schema & Data Type Guarantees Verified Against PostgreSQL

1. **UUID Fields (`id`, `raw_evidence_id`, `event_id`):**  
   Stored natively as PostgreSQL `uuid` type (16 bytes). Python `uuid.UUID` objects roundtrip without string conversion or loss of identity.
2. **Raw and Normalized Payloads (`raw_payload`, `normalized_payload`, `attributes`):**  
   Stored as native PostgreSQL `json` type. Nested structures, boolean primitives, numerical values, and arrays maintain strict type integrity.
3. **Timestamps (`ingested_at`, `event_timestamp`):**  
   Stored as `TIMESTAMP WITH TIME ZONE` (`TIMESTAMPTZ`). Non-UTC inputs (e.g. `+05:30`) preserve the exact epoch instant and convert losslessly to UTC.
4. **Hashes (`sha256_hash`):**  
   Stored as `VARCHAR(64)`. PostgreSQL enforces character length limits strictly (rejecting strings $>64$ characters with `StringDataRightTruncation`).
5. **Deduplication via SAVEPOINT Rollback:**  
   When concurrent or duplicate ingestion attempts trigger a `UniqueViolation` on `ix_raw_evidence_sha256_hash`, PostgreSQL rolls back to the nested `SAVEPOINT`, leaving the outer transaction healthy and allowing subsequent events to commit.
