# P1-H9 Test Cases: PostgreSQL 17 Integration & Persistence Lifecycle

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P1H9-TC |
| **Milestone** | P1-H9: PostgreSQL Integration Test Suite |
| **Checkpoint Commit** | `7998be8` (`7998be8dd7932b6f07432ef3c97429344a5dd590`) |
| **Governing SRS / ADR** | ADR-003: Database Persistence Architecture, Non-Functional Reliability Requirements |
| **Component Scope** | Database Integration (`tests/integration/test_postgres_lifecycle.py`), Test Fixtures (`tests/conftest.py`) |
| **Last Updated** | 2026-09-23 |

---

## 1. Purpose & Scope

This document specifies the integration test cases for **Milestone P1-H9**. Milestone P1-H9 established authoritative persistence and lifecycle testing against a live PostgreSQL 17 instance with `pgvector` on dedicated host port `5433`.

While Tier 1 tests utilize SQLite in-memory databases for fast feedback, Tier 2 integration tests enforce production fidelity:
1. **Zero Silent Fallback:** Prohibits silent driver or database fallback if PostgreSQL is unreachable.
2. **Native Data Types:** Validates 16-byte binary UUIDs, native JSON serialization, and timezone-aware timestamps (`TIMESTAMPTZ`).
3. **Database-Level Deduplication & Savepoints:** Verifies that real PostgreSQL `UniqueViolation` errors trigger nested savepoint rollback without session invalidation.
4. **Referential Integrity:** Verifies `ON DELETE CASCADE` foreign keys drop child records when parent evidence is deleted.
5. **Bidirectional Migration:** Verifies live Alembic online upgrades and downgrades against PostgreSQL.

---

## 2. Test Case Catalogue

### TC-P1H9-001 — PostgreSQL Connectivity & Dialect Assertion
* **Test ID:** `TC-P1H9-001`
* **Module:** `backend/tests/integration/test_postgres_lifecycle.py`
* **Source Test:** `test_postgres_connectivity_and_dialect`
* **Objective:** Verify active TCP connection to PostgreSQL container (port 5433) and assert dialect is strictly `postgresql`.
* **Preconditions:** PostgreSQL container running (`docker compose up -d postgres`).
* **Input:** `postgres_engine.connect()`, execute `SELECT version()`.
* **Expected Result:**
  * `conn.dialect.name == "postgresql"`.
  * Version string contains `"PostgreSQL"`.
  * Silent fallback to SQLite or mock engines is rejected.
* **Classification:** Test Specification (Corroborated by commit `7998be8`).

---

### TC-P1H9-002 — Online Alembic Migration Upgrade & Schema Parity
* **Test ID:** `TC-P1H9-002`
* **Module:** `backend/tests/integration/test_postgres_lifecycle.py`
* **Source Test:** `test_postgres_alembic_upgrade_lifecycle`
* **Objective:** Apply Alembic migrations to `head` against live PostgreSQL; inspect table existence, native column types, indices, and schema parity.
* **Preconditions:** Connected to clean `aisop_test` database.
* **Input:** `command.upgrade(postgres_alembic_config, "head")`.
* **Expected Result:**
  * Tables created: `raw_evidence`, `normalized_events`, `extracted_entities`, `alembic_version`.
  * Native types verified: `UUID` for IDs, `JSON` for payloads, `TIMESTAMP WITH TIME ZONE` for timestamps.
  * Unique index `ix_raw_evidence_sha256_hash` present.
  * Foreign key `normalized_events.raw_evidence_id` configured with `ON DELETE CASCADE`.
  * `compare_metadata(ctx, Base.metadata) == []` (zero schema drift).
* **Classification:** Test Specification (Corroborated by commit `7998be8`).

---

### TC-P1H9-003 — ORM CRUD & Native Data Type Fidelity
* **Test ID:** `TC-P1H9-003`
* **Module:** `backend/tests/integration/test_postgres_lifecycle.py`
* **Source Test:** `test_postgres_orm_crud_and_datatype_fidelity`
* **Objective:** Verify persistence and retrieval fidelity for native PostgreSQL UUIDs, nested JSON structures, and TIMESTAMPTZ epoch instants across non-UTC offsets.
* **Preconditions:** Database upgraded to `head`.
* **Input:** Insert `RawEvidence`, `NormalizedEventModel`, `ExtractedEntityModel` with +05:30 timestamp and nested dictionary payload.
* **Expected Result:**
  * Primary keys retrieved as native `uuid.UUID` instances.
  * Nested dictionary payloads round-trip with exact key/value and array preservation.
  * Timestamp equality preserved across timezone conversions (`astimezone(timezone.utc)` matches exact epoch instant).
* **Classification:** Test Specification (Corroborated by commit `7998be8`).

---

### TC-P1H9-004 — Ingestion Deduplication & PostgreSQL Savepoint Recovery
* **Test ID:** `TC-P1H9-004`
* **Module:** `backend/tests/integration/test_postgres_lifecycle.py`
* **Source Test:** `test_postgres_ingestion_service_deduplication`
* **Objective:** Validate batch deduplication, direct PostgreSQL `UniqueViolation` constraint handling, nested `SAVEPOINT` rollback, and session recovery.
* **Preconditions:** Empty evidence tables in `aisop_test`.
* **Input:**
  1. Ingest batch with 1 event.
  2. Ingest duplicate batch with same event.
  3. Force concurrent collision triggering `psycopg.errors.UniqueViolation` within `async with session.begin_nested()`.
  4. Insert valid event following collision rollback.
  5. Ingest intra-batch duplicate `[EventA, EventA, EventB]`.
* **Expected Result:**
  * Duplicate batch yields `total_skipped_duplicates == 1`.
  * Constraint collision raises `IntegrityError` originating from `psycopg.errors.UniqueViolation` on `ix_raw_evidence_sha256_hash`.
  * Savepoint rollback recovers session; subsequent record commits successfully.
  * Intra-batch duplicate correctly deduplicates (`total_normalized == 2`, `total_skipped_duplicates == 1`).
* **Classification:** Test Specification (Corroborated by commit `7998be8`).

---

### TC-P1H9-005 — PostgreSQL Foreign Key ON DELETE CASCADE
* **Test ID:** `TC-P1H9-005`
* **Module:** `backend/tests/integration/test_postgres_lifecycle.py`
* **Source Test:** `test_postgres_foreign_key_cascades`
* **Objective:** Verify that deleting a parent `RawEvidence` record automatically cascade-deletes linked `NormalizedEventModel` and `ExtractedEntityModel` records at the database level.
* **Preconditions:** Parent and child records persisted in PostgreSQL.
* **Input:** `DELETE FROM raw_evidence WHERE id = :evidence_id`.
* **Expected Result:**
  * Normalized event count drops to 0.
  * Extracted entity count drops to 0.
  * Database referential integrity maintained with zero orphaned child rows.
* **Classification:** Test Specification (Corroborated by commit `7998be8`).

---

### TC-P1H9-006 — Online Alembic Downgrade & Re-Upgrade Lifecycle
* **Test ID:** `TC-P1H9-006`
* **Module:** `backend/tests/integration/test_postgres_lifecycle.py`
* **Source Test:** `test_postgres_alembic_downgrade_lifecycle`
* **Objective:** Execute online downgrade to `base`, verify total teardown of application tables and version records, and re-upgrade to `head`.
* **Preconditions:** Database at `head`.
* **Input:**
  1. `command.downgrade(postgres_alembic_config, "base")`.
  2. Table inspection.
  3. `command.upgrade(postgres_alembic_config, "head")`.
* **Expected Result:**
  * Post-downgrade: `raw_evidence`, `normalized_events`, `extracted_entities` absent from schema; `alembic_version` contains 0 rows.
  * Post-reupgrade: All tables restored cleanly to canonical state.
* **Classification:** Test Specification (Corroborated by commit `7998be8`).
