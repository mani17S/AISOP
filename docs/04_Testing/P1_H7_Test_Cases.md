# P1-H7 Test Cases: Database Schema Migration Lifecycle

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P1H7-TC |
| **Milestone** | P1-H7: Database Schema Migration Lifecycle |
| **Checkpoint Commit** | `164a65e` (`164a65e692f35371a79d66f11a1a0285b03241d1`) |
| **Governing SRS / ADR** | Database Persistence Architecture, ADR-003: Storage & Ingestion Architecture |
| **Component Scope** | Alembic Configuration (`alembic.ini`, `migrations/env.py`, `versions/20260917_0001_initial_evidence_schema.py`) |
| **Last Updated** | 2026-09-23 |

---

## 1. Purpose & Scope

This document specifies the test cases for **Milestone P1-H7**. Milestone P1-H7 established the formal database schema migration framework using Alembic and SQLAlchemy metadata inspection.

Prior to P1-H7, database schemas were created imperatively via `Base.metadata.create_all()`. P1-H7 established:
1. Version-controlled DDL revisions tracking schema evolution.
2. Offline SQL script generation (`--sql`) enabling DBA audit before execution.
3. Bidirectional lifecycle support (forward upgrades and backward downgrades).
4. Schema parity verification guaranteeing zero drift between declarative Python models and Alembic revision DDL.
5. Inverted index creation (`ix_raw_evidence_sha256_hash`, `ix_normalized_events_type_time`, `ix_extracted_entities_type_value`).

---

## 2. Test Case Catalogue

### TC-P1H7-001 — Alembic Configuration & Revision Discovery
* **Test ID:** `TC-P1H7-001`
* **Module:** `backend/tests/unit/test_migrations.py`
* **Source Test:** `test_alembic_config_discovery`
* **Objective:** Verify Alembic discovers configuration files, script directory, and identifies `0001_initial_evidence_schema` as the current head revision.
* **Preconditions:** `alembic.ini` present in root and backend directory; version scripts located in `backend/app/db/migrations/versions`.
* **Input:** `ScriptDirectory.from_config(alembic_config)`.
* **Expected Result:** Single head revision detected matching `"0001_initial_evidence_schema"`.
* **Classification:** Test Specification (Reconstructed from commit `164a65e`).

---

### TC-P1H7-002 — Target Metadata Table & Column Invariants
* **Test ID:** `TC-P1H7-002`
* **Module:** `backend/tests/unit/test_migrations.py`
* **Source Test:** `test_target_metadata_tables`
* **Objective:** Verify `Base.metadata` declares all required Phase 1 tables and columns with correct constraints.
* **Preconditions:** Models imported (`RawEvidence`, `NormalizedEventModel`, `ExtractedEntityModel`).
* **Input:** Inspect `Base.metadata.tables.keys()`.
* **Expected Result:**
  * Tables present: `raw_evidence`, `normalized_events`, `extracted_entities`.
  * `raw_evidence` columns: `id`, `source_type`, `source_identifier`, `sha256_hash`, `raw_payload`, `ingested_at`.
  * `normalized_events` columns: `id`, `raw_evidence_id`, `event_id`, `event_type`, `event_timestamp`, `provider`, `action`, `outcome`, `severity`, `normalized_payload`.
  * `extracted_entities` columns: `id`, `event_id`, `raw_evidence_id`, `entity_type`, `entity_value`, `role`, `attributes`.
* **Classification:** Test Specification (Reconstructed from commit `164a65e`).

---

### TC-P1H7-003 — Offline SQL Upgrade Generation
* **Test ID:** `TC-P1H7-003`
* **Module:** `backend/tests/unit/test_migrations.py`
* **Source Test:** `test_offline_sql_upgrade`
* **Objective:** Verify `alembic upgrade head --sql` produces valid SQL DDL without requiring an active database connection.
* **Preconditions:** Valid `alembic.ini` and revision file.
* **Input:** `command.upgrade(alembic_config, "head", sql=True)`.
* **Expected Result:** Generated SQL stdout contains:
  * `CREATE TABLE raw_evidence`
  * `CREATE TABLE normalized_events`
  * `CREATE TABLE extracted_entities`
  * `CREATE TABLE alembic_version`
  * Indexes: `ix_raw_evidence_sha256_hash`, `ix_normalized_events_type_time`, `ix_extracted_entities_type_value`
  * Final `COMMIT;`
* **Classification:** Test Specification (Reconstructed from commit `164a65e`).

---

### TC-P1H7-004 — Offline SQL Downgrade Generation
* **Test ID:** `TC-P1H7-004`
* **Module:** `backend/tests/unit/test_migrations.py`
* **Source Test:** `test_offline_sql_downgrade`
* **Objective:** Verify `alembic downgrade base --sql` produces valid SQL teardown DDL in reverse dependency order.
* **Preconditions:** Revision `0001_initial_evidence_schema` registered.
* **Input:** `command.downgrade(alembic_config, "0001_initial_evidence_schema:base", sql=True)`.
* **Expected Result:** Generated SQL stdout contains drop statements in reverse foreign key order:
  1. `DROP TABLE extracted_entities;`
  2. `DROP TABLE normalized_events;`
  3. `DROP TABLE raw_evidence;`
  4. `DELETE FROM alembic_version;`
* **Classification:** Test Specification (Reconstructed from commit `164a65e`).

---

### TC-P1H7-005 — Isolated Online Migration Lifecycle & Schema Parity
* **Test ID:** `TC-P1H7-005`
* **Module:** `backend/tests/unit/test_migrations.py`
* **Source Test:** `test_isolated_migration_lifecycle`
* **Objective:** Execute full forward and backward migration against an isolated database engine, verifying foreign keys and zero drift against `Base.metadata`.
* **Preconditions:** Isolated SQLite in-memory engine.
* **Input:**
  1. `command.upgrade(alembic_config, "head")`
  2. Schema inspection and `compare_metadata(ctx, Base.metadata)`
  3. `command.downgrade(alembic_config, "base")`
* **Expected Result:**
  * All 4 tables created after upgrade.
  * Foreign key constraints properly established on `normalized_events` -> `raw_evidence`, and `extracted_entities` -> `normalized_events` / `raw_evidence`.
  * `compare_metadata` returns `[]` (zero schema divergence).
  * All tables cleanly dropped after downgrade.
* **Classification:** Test Specification (Reconstructed from commit `164a65e`).
