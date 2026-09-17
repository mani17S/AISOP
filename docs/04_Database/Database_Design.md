# AISOP Database Design & Schema Architecture

| Field | Value |
|---|---|
| **Subsystem** | Data Layer & Persistence |
| **Engine** | PostgreSQL 17 (+ pgvector extension support) |
| **ORM** | SQLAlchemy 2.0 (Modern Declarative Mapping) |
| **Migration Manager** | Alembic 1.20+ |
| **Status** | ACTIVE |

---

## 1. Architectural Philosophy: Evidence-First Principle

The AISOP database is designed around strict digital forensics and SOC investigation principles:
1. **Raw Evidence Immutability:** Raw log records are stored cryptographically unadulterated with SHA-256 integrity hashes.
2. **Canonical Normalization:** Telemetry from disparate security sources (Sysmon, Windows Event Logs, Auth Logs) is parsed into uniform security events with standard severity, outcome, and timestamp semantics.
3. **Atomic Entity Extraction:** Extracted IOCs (IPs, Hosts, Users, Hashes, Domains) are stored as distinct relational records linked to both normalized events and raw evidence to enable ultra-fast entity correlation.

---

## 2. Entity-Relationship & Schema Definition

### 2.1 Table: `raw_evidence`
Immutable repository of ingested telemetry.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `UUID` | Primary Key, Index | Unique record identifier (UUID v4) |
| `source_type` | `VARCHAR(50)` | NOT NULL, Index | Log source type (e.g., `sysmon`, `windows_event`) |
| `source_identifier`| `VARCHAR(255)` | NOT NULL, Index | Agent hostname, IP, or collector identifier |
| `sha256_hash` | `VARCHAR(64)` | NOT NULL, UNIQUE, Index | Cryptographic SHA-256 hash of payload |
| `raw_payload` | `JSON` | NOT NULL | Complete, unadulterated raw log payload |
| `ingested_at` | `TIMESTAMPTZ` | NOT NULL | UTC ingestion receipt timestamp |

**Indexes:**
* `ix_raw_evidence_id`: Primary key lookup.
* `ix_raw_evidence_source_type`: Filter by log vendor/collector.
* `ix_raw_evidence_source_identifier`: Filter by originating host or sensor.
* `ix_raw_evidence_sha256_hash`: Unique cryptographic deduplication index.

---

### 2.2 Table: `normalized_events`
Structured, vendor-neutral representation of observed security activity.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `UUID` | Primary Key, Index | Unique event identifier (UUID v4) |
| `raw_evidence_id` | `UUID` | NOT NULL, FK, Index | Reference to originating `raw_evidence.id` (CASCADE) |
| `event_id` | `VARCHAR(50)` | NOT NULL, Index | Provider event ID (e.g. Sysmon `1`, `3`, `7`) |
| `event_type` | `VARCHAR(100)`| NOT NULL, Index | Canonical event type (e.g. `process_create`) |
| `event_timestamp` | `TIMESTAMPTZ` | NOT NULL, Index | Observed time from log source (UTC) |
| `provider` | `VARCHAR(100)`| NOT NULL, DEFAULT `'unknown'` | Telemetry vendor/source name |
| `action` | `VARCHAR(50)` | NOT NULL, DEFAULT `'observed'`| Security action performed |
| `outcome` | `VARCHAR(50)` | NOT NULL, DEFAULT `'success'` | Outcome (`success`, `failure`, `blocked`) |
| `severity` | `VARCHAR(50)` | NOT NULL, DEFAULT `'informational'` | SOC triage severity |
| `normalized_payload`| `JSON` | NOT NULL | Normalized schema dictionary |

**Foreign Keys:**
* `fk_normalized_events_raw_evidence_id_raw_evidence`: `raw_evidence_id` -> `raw_evidence.id` (`ON DELETE CASCADE`)

**Indexes:**
* `ix_normalized_events_id`: Primary key index.
* `ix_normalized_events_raw_evidence_id`: Child event lookup by parent evidence.
* `ix_normalized_events_event_id`: Filtering by provider event ID.
* `ix_normalized_events_event_type`: Filtering by canonical event type.
* `ix_normalized_events_event_timestamp`: Time bounding filter.
* `ix_normalized_events_type_time`: Composite `(event_type, event_timestamp)` for timeline filtering.
* `ix_normalized_events_time_id`: Composite `(event_timestamp DESC, id DESC)` for deterministic pagination.

---

### 2.3 Table: `extracted_entities`
Atomic entities and IOCs extracted from events for rapid graph and correlation querying.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `UUID` | Primary Key, Index | Unique entity link identifier (UUID v4) |
| `event_id` | `UUID` | NOT NULL, FK, Index | Reference to `normalized_events.id` (CASCADE) |
| `raw_evidence_id` | `UUID` | NOT NULL, FK, Index | Direct provenance to `raw_evidence.id` (CASCADE) |
| `entity_type` | `VARCHAR(50)` | NOT NULL, Index | Entity category (`ip`, `host`, `user`, `hash`, etc.) |
| `entity_value` | `VARCHAR(500)`| NOT NULL, Index | Extracted indicator value |
| `role` | `VARCHAR(50)` | NOT NULL, DEFAULT `'observed'`| Entity role in event (`source`, `destination`, etc.) |
| `attributes` | `JSON` | NOT NULL, DEFAULT `'{}'` | Additional contextual properties |

**Foreign Keys:**
* `fk_extracted_entities_event_id_normalized_events`: `event_id` -> `normalized_events.id` (`ON DELETE CASCADE`)
* `fk_extracted_entities_raw_evidence_id_raw_evidence`: `raw_evidence_id` -> `raw_evidence.id` (`ON DELETE CASCADE`)

**Indexes:**
* `ix_extracted_entities_id`: Primary key index.
* `ix_extracted_entities_event_id`: Extracted entities for a given event.
* `ix_extracted_entities_raw_evidence_id`: Extracted entities for given raw evidence.
* `ix_extracted_entities_entity_type`: Filter by entity type.
* `ix_extracted_entities_entity_value`: Filter by indicator value.
* `ix_extracted_entities_type_value`: Composite `(entity_type, entity_value)` for IOC correlation lookups.

---

## 3. Schema Versioning & Migrations

All tables are tracked in the database via the `alembic_version` table. Revisions are versioned in `backend/app/db/migrations/versions/`.
* Initial Revision: `0001_initial_evidence_schema`
* Execution: Transactional DDL (`BEGIN ... COMMIT`)
