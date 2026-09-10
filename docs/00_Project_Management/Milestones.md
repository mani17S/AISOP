# AISOP Project Milestones

## Phase 1: Ingestion Pipeline & Canonical Data Model Hardening

| Milestone | Title | Status | Checkpoint / Baseline | Key Deliverables |
|:---|:---|:---:|:---|:---|
| **P1-H1** | Git Safety Checkpoint | COMPLETE | `63bee0b` | Clean local git baseline establishing Phase 0 architecture & initial ingestion pipeline. |
| **P1-H2** | Ingestion Deduplication | COMPLETE | `e1af0c9` | Option A contract: skips duplicates, no duplicate child rows, nested savepoint race handling. |
| **P1-H3** | Batch Query Optimization | COMPLETE | `e1af0c9` | Replaced $O(N)$ sequential lookups with batched chunked existence queries (`IN (...)`) and in-memory classification map. |
| **P1-H4** | Ingestion Security & Bounds Hardening | COMPLETE | Working Tree | Enforced `MAX_BATCH_SIZE=2000`, `MAX_EVENT_PAYLOAD_BYTES=65536`, `source_type`/`identifier` bounds, per-event atomic savepoint isolation, safe sample serialization. |
| **P1-H5** | SOC Investigation Query API Expansion | PENDING | — | Entity lookups (IP, domain, hash, user, host), time-range filtering, and IOC cross-correlation queries. |
| **P1-H6** | Structured Logging & Observability | PENDING | — | Loguru structured JSON logging, correlation IDs, and ingest telemetry metrics. |
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
