# AISOP Database Migration & Schema Lifecycle Strategy

| Field | Value |
|---|---|
| **Subsystem** | Data Layer & Persistence |
| **Tooling** | Alembic 1.20+ with SQLAlchemy 2.0 Async |
| **Primary Target** | PostgreSQL 17 + pgvector (Containerized Docker / Native) |
| **Test Support** | SQLite in-memory isolated session testing (Option A) |
| **Status** | ACTIVE |

---

## 1. Overview & Objectives

AISOP enforces a reproducible, version-controlled database schema lifecycle managed exclusively through **Alembic**. Manual, uncontrolled, or unversioned schema modifications (`Base.metadata.create_all()` in production environments) are strictly forbidden.

All changes to relational tables, foreign key constraints, indexes, composite indexes, and database extensions must be codified in deterministic, reviewable migration revisions.

---

## 2. Migration Architecture

### 2.1 File & Directory Layout

```
AISOP/
├── alembic.ini                              # Project root Alembic configuration
├── backend/
│   ├── alembic.ini                          # Backend directory Alembic configuration
│   └── app/
│       └── db/
│           ├── base.py                      # SQLAlchemy DeclarativeBase & UUID mixins
│           ├── init_db.py                   # Programmatic migration invocation helper
│           ├── session.py                   # AsyncEngine and AsyncSession lifecycle
│           └── migrations/
│               ├── env.py                   # Async Alembic execution environment
│               ├── script.py.mako           # Revision template
│               ├── README                   # Migration documentation
│               └── versions/
│                   ├── __init__.py
│                   └── 20260917_0001_initial_evidence_schema.py
```

### 2.2 Async Engine Integration

`env.py` dynamically sources the active database connection string from `app.core.config.get_settings().DATABASE_URL` unless overridden via the CLI (`-x url=...`) or `alembic.ini`.

* **Online Migrations:** Instantiates an `AsyncEngine` via `create_async_engine` using `NullPool`, running migrations synchronously on the connection via `connection.run_sync(do_run_migrations)`.
* **Offline Migrations:** Emits clean, transactional SQL statements directly to standard output without establishing a live database connection (`alembic upgrade head --sql`).
* **Test Isolation:** Supports injected synchronous or asynchronous connections via `config.attributes["connection"]`, enabling in-memory test fixtures to execute migration cycles against isolated databases.

---

## 3. Standard Migration Commands

All commands can be executed either from the project root or from within the `backend/` directory:

| Task | Command (Root) | Command (Backend Dir) |
|---|---|---|
| **Upgrade to Head** | `python -m alembic upgrade head` | `python -m alembic upgrade head` |
| **Downgrade One Step** | `python -m alembic downgrade -1` | `python -m alembic downgrade -1` |
| **Downgrade to Base** | `python -m alembic downgrade base` | `python -m alembic downgrade base` |
| **View Current Revision** | `python -m alembic current` | `python -m alembic current` |
| **View History** | `python -m alembic history -v` | `python -m alembic history -v` |
| **Dry-Run SQL (Offline)** | `python -m alembic upgrade head --sql` | `python -m alembic upgrade head --sql` |
| **Dry-Run Downgrade SQL** | `python -m alembic downgrade <rev>:base --sql` | `python -m alembic downgrade <rev>:base --sql` |
| **Verify Schema Parity** | `python -m alembic check` | `python -m alembic check` |
| **Generate New Revision** | `python -m alembic revision --autogenerate -m "<msg>"` | `python -m alembic revision --autogenerate -m "<msg>"` |

---

## 4. PostgreSQL & pgvector Extension Policy

* **Current Schema Scope (P1-H7):**
  * The current models (`raw_evidence`, `normalized_events`, `extracted_entities`) are strictly relational and document-based (`JSON`, `Uuid`, `DateTime`, `String`).
  * No vector columns (`vector(N)`) exist in the current schema. Therefore, `CREATE EXTENSION IF NOT EXISTS vector;` is **not executed** in the initial migration (`0001_initial_evidence_schema`).
* **Future Vector Scope (ADR-002 / Phase 2):**
  * When vector embedding tables (e.g. `knowledge_embeddings`, MITRE ATT&CK vectors) are added, the corresponding migration revision will execute:
    ```python
    if op.get_bind().dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector;")
    ```
  * This guarantees standard relational tests and SQLite fallbacks remain functional without requiring PostgreSQL pgvector binaries until vector tables are introduced.

---

## 5. Production & Development Safety Rules

> [!WARNING]
> **Destructive Downgrade Risk:** Running downgrade operations (`alembic downgrade -1` or `alembic downgrade base`) drops AISOP tables and irrevocably destroys stored raw telemetry, canonical normalized events, and extracted entity data. Destructive downgrades require an independent database backup beforehand and must **never** be casually executed against shared, staging, or production environments. Always inspect the exact DDL statements beforehand using offline SQL (`python -m alembic downgrade <rev>:base --sql`).

1. **Transactional DDL:**
   * All PostgreSQL DDL executed by Alembic runs inside an explicit transaction block (`BEGIN; ... COMMIT;`). If any index or table creation fails, the entire migration rolls back atomically.
2. **Zero Startup Mutations:**
   * Application startup (`lifespan` in `app/main.py`) **never** runs `create_all()` or automated migrations. Schema upgrades must be deliberate operations executed during deployment pipelines or by operators.
3. **Reversible Downgrades & Data Loss Awareness:**
   * Every revision must provide an explicit, tested `downgrade()` implementation in reverse dependency order. Operators must recognize that schema downgrade drops schema objects and their data; application-level data migration or table export is required before executing downgrades on stateful databases.
4. **Foreign Key Integrity:**
   * Cascading deletes (`ondelete="CASCADE"`) are strictly defined on foreign keys (`normalized_events.raw_evidence_id -> raw_evidence.id`, `extracted_entities.event_id -> normalized_events.id`, `extracted_entities.raw_evidence_id -> raw_evidence.id`) to prevent orphaned security telemetry.
