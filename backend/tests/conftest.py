"""
AISOP Pytest Configuration & Test Fixtures.

Implements Database Testing Strategy (Option A):
Fast, isolated in-memory SQLite database session for unit and integration testing.
Requires zero external database daemons to run test suites.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator, Mapping

import pytest
from alembic.config import Config
from app.db.base import Base
import app.models  # noqa: F401

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

# Psycopg async on Windows requires SelectorEventLoop instead of ProactorEventLoop
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ── Fail-Closed PostgreSQL Test Database Guard (Gate B.2) ───────────────────

# Protected databases that must NEVER be targeted by tests or destructive fixtures
PROTECTED_DATABASE_NAMES: frozenset[str] = frozenset({
    "aisop",
    "aisop_test",
    "aisop_dev",
    "aisop_prod",
    "postgres",
})

# Anchored regex allowlist: Dedicated disposable test database names only
DISPOSABLE_DB_NAME_PATTERN = re.compile(r"^aisop_[a-z0-9_]+_disposable$")

# Permitted test database schemes
ALLOWED_SCHEMES: frozenset[str] = frozenset({
    "postgresql",
    "postgresql+psycopg",
    "postgresql+asyncpg",
})

# Permitted test hosts: Local test instances only
ALLOWED_TEST_HOSTS: frozenset[str] = frozenset({
    "localhost",
    "127.0.0.1",
    "::1",
})


def validate_test_database_target(
    db_url_raw: str | None = None,
    allow_destructive_raw: str | None = None,
    require_destructive_opt_in: bool = True,
) -> URL:
    """
    Validate that the test database target is an explicitly configured,
    strictly disposable local PostgreSQL instance.

    Security & Safety Invariants:
    1. No silent fallbacks: TEST_DATABASE_URL must be explicitly configured.
    2. Destructive test opt-in: ALLOW_DESTRUCTIVE_POSTGRES_TESTS=1 is required.
    3. URL parsing: Uses SQLAlchemy's make_url (rejects malformed URLs).
    4. Protected target rejection: aisop_test, aisop_dev, aisop_prod, aisop, and postgres are blocked.
    5. Disposable pattern match: Database name must match '^aisop_[a-z0-9_]+_disposable$'.
    6. Localhost boundary: Rejects non-local hosts to prevent remote testing.
    7. Credential sanitization: Raised exceptions render URLs with passwords hidden.

    Pure function: Does NOT connect to PostgreSQL or create database engines.
    """
    if db_url_raw is None:
        db_url_raw = os.getenv("TEST_DATABASE_URL")

    if not db_url_raw or not db_url_raw.strip():
        raise RuntimeError(
            "FAIL-CLOSED: TEST_DATABASE_URL is not set.\n"
            "Silent fallback to default or protected databases is prohibited.\n"
            "An explicit disposable test database URL must be configured, e.g.:\n"
            "  $env:TEST_DATABASE_URL = 'postgresql+psycopg://aisop:***@127.0.0.1:5433/aisop_stage7b_verify_disposable'"
        )

    # Validate destructive opt-in if required
    if require_destructive_opt_in:
        if allow_destructive_raw is None:
            allow_destructive_raw = os.getenv("ALLOW_DESTRUCTIVE_POSTGRES_TESTS")

        if allow_destructive_raw != "1":
            raise RuntimeError(
                "FAIL-CLOSED: Destructive PostgreSQL testing is not opted-in.\n"
                "To execute fixtures that create tables or delete rows, you must explicitly set:\n"
                "  $env:ALLOW_DESTRUCTIVE_POSTGRES_TESTS = '1'"
            )

    # Parse using SQLAlchemy URL parser
    try:
        url = make_url(db_url_raw.strip())
    except Exception:
        raise RuntimeError(
            "FAIL-CLOSED: Malformed TEST_DATABASE_URL could not be parsed by SQLAlchemy."
        ) from None

    # Safe sanitized URL string for error messages (passwords redacted)
    safe_rendered = url.render_as_string(hide_password=True)

    # Check scheme/driver
    if url.drivername not in ALLOWED_SCHEMES:
        raise RuntimeError(
            f"FAIL-CLOSED: Unsupported database scheme '{url.drivername}' in {safe_rendered}.\n"
            f"Permitted schemes: {sorted(ALLOWED_SCHEMES)}"
        )

    # Check host: must be local instance
    host = (url.host or "").strip().lower()
    if not host or host not in ALLOWED_TEST_HOSTS:
        raise RuntimeError(
            f"FAIL-CLOSED: Untrusted test host '{host or 'None'}' in {safe_rendered}.\n"
            f"Operational policy requires dedicated local instances on {sorted(ALLOWED_TEST_HOSTS)}."
        )

    # Check database component presence
    if not url.database or not url.database.strip():
        raise RuntimeError(
            f"FAIL-CLOSED: Missing database name in {safe_rendered}."
        )

    db_name = url.database.strip().lower()

    # Reject known protected databases
    if db_name in PROTECTED_DATABASE_NAMES:
        raise RuntimeError(
            f"FAIL-CLOSED: Refusing to target protected database '{db_name}' in {safe_rendered}.\n"
            "Tests are strictly forbidden from connecting to or mutating protected databases."
        )

    # Require anchored pattern match
    if not DISPOSABLE_DB_NAME_PATTERN.match(db_name):
        raise RuntimeError(
            f"FAIL-CLOSED: Non-disposable database name '{db_name}' in {safe_rendered}.\n"
            "Test database name must match the pattern '^aisop_[a-z0-9_]+_disposable$'."
        )

    return url


# ── Stage 7B: verified-target identity (fail closed; pure, no connection) ──────────────────────────────────
# The launcher (documented in docs/Project_Management/Stage7B_PostgreSQL_Verification_Plan.md) inspects Docker metadata and exports the
# verified identity; the tests refuse to run if any value is missing or differs from the single approved target below.
APPROVED_PG_HOST = "127.0.0.1"
APPROVED_PG_PORT = 5433
APPROVED_PG_CONTAINER = "aisop-postgres"
APPROVED_PG_IMAGE = "pgvector/pgvector:pg17"
APPROVED_PG_VOLUME = "aisop_postgres_data"
APPROVED_PG_DATABASE = "aisop_stage7b_verify_disposable"
DISPOSABLE_MARKER = f"aisop-disposable-test-target:{APPROVED_PG_DATABASE}"
_IDENTITY_ENV = {
    "AISOP_PG_VERIFIED_CONTAINER": APPROVED_PG_CONTAINER,
    "AISOP_PG_VERIFIED_IMAGE": APPROVED_PG_IMAGE,
    "AISOP_PG_VERIFIED_VOLUME": APPROVED_PG_VOLUME,
    "AISOP_PG_DISPOSABLE_MARKER": DISPOSABLE_MARKER,
}


def verify_approved_target_identity(url: URL, env: Mapping[str, str] | None = None) -> URL:
    """
    Pure function (no connection). The URL must be exactly the approved target: host 127.0.0.1, port 5433, database
    ``aisop_stage7b_verify_disposable``; and the launcher-exported identity (container, image, volume, disposable marker) must be present and
    equal to the approved values. Any missing or mismatching value fails closed. Values are never echoed (only the variable NAME).
    """
    env = os.environ if env is None else env
    if (url.host or "") != APPROVED_PG_HOST:
        raise RuntimeError(f"FAIL-CLOSED: host must be exactly {APPROVED_PG_HOST}.")
    if url.port != APPROVED_PG_PORT:
        raise RuntimeError(f"FAIL-CLOSED: port must be exactly {APPROVED_PG_PORT} (a missing port would default to 5432).")
    if (url.database or "") != APPROVED_PG_DATABASE:
        raise RuntimeError("FAIL-CLOSED: database is not the single approved disposable target.")
    for name, expected in _IDENTITY_ENV.items():
        got = env.get(name)
        if not got:
            raise RuntimeError(f"FAIL-CLOSED: {name} is not set; the launcher must export the verified identity.")
        if got != expected:
            raise RuntimeError(f"FAIL-CLOSED: {name} does not match the approved target identity.")
    return url


def assert_target_is_marked_disposable(conn_str: str) -> None:
    """
    READ-ONLY database-side check (SELECTs only; never creates or alters anything): the database must exist (no implicit creation), carry the
    disposable-target marker as its database comment, and sit at the single expected Alembic head. Raises RuntimeError otherwise.
    """
    import psycopg

    try:
        with psycopg.connect(conn_str, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("SELECT current_database(), shobj_description(d.oid, 'pg_database') FROM pg_database d WHERE d.datname = current_database()")
            name, comment = cur.fetchone()
            if name != APPROVED_PG_DATABASE or comment != DISPOSABLE_MARKER:
                raise RuntimeError("FAIL-CLOSED: the database does not carry the disposable-target marker.")
            cur.execute("SELECT to_regclass('public.alembic_version')")
            if cur.fetchone()[0] is None:
                raise RuntimeError("FAIL-CLOSED: alembic_version is missing; the schema must already be at head (tests never migrate).")
            cur.execute("SELECT version_num FROM alembic_version")
            revs = [r[0] for r in cur.fetchall()]
            if revs != ["0004_p3h2_rbac_case_scoping"]:
                raise RuntimeError("FAIL-CLOSED: the schema is not at the single expected head revision.")
    except RuntimeError:
        raise
    except Exception as exc:  # noqa: BLE001 - never leak the connection string
        raise RuntimeError(f"FAIL-CLOSED: could not verify the disposable target ({type(exc).__name__}); nothing was created.") from None


def get_test_postgres_url(require_destructive_opt_in: bool = True) -> str:
    """
    Retrieve and validate the PostgreSQL test database URL.
    Fails closed if the database target is unconfigured, protected, or non-disposable.
    """
    url = validate_test_database_target(require_destructive_opt_in=require_destructive_opt_in)
    verify_approved_target_identity(url)
    return url.render_as_string(hide_password=False)


def ensure_test_database_exists(db_url: str) -> None:
    """
    Stage 7B: despite the historical name this NEVER creates a database. It verifies, read-only, that the approved target already exists,
    carries the disposable-target marker and is at the expected migration head. A missing database is an error, not something to create.
    """
    assert_target_is_marked_disposable(make_url(db_url).render_as_string(hide_password=False).replace("+psycopg", "").replace("+asyncpg", ""))


class AsyncSessionAdapter:
    """
    Adapts a synchronous SQLite session into an async-compatible session
    for fast isolated unit and endpoint testing without external drivers.
    """

    def __init__(self, sync_session: Session) -> None:
        self._sync = sync_session

    def add(self, obj: Any) -> None:
        self._sync.add(obj)

    def add_all(self, objs: list[Any]) -> None:
        self._sync.add_all(objs)

    async def commit(self) -> None:
        self._sync.commit()

    async def rollback(self) -> None:
        self._sync.rollback()

    async def flush(self) -> None:
        self._sync.flush()

    async def refresh(self, obj: Any) -> None:
        self._sync.refresh(obj)

    async def close(self) -> None:
        self._sync.close()

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self._sync.execute(statement, *args, **kwargs)

    @asynccontextmanager
    async def begin_nested(self) -> AsyncGenerator[Any, None]:
        """Provide nested transaction (SAVEPOINT) support for concurrency testing."""
        nested = self._sync.begin_nested()
        try:
            yield nested
            nested.commit()
        except Exception:
            nested.rollback()
            raise


@pytest.fixture(scope="session")
def sqlite_engine():
    """Create in-memory SQLite engine with tables for test session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def db_session(sqlite_engine) -> AsyncGenerator[AsyncSessionAdapter, None]:
    """Provide an isolated test database session per test function."""
    connection = sqlite_engine.connect()
    session_factory = sessionmaker(bind=connection)
    sync_session = session_factory()
    async_adapter = AsyncSessionAdapter(sync_session)

    try:
        yield async_adapter
    finally:
        sync_session.close()
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())
        connection.commit()
        connection.close()


@pytest.fixture(scope="session")
def postgres_sync_engine():
    """
    Session-scoped synchronous SQLAlchemy Engine for schema inspection,
    Alembic migrations, and DDL operations against PostgreSQL.
    """
    test_url = get_test_postgres_url()
    ensure_test_database_exists(test_url)

    engine = create_engine(test_url, poolclass=NullPool)
    if engine.dialect.name != "postgresql":
        engine.dispose()
        raise RuntimeError(
            f"Expected PostgreSQL dialect, got '{engine.dialect.name}'. "
            "Silent fallback is prohibited."
        )

    yield engine

    engine.dispose()


@pytest.fixture(scope="session")
def postgres_engine(postgres_sync_engine):
    """
    Session-scoped SQLAlchemy AsyncEngine for PostgreSQL integration tests.
    Enforces that dialect is 'postgresql' and fails fast if unavailable.
    """
    test_url = get_test_postgres_url()

    engine = create_async_engine(
        test_url,
        poolclass=NullPool,
    )
    if engine.dialect.name != "postgresql":
        engine.sync_engine.dispose()
        raise RuntimeError(
            f"Expected PostgreSQL dialect, got '{engine.dialect.name}'. "
            "Silent fallback is prohibited."
        )

    yield engine

    engine.sync_engine.dispose()


class OwnedRowTracker:
    """
    Records the rows ONE session inserts and later deletes exactly those rows (by primary key), one transaction per row.
    Never truncates, never deletes rows it did not insert, never touches ``case_audit_events`` (append-only), never runs DDL.
    Rows that cannot be deleted (still referenced) are left in place and reported.
    """

    PROTECTED_TABLES = frozenset({"case_audit_events"})

    def __init__(self) -> None:
        self._owned: list[tuple[Any, Any]] = []
        self.left_ids: list[str] = []
        self.retained_append_only = 0

    def attach(self, sync_session: Any) -> None:
        from sqlalchemy import event

        event.listen(sync_session, "before_flush", self._before_flush)

    def _before_flush(self, sync_session: Any, _ctx: Any, _instances: Any) -> None:
        for obj in list(sync_session.new):
            self._owned.append((obj.__table__, obj))

    def cleanup(self, engine: Any) -> tuple[int, int]:
        """
        Delete exactly the owned rows, children before parents (foreign-key dependency order of the metadata, then reverse insertion order).
        Every statement is ``DELETE ... WHERE <primary key> = <value>`` for one tracked row; there is no other delete path and no fallback. A row
        whose identity cannot be proven (rolled back, transient, composite mismatch) or whose delete fails is LEFT IN PLACE for manual review.
        Returns (deleted, left_in_place); ``left_ids`` names what was left (table and key only, never values).
        """
        from sqlalchemy import inspect as sa_inspect

        order = {t.name: i for i, t in enumerate(Base.metadata.sorted_tables)}
        keys: list[tuple[int, int, Any, tuple[Any, ...]]] = []
        self.left_ids: list[str] = []
        self.retained_append_only = 0
        for seq, (table, obj) in enumerate(self._owned):
            try:
                ident = sa_inspect(obj).identity
            except Exception:  # noqa: BLE001
                ident = None
            if table.name in self.PROTECTED_TABLES:
                self.retained_append_only += 1
            elif not ident:
                self.left_ids.append(f"{table.name}:ownership-not-provable")
            else:
                keys.append((order.get(table.name, 0), seq, table, tuple(ident)))
        deleted = 0
        for _o, _s, table, ident in sorted(keys, key=lambda k: (-k[0], -k[1])):
            pk_cols = list(table.primary_key.columns)
            if len(pk_cols) != len(ident):
                self.left_ids.append(f"{table.name}:composite-key-mismatch")
                continue
            stmt = table.delete()
            for col, val in zip(pk_cols, ident):
                stmt = stmt.where(col == val)
            try:
                with engine.begin() as conn:
                    result = conn.execute(stmt)
                deleted += result.rowcount or 0
            except Exception as exc:  # noqa: BLE001 - reported, never widened
                self.left_ids.append(f"{table.name}:{type(exc).__name__}")
        return deleted, len(self.left_ids)


@pytest.fixture
async def postgres_session(
    postgres_engine: AsyncEngine,
    postgres_sync_engine,
) -> AsyncGenerator[AsyncSession, None]:
    """
    Function-scoped AsyncSession connected to live PostgreSQL.

    Stage 7B cleanup contract: ONLY the rows this session itself inserted are removed, identified by primary key (every row is created with a
    fresh UUID by the test). Nothing is truncated, no table is emptied, no trigger is disabled and no DDL runs. ``case_audit_events`` is
    append-only by design (triggers block DELETE), so audit rows are never removed; a row that cannot be removed (for example a case or
    analyst still referenced by an audit row) is left in place. All leftovers carry unique ids inside the dedicated disposable database.
    """
    session_factory = async_sessionmaker(
        bind=postgres_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    tracker = OwnedRowTracker()

    async with session_factory() as session:
        tracker.attach(session.sync_session)
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
            # Defense-in-depth: re-verify the approved target before ANY delete.
            verify_approved_target_identity(validate_test_database_target(db_url_raw=str(postgres_sync_engine.url), require_destructive_opt_in=True))
            deleted, left = tracker.cleanup(postgres_sync_engine)
            if left:                                           # reported, never escalated into a wider delete
                import warnings
                warnings.warn(f"postgres_session cleanup: {deleted} owned row(s) deleted, {left} left in place for review: {sorted(set(tracker.left_ids))}")


@pytest.fixture
def postgres_alembic_config() -> Config:
    """Load alembic.ini configured with the PostgreSQL test database URL."""
    backend_dir = Path(__file__).resolve().parents[1]
    alembic_ini_path = backend_dir / "alembic.ini"
    if not alembic_ini_path.exists():
        alembic_ini_path = backend_dir.parent / "alembic.ini"
    cfg = Config(str(alembic_ini_path))
    cfg.set_main_option("sqlalchemy.url", get_test_postgres_url())
    return cfg
