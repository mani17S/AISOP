"""
AISOP Pytest Configuration & Test Fixtures.

Implements Database Testing Strategy (Option A):
Fast, isolated in-memory SQLite database session for unit and integration testing.
Requires zero external database daemons to run test suites.
"""

from __future__ import annotations

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator

import pytest
from alembic.config import Config
from app.db.base import Base
from app.models.evidence import (  # noqa: F401
    ExtractedEntityModel,
    NormalizedEventModel,
    RawEvidence,
)
from app.models.knowledge import KnowledgeEmbedding  # noqa: F401
from sqlalchemy import create_engine
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

DEFAULT_TEST_POSTGRES_URL = "postgresql+psycopg://aisop:aisop@localhost:5433/aisop_test"


def get_test_postgres_url() -> str:
    """Retrieve the PostgreSQL test database URL from environment or default."""
    return os.getenv("TEST_DATABASE_URL", DEFAULT_TEST_POSTGRES_URL)


def ensure_test_database_exists(db_url: str) -> None:
    """Ensure the target PostgreSQL test database exists prior to running tests."""
    import psycopg
    from sqlalchemy.engine import make_url

    url = make_url(db_url)
    target_db = url.database
    admin_conn_str = (
        f"postgresql://{url.username}:{url.password}@{url.host}:{url.port}/postgres"
    )
    try:
        with psycopg.connect(admin_conn_str, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM pg_database WHERE datname = %s", (target_db,)
                )
                if not cur.fetchone():
                    cur.execute(f'CREATE DATABASE "{target_db}"')
    except Exception as exc:
        raise RuntimeError(
            f"Failed to ensure test database '{target_db}' on {url.host}:{url.port}: {exc}\n"
            "Ensure the PostgreSQL test container is running (e.g. 'docker compose up -d postgres')."
        ) from exc


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


@pytest.fixture
async def postgres_session(
    postgres_engine: AsyncEngine,
    postgres_sync_engine,
) -> AsyncGenerator[AsyncSession, None]:
    """
    Function-scoped AsyncSession connected to live PostgreSQL.
    Cleans up all table data after each test while preserving schema.
    """
    session_factory = async_sessionmaker(
        bind=postgres_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
            # Clean up all table rows between test runs synchronously in reverse dependency order
            with postgres_sync_engine.begin() as conn:
                for table in reversed(Base.metadata.sorted_tables):
                    conn.execute(table.delete())


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
