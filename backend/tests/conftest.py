"""
AISOP Pytest Configuration & Test Fixtures.

Implements Database Testing Strategy (Option A):
Fast, isolated in-memory SQLite database session for unit and integration testing.
Requires zero external database daemons to run test suites.
"""

from __future__ import annotations

from typing import Any, AsyncGenerator
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence  # noqa: F401


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
    transaction = connection.begin()
    session_factory = sessionmaker(bind=connection)
    sync_session = session_factory()
    async_adapter = AsyncSessionAdapter(sync_session)

    try:
        yield async_adapter
    finally:
        sync_session.close()
        transaction.rollback()
        connection.close()
