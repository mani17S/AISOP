"""
AISOP Database Engine & Session Management.

Provides asynchronous database connections via SQLAlchemy 2.0.
Default target: PostgreSQL via psycopg driver.
Testing support: Overridable session dependency for fast in-memory SQLite unit testing (Option A).
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import inspect
from typing import Any, AsyncGenerator, Callable

from fastapi import Request
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None



def get_engine() -> AsyncEngine:
    """Retrieve or initialize the singleton AsyncEngine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        engine_kwargs: dict[str, Any] = {"echo": settings.DATABASE_ECHO, "future": True}
        if not settings.DATABASE_URL.startswith("sqlite"):
            # A request can hold a route session while authentication and role checks open others, so the pool must
            # be larger than the expected concurrency. pre_ping replaces connections that died (for example after a
            # database restart) instead of failing the first request that picks one up.
            engine_kwargs.update(
                pool_size=settings.DB_POOL_SIZE,
                max_overflow=settings.DB_MAX_OVERFLOW,
                pool_timeout=settings.DB_POOL_TIMEOUT_SECONDS,
                pool_pre_ping=True,
            )
            # Fail a stalled connection attempt in seconds instead of minutes.
            engine_kwargs["connect_args"] = {"connect_timeout": 10}
        _engine = create_async_engine(settings.DATABASE_URL, **engine_kwargs)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Retrieve or initialize the sessionmaker."""
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


def _adapt_session_override_to_factory(override_fn: Any) -> Any:
    """
    Adapt a session generator or session provider into an isolated session factory.
    Enables tests overriding get_db_session to transparently supply sessions to isolated_session.
    """
    if not callable(override_fn):
        return lambda: override_fn

    if inspect.isasyncgenfunction(override_fn):
        def _factory() -> Any:
            @asynccontextmanager
            async def _cm() -> AsyncGenerator[Any, None]:
                gen = override_fn()
                val = await gen.__anext__()
                try:
                    yield val
                    try:
                        await gen.__anext__()
                    except (StopAsyncIteration, GeneratorExit):
                        pass
                except BaseException as exc:
                    try:
                        await gen.athrow(exc)
                    except (StopAsyncIteration, GeneratorExit):
                        pass
                    raise
            return _cm()
        return _factory

    def _adapted_factory() -> Any:
        res = override_fn()
        if inspect.isasyncgen(res):
            @asynccontextmanager
            async def _cm() -> AsyncGenerator[Any, None]:
                val = await res.__anext__()
                try:
                    yield val
                    try:
                        await res.__anext__()
                    except (StopAsyncIteration, GeneratorExit):
                        pass
                except BaseException as exc:
                    try:
                        await res.athrow(exc)
                    except (StopAsyncIteration, GeneratorExit):
                        pass
                    raise
            return _cm()
        return res
    return _adapted_factory


def get_db_session_factory(request: Request = None) -> Any:
    """
    FastAPI dependency for accessing the database session factory.
    If running within an overridden test application where get_db_session is overridden,
    transparently adapts the override into an isolated factory.
    """
    if request is not None and hasattr(request, "app"):
        if get_db_session_factory in request.app.dependency_overrides:
            override = request.app.dependency_overrides[get_db_session_factory]
            return override() if callable(override) else override
        if get_db_session in request.app.dependency_overrides:
            override = request.app.dependency_overrides[get_db_session]
            return _adapt_session_override_to_factory(override)
    return get_session_factory()


@asynccontextmanager
async def isolated_session(
    session_factory: Any | None = None,
    fallback_session: Any | None = None,
) -> AsyncGenerator[Any, None]:
    """
    Context manager yielding an isolated session.
    If session_factory is provided, instantiates a fresh session, commits on clean exit,
    rolls back on exception or cancellation, and guarantees session closure.
    If fallback_session is provided (e.g. legacy test adapter), manages commit/rollback on it.
    """
    if session_factory is not None:
        candidate = session_factory()
        if hasattr(candidate, "__aenter__"):
            async with candidate as session:
                try:
                    yield session
                    await session.commit()
                except BaseException:
                    await session.rollback()
                    raise
        else:
            try:
                yield candidate
                if hasattr(candidate, "commit"):
                    if asyncio.iscoroutinefunction(candidate.commit):
                        await candidate.commit()
                    else:
                        candidate.commit()
            except BaseException:
                if hasattr(candidate, "rollback"):
                    if asyncio.iscoroutinefunction(candidate.rollback):
                        await candidate.rollback()
                    else:
                        candidate.rollback()
                raise
            finally:
                if hasattr(candidate, "close"):
                    if asyncio.iscoroutinefunction(candidate.close):
                        await candidate.close()
                    else:
                        candidate.close()
    elif fallback_session is not None:
        try:
            yield fallback_session
            if hasattr(fallback_session, "commit"):
                if asyncio.iscoroutinefunction(fallback_session.commit):
                    await fallback_session.commit()
                else:
                    fallback_session.commit()
        except BaseException:
            if hasattr(fallback_session, "rollback"):
                if asyncio.iscoroutinefunction(fallback_session.rollback):
                    await fallback_session.rollback()
                else:
                    fallback_session.rollback()
            raise
    else:
        factory = get_session_factory()
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise



async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency yielding an async database session.
    Commits on clean exit, rolls back on exception.
    """
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
