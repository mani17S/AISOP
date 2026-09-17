"""
Alembic Environment Configuration for AISOP.

Supports asynchronous migrations using SQLAlchemy 2.0 and psycopg driver.
Loads database URL dynamically from application settings.
"""

from __future__ import annotations

import asyncio
import sys
from logging.config import fileConfig
from pathlib import Path
from typing import Any

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

# Ensure backend directory is in sys.path for application module resolution
backend_dir = Path(__file__).resolve().parents[3]
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

# Ensure all models in app.models are registered on Base.metadata
import app.models  # noqa: F401
from app.core.config import get_settings
from app.db.base import Base
from app.models.evidence import (  # noqa: F401
    ExtractedEntityModel,
    NormalizedEventModel,
    RawEvidence,
)

# Alembic Config object, which provides access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except Exception:
        pass

# Target metadata for autogenerate support
target_metadata = Base.metadata


def get_database_url() -> str:
    """Retrieve database URL from alembic config override or application settings."""
    url = config.get_main_option("sqlalchemy.url")
    if url and url.strip():
        return url
    return get_settings().DATABASE_URL


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    Configures the context with just a URL and not an Engine, though an Engine
    is acceptable here as well. By skipping the Engine creation we don't even
    need a DBAPI to be available. Calls to context.execute() here emit the
    given string to the script output.
    """
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Execute migrations synchronously within a connection context."""
    is_sqlite = connection.dialect.name == "sqlite"
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=is_sqlite,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an AsyncEngine and run migrations online."""
    # Check if an external connection was injected into config attributes (e.g. testing)
    injected_conn = config.attributes.get("connection", None)
    if injected_conn is not None:
        if hasattr(injected_conn, "run_sync"):
            await injected_conn.run_sync(do_run_migrations)
        else:
            do_run_migrations(injected_conn)
        return

    url = get_database_url()
    connectable = create_async_engine(
        url,
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode using asyncio."""
    # Check if a synchronous connection was injected directly
    injected_conn = config.attributes.get("connection", None)
    if injected_conn is not None and not hasattr(injected_conn, "run_sync"):
        do_run_migrations(injected_conn)
        return

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
