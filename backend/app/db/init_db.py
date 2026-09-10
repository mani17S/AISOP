"""
AISOP Database Initialization Script.

Initializes database extensions (e.g. pgvector) and creates tables for local deployment.
"""

from __future__ import annotations

import asyncio
from sqlalchemy import text
from app.db.base import Base
from app.db.session import get_engine
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence  # noqa: F401


async def init_database() -> None:
    """Initialize database extensions and create tables."""
    engine = get_engine()
    async with engine.begin() as conn:
        # Check dialect: if postgresql, ensure vector extension exists
        if engine.dialect.name == "postgresql":
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
        await conn.run_sync(Base.metadata.create_all)


if __name__ == "__main__":
    asyncio.run(init_database())
