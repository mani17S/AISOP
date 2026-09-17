"""
AISOP Database Initialization Script.

Applies version-controlled Alembic migrations to establish the database schema.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from loguru import logger


def init_database() -> None:
    """Run Alembic migrations to bring the database schema to head."""
    backend_dir = Path(__file__).resolve().parents[2]
    alembic_ini_path = backend_dir / "alembic.ini"
    if not alembic_ini_path.exists():
        alembic_ini_path = backend_dir.parent / "alembic.ini"

    logger.info(
        "Applying Alembic database migrations",
        config_path=str(alembic_ini_path),
    )
    alembic_cfg = Config(str(alembic_ini_path))
    command.upgrade(alembic_cfg, "head")
    logger.info("Database schema successfully migrated to head")


if __name__ == "__main__":
    init_database()
