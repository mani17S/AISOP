"""
AISOP Health & Readiness Verification Endpoints.

GET /api/v1/health        — Process Liveness: is the web application running?
GET /api/v1/health/ready  — Deep Subsystem Readiness: can the platform serve traffic?
                            Probes relational connectivity, PostgreSQL pgvector extension,
                            knowledge embedding schema, vector dimension compatibility,
                            and local LLM provider availability.
"""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings
from app.db.session import get_db_session
from app.modules.ai.llm.manager import get_llm_provider
from fastapi import APIRouter, Depends, HTTPException
from app.core.errors import SERVICE_UNAVAILABLE, StructuredHttpError
from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(tags=["Health"])


def _detect_dialect(session: Any) -> str:
    """
    Safely determine database dialect name without raising exceptions.
    Inspects AsyncSession.bind, AsyncSessionAdapter._sync.bind, or session.get_bind().
    """
    bind = getattr(session, "bind", None)
    if bind is not None and hasattr(bind, "dialect"):
        return getattr(bind.dialect, "name", "unknown")

    sync_session = getattr(session, "_sync", None)
    if sync_session is not None:
        sync_bind = getattr(sync_session, "bind", None)
        if sync_bind is not None and hasattr(sync_bind, "dialect"):
            return getattr(sync_bind.dialect, "name", "unknown")

    get_bind_fn = getattr(session, "get_bind", None)
    if callable(get_bind_fn):
        try:
            b = get_bind_fn()
            if b is not None and hasattr(b, "dialect"):
                return getattr(b.dialect, "name", "unknown")
        except Exception:
            pass

    return "unknown"


async def _probe_database(
    session: AsyncSession,
    settings: Any,
) -> tuple[dict[str, Any], bool]:
    """
    Perform deep, read-only readiness probes against the database engine.

    Guarantees:
    1. Read-only queries only (no DDL, DML, or extension creation).
    2. Zero credential or internal connection string leakage in returned payloads.
    3. Distinct handling of production PostgreSQL (deep catalog probe) vs SQLite (test fallback).
    4. Validates presence of the PostgreSQL 'vector' extension in pg_extension.
    5. Validates presence of the 'knowledge_embeddings' table.
    6. Validates 'embedding' column type ('vector') and dimension consistency (768).

    Note:
    Checking catalog presence confirms extension and schema readiness, but does NOT
    prove physical HNSW index graph integrity or end-to-end embedding generation.
    """
    dialect = _detect_dialect(session)

    # ── 1. Basic relational connectivity query ─────────────────────────────
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error(
            "Readiness check failed: database connectivity probe rejected",
            engine=dialect,
            error=str(exc),
        )
        return {
            "status": "error",
            "engine": dialect,
            "detail": "Database connection unreachable",
        }, False

    # ── 2. PostgreSQL deep readiness inspection ────────────────────────────
    if dialect == "postgresql":
        try:
            # 2.1 Extension check
            ext_res = await session.execute(
                text("SELECT extname, extversion FROM pg_extension WHERE extname = 'vector'")
            )
            ext_row = ext_res.first()
            if not ext_row:
                logger.warning(
                    "Readiness probe failed: PostgreSQL 'vector' extension is not installed"
                )
                return {
                    "status": "error",
                    "engine": "postgresql",
                    "pgvector": {
                        "status": "error",
                        "installed": False,
                        "detail": "Extension 'vector' is not registered in pg_extension",
                    },
                    "detail": "PostgreSQL vector extension missing",
                }, False

            ext_version = str(ext_row[1]) if ext_row[1] is not None else "unknown"

            # 2.2 Knowledge embedding schema accessibility check
            tbl_res = await session.execute(
                text(
                    "SELECT EXISTS ("
                    "  SELECT 1 FROM information_schema.tables "
                    "  WHERE table_name = 'knowledge_embeddings'"
                    ")"
                )
            )
            tbl_exists = bool(tbl_res.scalar())
            if not tbl_exists:
                logger.warning(
                    "Readiness probe failed: table 'knowledge_embeddings' missing from schema"
                )
                return {
                    "status": "error",
                    "engine": "postgresql",
                    "pgvector": {
                        "status": "ok",
                        "installed": True,
                        "version": ext_version,
                    },
                    "schema": {
                        "status": "error",
                        "table": "knowledge_embeddings",
                        "detail": "Table 'knowledge_embeddings' not found in schema",
                    },
                    "detail": "Knowledge embedding schema missing",
                }, False

            # 2.3 Vector column and dimension configuration check
            col_res = await session.execute(
                text(
                    "SELECT a.attname, a.atttypmod, t.typname "
                    "FROM pg_attribute a "
                    "JOIN pg_class c ON a.attrelid = c.oid "
                    "JOIN pg_type t ON a.atttypid = t.oid "
                    "WHERE c.relname = 'knowledge_embeddings' "
                    "  AND a.attname = 'embedding' "
                    "  AND a.attnum > 0 "
                    "  AND NOT a.attisdropped"
                )
            )
            col_row = col_res.first()
            if not col_row:
                logger.warning(
                    "Readiness probe failed: 'embedding' column missing from 'knowledge_embeddings'"
                )
                return {
                    "status": "error",
                    "engine": "postgresql",
                    "pgvector": {
                        "status": "ok",
                        "installed": True,
                        "version": ext_version,
                    },
                    "schema": {
                        "status": "error",
                        "table": "knowledge_embeddings",
                        "column": "embedding",
                        "detail": "Column 'embedding' missing from 'knowledge_embeddings'",
                    },
                    "detail": "Vector embedding column missing",
                }, False

            attname, atttypmod, typname = col_row[0], col_row[1], col_row[2]
            if typname != "vector":
                logger.warning(
                    "Readiness probe failed: column 'embedding' has unexpected type",
                    type=typname,
                    expected="vector",
                )
                return {
                    "status": "error",
                    "engine": "postgresql",
                    "pgvector": {
                        "status": "ok",
                        "installed": True,
                        "version": ext_version,
                    },
                    "schema": {
                        "status": "error",
                        "table": "knowledge_embeddings",
                        "column": "embedding",
                        "data_type": typname,
                        "detail": f"Column 'embedding' has unexpected type '{typname}', expected 'vector'",
                    },
                    "detail": "Vector column type mismatch",
                }, False

            # pgvector encodes dimension in atttypmod (> 0 for constrained vector(dim), -1 for unconstrained)
            configured_dim = atttypmod if atttypmod > 0 else settings.EMBEDDING_DIMENSIONS
            if atttypmod > 0 and atttypmod != settings.EMBEDDING_DIMENSIONS:
                logger.warning(
                    "Readiness probe failed: vector dimension configuration mismatch",
                    table_dimension=atttypmod,
                    app_dimension=settings.EMBEDDING_DIMENSIONS,
                )
                return {
                    "status": "error",
                    "engine": "postgresql",
                    "pgvector": {
                        "status": "ok",
                        "installed": True,
                        "version": ext_version,
                    },
                    "schema": {
                        "status": "error",
                        "table": "knowledge_embeddings",
                        "column": "embedding",
                        "configured_dimension": atttypmod,
                        "expected_dimension": settings.EMBEDDING_DIMENSIONS,
                        "detail": (
                            f"Vector dimension mismatch (table: {atttypmod}, "
                            f"app: {settings.EMBEDDING_DIMENSIONS})"
                        ),
                    },
                    "detail": "Vector dimension configuration mismatch",
                }, False

            return {
                "status": "ok",
                "engine": "postgresql",
                "pgvector": {
                    "status": "ok",
                    "installed": True,
                    "version": ext_version,
                },
                "schema": {
                    "status": "ok",
                    "table": "knowledge_embeddings",
                    "column": "embedding",
                    "dimension": configured_dim,
                },
            }, True

        except Exception as exc:
            logger.error(
                "Readiness check failed: PostgreSQL catalog inspection error",
                error=str(exc),
            )
            return {
                "status": "error",
                "engine": "postgresql",
                "detail": "Database catalog inspection failed",
            }, False

    # ── 3. SQLite fallback mode (development and unit tests) ───────────────
    if dialect == "sqlite":
        try:
            tbl_res = await session.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='knowledge_embeddings'")
            )
            tbl_exists = tbl_res.first() is not None
            return {
                "status": "ok",
                "engine": "sqlite",
                "mode": "test_fallback",
                "pgvector": {
                    "status": "skipped",
                    "available": False,
                    "detail": "pgvector is not supported on SQLite (test/development fallback mode)",
                },
                "schema": {
                    "status": "ok" if tbl_exists else "uninitialized",
                    "table": "knowledge_embeddings",
                    "dimension": settings.EMBEDDING_DIMENSIONS,
                },
            }, True
        except Exception as exc:
            logger.error(
                "Readiness check failed: SQLite schema inspection error",
                error=str(exc),
            )
            return {
                "status": "error",
                "engine": "sqlite",
                "detail": "Database schema inspection failed",
            }, False

    # ── 4. Unrecognized dialect (relational connectivity verified) ────────
    return {
        "status": "ok",
        "engine": dialect,
        "detail": "Relational connectivity verified",
    }, True


@router.get("/health", summary="Liveness check")
async def get_health() -> dict[str, Any]:
    """Returns immediately if the process is running."""
    settings = get_settings()
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/health/ready", summary="Readiness check")
async def get_readiness(
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """
    Probes deep database readiness (PostgreSQL + pgvector + knowledge schema)
    and LLM provider availability.

    Returns HTTP 200 when all subsystems are reachable and correctly configured.
    Returns HTTP 503 when any required subsystem is unavailable or misconfigured,
    with per-component status detail in the response body.
    """
    settings = get_settings()
    checks: dict[str, Any] = {}
    all_ok = True

    # ── Database probe ────────────────────────────────────────────────────
    db_check, db_ok = await _probe_database(session, settings)
    checks["database"] = db_check
    if not db_ok:
        all_ok = False

    # ── LLM provider probe ────────────────────────────────────────────────
    if not settings.LLM_ENABLED:
        # AI disabled by configuration: report it, make NO provider/model call, and do not degrade readiness.
        checks["llm_provider"] = {"status": "disabled", "provider": "none", "detail": "AI assistance is disabled by configuration"}
    else:
        try:
            provider = get_llm_provider(settings)
            health = await provider.health()
            checks["llm_provider"] = {
                "status": health.status,          # "healthy" | "degraded" | "unavailable"
                "provider": health.provider,
                "model": health.model,
                "latency_ms": health.latency_ms,
            }
            if health.status == "unavailable":
                all_ok = False
            if health.error:
                checks["llm_provider"]["detail"] = health.error
        except Exception as exc:
            logger.error("Readiness check: LLM provider probe error", error=type(exc).__name__)
            checks["llm_provider"] = {
                "status": "error",
                "detail": "LLM provider probe failed",
            }
            all_ok = False

    response: dict[str, Any] = {
        "status": "ok" if all_ok else "degraded",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "checks": checks,
    }

    if not all_ok:
        raise StructuredHttpError(503, SERVICE_UNAVAILABLE, "The service is not ready.", response)

    return response
