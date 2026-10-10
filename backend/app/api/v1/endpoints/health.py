"""
AISOP Health Check Endpoints.

GET /health        — Liveness: is the process alive?
GET /health/ready  — Readiness: can the process serve traffic?
                     Probes the database connection and LLM provider.
"""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings
from app.db.session import get_db_session
from app.modules.ai.llm.manager import get_llm_provider
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(tags=["Health"])


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
    Probes database connectivity and LLM provider availability.

    Returns HTTP 200 when all subsystems are reachable.
    Returns HTTP 503 when any required subsystem is unavailable,
    with per-component status detail in the response body.
    """
    from fastapi import HTTPException

    settings = get_settings()
    checks: dict[str, Any] = {}
    all_ok = True

    # ── Database probe ────────────────────────────────────────────────────
    try:
        await session.execute(text("SELECT 1"))
        checks["database"] = {"status": "ok"}
    except Exception as exc:
        checks["database"] = {"status": "error", "detail": str(exc)}
        all_ok = False

    # ── LLM provider probe ────────────────────────────────────────────────
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
        checks["llm_provider"] = {"status": "error", "detail": str(exc)}
        all_ok = False

    response: dict[str, Any] = {
        "status": "ok" if all_ok else "degraded",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "checks": checks,
    }

    if not all_ok:
        raise HTTPException(status_code=503, detail=response)

    return response
