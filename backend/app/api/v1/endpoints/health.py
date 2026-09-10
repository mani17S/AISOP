"""
AISOP Health Check Endpoint.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter
from app.core.config import get_settings

router = APIRouter(tags=["Health"])


@router.get("/health", summary="System Health Check")
async def get_health() -> dict[str, Any]:
    settings = get_settings()
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }
