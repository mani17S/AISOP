"""
Security page API: what the server observed being done to it (failed logins, lockouts, probes, oversized requests).

Readable only by a security admin identified from the database. A key with no analyst behind it (a legacy machine key) is
refused, so this endpoint fails closed. Responses are counts and cleaned samples; no credential is ever stored.
"""

from __future__ import annotations

from typing import Any

from app.core.auth import AuthenticatedClient, verify_api_key
from app.core.rbac import can_view_security_monitoring
from app.db.session import get_db_session
from app.services.security_event_service import overview
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

router = APIRouter(prefix="/security", tags=["Security monitoring"])


@router.get("/overview", summary="Attacks observed on this server in a recent window")
async def security_overview(
    request: Request,
    hours: int = Query(24, ge=1, le=168, description="Window length in hours, 1 to 168"),
    session: Any = Depends(get_db_session),
    client: AuthenticatedClient = Depends(verify_api_key),
) -> dict[str, Any]:
    if client.analyst is None or not can_view_security_monitoring(client.analyst.global_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security monitoring is limited to the security admin role.",
        )
    buffer = getattr(request.app.state, "security_events", None)
    return await overview(
        session,
        hours=hours,
        not_recorded_since_start=getattr(buffer, "dropped_total", 0),
    )
