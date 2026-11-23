"""
Who the server says the caller is.

Lets the interface show the real account and role (instead of a role selector) and nothing else. It returns only what the server
already holds about the authenticated caller: account name, global role, client name. Never the key, its hash, its prefix or any
other account. A machine key with no account behind it says so and claims no role.
"""

from __future__ import annotations

from typing import Any

from app.core.auth import AuthenticatedClient, verify_api_key
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/me", summary="The authenticated caller's account and role, as the server sees it")
async def who_am_i(client: AuthenticatedClient = Depends(verify_api_key)) -> dict[str, Any]:
    analyst = client.analyst
    if analyst is None:
        return {"authenticated": True, "username": None, "global_role": None, "client_name": client.client_id}
    role = analyst.global_role
    return {
        "authenticated": True,
        "username": analyst.username,
        "global_role": getattr(role, "value", str(role)),
        "client_name": analyst.client_id,
    }
