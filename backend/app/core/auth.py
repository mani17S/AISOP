"""
AISOP API Ingress Authentication & Security Perimeter.

Enforces Bearer token and API key authentication on protected endpoints
in accordance with AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001, OWASP A07, and API2:2023.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Request, status
from app.core.errors import RATE_LIMITED, CodedHTTPException
from app.core.security_events import REASON_AUTH_LOCKED_OUT
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.core.config import Settings, get_settings
from app.core.rbac import (
    AuthenticatedAnalyst,
    hash_canonical_token,
    is_canonical_token,
    parse_canonical_token,
    parse_global_role,
)
from app.db.session import get_db_session_factory, isolated_session
from app.middleware.rate_limit import resolve_client_ip
from app.models.analyst import AnalystApiClient

#: last_used_at is refreshed at most this often per key, so authentication stays read-only on the hot path.
LAST_USED_REFRESH = timedelta(minutes=5)


def _equal(a: str, b: str) -> bool:
    """Constant-time equality for arbitrary text. compare_digest on str raises TypeError for non-ASCII, so compare bytes."""
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class AuthLockedOut(HTTPException):
    """429 for a client address locked out after repeated rejected credentials (stable code RATE_LIMITED)."""

    code = RATE_LIMITED

    def __init__(self, retry_after: int) -> None:
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed authentication attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )


class AuthenticatedClient(BaseModel):
    """
    Identity contract for an authenticated API client.

    Represents verified client metadata after constant-time credential comparison.
    Associates with resolved human analyst identity when authenticated via canonical token.
    """

    client_id: str = Field(
        default="api-client",
        description="Logical identifier for the authenticated machine client or analyst",
    )
    authenticated: bool = Field(
        default=True,
        description="Whether client credentials were cryptographically verified",
    )
    analyst: AuthenticatedAnalyst | None = Field(
        default=None,
        description="Resolved human analyst or principal identity from database",
    )


def parse_configured_keys(configured_keys: list[str]) -> list[tuple[str, str]]:
    """
    Parse configured key entries into (client_id, secret_token) tuples.

    Supports:
    - Simple token string: "secret-token-value" -> ("api-client", "secret-token-value")
    - Named client format: "sensor-01:secret-token-value" -> ("sensor-01", "secret-token-value")

    Entries containing only whitespace are skipped.
    """
    parsed: list[tuple[str, str]] = []
    for entry in configured_keys:
        cleaned = entry.strip()
        if not cleaned:
            continue
        if ":" in cleaned:
            cid, token = cleaned.split(":", 1)
            cid = cid.strip()
            token = token.strip()
            if cid and token:
                parsed.append((cid, token))
        else:
            parsed.append(("api-client", cleaned))
    return parsed


def _get_optional_db_session() -> AsyncSession | None:
    """Optional direct session dependency for testing or custom invocation."""
    return None


async def verify_api_key(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    settings: Settings = Depends(get_settings),
    session_factory: Any = Depends(get_db_session_factory),
    session: Any = Depends(_get_optional_db_session),
    request: Request = None,  # type: ignore[assignment]  (None only for direct calls in tests)
) -> AuthenticatedClient:
    """
    Central authentication dependency for protected AISOP API routes.

    Accepts credentials via:
    1. HTTP Authorization header: 'Authorization: Bearer <token>'
    2. HTTP X-API-Key header: 'X-API-Key: <token>'

    Security Invariants:
    - Database-backed canonical token authentication (aisop_<env>_<16hex>_<64hex>).
    - Constant-time secret digest comparison using `secrets.compare_digest` (on bytes, so non-ASCII input is a 401, not a 500).
    - Fail-closed defaults: Inactive analysts, expired/revoked clients, unknown prefixes fail closed (401).
    - Safe error responses: Generic 401 messages that never leak keys, tokens, or configuration details.
    - Legacy static key rejection when `API_AUTH_ALLOW_LEGACY_KEYS=False`.
    - Conflicting credential rejection: Rejects conflicting credentials provided in both headers.
    - Brute-force protection: repeated rejected credentials from one client address (or address and key prefix) are
      answered with 429 and Retry-After before any database work (app.core.auth_throttle, API2/API4:2023).
    - Scoped Session Isolation: Database connection is scoped strictly to the token lookup
      operation and closed before subsequent route execution or inference begins (SEC-D243-002).
    """
    if hasattr(session_factory, "dependency"):
        session_factory = None
    if hasattr(session, "dependency"):
        session = None
    if hasattr(settings, "dependency") or settings is None:
        settings = get_settings()

    # If explicitly disabled in non-production environment
    if not settings.API_AUTH_ENABLED:
        return AuthenticatedClient(client_id="anonymous-dev", authenticated=False, analyst=None)

    throttle = getattr(getattr(getattr(request, "app", None), "state", None), "auth_throttle", None)
    client_ip = resolve_client_ip(request, settings.RATE_LIMIT_TRUSTED_PROXIES) if throttle is not None else None
    key_prefix: str | None = None

    def locked_out() -> None:
        wait = throttle.retry_after(client_ip, key_prefix) if throttle is not None and client_ip is not None else 0
        if wait:
            if request is not None:
                request.state.security_reason = REASON_AUTH_LOCKED_OUT  # lets the Security page tell a lockout from throttling
            raise AuthLockedOut(wait)

    def failed() -> None:
        """A credential was presented and refused: count it toward the lockout (called just before raising the 401)."""
        if throttle is not None and client_ip is not None:
            throttle.record_failure(client_ip, key_prefix)

    if authorization is not None or x_api_key is not None:
        locked_out()

    candidate_key: str | None = None
    auth_bearer_key: str | None = None
    x_api_header_key: str | None = None

    # 1. Parse Authorization: Bearer <token>
    if authorization is not None:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            auth_bearer_key = parts[1].strip()
            if not auth_bearer_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication credentials missing.",
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
        else:
            failed()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme. Bearer token required.",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

    # 2. Parse X-API-Key: <token>
    if x_api_key is not None:
        x_api_header_key = x_api_key.strip()
        if not x_api_header_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication credentials missing.",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

    # 3. Handle conflict if both headers are present
    if auth_bearer_key is not None and x_api_header_key is not None:
        if not _equal(auth_bearer_key, x_api_header_key):
            failed()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Conflicting authentication credentials provided.",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        candidate_key = auth_bearer_key
    elif auth_bearer_key is not None:
        candidate_key = auth_bearer_key
    elif x_api_header_key is not None:
        candidate_key = x_api_header_key
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Canonical token evaluation (Database-backed)
    if is_canonical_token(candidate_key):
        env, prefix, _ = parse_canonical_token(candidate_key)
        key_prefix = prefix
        locked_out()  # now that the prefix is known, also honour the (address, prefix) lockout

        # Environment policy enforcement: test tokens strictly forbidden in staging and production
        if settings.ENVIRONMENT in ("staging", "production") and env == "test":
            failed()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials.",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        try:
            async with isolated_session(session_factory=session_factory, fallback_session=session) as auth_session:
                stmt = (
                    select(AnalystApiClient)
                    .options(joinedload(AnalystApiClient.analyst))
                    .where(AnalystApiClient.token_prefix == prefix)
                )
                result = await auth_session.execute(stmt)
                client_record = result.scalars().first()
                if client_record is None:
                    auth_data = None
                else:
                    analyst_rec = client_record.analyst
                    auth_data = {
                        "client_is_active": client_record.is_active,
                        "expires_at": client_record.expires_at,
                        "hashed_secret": client_record.hashed_secret,
                        "client_name": client_record.client_name,
                        "analyst_id": analyst_rec.id if analyst_rec else None,
                        "analyst_username": analyst_rec.username if analyst_rec else None,
                        "analyst_global_role": analyst_rec.global_role if analyst_rec else None,
                        "analyst_is_active": analyst_rec.is_active if analyst_rec else False,
                    }
                    # Last-use stamp: only for a fully valid credential, at most once per LAST_USED_REFRESH, and in this same
                    # short session (no extra connection), so authentication keeps its single scoped session.
                    now_utc = datetime.now(timezone.utc)
                    last_used = client_record.last_used_at
                    if (
                        client_record.is_active
                        and analyst_rec is not None
                        and analyst_rec.is_active
                        and (client_record.expires_at is None or now_utc <= _utc(client_record.expires_at))
                        and _equal(hash_canonical_token(candidate_key), client_record.hashed_secret)
                        and (last_used is None or now_utc - _utc(last_used) > LAST_USED_REFRESH)
                    ):
                        await auth_session.execute(
                            update(AnalystApiClient).where(AnalystApiClient.id == client_record.id).values(last_used_at=now_utc)
                        )
        except HTTPException:
            raise
        except Exception as exc:
            logger.error(
                "Database error during token verification",
                error_type=type(exc).__name__,
            )
            raise CodedHTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication service unavailable.",
                code="AUTHENTICATION_SERVICE_UNAVAILABLE",
            ) from None

        if auth_data is None or not auth_data["client_is_active"]:
            failed()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials.",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        # Verify client expiry if set
        if auth_data["expires_at"] is not None:
            now_utc = datetime.now(timezone.utc)
            expires_at = _utc(auth_data["expires_at"])
            if now_utc > expires_at:
                failed()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials.",
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )

        # Verify token digest using constant-time comparison
        expected_digest = hash_canonical_token(candidate_key)
        if not _equal(expected_digest, auth_data["hashed_secret"]):
            failed()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials.",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        # Validate associated analyst record
        if not auth_data["analyst_id"] or not auth_data["analyst_is_active"]:
            failed()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials.",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        try:
            parsed_role = parse_global_role(auth_data["analyst_global_role"])
        except ValueError:
            failed()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials.",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        analyst_identity = AuthenticatedAnalyst(
            analyst_id=auth_data["analyst_id"],
            username=auth_data["analyst_username"],
            global_role=parsed_role,
            client_id=auth_data["client_name"],
            is_active=auth_data["analyst_is_active"],
        )

        if throttle is not None and client_ip is not None:
            throttle.record_success(client_ip, key_prefix)

        return AuthenticatedClient(
            client_id=auth_data["client_name"],
            authenticated=True,
            analyst=analyst_identity,
        )

    # 5. Non-canonical token handling (Legacy static keys)
    # Strictly reject legacy keys if API_AUTH_ALLOW_LEGACY_KEYS is False
    if not settings.API_AUTH_ALLOW_LEGACY_KEYS:
        failed()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    # Legacy mode explicitly enabled: evaluate against configured valid keys
    parsed_keys = parse_configured_keys(settings.API_AUTH_KEYS)
    if not parsed_keys:
        failed()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. No valid credentials configured on server.",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    matched: tuple[str, str] | None = None
    for client_id, secret_token in parsed_keys:  # every configured key is compared (no early exit)
        if _equal(candidate_key, secret_token) and matched is None:
            matched = (client_id, secret_token)
    if matched is not None:
        return AuthenticatedClient(
            client_id=matched[0],
            authenticated=True,
            analyst=None,
        )

    failed()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials.",
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )
