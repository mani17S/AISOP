#!/usr/bin/env python3
"""
AISOP Demo Identity Provisioning Utility.

Provisions two separate canonical identities for local academic viva demonstrations:
1. Demo Analyst:
   - Username: viva_analyst
   - Role: analyst_tier_1
   - Client Name: viva-tier1-workstation
2. System Ingest Identity:
   - Username: viva_sensor
   - Role: ingest
   - Client Name: viva-sysmon-forwarder

Security Invariants:
- Uses cryptographically secure random generation (secrets module).
- Canonical token structure: aisop_<env>_<16hex>_<64hex> (92 characters).
- Plaintext secrets are NEVER persisted to the database. Only token_prefix (16 hex)
  and hashed_secret (SHA-256 digest of the complete canonical token) are stored.
- Tokens are displayed exactly ONCE to the operator on stdout and never logged.
- Atomic transaction execution with automatic rollback on error.
- Strict pre-flight collision checks: fails closed if usernames or client names exist.
- Explicit operator confirmation required prior to any database write.
- Revocation support: deactivates both identities on demand without data loss.
- Rotation support: safely rotates credentials for existing identities in-place while
  strictly preserving IDs, case assignments, creation timestamps, and audit history.
- Expiration support: attaches expires_at timestamp (default: 48 hours).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Psycopg async on Windows requires SelectorEventLoop instead of ProactorEventLoop
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Ensure repository root and backend are on sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
REPO_ROOT = BACKEND_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.rbac import CANONICAL_TOKEN_REGEX, GlobalRole, hash_canonical_token
from app.db.session import get_session_factory
from app.models.analyst import Analyst, AnalystApiClient

DEMO_CONFIGS = [
    {
        "username": "viva_analyst",
        "email": "viva_analyst@aisop.local",
        "global_role": GlobalRole.ANALYST_TIER_1.value,
        "client_name": "viva-tier1-workstation",
        "label": "Demo Security Analyst (Tier-1 Triage & Investigation)",
    },
    {
        "username": "viva_sensor",
        "email": "viva_sensor@aisop.local",
        "global_role": GlobalRole.INGEST.value,
        "client_name": "viva-sysmon-forwarder",
        "label": "System Ingest Identity (Sysmon / SIEM Forwarder)",
    },
]


def generate_canonical_credential(env: str = "live") -> tuple[str, str, str]:
    """
    Generate an unguessable canonical AISOP API credential.

    Returns:
        tuple[str, str, str]: (full_token, token_prefix, hashed_secret)
    """
    # 16 lowercase hex characters for non-secret lookup prefix (64 bits of entropy)
    prefix = secrets.token_hex(8)
    # 64 lowercase hex characters for high-entropy secret (256 bits of entropy)
    secret = secrets.token_hex(32)
    # Full canonical token string (length: 92)
    full_token = f"aisop_{env}_{prefix}_{secret}"
    if not CANONICAL_TOKEN_REGEX.fullmatch(full_token):
        raise ValueError("Generated token failed canonical regular expression validation.")
    # Cryptographic SHA-256 digest of complete canonical token
    hashed_secret = hash_canonical_token(full_token)
    return full_token, prefix, hashed_secret


async def check_existing_demo_identities(
    session: AsyncSession,
) -> dict[str, Any]:
    """
    Check whether any demo analysts or API clients already exist in the database.

    Returns:
        dict with 'analysts' and 'clients' found.
    """
    usernames = [cfg["username"] for cfg in DEMO_CONFIGS]
    client_names = [cfg["client_name"] for cfg in DEMO_CONFIGS]

    analyst_stmt = select(Analyst).where(Analyst.username.in_(usernames))
    analyst_res = await session.execute(analyst_stmt)
    existing_analysts = analyst_res.scalars().all()

    client_stmt = select(AnalystApiClient).where(AnalystApiClient.client_name.in_(client_names))
    client_res = await session.execute(client_stmt)
    existing_clients = client_res.scalars().all()

    return {
        "analysts": existing_analysts,
        "clients": existing_clients,
        "has_collisions": bool(existing_analysts or existing_clients),
    }


async def provision_identities(
    session: AsyncSession,
    *,
    env: str = "live",
    expires_in_hours: int | None = 48,
) -> list[dict[str, Any]]:
    """
    Execute atomic provisioning of demo identities.

    Raises:
        RuntimeError: If collisions exist or transaction fails.
    """
    # 1. Pre-flight collision verification
    status = await check_existing_demo_identities(session)
    if status["has_collisions"]:
        collision_details = []
        for a in status["analysts"]:
            collision_details.append(f"Analyst username '{a.username}' (ID: {a.id}, active: {a.is_active})")
        for c in status["clients"]:
            collision_details.append(f"API Client '{c.client_name}' (Prefix: {c.token_prefix}, active: {c.is_active})")
        raise RuntimeError(
            "Collision detected: demo identities or clients already exist in database:\n  - "
            + "\n  - ".join(collision_details)
        )

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=expires_in_hours) if expires_in_hours else None

    provisioned_results = []

    try:
        # 2. Atomic creation of records
        for cfg in DEMO_CONFIGS:
            full_token, prefix, hashed_secret = generate_canonical_credential(env=env)

            # Check prefix uniqueness (defense-in-depth)
            p_check = await session.execute(
                select(AnalystApiClient).where(AnalystApiClient.token_prefix == prefix)
            )
            if p_check.scalars().first() is not None:
                raise RuntimeError(f"Unexpected token prefix collision: {prefix}")

            analyst = Analyst(
                id=uuid.uuid4(),
                username=cfg["username"],
                email=cfg["email"],
                global_role=cfg["global_role"],
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            session.add(analyst)
            await session.flush()

            client = AnalystApiClient(
                id=uuid.uuid4(),
                analyst_id=analyst.id,
                client_name=cfg["client_name"],
                token_prefix=prefix,
                hashed_secret=hashed_secret,
                is_active=True,
                expires_at=expires_at,
                created_at=now,
            )
            session.add(client)

            provisioned_results.append({
                "label": cfg["label"],
                "username": cfg["username"],
                "global_role": cfg["global_role"],
                "client_name": cfg["client_name"],
                "analyst_id": str(analyst.id),
                "client_id": str(client.id),
                "token_prefix": prefix,
                "raw_token": full_token,
                "expires_at": expires_at.isoformat() if expires_at else "Never",
            })

        await session.commit()
        return provisioned_results
    except Exception:
        await session.rollback()
        raise


async def rotate_identities(
    session: AsyncSession,
    *,
    env: str = "live",
    expires_in_hours: int | None = 48,
) -> list[dict[str, Any]]:
    """
    Rotate credentials in-place for existing demo identities.

    Invariants:
    - Verifies exactly one analyst and one API client per demo identity.
    - Verifies client-analyst ownership and global roles match expected configuration.
    - Fails closed if any record is missing, duplicated, mismatched, or inconsistent.
    - Generates fresh unguessable canonical credentials.
    - Checks token-prefix uniqueness against other clients.
    - Updates client token_prefix and hashed_secret in-place.
    - Sets is_active=True on both analysts and clients.
    - Sets a fresh expiration timestamp.
    - Preserves analyst IDs, client IDs, case assignments, creation timestamps, and audit history.
    - Updates analyst updated_at timestamp.
    - Executes in a single database transaction with automatic rollback on error.

    Raises:
        RuntimeError: If verification fails, records are inconsistent, or collision occurs.
    """
    usernames = [cfg["username"] for cfg in DEMO_CONFIGS]
    client_names = [cfg["client_name"] for cfg in DEMO_CONFIGS]

    # 1. Retrieve existing demo analysts
    analyst_stmt = select(Analyst).where(Analyst.username.in_(usernames))
    analyst_res = await session.execute(analyst_stmt)
    analysts = analyst_res.scalars().all()
    analyst_by_user = {a.username: a for a in analysts}

    if len(analysts) != len(DEMO_CONFIGS) or any(u not in analyst_by_user for u in usernames):
        missing = [u for u in usernames if u not in analyst_by_user]
        raise RuntimeError(
            f"Rotation pre-flight check failed: Expected {len(DEMO_CONFIGS)} demo analysts, found {len(analysts)}. "
            f"Missing analyst(s): {', '.join(missing) if missing else 'None'}. "
            "Cannot rotate non-existent identities; run initial provisioning first."
        )

    # 2. Retrieve existing demo API clients
    client_stmt = select(AnalystApiClient).where(AnalystApiClient.client_name.in_(client_names))
    client_res = await session.execute(client_stmt)
    clients = client_res.scalars().all()
    client_by_name = {c.client_name: c for c in clients}

    if len(clients) != len(DEMO_CONFIGS) or any(cn not in client_by_name for cn in client_names):
        missing = [cn for cn in client_names if cn not in client_by_name]
        raise RuntimeError(
            f"Rotation pre-flight check failed: Expected {len(DEMO_CONFIGS)} demo API clients, found {len(clients)}. "
            f"Missing client(s): {', '.join(missing) if missing else 'None'}. "
            "Cannot rotate non-existent clients; run initial provisioning first."
        )

    # 3. Consistency checks for each identity
    for cfg in DEMO_CONFIGS:
        analyst = analyst_by_user[cfg["username"]]
        client = client_by_name[cfg["client_name"]]

        # Check client ownership
        if client.analyst_id != analyst.id:
            raise RuntimeError(
                f"Rotation pre-flight check failed: Client '{client.client_name}' is associated with analyst ID "
                f"{client.analyst_id}, expected {analyst.id} ('{analyst.username}')."
            )

        # Check role consistency
        if analyst.global_role != cfg["global_role"]:
            raise RuntimeError(
                f"Rotation pre-flight check failed: Analyst '{analyst.username}' has global role "
                f"'{analyst.global_role}', expected '{cfg['global_role']}'."
            )

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=expires_in_hours) if expires_in_hours else None

    rotated_results = []

    try:
        # 4. Perform atomic credential rotation
        for cfg in DEMO_CONFIGS:
            analyst = analyst_by_user[cfg["username"]]
            client = client_by_name[cfg["client_name"]]

            full_token, prefix, hashed_secret = generate_canonical_credential(env=env)

            # Check prefix uniqueness against other clients excluding the current client being rotated
            p_check = await session.execute(
                select(AnalystApiClient).where(
                    AnalystApiClient.token_prefix == prefix,
                    AnalystApiClient.id != client.id,
                )
            )
            if p_check.scalars().first() is not None:
                raise RuntimeError(f"Unexpected token prefix collision during rotation: {prefix}")

            # Update client credentials, expiration, and active status in-place
            client.token_prefix = prefix
            client.hashed_secret = hashed_secret
            client.is_active = True
            client.expires_at = expires_at

            # Update analyst active status and updated_at timestamp
            analyst.is_active = True
            analyst.updated_at = now

            rotated_results.append({
                "label": cfg["label"],
                "username": cfg["username"],
                "global_role": cfg["global_role"],
                "client_name": cfg["client_name"],
                "analyst_id": str(analyst.id),
                "client_id": str(client.id),
                "token_prefix": prefix,
                "raw_token": full_token,
                "expires_at": expires_at.isoformat() if expires_at else "Never",
            })

        await session.commit()
        return rotated_results
    except Exception:
        await session.rollback()
        raise


async def revoke_identities(session: AsyncSession) -> dict[str, int]:
    """
    Deactivate demo identities and their API clients without deleting database records.
    """
    usernames = [cfg["username"] for cfg in DEMO_CONFIGS]
    client_names = [cfg["client_name"] for cfg in DEMO_CONFIGS]

    try:
        a_stmt = (
            update(Analyst)
            .where(Analyst.username.in_(usernames))
            .values(is_active=False, updated_at=datetime.now(timezone.utc))
        )
        a_res = await session.execute(a_stmt)

        c_stmt = (
            update(AnalystApiClient)
            .where(AnalystApiClient.client_name.in_(client_names))
            .values(is_active=False)
        )
        c_res = await session.execute(c_stmt)

        await session.commit()
        return {
            "analysts_deactivated": a_res.rowcount,
            "clients_deactivated": c_res.rowcount,
        }
    except Exception:
        await session.rollback()
        raise


def format_credentials_output(
    provisioned: list[dict[str, Any]],
    *,
    title: str = "AISOP DEMO IDENTITY PROVISIONING - SECURE ONE-TIME CREDENTIAL OUTPUT",
) -> str:
    """Format one-time credentials for operator terminal display."""
    lines = [
        "",
        "=" * 88,
        f"  {title}",
        "=" * 88,
        "  WARNING: Plaintext credentials are displayed EXACTLY ONCE and cannot be",
        "  recovered from the database. Copy and store them securely for the viva.",
        "-" * 88,
    ]

    for item in provisioned:
        lines.extend([
            f"  Identity:    {item['label']}",
            f"  Username:    {item['username']}",
            f"  Global Role: {item['global_role']}",
            f"  Client Name: {item['client_name']}",
            f"  Analyst ID:  {item['analyst_id']}",
            f"  Expires At:  {item['expires_at']}",
            f"  Token Prefix:{item['token_prefix']}",
            f"  API TOKEN:   {item['raw_token']}",
            "-" * 88,
        ])

    analyst_token = next(
        (p["raw_token"] for p in provisioned if p["global_role"] == GlobalRole.ANALYST_TIER_1.value),
        None,
    )
    sensor_token = next(
        (p["raw_token"] for p in provisioned if p["global_role"] == GlobalRole.INGEST.value),
        None,
    )

    lines.extend([
        "  OPERATOR USAGE INSTRUCTIONS:",
        "",
        "  1. Analyst Frontend Access:",
        "     - Open http://127.0.0.1:3000 in your browser.",
        "     - Click 'Set API Key' (or 'Key Configured') in the top navigation bar.",
        f"     - Paste the 'viva_analyst' token:",
        f"       {analyst_token}",
        "     - Click 'Save Key'. The Dashboard will immediately reload with active telemetry.",
        "",
        "  2. SIEM / Sysmon Telemetry Ingestion:",
        "     - Submit vendor alert batches using the 'viva_sensor' token in the header:",
        f"       curl.exe -X POST http://127.0.0.1:8000/api/v1/alerts/ingest `",
        f"         -H \"X-API-Key: {sensor_token}\" `",
        "         -H \"Content-Type: application/json\" `",
        "         -d @datasets/samples/alerts/edr_crowdstrike_malware.json",
        "",
        "  3. Credential Rotation (if needed):",
        "     - Rotate tokens without affecting cases, history, or database IDs:",
        "       python backend/scripts/provision_demo_identities.py --rotate --yes",
        "",
        "  4. Post-Viva Revocation:",
        "     - Deactivate credentials immediately after the presentation:",
        "       python backend/scripts/provision_demo_identities.py --revoke --yes",
        "=" * 88,
        "",
    ])
    return "\n".join(lines)


async def main_async() -> int:
    parser = argparse.ArgumentParser(
        description="AISOP Demo Identity Provisioning Utility (P6.6)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Bypass interactive confirmation prompt (required for scripted execution).",
    )
    parser.add_argument(
        "--expires-in-hours",
        type=int,
        default=48,
        help="Token expiration period in hours (default: 48 hours for academic viva). Set to 0 for no expiration.",
    )
    parser.add_argument(
        "--env",
        type=str,
        default="live",
        choices=["live", "test"],
        help="Canonical environment prefix for token format (default: 'live').",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Check whether demo identities already exist without modifying database state.",
    )
    parser.add_argument(
        "--revoke",
        action="store_true",
        help="Revoke (deactivate) existing demo identities and API clients.",
    )
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="Rotate credentials for existing demo identities without modifying UUIDs, assignments, or audit history.",
    )

    args = parser.parse_args()

    # Reject conflicting combinations of operations
    action_flags = [
        ("--status", args.status),
        ("--revoke", args.revoke),
        ("--rotate", args.rotate),
    ]
    selected_actions = [flag for flag, selected in action_flags if selected]
    if len(selected_actions) > 1:
        print(
            f"\n[ERROR] Conflicting command-line arguments: {', '.join(selected_actions)}. "
            "Please specify only one operation at a time.",
            file=sys.stderr,
        )
        return 1

    settings = get_settings()
    session_factory = get_session_factory()

    async with session_factory() as session:
        target_db = settings.DATABASE_URL.split("@")[-1] if "@" in settings.DATABASE_URL else settings.DATABASE_URL

        # 1. Check / Status Mode
        if args.status:
            status = await check_existing_demo_identities(session)
            print("\nAISOP Demo Identity Database Status:")
            print(f"  Target Database: {target_db}")
            print(f"  Existing Demo Analysts:    {len(status['analysts'])}")
            for a in status["analysts"]:
                print(f"    - {a.username} (Role: {a.global_role}, Active: {a.is_active}, Created: {a.created_at})")
            print(f"  Existing Demo API Clients: {len(status['clients'])}")
            for c in status["clients"]:
                print(f"    - {c.client_name} (Prefix: {c.token_prefix}, Active: {c.is_active}, Expires: {c.expires_at})")
            return 0

        # 2. Revocation Mode
        if args.revoke:
            if not args.yes:
                confirm = input("\nConfirm deactivation of all demo identities? (yes/no): ").strip().lower()
                if confirm != "yes":
                    print("[ABORTED] Operator declined confirmation. Zero changes made.")
                    return 0

            counts = await revoke_identities(session)
            print(f"\n[REVOKED] Deactivated {counts['analysts_deactivated']} analyst(s) and {counts['clients_deactivated']} API client(s).")
            return 0

        # 3. Credential Rotation Mode
        if args.rotate:
            if not args.yes:
                print("\n" + "=" * 60)
                print("  AISOP DEMO IDENTITY CREDENTIAL ROTATION PLAN")
                print("=" * 60)
                print(f"  Target Database:    {target_db}")
                print(f"  Token Environment:  {args.env}")
                print(f"  Expiration Window:  {args.expires_in_hours} hours" if args.expires_in_hours > 0 else "  Expiration Window:  Never")
                print("  Identities to rotate:")
                for cfg in DEMO_CONFIGS:
                    print(f"    - {cfg['username']} ({cfg['global_role']}) -> {cfg['client_name']}")
                print("=" * 60)
                confirm = input("\nConfirm credential rotation for existing demo identities? (yes/no): ").strip().lower()
                if confirm != "yes":
                    print("[ABORTED] Operator declined confirmation. Zero database modifications performed.")
                    return 0

            expires_val = args.expires_in_hours if args.expires_in_hours > 0 else None
            rotated = await rotate_identities(
                session,
                env=args.env,
                expires_in_hours=expires_val,
            )

            output = format_credentials_output(
                rotated,
                title="AISOP DEMO IDENTITY CREDENTIAL ROTATION - SECURE ONE-TIME CREDENTIAL OUTPUT",
            )
            print(output)
            return 0

        # 4. Initial Provisioning Mode
        # Check for existing records first
        status = await check_existing_demo_identities(session)
        if status["has_collisions"]:
            print("\n[ERROR] Demo identities already exist in the database:")
            for a in status["analysts"]:
                print(f"  - Analyst '{a.username}' (Active: {a.is_active})")
            for c in status["clients"]:
                print(f"  - Client '{c.client_name}' (Prefix: {c.token_prefix}, Active: {c.is_active})")
            print("\nAborting. To check status: python backend/scripts/provision_demo_identities.py --status")
            print("To rotate credentials:  python backend/scripts/provision_demo_identities.py --rotate")
            print("To revoke existing:     python backend/scripts/provision_demo_identities.py --revoke")
            return 1

        # Operator Confirmation Gate
        if not args.yes:
            print("\n" + "=" * 60)
            print("  AISOP DEMO IDENTITY PROVISIONING PLAN")
            print("=" * 60)
            print(f"  Target Database:    {target_db}")
            print(f"  Token Environment:  {args.env}")
            print(f"  Expiration Window:  {args.expires_in_hours} hours" if args.expires_in_hours > 0 else "  Expiration Window:  Never")
            print("  Identities to add:")
            for cfg in DEMO_CONFIGS:
                print(f"    - {cfg['username']} ({cfg['global_role']}) -> {cfg['client_name']}")
            print("=" * 60)
            confirm = input("\nConfirm writing these demo identities to database? (yes/no): ").strip().lower()
            if confirm != "yes":
                print("[ABORTED] Operator declined confirmation. Zero database modifications performed.")
                return 0

        expires_val = args.expires_in_hours if args.expires_in_hours > 0 else None
        provisioned = await provision_identities(
            session,
            env=args.env,
            expires_in_hours=expires_val,
        )

        output = format_credentials_output(provisioned)
        print(output)
        return 0


def main() -> None:
    try:
        code = asyncio.run(main_async())
        sys.exit(code)
    except KeyboardInterrupt:
        print("\n[CANCELLED] Operation interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        print(f"\n[FATAL ERROR] Provisioning failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
