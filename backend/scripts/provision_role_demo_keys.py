#!/usr/bin/env python3
"""
Create demo identities for the roles the main provisioning script does not cover: a lead (analyst_tier_2) and a security
admin (security_admin), so each role can be shown with its own key instead of switching a selector.

    .venv\\Scripts\\python.exe backend\\scripts\\provision_role_demo_keys.py --out D:\\AISOP-Control\\role_demo_keys.txt --expires 2027-01-10

Tokens are written to the --out file only and are NEVER printed. The database is whichever DATABASE_URL points at.
Refuses to run if the usernames already exist (nothing is overwritten). Each key is stored hashed (SHA-256); the plaintext
cannot be recovered later. Synthetic demo identities only.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from app.core.auth import hash_canonical_token  # noqa: E402
from app.db.session import get_session_factory  # noqa: E402
from app.models.analyst import Analyst, AnalystApiClient  # noqa: E402

IDENTITIES = (
    ("viva_lead", "analyst_tier_2", "viva-lead-workstation", "Lead: assigns analysts, closes cases"),
    ("viva_admin", "security_admin", "viva-admin-console", "Security admin: security page, no implicit case access"),
)


async def main_async() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="file the tokens are written to (use a D: path outside the repository)")
    ap.add_argument("--expires", required=True, help="expiry date, YYYY-MM-DD (end of that day, UTC)")
    ap.add_argument("--env", default="live", choices=["live", "test"])
    args = ap.parse_args()
    expires_at = datetime.strptime(args.expires, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        print("The expiry date is in the past.", file=sys.stderr)
        return 1

    factory = get_session_factory()
    lines: list[str] = []
    async with factory() as session:
        taken = (await session.execute(select(Analyst.username).where(Analyst.username.in_([i[0] for i in IDENTITIES])))).scalars().all()
        if taken:
            print(f"Refusing to continue: these usernames already exist: {', '.join(sorted(taken))}", file=sys.stderr)
            return 1
        now = datetime.now(timezone.utc)
        for username, role, client_name, _label in IDENTITIES:
            analyst = Analyst(id=uuid.uuid4(), username=username, email=f"{username}@example.invalid", global_role=role, is_active=True, created_at=now, updated_at=now)
            session.add(analyst)
            await session.flush()
            prefix = secrets.token_hex(8)
            token = f"aisop_{args.env}_{prefix}_{secrets.token_hex(32)}"
            session.add(
                AnalystApiClient(
                    id=uuid.uuid4(),
                    analyst_id=analyst.id,
                    client_name=client_name,
                    token_prefix=prefix,
                    hashed_secret=hash_canonical_token(token),
                    is_active=True,
                    expires_at=expires_at,
                    created_at=now,
                )
            )
            lines.append(f"{username}={token}")
        await session.commit()
    out = Path(args.out)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Created {len(IDENTITIES)} identities ({', '.join(i[0] for i in IDENTITIES)}), expiring {expires_at.date()}. Tokens written to {out}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async()))
