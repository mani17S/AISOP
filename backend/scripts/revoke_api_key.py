#!/usr/bin/env python3
"""
Revoke an API key immediately. This is the containment step when a key may be stolen: the key stops working on its next request.

    .venv\\Scripts\\python.exe backend\\scripts\\revoke_api_key.py --prefix 0123456789abcdef
    .venv\\Scripts\\python.exe backend\\scripts\\revoke_api_key.py --prefix 0123456789abcdef --deactivate-analyst

The prefix is the 16 hex identifier that appears on the Security page alerts and in the key (aisop_live_<prefix>_<secret>). It is
not secret and the key itself is never needed. The database is whichever DATABASE_URL points at. Nothing is deleted: the client
row is deactivated, so the audit trail and the case history keep pointing at the same account.
--deactivate-analyst also deactivates the account, which stops every key it owns.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from pathlib import Path

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from app.db.session import get_session_factory  # noqa: E402
from app.models.analyst import Analyst, AnalystApiClient  # noqa: E402


async def main_async() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", required=True, help="the 16 hex key identifier")
    ap.add_argument("--deactivate-analyst", action="store_true", help="also deactivate the account (stops all of its keys)")
    args = ap.parse_args()
    if not re.fullmatch(r"[0-9a-f]{16}", args.prefix):
        print("The prefix must be exactly 16 lowercase hex characters (not the whole key).", file=sys.stderr)
        return 1
    async with get_session_factory()() as session:
        client = (await session.execute(select(AnalystApiClient).where(AnalystApiClient.token_prefix == args.prefix))).scalars().first()
        if client is None:
            print("No key with that identifier exists in this database.", file=sys.stderr)
            return 1
        analyst = (await session.execute(select(Analyst).where(Analyst.id == client.analyst_id))).scalars().first()
        was_active = bool(client.is_active)
        client.is_active = False
        if args.deactivate_analyst and analyst is not None:
            analyst.is_active = False
        await session.commit()
    who = analyst.username if analyst is not None else "unknown account"
    print(f"Key {args.prefix} ({client.client_name}, account {who}) is revoked." + ("" if was_active else " It was already inactive."))
    if args.deactivate_analyst:
        print(f"Account {who} is deactivated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async()))
