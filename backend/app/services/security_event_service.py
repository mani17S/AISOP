"""
Security events: write the in-memory counts to the database, purge old rows, and summarise them for the Security page.

Aggregation is done in Python over a bounded number of rows so it behaves the same on PostgreSQL and SQLite. Everything
returned is a count or a cleaned, truncated sample; nothing here can reveal a credential because none is ever stored.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.security_events import SecurityEventBuffer
from app.models.security_event import SecurityEventModel
from sqlalchemy import delete, select

#: At most this many rows are read to build one overview (a window under attack could hold more; the page says so).
MAX_ROWS_READ = 20_000
RECENT_LIMIT = 50
TOP_LIMIT = 10

NOTES = (
    "This page shows what this server process observed. It does not prove that nothing else happened: traffic stopped "
    "before it reached the application is never seen, and counts are lost if the server restarts before they are written.",
    "A source address is the nearest address the server could trust. Behind a proxy it is the proxy address unless the "
    "proxy is configured as trusted.",
    "Nothing here blocks anything. Blocking is done by the lockout, the rate limits and the request size caps.",
)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return _aware(value).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def flush_security_events(buffer: SecurityEventBuffer, session: Any) -> int:
    """Write what the buffer holds as rows. Returns the number of rows written."""
    buckets, _ = buffer.drain()
    if not buckets:
        return 0
    now = datetime.now(timezone.utc)
    for b in buckets:
        session.add(
            SecurityEventModel(
                bucket_minute=b.bucket_minute,
                kind=b.kind,
                source_ip=b.source_ip,
                method=b.method,
                path_sample=b.path,
                user_agent_sample=b.user_agent or None,
                status_code=b.status_code,
                event_count=b.count,
                recorded_at=now,
            )
        )
    try:
        await session.commit()
    except Exception:
        await session.rollback()
        buffer.restore(buckets)  # keep the counts for the next attempt: a refused write must not erase evidence of an attack
        raise
    return len(buckets)


async def purge_older_than(session: Any, days: int, now: datetime | None = None) -> int:
    """Delete rows older than ``days``. Returns how many were deleted."""
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    result = await session.execute(delete(SecurityEventModel).where(SecurityEventModel.bucket_minute < cutoff))
    await session.commit()
    return int(result.rowcount or 0)


async def overview(session: Any, hours: int, not_recorded_since_start: int, now: datetime | None = None) -> dict[str, Any]:
    end = now or datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    rows = (
        (
            await session.execute(
                select(SecurityEventModel)
                .where(SecurityEventModel.bucket_minute >= start)
                .order_by(SecurityEventModel.bucket_minute.desc())
                .limit(MAX_ROWS_READ)
            )
        )
        .scalars()
        .all()
    )
    by_kind: Counter[str] = Counter()
    by_source: Counter[str] = Counter()
    kinds_by_source: dict[str, Counter[str]] = {}
    by_path: Counter[tuple[str, str]] = Counter()
    by_hour: Counter[datetime] = Counter()
    for r in rows:
        n = int(r.event_count)
        minute = _aware(r.bucket_minute)
        by_kind[r.kind] += n
        by_source[r.source_ip] += n
        kinds_by_source.setdefault(r.source_ip, Counter())[r.kind] += n
        by_path[(r.kind, r.path_sample)] += n
        by_hour[minute.replace(minute=0, second=0, microsecond=0)] += n

    timeline = []
    cursor = start.replace(minute=0, second=0, microsecond=0)
    while cursor <= end:
        timeline.append({"hour": _iso(cursor), "count": by_hour.get(cursor, 0)})
        cursor += timedelta(hours=1)

    return {
        "window_hours": hours,
        "window_start": _iso(start),
        "window_end": _iso(end),
        "total_events": sum(by_kind.values()),
        "totals_by_kind": [{"kind": k, "count": c} for k, c in by_kind.most_common()],
        "timeline": timeline,
        "top_sources": [
            {"source_ip": ip, "count": c, "kinds": [{"kind": k, "count": kc} for k, kc in kinds_by_source[ip].most_common(3)]}
            for ip, c in by_source.most_common(TOP_LIMIT)
        ],
        "top_paths": [{"kind": k, "path": p, "count": c} for (k, p), c in by_path.most_common(TOP_LIMIT)],
        "recent": [
            {
                "time": _iso(r.bucket_minute),
                "kind": r.kind,
                "status_code": r.status_code,
                "method": r.method,
                "path": r.path_sample,
                "source_ip": r.source_ip,
                "user_agent": r.user_agent_sample,
                "count": int(r.event_count),
            }
            for r in rows[:RECENT_LIMIT]
        ],
        "rows_read": len(rows),
        "truncated": len(rows) >= MAX_ROWS_READ,
        "not_recorded_since_start": not_recorded_since_start,
        "notes": list(NOTES),
    }
