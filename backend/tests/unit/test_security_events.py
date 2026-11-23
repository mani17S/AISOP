"""
Attack visibility: what the server observed being done to it.

The recorder counts suspicious responses per minute, source address and kind. It never stores a credential, a request
body or a header value other than a cleaned and truncated user agent, caps its own memory under attack, and is readable
only by a security admin. A quiet page is not proof that nothing happened: it shows what this process saw.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from fastapi import FastAPI

from app.api.dependencies import get_current_analyst  # noqa: F401  (keeps import order the same as the other API tests)
from app.core.config import Settings, get_settings
from app.core.security_events import SecurityEventBuffer, classify, clean_text
from app.db.session import get_db_session
from app.main import create_app
from app.services.security_event_service import flush_security_events, purge_older_than
from tests.unit.test_case_api import seed_analyst_with_token


# ── pure rules ────────────────────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "status_code,route_matched,reason,expected",
    [
        (401, True, None, "auth_failed"),
        (403, True, None, "forbidden"),
        (404, False, None, "unknown_path"),
        (404, True, None, None),  # a missing record on a real route is ordinary use, not a probe
        (405, False, None, "method_not_allowed"),
        (413, True, None, "payload_too_large"),
        (415, True, None, "unsupported_media_type"),
        (422, True, None, "malformed_request"),
        (400, True, None, "malformed_request"),
        (429, True, None, "rate_limited"),
        (429, True, "auth_locked_out", "auth_locked_out"),
        (200, True, None, None),
        (201, True, None, None),
        (500, True, None, None),
    ],
)
def test_classify(status_code, route_matched, reason, expected):
    assert classify(status_code, route_matched, reason) == expected


def test_clean_text_removes_control_characters_and_bounds_length():
    hostile = "\x1b[31mred\x1b[0m\r\nSet-Cookie: x=1\x00\x07 " + "A" * 500
    out = clean_text(hostile, 80)
    assert len(out) <= 80
    assert all(ord(c) >= 32 and ord(c) != 127 for c in out)
    assert "\n" not in out and "\r" not in out and "\x1b" not in out
    assert clean_text(None, 10) == "" and clean_text(12345, 10) == "12345"


def test_buffer_merges_repeats_and_keeps_only_the_first_samples():
    buf = SecurityEventBuffer(max_keys=10)
    t = datetime(2026, 11, 22, 10, 0, 30, tzinfo=timezone.utc)
    for _ in range(5):
        buf.record("auth_failed", "203.0.113.7", "GET", "/api/v1/cases", 401, "curl/8", t)
    buf.record("auth_failed", "203.0.113.7", "GET", "/api/v1/cases", 401, "other", t.replace(second=59))  # same minute
    buckets, dropped = buf.drain()
    assert dropped == 0 and len(buckets) == 1
    assert buckets[0].count == 6 and buckets[0].user_agent == "curl/8"
    assert buckets[0].bucket_minute == t.replace(second=0, microsecond=0)
    assert buf.drain() == ([], 0), "drain empties the buffer"


def test_buffer_caps_memory_under_a_flood_from_many_sources_and_counts_what_it_dropped():
    buf = SecurityEventBuffer(max_keys=50)
    t = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(1000):
        buf.record("unknown_path", f"198.51.100.{i % 250}", "GET", f"/probe-{i}", 404, "scanner", t.replace(minute=i % 60))
    buckets, dropped = buf.drain()
    assert len(buckets) <= 50
    assert dropped == 1000 - sum(b.count for b in buckets) and dropped > 0
    assert buf.dropped_total == dropped


def test_buffer_cleans_what_it_stores():
    buf = SecurityEventBuffer()
    t = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)
    buf.record("unknown_path", "203.0.113.9\r\nX: y", "GET\x00", "/a\r\nb" + "z" * 400, 404, "ua\x1b[31m" + "u" * 400, t)
    [b] = buf.drain()[0]
    for value in (b.source_ip, b.method, b.path, b.user_agent):
        assert "\r" not in value and "\n" not in value and "\x00" not in value and "\x1b" not in value
    assert len(b.path) <= 160 and len(b.user_agent) <= 160 and len(b.source_ip) <= 64 and len(b.method) <= 8


# ── through the real application ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def auth_settings() -> Settings:
    return Settings(_env_file=None, API_AUTH_ENABLED=True, API_AUTH_ALLOW_LEGACY_KEYS=False, RATE_LIMIT_ENABLED=False)


@pytest.fixture
def app_instance(db_session, auth_settings: Settings) -> FastAPI:
    app = create_app()

    async def override_get_db():
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    app.dependency_overrides[get_db_session] = override_get_db
    app.dependency_overrides[get_settings] = lambda: auth_settings
    return app


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _kinds(app) -> dict[str, int]:
    out: dict[str, int] = {}
    for key, bucket in app.state.security_events._buckets.items():
        out[bucket.kind] = out.get(bucket.kind, 0) + bucket.count
    return out


@pytest.mark.anyio
async def test_a_rejected_credential_a_probe_and_a_normal_request_are_told_apart(app_instance, db_session):
    token, _ = await seed_analyst_with_token(db_session, prefix="sec-ok-1", username="sec_analyst", global_role="analyst_tier_1")
    bogus = "aisop_live_" + "0" * 16 + "_" + "f" * 64
    async with _client(app_instance) as c:
        assert (await c.get("/api/v1/health")).status_code == 200
        assert (await c.get("/api/v1/cases")).status_code == 401  # no credential
        assert (await c.get("/api/v1/cases", headers={"X-API-Key": bogus})).status_code == 401  # wrong credential
        assert (await c.get("/wp-admin/setup-config.php")).status_code == 404  # a scanner probing for another product
        assert (await c.get(f"/api/v1/cases/{uuid.uuid4()}", headers={"Authorization": f"Bearer {token}"})).status_code == 404
    kinds = _kinds(app_instance)
    assert kinds.get("auth_failed") == 2
    assert kinds.get("unknown_path") == 1
    assert sum(kinds.values()) == 3, "health, and a missing record on a real route, are not attacks"


@pytest.mark.anyio
async def test_no_credential_or_body_is_ever_recorded(app_instance, db_session):
    secret = "aisop_live_" + "a1" * 8 + "_" + "c3" * 32
    async with _client(app_instance) as c:
        await c.get("/api/v1/cases", headers={"X-API-Key": secret, "User-Agent": "scanner/1.0"})
        await c.post("/api/v1/alerts/ingest", headers={"Authorization": f"Bearer {secret}"}, json={"password": "hunter2-secret-body"})
    dump = json.dumps([vars(b) if hasattr(b, "__dict__") else str(b) for b in app_instance.state.security_events._buckets.values()], default=str)
    assert secret not in dump and "a1a1a1a1a1a1a1a1" not in dump and "hunter2-secret-body" not in dump
    assert "scanner/1.0" in dump  # the user agent is kept, cleaned


@pytest.mark.anyio
async def test_a_login_lockout_is_recorded_as_a_lockout_not_as_ordinary_rate_limiting(app_instance, db_session):
    bogus = "aisop_live_" + "1" * 16 + "_" + "2" * 64
    async with _client(app_instance) as c:
        codes = [(await c.get("/api/v1/cases", headers={"X-API-Key": bogus})).status_code for _ in range(30)]
    assert 429 in codes, "repeated bad keys are locked out"
    kinds = _kinds(app_instance)
    assert kinds.get("auth_locked_out", 0) >= 1 and kinds.get("rate_limited", 0) == 0


@pytest.mark.anyio
async def test_only_a_security_admin_can_read_the_overview(app_instance, db_session):
    admin, _ = await seed_analyst_with_token(db_session, prefix="sec-admin-1", username="sec_admin", global_role="security_admin")
    analyst, _ = await seed_analyst_with_token(db_session, prefix="sec-tier1-1", username="sec_t1", global_role="analyst_tier_1")
    lead, _ = await seed_analyst_with_token(db_session, prefix="sec-tier2-1", username="sec_t2", global_role="analyst_tier_2")
    async with _client(app_instance) as c:
        assert (await c.get("/api/v1/security/overview")).status_code == 401
        assert (await c.get("/api/v1/security/overview", headers={"Authorization": f"Bearer {analyst}"})).status_code == 403
        assert (await c.get("/api/v1/security/overview", headers={"Authorization": f"Bearer {lead}"})).status_code == 403
        assert (await c.get("/api/v1/security/overview", headers={"Authorization": f"Bearer {admin}"})).status_code == 200


@pytest.mark.anyio
async def test_overview_reports_what_was_flushed_and_says_what_it_cannot_know(app_instance, db_session):
    admin, _ = await seed_analyst_with_token(db_session, prefix="sec-admin-2", username="sec_admin2", global_role="security_admin")
    async with _client(app_instance) as c:
        for _ in range(4):
            await c.get("/api/v1/cases")
        await c.get("/.env")
        await flush_security_events(app_instance.state.security_events, db_session)
        body = (await c.get("/api/v1/security/overview?hours=24", headers={"Authorization": f"Bearer {admin}"})).json()
    totals = {row["kind"]: row["count"] for row in body["totals_by_kind"]}
    assert totals["auth_failed"] == 4 and totals["unknown_path"] == 1
    assert body["window_hours"] == 24 and body["total_events"] >= 5
    assert any(r["path"] == "/.env" and r["kind"] == "unknown_path" for r in body["recent"])
    assert body["top_sources"] and body["top_paths"] and body["timeline"]
    assert body["not_recorded_since_start"] == 0
    assert any("does not prove" in note for note in body["notes"]), "a quiet page must not read as proof of safety"
    assert all("X-API-Key" not in json.dumps(r) for r in body["recent"])


@pytest.mark.anyio
async def test_the_window_is_bounded(app_instance, db_session):
    admin, _ = await seed_analyst_with_token(db_session, prefix="sec-admin-3", username="sec_admin3", global_role="security_admin")
    async with _client(app_instance) as c:
        for hours in (0, -5, 100000, "abc"):
            r = await c.get(f"/api/v1/security/overview?hours={hours}", headers={"Authorization": f"Bearer {admin}"})
            assert r.status_code == 422, hours


@pytest.mark.anyio
async def test_old_rows_are_purged(app_instance, db_session):
    buf = app_instance.state.security_events
    old = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    buf.record("auth_failed", "203.0.113.1", "GET", "/api/v1/cases", 401, "x", old)
    await flush_security_events(buf, db_session)
    assert await purge_older_than(db_session, days=30, now=datetime(2026, 11, 22, tzinfo=timezone.utc)) == 1
    assert await purge_older_than(db_session, days=30, now=datetime(2026, 11, 22, tzinfo=timezone.utc)) == 0


# ── a failed write must not lose the counts ──────────────────────────────────────────────────────────────────

class _FailingSession:
    def __init__(self):
        self.added = []
        self.rolled_back = False

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        raise RuntimeError("database refused the write")

    async def rollback(self):
        self.rolled_back = True


@pytest.mark.anyio
async def test_a_failed_write_puts_the_counts_back_so_the_next_attempt_can_save_them():
    buf = SecurityEventBuffer()
    t = datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc)
    for _ in range(3):
        buf.record("auth_failed", "203.0.113.7", "GET", "/api/v1/cases", 401, "curl", t)
    session = _FailingSession()
    with pytest.raises(RuntimeError):
        await flush_security_events(buf, session)
    assert session.rolled_back
    # the events that arrived meanwhile merge with the restored ones
    buf.record("auth_failed", "203.0.113.7", "GET", "/api/v1/cases", 401, "curl", t)
    [bucket], dropped = buf.drain()
    assert bucket.count == 4 and dropped == 0


def test_restore_respects_the_memory_cap():
    buf = SecurityEventBuffer(max_keys=2)
    t = datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc)
    for i in range(2):
        buf.record("unknown_path", f"198.51.100.{i}", "GET", "/x", 404, "s", t)
    taken, _ = buf.drain()
    buf.record("unknown_path", "198.51.100.9", "GET", "/y", 404, "s", t)
    buf.record("unknown_path", "198.51.100.8", "GET", "/y", 404, "s", t)
    buf.restore(taken)  # the buffer already holds 2 keys: restoring must not exceed the cap
    buckets, dropped = buf.drain()
    assert len(buckets) <= 2 and dropped == sum(b.count for b in taken)


# ── what the page reports must be what actually happened ─────────────────────────────────────────────────────

def test_different_probed_paths_are_counted_separately_not_merged_into_the_first():
    buf = SecurityEventBuffer()
    t = datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc)
    for path in ("/.env", "/wp-login.php", "/phpmyadmin/", "/.env"):
        buf.record("unknown_path", "203.0.113.7", "GET", path, 404, "zgrab", t)
    buckets, _ = buf.drain()
    counts = {b.path: b.count for b in buckets}
    assert counts == {"/.env": 2, "/wp-login.php": 1, "/phpmyadmin/": 1}


@pytest.mark.anyio
async def test_a_matched_route_is_reported_with_its_full_path_and_ids_are_replaced(app_instance, db_session):
    token, _ = await seed_analyst_with_token(db_session, prefix="sec-viewer-9", username="sec_v9", global_role="analyst_tier_1")
    case_id = uuid.uuid4()
    async with _client(app_instance) as c:
        # wrong method on a real, parameterised route: recorded with the route path, not with this particular id
        await c.delete(f"/api/v1/cases/{case_id}", headers={"Authorization": f"Bearer {token}"})
        await c.get("/api/v1/cases")  # no credential
    paths = {b.path for b in app_instance.state.security_events._buckets.values()}
    assert "/api/v1/cases" in paths
    assert not any(str(case_id) in p for p in paths), "an identifier must never become part of what is stored"
    assert "/api/v1/cases/{id}" in paths
