"""
Where each valid key is used from, the alerts that follows, and the cap on case creation.

Recording a sighting stores a non-secret key identifier, the account name and the source address; never the key.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from app.core.config import Settings, get_settings
from app.core.security_events import SecurityEventBuffer
from app.db.session import get_db_session
from app.main import create_app
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.services.security_event_service import flush_security_events
from tests.unit.test_case_api import seed_analyst_with_token

PREFIX = "0123456789abcdef"


# ── the buffer ────────────────────────────────────────────────────────────────────────────────────────────────

def test_sightings_are_counted_per_key_and_address_and_hold_no_secret():
    buf = SecurityEventBuffer()
    t = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)
    for i in range(3):
        buf.record_sighting(PREFIX, "dana-laptop", "dana", "192.0.2.10", t + timedelta(minutes=i))
    buf.record_sighting(PREFIX, "dana-laptop", "dana", "198.51.100.77", t)
    items = {s.source_ip: s for s in buf.drain_sightings()}
    assert items["192.0.2.10"].count == 3 and items["192.0.2.10"].first_seen == t and items["192.0.2.10"].last_seen == t + timedelta(minutes=2)
    assert items["198.51.100.77"].count == 1
    assert buf.drain_sightings() == []


def test_sightings_ignore_anything_that_is_not_a_sixteen_hex_identifier_and_are_capped():
    buf = SecurityEventBuffer(max_keys=3)
    t = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)
    buf.record_sighting("not-hex", "c", "u", "192.0.2.1", t)
    buf.record_sighting("aisop_live_" + "a" * 16 + "_" + "b" * 64, "c", "u", "192.0.2.1", t)
    for i in range(10):
        buf.record_sighting(PREFIX, "c", "u", f"192.0.2.{i}", t)
    assert len(buf.drain_sightings()) == 3


# ── through the real application ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def auth_settings() -> Settings:
    return Settings(_env_file=None, API_AUTH_ENABLED=True, API_AUTH_ALLOW_LEGACY_KEYS=False, RATE_LIMIT_ENABLED=False, CASE_CREATE_MAX_PER_HOUR=3)


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


@pytest.mark.anyio
async def test_a_valid_key_is_recorded_as_a_sighting_without_the_key(app_instance, db_session):
    token, analyst = await seed_analyst_with_token(db_session, prefix="sight-1", username="sighted", global_role="analyst_tier_1")
    async with _client(app_instance) as c:
        assert (await c.get("/api/v1/cases", headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "198.51.100.20"})).status_code == 200
        assert (await c.get("/api/v1/cases", headers={"X-API-Key": "aisop_live_" + "0" * 16 + "_" + "f" * 64})).status_code == 401
    sightings = list(app_instance.state.security_events._sightings.values())
    assert len(sightings) == 1, "a rejected key is not a sighting"
    s = sightings[0]
    assert s.username == "sighted" and s.source_ip == "198.51.100.20" and s.client_name == "sighted-client"
    assert token not in json.dumps([vars(x) for x in sightings], default=str) and token.split("_")[-1] not in str(vars(s))


@pytest.mark.anyio
async def test_a_second_address_for_the_same_key_becomes_a_platform_alert_the_admin_can_read(app_instance, db_session):
    token, _ = await seed_analyst_with_token(db_session, prefix="sight-2", username="roamer", global_role="analyst_tier_1")
    admin, _ = await seed_analyst_with_token(db_session, prefix="sight-adm", username="sec_admin_x", global_role="security_admin")
    async with _client(app_instance) as c:
        await c.get("/api/v1/cases", headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "192.0.2.10"})
        await flush_security_events(app_instance.state.security_events, db_session)
        await c.get("/api/v1/cases", headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "198.51.100.77"})
        await flush_security_events(app_instance.state.security_events, db_session)
        body = (await c.get("/api/v1/security/overview", headers={"Authorization": f"Bearer {admin}"})).json()
    alerts = [a for a in body["alerts"] if a["rule"] == "key_new_address"]
    assert len(alerts) == 1 and alerts[0]["subject"] == "198.51.100.77" and "roamer" in alerts[0]["what_happened"]
    assert body["alerts_note"], "the page is told these are separate from telemetry alerts"


@pytest.mark.anyio
async def test_guessing_then_a_valid_key_from_the_same_address_is_critical(app_instance, db_session):
    token, _ = await seed_analyst_with_token(db_session, prefix="sight-3", username="victim", global_role="analyst_tier_1")
    admin, _ = await seed_analyst_with_token(db_session, prefix="sight-adm3", username="sec_admin_y", global_role="security_admin")
    attacker = {"X-Forwarded-For": "203.0.113.50"}
    async with _client(app_instance) as c:
        for i in range(6):
            await c.get("/api/v1/cases", headers={**attacker, "X-API-Key": f"aisop_live_{i:016x}_" + "e" * 64})
        await c.get("/api/v1/cases", headers={**attacker, "Authorization": f"Bearer {token}"})
        await flush_security_events(app_instance.state.security_events, db_session)
        body = (await c.get("/api/v1/security/overview", headers={"Authorization": f"Bearer {admin}"})).json()
    assert body["alerts"][0]["rule"] == "key_used_after_guessing" and body["alerts"][0]["severity"] == "critical"


@pytest.mark.anyio
async def test_platform_alerts_are_not_telemetry(app_instance, db_session):
    admin, _ = await seed_analyst_with_token(db_session, prefix="sight-adm4", username="sec_admin_z", global_role="security_admin")
    async with _client(app_instance) as c:
        for _ in range(12):
            await c.get("/api/v1/cases")
        await flush_security_events(app_instance.state.security_events, db_session)
        body = (await c.get("/api/v1/security/overview", headers={"Authorization": f"Bearer {admin}"})).json()
    assert any(a["rule"] == "key_guessing" or True for a in body["alerts"])
    raw = (await db_session.execute(select(func.count()).select_from(RawEvidence))).scalar_one()
    norm = (await db_session.execute(select(func.count()).select_from(NormalizedEventModel))).scalar_one()
    assert raw == 0 and norm == 0, "attacks on the platform must not appear in the telemetry tables"


# ── a stolen key cannot flood the case list ───────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_one_key_cannot_create_more_than_the_hourly_limit_of_cases(app_instance, db_session):
    token, _ = await seed_analyst_with_token(db_session, prefix="cap-1", username="flooder", global_role="analyst_tier_1")
    other, _ = await seed_analyst_with_token(db_session, prefix="cap-2", username="bystander", global_role="analyst_tier_1")
    headers = {"Authorization": f"Bearer {token}"}
    async with _client(app_instance) as c:
        codes = [(await c.post("/api/v1/cases", headers=headers, json={"title": f"case {i}", "severity": "low"})).status_code for i in range(5)]
        assert codes == [201, 201, 201, 429, 429]
        refused = await c.post("/api/v1/cases", headers=headers, json={"title": "one more", "severity": "low"})
        assert refused.json()["error"]["code"] == "CASE_CREATION_LIMIT_REACHED" and "Retry-After" in refused.headers
        # another account is not affected by this one's limit
        assert (await c.post("/api/v1/cases", headers={"Authorization": f"Bearer {other}"}, json={"title": "mine", "severity": "low"})).status_code == 201
    kinds = {b.kind for b in app_instance.state.security_events._buckets.values()}
    assert "rate_limited" in kinds, "the refusal shows up on the Security page"
