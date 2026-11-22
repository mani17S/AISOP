"""
Event time versus ingestion time, and time zones (UTC, IST and others).

An alert's own event time is the time it was generated at the source. It is kept exactly as an instant and never replaced
by the ingestion time. (A time with no zone is handled by the Stage 7B design: UTC is assumed, flagged on the record and
disclosed in the report; see test_stage7b_legacy_and_identity.py.) No network; SQLite in-memory like the other alert tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.modules.alerts.adapter_protocol import require_event_time
from tests.unit.test_hostile_telemetry import ingest, load_fixture, set_event_time, stored_rows


def _utc(value: str) -> datetime:
    return require_event_time(value).astimezone(timezone.utc)


def test_the_same_instant_written_in_utc_ist_and_new_york_is_the_same_utc_time():
    assert _utc("2026-11-10T16:30:00Z") == _utc("2026-11-10T22:00:00+05:30") == _utc("2026-11-10T11:30:00-05:00")
    assert _utc("2026-11-10T22:00:00+05:30") == datetime(2026, 11, 10, 16, 30, tzinfo=timezone.utc)


def test_an_alert_generated_at_10pm_ist_and_ingested_at_2am_keeps_its_own_event_time(db_session):
    rec = load_fixture("generic_siem_correlation_alert.json")
    set_event_time(rec, "2026-11-10T22:00:00+05:30")  # generated at 22:00 IST = 16:30 UTC
    resp = ingest(db_session, "generic_siem", [rec])
    assert resp.total_normalized == 1 and resp.errors == []
    raws, events = stored_rows(db_session)
    event_time = events[0].event_timestamp
    event_time = event_time if event_time.tzinfo else event_time.replace(tzinfo=timezone.utc)
    ingested = raws[0].ingested_at
    ingested = ingested if ingested.tzinfo else ingested.replace(tzinfo=timezone.utc)
    assert event_time.astimezone(timezone.utc) == datetime(2026, 11, 10, 16, 30, tzinfo=timezone.utc)
    # The two times are different facts and both are kept. Ingestion happened now, not at the event time.
    assert ingested != event_time and abs((ingested - datetime.now(timezone.utc)).total_seconds()) < 120
    assert ingested - event_time > timedelta(days=1)  # this fixture's event is in the past: a late arrival, kept as such


def test_a_missing_event_time_is_never_replaced_by_the_ingestion_time(db_session):
    from tests.unit.test_hostile_telemetry import _MISSING

    rec = load_fixture("generic_siem_correlation_alert.json")
    set_event_time(rec, _MISSING)
    resp = ingest(db_session, "generic_siem", [rec])
    assert resp.total_normalized == 0 and "ALERT_TIMESTAMP_MISSING_OR_INVALID" in resp.errors[0].error
