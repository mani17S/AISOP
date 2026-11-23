"""
Platform security alerts: alerts about AISOP itself (someone guessing keys, probing for secrets, a key used from somewhere
new), kept apart from the telemetry alerts that come from the customer's sources.

The rules work on what the server observed and are honest about it: a valid key used from a new address may be its owner on a
new network, so the alert says to confirm with the owner and does not claim a breach. No network, no database.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

from app.services.security_alert_service import derive_alerts

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
START = NOW - timedelta(hours=24)


def ev(kind, ip, path="/api/v1/cases", count=1, minutes_ago=5):
    return NS(kind=kind, source_ip=ip, path_sample=path, event_count=count, bucket_minute=NOW - timedelta(minutes=minutes_ago))


def seen(prefix, ip, first_minutes_ago, last_minutes_ago=1, user="dana", client="dana-laptop", n=3):
    return NS(token_prefix=prefix, client_name=client, username=user, source_ip=ip, request_count=n,
              first_seen=NOW - timedelta(minutes=first_minutes_ago), last_seen=NOW - timedelta(minutes=last_minutes_ago))


def run(events=(), sightings=(), cases=()):
    return derive_alerts(list(events), list(sightings), list(cases), now=NOW, window_start=START)


def rules(alerts):
    return {a["rule"] for a in alerts}


# ── guessing keys ─────────────────────────────────────────────────────────────────────────────────────────────

def test_many_rejected_keys_from_one_address_raise_a_key_guessing_alert():
    alerts = run([ev("auth_failed", "203.0.113.7", count=12)])
    [a] = [x for x in alerts if x["rule"] == "key_guessing"]
    assert a["severity"] == "high" and a["subject"] == "203.0.113.7" and a["count"] == 12
    assert "203.0.113.7" in a["title"]
    assert a["what_happened"] and a["why_it_matters"] and a["recommended_action"]


def test_a_lockout_alone_is_enough_for_a_key_guessing_alert():
    assert "key_guessing" in rules(run([ev("auth_locked_out", "203.0.113.8", count=1)]))


def test_a_few_typos_are_not_an_alert():
    assert run([ev("auth_failed", "198.51.100.4", count=3)]) == []


def test_failures_from_different_addresses_are_not_added_together():
    assert "key_guessing" not in rules(run([ev("auth_failed", f"203.0.113.{i}", count=4) for i in range(1, 6)]))


# ── probing for secrets ───────────────────────────────────────────────────────────────────────────────────────

def test_requests_for_secret_and_admin_paths_raise_a_probing_alert():
    paths = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/.aws/credentials"]
    alerts = run([ev("unknown_path", "203.0.113.9", path=p) for p in paths])
    [a] = [x for x in alerts if x["rule"] == "secret_probing"]
    assert a["severity"] == "medium" and a["count"] == 5 and a["subject"] == "203.0.113.9"


def test_one_stray_404_is_not_a_probing_alert():
    assert run([ev("unknown_path", "203.0.113.9", path="/favicon.ico"), ev("unknown_path", "203.0.113.9", path="/.env")]) == []


# ── a key that works after guessing ───────────────────────────────────────────────────────────────────────────

def test_a_valid_key_used_from_an_address_that_was_guessing_keys_is_critical():
    alerts = run([ev("auth_failed", "203.0.113.7", count=6, minutes_ago=30)], [seen("a" * 16, "203.0.113.7", first_minutes_ago=10)])
    [a] = [x for x in alerts if x["rule"] == "key_used_after_guessing"]
    assert a["severity"] == "critical" and a["subject"] == "203.0.113.7"
    assert alerts[0]["rule"] == "key_used_after_guessing", "the most serious alert is listed first"


def test_the_same_address_succeeding_without_failures_is_ordinary():
    assert run([], [seen("a" * 16, "203.0.113.7", first_minutes_ago=600)]) == []


# ── a key from somewhere new ──────────────────────────────────────────────────────────────────────────────────

def test_a_key_first_used_from_a_new_address_raises_an_alert_naming_the_owner():
    p = "b" * 16
    alerts = run([], [seen(p, "192.0.2.10", first_minutes_ago=5000, last_minutes_ago=100), seen(p, "198.51.100.77", first_minutes_ago=20)])
    [a] = [x for x in alerts if x["rule"] == "key_new_address"]
    assert a["severity"] == "high" and a["subject"] == "198.51.100.77"
    assert "dana" in a["what_happened"] and "192.0.2.10" not in a["title"]
    assert "owner" in a["recommended_action"].lower() and "not necessarily" in a["why_it_matters"].lower()


def test_the_first_ever_sighting_of_a_key_is_not_new_and_old_second_addresses_are_not_in_the_window():
    p = "c" * 16
    assert run([], [seen(p, "192.0.2.10", first_minutes_ago=30)]) == []
    old_second = seen(p, "198.51.100.77", first_minutes_ago=60 * 24 * 5, last_minutes_ago=60 * 24 * 4)
    assert run([], [seen(p, "192.0.2.10", first_minutes_ago=60 * 24 * 9, last_minutes_ago=2), old_second]) == []


# ── case creation burst ───────────────────────────────────────────────────────────────────────────────────────

def test_many_cases_created_by_one_account_in_an_hour_raise_an_alert():
    cases = [("dana", NOW - timedelta(minutes=m)) for m in range(12)]
    [a] = run([], [], cases)
    assert a["rule"] == "case_burst" and a["severity"] == "medium" and a["subject"] == "dana" and a["count"] == 12


def test_a_normal_number_of_cases_is_not_an_alert():
    assert run([], [], [("dana", NOW - timedelta(minutes=m)) for m in range(4)]) == []


def test_cases_spread_over_many_hours_are_not_a_burst():
    assert run([], [], [("dana", NOW - timedelta(hours=h)) for h in range(2, 14)]) == []


# ── shape ─────────────────────────────────────────────────────────────────────────────────────────────────────

def test_alerts_have_stable_ids_and_the_required_fields():
    events = [ev("auth_failed", "203.0.113.7", count=12)]
    first, second = run(events), run(events)
    assert first[0]["id"] == second[0]["id"]
    for key in ("id", "rule", "severity", "title", "what_happened", "why_it_matters", "recommended_action", "subject", "first_seen", "last_seen", "count"):
        assert key in first[0], key
    assert first[0]["first_seen"].endswith("Z")


def test_alerts_never_contain_a_credential_or_a_prefix():
    p = "d" * 16
    text = str(run([ev("auth_failed", "203.0.113.7", count=12)], [seen(p, "203.0.113.7", 10), seen(p, "198.51.100.5", 5)]))
    assert p not in text and "aisop_live_" not in text
