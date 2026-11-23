"""
Platform security alerts: alerts about AISOP itself, derived from what the server observed.

These are NOT the telemetry alerts in the alerts table (those come from the customer's sources and describe their
environment). These describe attempts against this platform: someone guessing API keys, probing for secrets and admin panels,
a key used from an address that was just guessing keys, a key used from a new address, a burst of case creation by one account.

The rules are plain thresholds, written out so they can be defended and changed. They detect; they do not prove. A valid key from
a new address may be its owner on a new network, and every alert says what to check. Nothing here contains a credential.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

#: Rejected keys (or any lockout) from one address in the window before it is called key guessing.
KEY_GUESSING_FAILURES = 10
#: Rejected keys from one address before a later valid use from that address is called critical.
GUESSED_THEN_VALID_FAILURES = 5
#: Requests for secret or admin paths from one address before it is called probing.
SECRET_PROBE_REQUESTS = 3
#: Cases created by one account within an hour before it is called a burst.
CASE_BURST_PER_HOUR = 10

_SECRET_PATHS = re.compile(
    r"(\.env|\.git|\.aws|\.ssh|\.htpasswd|id_rsa|wp-admin|wp-login|xmlrpc|phpmyadmin|config\.php|credentials|backup\.(zip|sql|tar)"
    r"|actuator|server-status|eval-stdin|/\.DS_Store)",
    re.IGNORECASE,
)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2}


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return _aware(value).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _alert(rule: str, severity: str, subject: str, title: str, what: str, why: str, action: str, first: datetime, last: datetime, count: int, ident: str | None = None) -> dict[str, Any]:
    return {
        "id": hashlib.sha256(f"{rule}|{ident or subject}".encode()).hexdigest()[:12],
        "rule": rule,
        "severity": severity,
        "title": title,
        "what_happened": what,
        "why_it_matters": why,
        "recommended_action": action,
        "subject": subject,
        "first_seen": _iso(first),
        "last_seen": _iso(last),
        "count": int(count),
    }


def derive_alerts(events: Iterable[Any], sightings: Iterable[Any], case_creations: Iterable[tuple[str, datetime]], now: datetime, window_start: datetime) -> list[dict[str, Any]]:
    """Platform security alerts for the window, most serious first."""
    alerts: list[dict[str, Any]] = []
    failures: dict[str, int] = defaultdict(int)
    failure_first: dict[str, datetime] = {}
    failure_last: dict[str, datetime] = {}
    lockouts: dict[str, int] = defaultdict(int)
    probes: dict[str, int] = defaultdict(int)
    probe_first: dict[str, datetime] = {}
    probe_last: dict[str, datetime] = {}

    for e in events:
        when, ip, n = _aware(e.bucket_minute), e.source_ip, int(e.event_count)
        if e.kind == "auth_failed":
            failures[ip] += n
            failure_first[ip] = min(failure_first.get(ip, when), when)
            failure_last[ip] = max(failure_last.get(ip, when), when)
        elif e.kind == "auth_locked_out":
            lockouts[ip] += n
            failure_first[ip] = min(failure_first.get(ip, when), when)
            failure_last[ip] = max(failure_last.get(ip, when), when)
        elif e.kind == "unknown_path" and _SECRET_PATHS.search(e.path_sample or ""):
            probes[ip] += n
            probe_first[ip] = min(probe_first.get(ip, when), when)
            probe_last[ip] = max(probe_last.get(ip, when), when)

    for ip in sorted(set(failures) | set(lockouts)):
        total = failures[ip] + lockouts[ip]
        if failures[ip] >= KEY_GUESSING_FAILURES or lockouts[ip] >= 1:
            alerts.append(
                _alert(
                    "key_guessing", "high", ip,
                    f"Repeated failed API key attempts from {ip}",
                    f"{failures[ip]} requests from {ip} presented an API key the server rejected"
                    + (f", and {lockouts[ip]} further requests were locked out." if lockouts[ip] else "."),
                    "Someone may be trying to guess or reuse a key. A key that is eventually accepted would let them read cases and create new ones.",
                    "Check whether this address belongs to an analyst or a sensor. If not, block it at the host or network edge, and make sure no key was accepted from it (see any alert about a valid key used from this address).",
                    failure_first[ip], failure_last[ip], total,
                )
            )

    for ip, n in sorted(probes.items()):
        if n >= SECRET_PROBE_REQUESTS:
            alerts.append(
                _alert(
                    "secret_probing", "medium", ip,
                    f"Probing for secrets and admin panels from {ip}",
                    f"{n} requests from {ip} asked for paths such as environment files, version-control folders, cloud credential files or other products' admin pages.",
                    "This is automated scanning. AISOP has none of these paths, so the requests failed, but the same source often tries API keys next.",
                    "No action is needed for the requests themselves. Watch this address for key guessing, and confirm no secret file is served by anything in front of AISOP.",
                    probe_first[ip], probe_last[ip], n,
                )
            )

    by_key: dict[str, list[Any]] = defaultdict(list)
    for s in sightings:
        by_key[s.token_prefix].append(s)

    for s in (x for group in by_key.values() for x in group):
        ip = s.source_ip
        if failures.get(ip, 0) >= GUESSED_THEN_VALID_FAILURES and _aware(s.last_seen) >= failure_first.get(ip, _aware(s.last_seen)):
            alerts.append(
                _alert(
                    "key_used_after_guessing", "critical", ip,
                    f"A valid API key was used from {ip}, which had been guessing keys",
                    f"{failures[ip]} rejected keys came from {ip}, and the key of {s.username} ({s.client_name}) was then accepted from the same address.",
                    "This is the pattern of a stolen or guessed key being used. If it is not the owner, the holder can read assigned cases and create new ones.",
                    f"Confirm with {s.username} right away. If it was not them, revoke this key now (backend/scripts/revoke_api_key.py), then review the cases that account created or changed in the audit trail.",
                    failure_first[ip], _aware(s.last_seen), failures[ip],
                )
            )

    for group in by_key.values():
        ordered = sorted(group, key=lambda x: _aware(x.first_seen))
        if len({x.source_ip for x in ordered}) < 2:
            continue
        for s in ordered[1:]:
            if _aware(s.first_seen) >= _aware(window_start):
                alerts.append(
                    _alert(
                        "key_new_address", "high", s.source_ip,
                        f"An API key was used from a new address, {s.source_ip}",
                        f"The key of {s.username} ({s.client_name}) was first used from {s.source_ip}. Earlier it was only seen from other addresses.",
                        "A stolen key looks exactly like this. It is also what an analyst on a new network or VPN looks like, so this is not necessarily a breach.",
                        f"Ask the owner ({s.username}) whether they are on a new network. If not, revoke the key (backend/scripts/revoke_api_key.py) and check the cases it touched.",
                        _aware(s.first_seen), _aware(s.last_seen), int(s.request_count), ident=f"{s.client_name}@{s.source_ip}",
                    )
                )

    hour_ago = _aware(now) - timedelta(hours=1)
    recent: dict[str, list[datetime]] = defaultdict(list)
    for username, created in case_creations:
        if _aware(created) >= hour_ago:
            recent[username].append(_aware(created))
    for username, times in sorted(recent.items()):
        if len(times) >= CASE_BURST_PER_HOUR:
            alerts.append(
                _alert(
                    "case_burst", "medium", username,
                    f"{len(times)} cases created by {username} in the last hour",
                    f"The account {username} created {len(times)} cases in one hour, above the {CASE_BURST_PER_HOUR} that is treated as unusual.",
                    "A stolen key can be used to flood the case list. It can also be a legitimate bulk promotion of alerts.",
                    f"Ask {username} whether this was intended. If not, revoke their key and review the new cases. The server also refuses further case creation above its hourly limit.",
                    min(times), max(times), len(times),
                )
            )

    alerts.sort(key=lambda a: (_SEVERITY_RANK[a["severity"]], _neg(a["last_seen"])))
    return alerts


def _neg(iso: str) -> float:
    """Sort key putting the latest last_seen first within a severity."""
    return -datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
