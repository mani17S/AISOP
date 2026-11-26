"""
Alert adapters must not invent a host, user, severity, sender/recipient or provider the record does not state
(CLAUDE.md evidence-integrity rule). A shared invented name would also create false correlation links.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.modules.alerts.adapters.cloud_audit_adapter import CloudAuditAdapter
from app.modules.alerts.adapters.edr_malware_adapter import EdrMalwareAdapter
from app.modules.alerts.adapters.email_phishing_adapter import EmailPhishingAdapter
from app.modules.alerts.adapters.firewall_ids_adapter import NetworkIdsAdapter
from app.modules.alerts.adapters.generic_siem_adapter import GenericSiemAdapter
from app.modules.alerts.adapters.linux_auth_adapter import LinuxAuthAdapter
from app.modules.alerts.adapters.sysmon_adapter import SysmonAlertAdapter
from app.modules.alerts.adapters.windows_security_adapter import WindowsSecurityAdapter
from app.modules.correlation.correlator import correlate
from app.modules.correlation.normalize import normalize_records
from app.modules.evidence.entity_extractor import extract_entities

T1 = "2026-11-07T09:00:00Z"
T2 = "2026-11-07T09:00:05Z"


def _edr(detect_id: str, ts: str, **extra: Any) -> dict[str, Any]:
    return {"source_type": "edr_malware", "detect_id": detect_id, "threat_name": f"threat-{detect_id}", "timestamp": ts, **extra}


def _win(event_id: int, ts: str, event_data: dict[str, Any], computer: str | None = None) -> dict[str, Any]:
    system: dict[str, Any] = {"EventID": event_id, "TimeCreated": {"@SystemTime": ts}}
    if computer:
        system["Computer"] = computer
    return {"Event": {"System": system, "EventData": event_data}}


def _sysmon(ts: str, event_data: dict[str, Any], computer: str | None = None) -> dict[str, Any]:
    system: dict[str, Any] = {"EventID": 1, "TimeCreated": {"@SystemTime": ts}}
    if computer:
        system["Computer"] = computer
    return {"Event": {"System": system, "EventData": {"Image": "C:\\x\\a.exe", **event_data}}}


def _types(alert) -> set[str]:
    return {e.entity_type for e in alert.entities}


# --- missing host -----------------------------------------------------------------------------------------------

def test_edr_without_host_has_no_host_entity_and_no_invented_name():
    alert = EdrMalwareAdapter().adapt(_edr("a", T1))
    assert alert.host is None
    assert "host" not in _types(alert)
    assert "WORKSTATION-01" not in alert.model_dump_json()


def test_sysmon_without_host_or_user_has_neither_entity():
    alert = SysmonAlertAdapter().adapt(_sysmon(T1, {}))
    assert alert.host is None and alert.user is None
    assert not ({"host", "user"} & _types(alert))
    blob = alert.model_dump_json()
    assert "UNKNOWN-HOST" not in blob and "SYSTEM" not in blob


def test_windows_security_without_host_or_user_has_neither_entity():
    alert = WindowsSecurityAdapter().adapt(_win(4625, T1, {"IpAddress": "198.51.100.7"}))
    assert alert.host is None and alert.user is None
    assert not ({"host", "user"} & _types(alert))
    assert "WINDOWS-ENDPOINT" not in alert.model_dump_json()
    assert "unknown" not in alert.title.lower().replace("(no account recorded)", "")


def test_linux_auth_without_host_has_no_host_entity():
    alert = LinuxAuthAdapter().adapt({"message": "Failed password for root from 198.51.100.9 port 22 ssh2", "timestamp": T1})
    assert alert.host is None
    assert "host" not in _types(alert)
    assert alert.vendor_severity is None  # the record gave none


def test_cloud_audit_without_principal_has_no_user_and_no_text_none():
    alert = CloudAuditAdapter().adapt({"id": "c1", "title": "x", "createdAt": T1, "userIdentity": {"type": "Root"}})
    assert alert.user is None
    assert "user" not in _types(alert)
    assert "cloud-service-account" not in alert.model_dump_json()
    assert "[None]" not in (alert.raw_payload_summary or "")


def test_email_without_sender_or_recipient_has_no_address_entities():
    alert = EmailPhishingAdapter().adapt({"message_id": "m1", "threat_type": "Phishing", "sender": "", "timestamp": T1})
    assert alert.user is None
    assert not ({"email", "user"} & _types(alert))
    blob = alert.model_dump_json()
    assert "unknown@external.com" not in blob and "victim@internal.com" not in blob


# --- missing user is distinct from missing host, and a stated value is kept -------------------------------------

def test_stated_host_and_user_are_kept():
    alert = WindowsSecurityAdapter().adapt(_win(4625, T1, {"TargetUserName": "jsmith"}, computer="SRV-01"))
    assert alert.host is not None and alert.host.hostname == "SRV-01"
    assert alert.user is not None and alert.user.username == "jsmith"
    assert {"host", "user"} <= _types(alert)


# --- no link between records that both lack a host / user -------------------------------------------------------

def test_two_hostless_records_do_not_link():
    res = normalize_records([_edr("a", T1), _edr("b", T2)])
    assert len(res.events) == 2
    assert all(e.host is None and e.host_source == "none" for e in res.events)
    assert not any(t == "host" for e in res.events for t, _ in e.entities)
    assert correlate(res.events).links == []


def test_two_userless_records_do_not_link():
    recs = [_win(4625, T1, {"IpAddress": "198.51.100.1"}, computer="A"), _win(4625, T2, {"IpAddress": "198.51.100.2"}, computer="B")]
    res = normalize_records(recs)
    assert len(res.events) == 2
    assert all(e.user is None for e in res.events)
    assert not any(t == "user" for e in res.events for t, _ in e.entities)
    assert correlate(res.events).links == []


def test_control_a_stated_shared_host_still_links():
    res = normalize_records([_edr("a", T1, host="SRV-9"), _edr("b", T2, host="SRV-9")])
    assert len(correlate(res.events).links) == 1


def test_entity_extractor_creates_no_host_or_user_for_a_hostless_userless_alert():
    event = SysmonAlertAdapter().adapt(_sysmon(T1, {})).to_canonical_event()
    assert not ({"host", "user"} & {e.entity_type for e in extract_entities(event)})


# --- severity -----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "adapter,record",
    [
        (EdrMalwareAdapter(), _edr("a", T1)),
        (EmailPhishingAdapter(), {"message_id": "m", "sender": "a@evil.test", "recipient": "b@corp.test", "timestamp": T1}),
        (GenericSiemAdapter(), {"rule_name": "r", "timestamp": T1}),
        (CloudAuditAdapter(), {"id": "c", "title": "x", "createdAt": T1}),
        (NetworkIdsAdapter(), {"source_type": "firewall_ids", "signature": "s", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "timestamp": T1}),
    ],
)
def test_missing_severity_is_unknown_not_guessed(adapter, record):
    alert = adapter.adapt(record)
    assert alert.severity == "unknown"
    assert alert.vendor_severity is None


def test_stated_severity_is_still_mapped():
    assert EdrMalwareAdapter().adapt(_edr("a", T1, severity="critical")).severity == "critical"
    assert CloudAuditAdapter().adapt({"id": "c", "title": "x", "createdAt": T1, "severity": 8.0}).severity == "high"
    assert NetworkIdsAdapter().adapt({"source_type": "firewall_ids", "signature": "s", "severity": "informational", "timestamp": T1}).severity == "informational"


# --- firewall / IDS provider follows the record -------------------------------------------------------------------

def _ids(**extra: Any) -> dict[str, Any]:
    return {"event_type": "alert", "alert": {"signature": "ET SCAN probe", "severity": 2}, "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "timestamp": T1, **extra}


def test_ids_provider_is_neutral_when_record_names_none():
    assert NetworkIdsAdapter().adapt(_ids()).provider == "firewall_ids"


@pytest.mark.parametrize("extra,expected", [({"provider": "Snort"}, "Snort"), ({"vendor": "Palo Alto"}, "Palo Alto"), ({"source_type": "suricata"}, "suricata")])
def test_ids_provider_follows_the_record(extra, expected):
    assert NetworkIdsAdapter().adapt(_ids(**extra)).provider == expected
