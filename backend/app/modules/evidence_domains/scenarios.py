"""
Synthetic, deterministic investigation scenarios for the source-agnostic pipeline (Stage 6, ADR-011).

Every record is an ``aisop.evidence/1`` envelope built from invented identities (``*.test`` / ``*.example`` names,
documentation-style users, made-up hashes). No customer data, no credentials, no external call. The three positive
scenarios need no SIEM alert and no Sysmon event; the negative builders return minimal record sets that must NOT
produce a corroborated incident (used by ``test_evidence_domain_scenarios.py`` and by the demo script).

Public IP addresses below are synthetic stand-ins chosen from globally routable space so that the independence rules
treat them as the specific artefacts they would be in real evidence; they identify nothing and are never contacted.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

ATTACKER_IP = "91.240.118.172"
C2_IP = "45.77.65.211"
SHA_TOOL = hashlib.sha256(b"synthetic-tool").hexdigest()
SHA_INVOICE = hashlib.sha256(b"synthetic-invoice-dropper").hexdigest()


def env(etype: str, system: str, data: dict[str, Any], *, t: Optional[str], category: Optional[str] = None,
        eid: Optional[str] = None, method: str = "api_export", correlation: Optional[dict[str, str]] = None,
        upstream_id: Optional[str] = None) -> dict[str, Any]:
    rec: dict[str, Any] = {"schema": "aisop.evidence/1", "evidence_type": etype,
                           "source": {"system": system, "category": category or etype.split(".")[0], "collection_method": method},
                           "data": data}
    if upstream_id:
        rec["source"]["upstream_id"] = upstream_id
    if correlation:
        rec["correlation"] = correlation
    if t is not None:
        rec["event_time"] = t
    if eid:
        rec["evidence_id"] = eid
    return rec


def scenario_a_identity_cloud() -> list[dict[str, Any]]:
    """Identity sign-in evidence + cloud audit: MFA push fatigue, sign-in, new cloud account, role assignment."""
    r = [env("identity.mfa", "idp-synthetic", {"user": "alice.example", "ip": ATTACKER_IP, "result": "denied"},
             t=f"2026-11-03T09:0{i}:00Z", eid=f"mfa-{i}") for i in range(2, 7)]
    r.append(env("identity.signin", "idp-synthetic", {"user": "alice.example", "ip": ATTACKER_IP, "session_id": "sess-7f3a", "result": "success"},
                 t="2026-11-03T09:07:00Z", eid="signin-1"))
    r.append(env("cloud.api_call", "cloudaudit-synthetic", {"actor": "alice.example", "action": "CreateUser", "resource": "user/svc-backup2",
                                                           "account": "acct-prod-01", "source_ip": ATTACKER_IP}, t="2026-11-03T09:12:00Z", eid="ct-1"))
    r.append(env("cloud.config_change", "cloudaudit-synthetic", {"actor": "alice.example", "action": "AttachUserPolicy", "resource": "user/svc-backup2",
                                                                "role": "AdministratorAccess", "account": "acct-prod-01", "source_ip": ATTACKER_IP},
                 t="2026-11-03T09:14:00Z", eid="ct-2"))
    return r


def scenario_b_network_endpoint() -> list[dict[str, Any]]:
    """DNS + firewall flow (network) joined to process/file artefacts (endpoint) through a resolved public IP and a hash."""
    return [
        env("forensic.file", "dfir-collector-synthetic", {"host": "ws-fin-07", "path": "C:\\Users\\Public\\svc.exe", "sha256": SHA_TOOL},
            t="2026-11-04T09:59:50Z", method="triage_collection"),
        env("network.dns", "resolver-synthetic", {"src_ip": "10.0.4.21", "query": "update-check.cdn-sync.test", "answers": [C2_IP], "host": "ws-fin-07"},
            t="2026-11-04T10:00:05Z"),
        env("forensic.process_artifact", "dfir-collector-synthetic", {"host": "ws-fin-07", "image": "C:\\Users\\Public\\svc.exe", "sha256": SHA_TOOL,
                                                                     "remote_ip": C2_IP, "source_artifact": "network_listing"},
            t="2026-11-04T10:00:08Z", method="triage_collection"),
        env("network.flow", "firewall-synthetic", {"src_ip": "10.0.4.21", "dst_ip": C2_IP, "dst_port": 443, "action": "allow", "host": "ws-fin-07"},
            t="2026-11-04T10:00:09Z"),
    ]


def scenario_c_email_forensic() -> list[dict[str, Any]]:
    """Phishing e-mail + forensic artefacts, plus one analyst statement (context only)."""
    return [
        env("email.message", "mailgw-synthetic", {"message_id": "<inv-8841@invoice-portal.test>", "from": "billing@invoice-portal.test",
                                                  "to": ["bob@corp.example"], "subject": "Overdue invoice", "urls": ["https://invoice-portal.test/pay?id=8841"],
                                                  "attachments": [{"name": "invoice.exe", "sha256": SHA_INVOICE}], "received_from_ip": ATTACKER_IP},
            t="2026-11-05T08:00:00Z"),
        env("network.dns", "resolver-synthetic", {"src_ip": "10.0.8.9", "query": "invoice-portal.test", "answers": [ATTACKER_IP]}, t="2026-11-05T08:20:00Z"),
        env("forensic.file", "dfir-collector-synthetic", {"host": "ws-hr-02", "path": "C:\\Users\\bob\\Downloads\\invoice.exe", "sha256": SHA_INVOICE},
            t="2026-11-05T08:21:00Z", method="triage_collection"),
        env("forensic.registry", "dfir-collector-synthetic", {"host": "ws-hr-02", "process": "invoice.exe",
                                                             "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"},
            t="2026-11-05T08:23:00Z", method="triage_collection"),
        env("forensic.memory_finding", "memory-tool-synthetic", {"host": "ws-hr-02", "tool": "memscan", "finding_type": "injected_code",
                                                                "process_name": "invoice.exe", "sha256": SHA_INVOICE}, t="2026-11-05T08:25:00Z",
            method="memory_analysis"),
        env("analyst.observation", "analyst-notes", {"analyst": "tier2.example", "statement": "Matches the invoice campaign seen last week.",
                                                     "entities": [{"type": "file_hash", "value": SHA_INVOICE}]}, t="2026-11-05T09:00:00Z", category="analyst",
            method="analyst_entry"),
    ]


# ── negative scenarios ───────────────────────────────────────────────────────
def negative_duplicates() -> list[dict[str, Any]]:
    """The same sign-in delivered three times (exact copy; renamed id; two seconds later): one observation, not three."""
    base = env("identity.signin", "idp-synthetic", {"user": "carol.example", "ip": ATTACKER_IP, "result": "success"}, t="2026-11-06T09:00:00Z", eid="dup-1")
    near = env("identity.signin", "idp-synthetic", {"user": "carol.example", "ip": ATTACKER_IP, "result": "success"}, t="2026-11-06T09:00:01Z", eid="dup-2")
    return [base, dict(base), near]


def negative_analyst_only() -> list[dict[str, Any]]:
    """An analyst statement about an indicator, and one machine record: the statement must not corroborate."""
    return [
        env("identity.signin", "idp-synthetic", {"user": "dave.example", "ip": ATTACKER_IP, "result": "success"}, t="2026-11-06T10:00:00Z"),
        env("analyst.observation", "analyst-notes", {"analyst": "tier1.example", "statement": "This address is hostile.",
                                                     "entities": [{"type": "ip", "value": ATTACKER_IP}]}, t="2026-11-06T10:05:00Z", category="analyst"),
    ]


def negative_unrelated() -> list[dict[str, Any]]:
    """Two sign-ins and a DNS query that share nothing specific (different users, addresses, hosts)."""
    return [
        env("identity.signin", "idp-synthetic", {"user": "erin.example", "ip": "203.0.113.5", "result": "success"}, t="2026-11-06T11:00:00Z"),
        env("identity.signin", "idp-synthetic2", {"user": "frank.example", "ip": "198.51.100.9", "result": "success"}, t="2026-11-06T11:03:00Z"),
        env("network.dns", "resolver-synthetic", {"src_ip": "10.9.9.9", "query": "intranet.corp.test", "answers": ["10.0.0.5"]}, t="2026-11-06T11:04:00Z"),
    ]


def negative_bad_times() -> list[dict[str, Any]]:
    """Missing, unparseable and out-of-range event times: preserved, never replaced by 'now'."""
    base = {"user": "gina.example", "ip": ATTACKER_IP, "result": "success"}
    return [env("identity.signin", "idp-synthetic", dict(base), t=None, eid="no-time"),
            env("identity.signin", "idp-synthetic", dict(base), t="yesterday-ish", eid="bad-time"),
            env("identity.signin", "idp-synthetic", dict(base), t="1850-01-01T00:00:00Z", eid="old-time")]


def negative_unknown_type() -> list[dict[str, Any]]:
    return [env("vendorx.widget_event", "vendorx", {"foo": "bar", "count": 3}, t="2026-11-06T12:00:00Z", category="vendorx")]


def negative_contradiction() -> list[dict[str, Any]]:
    return [
        env("identity.signin", "idp-a", {"user": "hank.example", "ip": ATTACKER_IP, "result": "success"}, t="2026-11-06T13:00:00Z"),
        env("identity.signin", "idp-b", {"user": "hank.example", "ip": ATTACKER_IP, "result": "failure"}, t="2026-11-06T13:00:01Z"),
    ]


def malformed_records() -> list[Any]:
    """Quarantined: wrong schema version, missing source, bad IP, non-object, oversized field."""
    return [
        {"schema": "aisop.evidence/9", "evidence_type": "identity.signin", "data": {}},
        {"schema": "aisop.evidence/1", "evidence_type": "identity.signin", "data": {"user": "x", "ip": "1.1.1.1"}},
        env("identity.signin", "idp", {"user": "ivy.example", "ip": "999.1.1.1"}, t="2026-11-06T14:00:00Z"),
        "not an object",
        env("identity.signin", "idp", {"user": "j" * 400, "ip": ATTACKER_IP}, t="2026-11-06T14:00:00Z"),
    ]


SCENARIOS = {"A": scenario_a_identity_cloud, "B": scenario_b_network_endpoint, "C": scenario_c_email_forensic}

__all__ = ["ATTACKER_IP", "C2_IP", "SCENARIOS", "env", "malformed_records", "negative_analyst_only", "negative_bad_times",
           "negative_contradiction", "negative_duplicates", "negative_unknown_type", "negative_unrelated",
           "scenario_a_identity_cloud", "scenario_b_network_endpoint", "scenario_c_email_forensic"]
