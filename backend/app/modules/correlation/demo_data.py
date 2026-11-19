"""
AISOP synthetic multi-source scenarios for the investigation workflow demo (Stage 3C-R, ADR-009).

All data are SYNTHETIC: documentation-style names, fictional host/user, and public IP addresses
chosen only so that the "public address" rules are exercised (they are not claims about real
infrastructure). Each scenario returns raw vendor-shaped records (exactly what the existing
adapters accept) and an optional asset inventory (IP -> host), plus the engineering assertions
used by the tests (expected structure, NOT ground-truth labels).

Sources covered: SIEM alert (generic_siem), identity (Windows Security 4624/4625), endpoint
(Sysmon 1/3/22), DNS and firewall/IDS (firewall_ids).
"""

from __future__ import annotations

import copy
from typing import Any

HOST = "WS-FIN-07"
USER = "jdoe"
ATTACKER_IP = "185.220.101.4"
C2_IP = "91.240.118.172"
C2_DOMAIN = "update.badcdn.example"
HOST_IP = "10.1.4.7"
GUID0 = "{A1B2C3D4-E5F6-7890-1234-56789ABCDE00}"
GUID1 = "{A1B2C3D4-E5F6-7890-1234-56789ABCDEF1}"
ENC_PS = "powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
SHA_PS = "ab" * 32


def _win(eid: int, rid: int, t: str, *, ip: str = ATTACKER_IP, user: str = USER, host: str = HOST, logon_id: str | None = None,
         sub_status: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "TargetUserName": user, "TargetDomainName": "CORP", "IpAddress": ip, "IpPort": "51234", "LogonType": "3",
    }
    if sub_status:
        data["SubStatus"] = sub_status
    if logon_id:
        data["TargetLogonId"] = logon_id
    return {"Event": {"System": {"Provider": {"@Name": "Microsoft-Windows-Security-Auditing"}, "EventID": eid,
                                 "EventRecordID": rid, "Computer": host, "TimeCreated": {"@SystemTime": t}},
                      "EventData": data}}


def _sysmon(eid: int, t: str, *, host: str = HOST, user: str = f"CORP\\{USER}", image: str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            guid: str = GUID1, **extra: Any) -> dict[str, Any]:
    data = {"UtcTime": t.replace("T", " ").replace("Z", ""), "ProcessGuid": guid, "ProcessId": "4412", "Image": image, "User": user}
    data.update(extra)
    return {"Event": {"System": {"Provider": {"@Name": "Microsoft-Windows-Sysmon"}, "EventID": eid, "Computer": host,
                                 "TimeCreated": {"@SystemTime": t}}, "EventData": data}}


def _siem(t: str, name: str, *, severity: str = "high", techniques: list[str] | None = None, host: str = HOST, user: str = USER,
          src_ip: str | None = ATTACKER_IP, rule_id: str = "R-100") -> dict[str, Any]:
    rec: dict[str, Any] = {"source_type": "generic_siem", "rule_id": rule_id, "rule_name": name, "severity": severity,
                           "timestamp": t, "hostname": host, "user": user, "mitre_techniques": techniques or []}
    if src_ip:
        rec["src_ip"] = src_ip
    return rec


def _fw(t: str, sig: str, sid: int, *, src: str = HOST_IP, dst: str = C2_IP, severity: str = "high") -> dict[str, Any]:
    return {"source_type": "firewall_ids", "timestamp": t, "src_ip": src, "dest_ip": dst, "dest_port": 443,
            "signature": sig, "signature_id": sid, "severity": severity, "protocol": "TCP"}


def _dns(t: str, query: str, *, src: str = HOST_IP, sig: str = "Suspicious DNS query", severity: str = "medium") -> dict[str, Any]:
    return {"source_type": "firewall_ids", "event_type": "dns", "timestamp": t, "src_ip": src, "query_name": query,
            "signature": sig, "severity": severity}


def intrusion_chain() -> list[dict[str, Any]]:
    """Credential attack -> valid logon -> encoded PowerShell -> DNS -> C2, seen by five source types."""
    return [
        _win(4625, 7001, "2026-11-10T09:00:05Z", sub_status="0xC000006A"),
        _win(4625, 7002, "2026-11-10T09:00:12Z", sub_status="0xC000006A"),
        _win(4625, 7003, "2026-11-10T09:00:20Z", sub_status="0xC000006A"),
        _siem("2026-11-10T09:00:30Z", "Multiple failed logons followed by success", techniques=["T1110"]),
        _win(4624, 7004, "2026-11-10T09:01:10Z", logon_id="0x5a1b"),
        _sysmon(1, "2026-11-10T09:02:00Z", CommandLine=ENC_PS, Hashes=f"SHA256={SHA_PS}", ParentImage=r"C:\Windows\explorer.exe",
                ParentProcessGuid=GUID0, ParentProcessId="1200", LogonId="0x5a1b"),
        _sysmon(22, "2026-11-10T09:02:28Z", QueryName=C2_DOMAIN, QueryResults=f"{C2_IP};", QueryStatus="0"),
        _dns("2026-11-10T09:02:29Z", C2_DOMAIN),
        _sysmon(3, "2026-11-10T09:02:30Z", Protocol="tcp", Initiated="true", SourceIp=HOST_IP, SourcePort="50123",
                DestinationIp=C2_IP, DestinationPort="443", DestinationHostname=C2_DOMAIN),
        _fw("2026-11-10T09:02:40Z", "ET MALWARE C2 beacon", 2001),
    ]


ASSETS = {HOST_IP: HOST.lower(), "10.1.9.9": "ws-hr-02"}


def duplicates_and_near_duplicates() -> list[dict[str, Any]]:
    base = intrusion_chain()
    near = copy.deepcopy(base[5])  # the Sysmon process record, re-emitted 0.4 s later with an extra field (different digest)
    near["Event"]["System"]["TimeCreated"]["@SystemTime"] = "2026-11-10T09:02:00.400Z"
    near["Event"]["EventData"]["UtcTime"] = "2026-11-10 09:02:00.400"
    near["Event"]["EventData"]["RuleName"] = "re-emitted-by-forwarder"
    return base + [copy.deepcopy(base[3]), copy.deepcopy(base[3]), copy.deepcopy(base[0]), near]


def contradiction() -> list[dict[str, Any]]:
    base = intrusion_chain()
    conflicting = _win(4625, 7099, "2026-11-10T09:01:10.500Z", sub_status="0xC000006A")  # failure 0.5 s after the success
    return base + [conflicting]


def unrelated_noise() -> list[dict[str, Any]]:
    base = intrusion_chain()
    noise = [
        _sysmon(1, "2026-11-10T08:55:00Z", image=r"C:\Windows\System32\calc.exe", guid="{B1B1B1B1-0000-0000-0000-000000000001}",
                CommandLine="calc.exe", Hashes="SHA256=" + "cd" * 32),                      # same host and user, earlier, no specific link
        _sysmon(1, "2026-11-10T09:03:00Z", host="WS-HR-02", user="CORP\\asmith", image=r"C:\Windows\System32\notepad.exe",
                guid="{C2C2C2C2-0000-0000-0000-000000000002}", CommandLine="notepad.exe report.txt", Hashes="SHA256=" + "ef" * 32),
        _win(4624, 7201, "2026-11-10T09:04:00Z", ip="10.1.9.9", user="asmith", host="WS-HR-02", logon_id="0x77"),
        _dns("2026-11-10T09:05:00Z", "updates.vendor.example", src="10.1.9.9", sig="DNS query", severity="informational"),
    ]
    return base + noise


def insufficient_unparseable() -> list[Any]:
    return [{"foo": "bar"}, "this is not json", {"message": "free text with no recognised vendor structure"}, 42]


def uncorroborated_single_alert() -> list[dict[str, Any]]:
    return [_siem("2026-11-10T14:00:00Z", "Suspicious outbound traffic", severity="medium", techniques=["T1071"], src_ip=None,
                  host="WS-OPS-03", user="svc-backup", rule_id="R-310")]


SCENARIOS: dict[str, dict[str, Any]] = {
    "01_intrusion_chain": {
        "title": "Multi-source intrusion chain (SIEM + identity + Sysmon + DNS + firewall)",
        "build": intrusion_chain, "assets": ASSETS,
        "expect": {"incidents": 1, "min_sources": 4, "techniques": ["T1027", "T1059.001", "T1071", "T1078", "T1110", "T1564.003"],
                   "verdict": "sufficient"},
    },
    "02_duplicates_near_duplicates": {
        "title": "Same chain plus exact duplicates and a near-duplicate re-emission",
        "build": duplicates_and_near_duplicates, "assets": ASSETS,
        "expect": {"incidents": 1, "duplicates_collapsed": 4, "verdict": "sufficient"},
    },
    "03_contradictory_evidence": {
        "title": "Same chain plus a failed logon recorded 0.5 s after the successful one",
        "build": contradiction, "assets": ASSETS,
        "expect": {"incidents": 1, "contradictions": 1, "verdict": "limited", "code": "CONTRADICTORY_EVIDENCE"},
    },
    "04_unrelated_and_weak_context": {
        "title": "Same chain plus an unrelated user/host and a same-host benign event",
        "build": unrelated_noise, "assets": ASSETS,
        "expect": {"main_incident_events": 11, "weak_context_events": 1, "separate_incidents": 3},
    },
    "05_insufficient_unparseable": {
        "title": "Only unrecognised records: abstention",
        "build": insufficient_unparseable, "assets": {},
        "expect": {"incidents": 0, "rejected": 4, "verdict": "insufficient"},
    },
    "06_uncorroborated_single_alert": {
        "title": "One SIEM alert and nothing else: bounded, uncorroborated",
        "build": uncorroborated_single_alert, "assets": {},
        "expect": {"incidents": 1, "verdict": "limited", "code": "UNCORROBORATED_QUESTION"},
    },
}

__all__ = ["ASSETS", "SCENARIOS", "intrusion_chain"]
