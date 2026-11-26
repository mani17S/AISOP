"""
AISOP Linux Authentication & Syslog Alert Adapter.

Adapts Linux auth.log, auditd, and journald authentication security events into CanonicalAlert models.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.modules.evidence.hasher import compute_sha256
from app.modules.alerts.adapter_protocol import require_event_time
from app.schemas.alert import (
    AlertCategory,
    AlertEntity,
    AlertObservable,
    AlertSeverity,
    CanonicalAlert,
    MitreAttackReference,
)
from app.schemas.entities import HostEntity, NetworkEntity, ProcessEntity, UserEntity


def _first_ip(message: str) -> str:
    """First valid IP address in an sshd or PAM line: ``from IP``, ``rhost=IP``, ``by IP`` or ``[IP]``. Every candidate is validated, so a word or an
    address with a trailing colon ("Received disconnect from 1.2.3.4: 11: ...") is never taken as an address."""
    for pattern in (r"\bfrom\s+(\S+)", r"\brhost=(\S+)", r"\bby\s+(\S+)", r"\[(\d{1,3}(?:\.\d{1,3}){3})\]"):
        for match in re.finditer(pattern, message):
            candidate = match.group(1).rstrip(":,;.")
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            return candidate
    return ""


def _user_from(message: str) -> str:
    """User name from an sshd or PAM line: ``Invalid user NAME``, ``invalid user NAME``, ``user=NAME``; empty if none."""
    for pattern in (r"[Ii]nvalid user\s+([^\s\[]+)", r"\buser=([^\s,;]+)"):
        match = re.search(pattern, message)
        if match and match.group(1).lower() not in ("unknown", "from"):
            return match.group(1)
    return ""


class LinuxAuthAdapter:
    """Adapter for Linux authentication and syslog security events (sshd, sudo, PAM)."""

    def adapter_name(self) -> str:
        return "linux_auth"

    def can_adapt(self, raw_data: dict[str, Any] | str) -> bool:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                # Direct syslog line string
                return any(k in raw_data for k in ["sshd[", "sudo:", "pam_unix", "Failed password"])
        if not isinstance(raw_data, dict):
            return False

        if raw_data.get("source_type", "").lower() == "linux_auth":
            return True

        program = str(raw_data.get("program") or raw_data.get("ident") or raw_data.get("app_name") or "")
        if program.lower() in ("sshd", "sudo", "pam", "login", "auditd"):
            return True

        msg = str(raw_data.get("message") or raw_data.get("log") or raw_data.get("raw") or "")
        return any(k in msg for k in ["sshd[", "sudo:", "pam_unix", "Failed password for", "invalid user"])

    def adapt(
        self,
        raw_data: dict[str, Any] | str,
        raw_ref: str | None = None,
    ) -> CanonicalAlert:
        if isinstance(raw_data, str):
            try:
                data: dict[str, Any] = json.loads(raw_data)
            except Exception:
                data = {"message": raw_data}
        else:
            data = dict(raw_data)

        if raw_ref is None:
            raw_ref = compute_sha256(data)

        message = str(data.get("message") or data.get("log") or data.get("raw") or "")
        hostname = str(data.get("host") or data.get("hostname") or "").strip()  # empty = none recorded; none is invented
        ts_val = data.get("timestamp") or data.get("@timestamp")

        ts = require_event_time(ts_val)

        # Parsing heuristics for sshd log patterns
        # e.g.: "Failed password for invalid user admin from 198.51.100.23 port 54321 ssh2"
        # e.g.: "Failed password for root from 198.51.100.23 port 54321 ssh2"
        # e.g.: "Accepted publickey for ubuntu from 203.0.113.10 port 49152 ssh2"
        src_ip = str(data.get("src_ip") or data.get("client_ip") or "")
        src_port: int | None = None
        if data.get("src_port"):
            try:
                src_port = int(data["src_port"])
            except Exception:
                pass

        user = str(data.get("user") or data.get("username") or "")

        if not src_ip:
            src_ip = _first_ip(message)

        if not src_port:
            port_match = re.search(r"port\s+(\d+)", message)
            if port_match:
                try:
                    src_port = int(port_match.group(1))
                except Exception:
                    pass

        if not user:
            user = _user_from(message)
        if not user:
            # "for NAME" names a user only in a Failed or Accepted authentication line; "getaddrinfo for host.example" names a host.
            user_match = re.search(r"(?:for invalid user|for user|for)\s+([a-zA-Z0-9_.-]+)", message) if re.search(r"\b(?:Failed|Accepted)\b", message) else None
            if user_match:
                user = user_match.group(1)

        is_failed_ssh = "Failed password" in message or "invalid user" in message.lower() or "authentication failure" in message
        is_sudo_abuse = "sudo:" in message
        is_accepted = "Accepted" in message

        category: AlertCategory = "credential_access" if is_failed_ssh else "suspicious_activity"
        severity: AlertSeverity = "medium"
        title = "Linux Authentication Event"
        mitre_list: list[MitreAttackReference] = []

        if is_failed_ssh:
            severity = "high" if (user.lower() in ("root", "admin") or "invalid user" in message) else "medium"
            title = f"SSH Authentication Failure for '{user or 'unknown'}' from {src_ip or 'unknown IP'}"
            mitre_list.append(
                MitreAttackReference(
                    tactic_id="TA0006",
                    tactic_name="Credential Access",
                    technique_id="T1110.001",
                    technique_name="Password Guessing",
                )
            )
        elif is_sudo_abuse:
            category = "privilege_escalation"
            severity = "medium"
            title = f"Privileged Command Execution via sudo by '{user or 'unknown'}'"
            mitre_list.append(
                MitreAttackReference(
                    tactic_id="TA0004",
                    tactic_name="Privilege Escalation",
                    technique_id="T1548.003",
                    technique_name="Sudo and Sudo Caching",
                )
            )
        elif is_accepted:
            category = "initial_access"
            severity = "informational"
            title = f"Successful SSH Login for '{user}' from {src_ip}"
            mitre_list.append(
                MitreAttackReference(
                    tactic_id="TA0001",
                    tactic_name="Initial Access",
                    technique_id="T1078",
                    technique_name="Valid Accounts",
                )
            )

        entities: list[AlertEntity] = []
        if hostname:
            entities.append(
                AlertEntity(
                    entity_type="host",
                    entity_value=hostname,
                    role="victim",
                    attributes={"hostname": hostname},
                )
            )
        observables: list[AlertObservable] = []

        if user:
            entities.append(
                AlertEntity(
                    entity_type="user",
                    entity_value=user,
                    role="target" if is_failed_ssh else "observed",
                    attributes={"username": user},
                )
            )

        if src_ip:
            entities.append(
                AlertEntity(
                    entity_type="ip",
                    entity_value=src_ip,
                    role="attacker" if is_failed_ssh else "source",
                    attributes={"port": src_port},
                )
            )
            observables.append(
                AlertObservable(type="ip", value=src_ip, relevance="suspicious" if is_failed_ssh else "context")
            )

        return CanonicalAlert(
            id=uuid4(),
            source_type="linux_auth",
            source_alert_id=str(data.get("id") or data.get("event_id") or f"auth-{uuid4().hex[:8]}"),
            title=title,
            description=message or (f"Linux authentication log on {hostname}" if hostname else "Linux authentication log"),
            severity=severity,
            vendor_severity=str(data["severity"]) if data.get("severity") else None,  # only what the vendor stated
            category=category,
            provider="Linux-Syslog-Auth",
            timestamp=ts,
            mitre_attack=mitre_list,
            entities=entities,
            observables=observables,
            host=HostEntity(hostname=hostname, os="Linux") if hostname else None,
            user=UserEntity(username=user) if user else None,
            network=NetworkEntity(source_ip=src_ip, source_port=src_port) if src_ip else None,
            process=ProcessEntity(process_name="sshd" if is_failed_ssh or is_accepted else "sudo"),
            raw_ref=raw_ref,
            raw_payload_summary=message[:120] if message else title,
            custom_fields={"raw_message": message, "program": data.get("program", "sshd")},
        )

