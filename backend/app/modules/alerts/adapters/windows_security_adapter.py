"""
AISOP Windows Security Event Adapter.

Adapts Windows Security Auditing events (EVTX JSON, e.g. Event IDs 4624, 4625, 4688, 4720, 1102)
into CanonicalAlert models.
"""

from __future__ import annotations

import json
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


class WindowsSecurityAdapter:
    """Adapter for Microsoft Windows Security Auditing event logs."""

    def adapter_name(self) -> str:
        return "windows_security"

    def can_adapt(self, raw_data: dict[str, Any] | str) -> bool:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                return False
        if not isinstance(raw_data, dict):
            return False

        # Check provider or channel
        provider = (
            raw_data.get("Event", {})
            .get("System", {})
            .get("Provider", {})
            .get("@Name", "")
        )
        if "security-auditing" in str(provider).lower():
            return True

        channel = (
            raw_data.get("Event", {}).get("System", {}).get("Channel", "")
            or raw_data.get("Channel", "")
        )
        if str(channel).lower() == "security":
            return True

        event_id = str(
            raw_data.get("Event", {}).get("System", {}).get("EventID")
            or raw_data.get("EventID")
            or raw_data.get("event_id")
            or ""
        )
        return event_id in ("4624", "4625", "4688", "4720", "4738", "1102")

    def adapt(
        self,
        raw_data: dict[str, Any] | str,
        raw_ref: str | None = None,
    ) -> CanonicalAlert:
        if isinstance(raw_data, str):
            data: dict[str, Any] = json.loads(raw_data)
        else:
            data = dict(raw_data)

        if raw_ref is None:
            raw_ref = compute_sha256(data)

        event_dict = data.get("Event", {}) if isinstance(data.get("Event"), dict) else data
        system = event_dict.get("System", {}) if isinstance(event_dict.get("System"), dict) else {}
        event_data = (
            event_dict.get("EventData", {})
            if isinstance(event_dict.get("EventData"), dict)
            else event_dict
        )

        event_id = str(
            system.get("EventID")
            or event_dict.get("EventID")
            or data.get("EventId")
            or data.get("event_id")
            or "4624"
        )
        computer = str(
            system.get("Computer")
            or event_data.get("WorkstationName")
            or event_data.get("Hostname")
            or data.get("computer")
            or data.get("host")
            or "WINDOWS-ENDPOINT"
        )

        # Time extraction
        flat_time = data.get("TimeCreated") if isinstance(data.get("TimeCreated"), str) else None  # flat forwarder export
        time_created = system.get("TimeCreated", {}).get("@SystemTime") or data.get("timestamp") or flat_time or data.get("@timestamp")
        ts = require_event_time(time_created)

        target_user = str(
            event_data.get("TargetUserName")
            or event_data.get("SubjectUserName")
            or data.get("user")
            or "unknown"
        )
        target_domain = str(
            event_data.get("TargetDomainName")
            or event_data.get("SubjectDomainName")
            or data.get("domain")
            or ""
        )
        ip_address = str(event_data.get("IpAddress") or data.get("src_ip") or "")
        ip_port = event_data.get("IpPort") or data.get("src_port")

        entities: list[AlertEntity] = [
            AlertEntity(
                entity_type="host",
                entity_value=computer,
                role="victim",
                attributes={"hostname": computer},
            ),
            AlertEntity(
                entity_type="user",
                entity_value=f"{target_domain}\\{target_user}" if target_domain else target_user,
                role="target",
                attributes={"username": target_user, "domain": target_domain},
            ),
        ]
        observables: list[AlertObservable] = []
        mitre_list: list[MitreAttackReference] = []

        host_entity = HostEntity(hostname=computer, domain=target_domain or None)
        user_entity = UserEntity(username=target_user, domain=target_domain or None)
        process_entity: ProcessEntity | None = None
        network_entity: NetworkEntity | None = None

        category: AlertCategory = "suspicious_activity"
        severity: AlertSeverity = "low"
        title = f"Windows Security Event {event_id}"
        description = f"Security event {event_id} observed on {computer}"

        if event_id == "4625":
            category = "credential_access"
            severity = "high"
            title = f"Windows Security 4625: Failed Logon for {target_user}"
            substatus = event_data.get("SubStatus", "0xC000006A")
            description = (
                f"Failed authentication attempt for account {target_user} from IP {ip_address or 'local'} "
                f"(SubStatus: {substatus})"
            )
            mitre_list.append(
                MitreAttackReference(
                    tactic_id="TA0006",
                    tactic_name="Credential Access",
                    technique_id="T1110.001",
                    technique_name="Password Guessing",
                )
            )
        elif event_id == "4624":
            category = "initial_access"
            severity = "informational"
            logon_type = str(event_data.get("LogonType", ""))
            title = f"Windows Security 4624: Successful Logon for {target_user}"
            description = f"Logon session established for {target_user} (LogonType: {logon_type})"
            mitre_list.append(
                MitreAttackReference(
                    tactic_id="TA0001",
                    tactic_name="Initial Access",
                    technique_id="T1078",
                    technique_name="Valid Accounts",
                )
            )
        elif event_id == "4688":
            category = "execution"
            severity = "medium"
            new_process = str(event_data.get("NewProcessName") or data.get("process") or "")
            cmdline = str(event_data.get("CommandLine") or data.get("command_line") or "")
            parent_proc = str(event_data.get("ParentProcessName") or "")
            title = f"Windows Security 4688: Process Creation ({new_process.split('\\')[-1]})"
            description = f"Process {new_process} created with command line: {cmdline}"
            mitre_list.append(
                MitreAttackReference(
                    tactic_id="TA0002",
                    tactic_name="Execution",
                    technique_id="T1059",
                    technique_name="Command and Scripting Interpreter",
                )
            )
            process_entity = ProcessEntity(
                image_path=new_process,
                process_name=new_process.split("\\")[-1] if new_process else None,
                command_line=cmdline or None,
                parent_image=parent_proc or None,
            )
            if cmdline:
                observables.append(AlertObservable(type="cmdline", value=cmdline, relevance="suspicious"))
                entities.append(
                    AlertEntity(
                        entity_type="process",
                        entity_value=new_process or cmdline,
                        role="observed",
                        attributes={"command_line": cmdline},
                    )
                )
        elif event_id == "4720":
            category = "persistence"
            severity = "high"
            title = f"Windows Security 4720: User Account Created ({target_user})"
            description = f"User account {target_user} was created by {event_data.get('SubjectUserName')}"
            mitre_list.append(
                MitreAttackReference(
                    tactic_id="TA0003",
                    tactic_name="Persistence",
                    technique_id="T1136.001",
                    technique_name="Local Account",
                )
            )
        elif event_id == "1102":
            category = "defense_evasion"
            severity = "critical"
            title = "Windows Security 1102: Audit Log Cleared"
            description = f"The security audit log on {computer} was cleared by {target_user}"
            mitre_list.append(
                MitreAttackReference(
                    tactic_id="TA0005",
                    tactic_name="Defense Evasion",
                    technique_id="T1070.001",
                    technique_name="Clear Windows Event Logs",
                )
            )

        if ip_address and ip_address not in ("-", "127.0.0.1", "::1"):
            entities.append(
                AlertEntity(
                    entity_type="ip",
                    entity_value=ip_address,
                    role="attacker" if severity in ("high", "critical") else "source",
                    attributes={"port": ip_port},
                )
            )
            observables.append(AlertObservable(type="ip", value=ip_address, relevance="suspicious"))
            network_entity = NetworkEntity(
                source_ip=ip_address,
                source_port=int(ip_port) if ip_port and str(ip_port).isdigit() else None,
            )

        return CanonicalAlert(
            id=uuid4(),
            source_type="windows_security",
            source_alert_id=str(system.get("EventRecordID") or f"winsec-{event_id}-{uuid4().hex[:8]}"),
            title=title,
            description=description,
            severity=severity,
            vendor_severity=str(event_id),
            category=category,
            provider="Microsoft-Windows-Security-Auditing",
            timestamp=ts,
            mitre_attack=mitre_list,
            entities=entities,
            observables=observables,
            host=host_entity,
            user=user_entity,
            process=process_entity,
            network=network_entity,
            raw_ref=raw_ref,
            raw_payload_summary=title,
            custom_fields={"event_id": event_id, "original_event": data},
        )

