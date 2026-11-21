"""
AISOP Sysmon Alert Adapter.

Adapts Microsoft Sysmon XML-converted or JSON telemetry into CanonicalAlert models.
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
from app.schemas.entities import (
    FileEntity,
    HostEntity,
    NetworkEntity,
    ProcessEntity,
    UserEntity,
)


class SysmonAlertAdapter:
    """Adapter for Windows Sysmon event logs."""

    def adapter_name(self) -> str:
        return "sysmon"

    def can_adapt(self, raw_data: dict[str, Any] | str) -> bool:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                return False
        if not isinstance(raw_data, dict):
            return False

        # Check for standard Sysmon structural markers
        if "Event" in raw_data and isinstance(raw_data["Event"], dict):
            event = raw_data["Event"]
            system = event.get("System", {})
            provider = system.get("Provider", {}).get("@Name", "")
            if "sysmon" in provider.lower():
                return True

        if "EventData" in raw_data and (
            "UtcTime" in raw_data["EventData"] or "ProcessGuid" in raw_data["EventData"]
        ):
            return True

        if raw_data.get("provider", "").lower() == "microsoft-windows-sysmon":
            return True

        return False

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

        # Unpack System and EventData if wrapped
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
            or "1"
        )
        computer = str(
            system.get("Computer")
            or event_data.get("Computer")
            or data.get("computer")
            or data.get("host")
            or "UNKNOWN-HOST"
        )
        user_val = str(
            event_data.get("User")
            or event_data.get("TargetUserName")
            or data.get("user")
            or "SYSTEM"
        )

        # Extract timestamps
        time_created = (
            system.get("TimeCreated", {}).get("@SystemTime")
            or event_data.get("UtcTime")
            or data.get("timestamp")
        )
        ts = require_event_time(time_created)

        rule_name = str(event_data.get("RuleName", "") or "")
        image = str(event_data.get("Image", "") or "")
        cmdline = str(event_data.get("CommandLine", "") or "")
        parent_image = str(event_data.get("ParentImage", "") or "")
        hashes_str = str(event_data.get("Hashes", "") or "")

        # Parse hashes (SHA256=xxx,MD5=yyy)
        hashes_dict: dict[str, str] = {}
        observables: list[AlertObservable] = []
        if hashes_str:
            for part in hashes_str.split(","):
                if "=" in part:
                    h_type, h_val = part.split("=", 1)
                    hashes_dict[h_type.strip().lower()] = h_val.strip()
                    observables.append(
                        AlertObservable(
                            type=f"hash_{h_type.strip().lower()}",
                            value=h_val.strip(),
                            relevance="suspicious",
                        )
                    )

        # MITRE ATT&CK extraction from RuleName (technique_id=T1059.001,technique_name=PowerShell)
        mitre_list: list[MitreAttackReference] = []
        if "technique_id=" in rule_name:
            import re

            t_id = re.search(r"technique_id=([^,]+)", rule_name)
            t_name = re.search(r"technique_name=([^,]+)", rule_name)
            mitre_list.append(
                MitreAttackReference(
                    technique_id=t_id.group(1).strip() if t_id else None,
                    technique_name=t_name.group(1).strip() if t_name else None,
                )
            )

        # Default classification based on EventID
        category: AlertCategory = "suspicious_activity"
        severity: AlertSeverity = "medium"

        if event_id == "1":
            category = "execution"
            if not mitre_list:
                mitre_list.append(
                    MitreAttackReference(
                        technique_id="T1059", technique_name="Command and Scripting Interpreter"
                    )
                )
            # Heuristic severity for known suspicious processes/flags
            low_cmd = cmdline.lower()
            if any(k in low_cmd for k in ["mimikatz", "-enc", "bypass", "vssadmin delete"]):
                severity = "critical"
            elif any(k in low_cmd for k in ["whoami", "net user", "certutil -urlcache"]):
                severity = "high"
        elif event_id == "3":
            category = "command_and_control"
            if not mitre_list:
                mitre_list.append(
                    MitreAttackReference(
                        technique_id="T1071", technique_name="Application Layer Protocol"
                    )
                )
        elif event_id == "7":
            category = "defense_evasion"
        elif event_id == "10":
            category = "privilege_escalation"
        elif event_id == "11":
            category = "persistence"

        # Build entities
        entities: list[AlertEntity] = [
            AlertEntity(
                entity_type="host",
                entity_value=computer,
                role="victim",
                attributes={"hostname": computer},
            ),
            AlertEntity(
                entity_type="user",
                entity_value=user_val,
                role="observed",
                attributes={"username": user_val},
            ),
        ]

        host_entity = HostEntity(hostname=computer)
        user_entity = UserEntity(username=user_val)

        process_entity: ProcessEntity | None = None
        if image or cmdline:
            pid = None
            try:
                pid = int(event_data.get("ProcessId", 0))
            except Exception:
                pass
            ppid = None
            try:
                ppid = int(event_data.get("ParentProcessId", 0))
            except Exception:
                pass
            process_entity = ProcessEntity(
                image_path=image,
                process_name=image.split("\\")[-1] if image else None,
                command_line=cmdline,
                pid=pid,
                ppid=ppid,
                parent_image=parent_image,
                hashes=hashes_dict,
            )
            entities.append(
                AlertEntity(
                    entity_type="process",
                    entity_value=image or cmdline,
                    role="attacker",
                    attributes={"command_line": cmdline, "pid": pid},
                )
            )
            if cmdline:
                observables.append(
                    AlertObservable(type="cmdline", value=cmdline, relevance="suspicious")
                )

        network_entity: NetworkEntity | None = None
        dest_ip = event_data.get("DestinationIp") or data.get("dest_ip")
        if dest_ip:
            src_ip = event_data.get("SourceIp") or data.get("src_ip")
            src_port = None
            try:
                src_port = int(event_data.get("SourcePort", 0))
            except Exception:
                pass
            dest_port = None
            try:
                dest_port = int(event_data.get("DestinationPort", 0))
            except Exception:
                pass
            network_entity = NetworkEntity(
                source_ip=str(src_ip) if src_ip else None,
                source_port=src_port,
                destination_ip=str(dest_ip),
                destination_port=dest_port,
                protocol=str(event_data.get("Protocol", "tcp")).lower(),
                destination_hostname=event_data.get("DestinationHostname"),
            )
            entities.append(
                AlertEntity(
                    entity_type="ip",
                    entity_value=str(dest_ip),
                    role="destination",
                    attributes={"port": dest_port},
                )
            )
            observables.append(
                AlertObservable(type="ip", value=str(dest_ip), relevance="suspicious")
            )

        title = (
            f"Sysmon Event {event_id}: {image.split('\\')[-1] if image else 'Suspicious Activity'}"
            if image
            else f"Sysmon Event {event_id} Detection"
        )

        return CanonicalAlert(
            id=uuid4(),
            source_type="sysmon",
            source_alert_id=str(data.get("RecordId") or event_id),
            title=title,
            description=f"Sysmon {event_id} alert on host {computer} executed by {user_val}",
            severity=severity,
            vendor_severity=str(event_id),
            category=category,
            provider="Microsoft-Windows-Sysmon",
            timestamp=ts,
            mitre_attack=mitre_list,
            entities=entities,
            observables=observables,
            host=host_entity,
            user=user_entity,
            process=process_entity,
            network=network_entity,
            raw_ref=raw_ref,
            raw_payload_summary=f"Sysmon {event_id} ({image})",
            custom_fields={
                "event_id": event_id,
                "rule_name": rule_name,
                "original_event": data,
            },
        )

