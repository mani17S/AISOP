"""
AISOP Network IDS & Firewall Alert Adapter.

Adapts network intrusion detection systems and next-generation firewall alerts
(e.g. Suricata EVE-JSON, Snort, Zeek notices, Palo Alto Threat Logs) into CanonicalAlert models.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.modules.evidence.hasher import compute_sha256
from app.schemas.alert import (
    AlertCategory,
    AlertEntity,
    AlertObservable,
    AlertSeverity,
    CanonicalAlert,
    MitreAttackReference,
)
from app.schemas.entities import DnsEntity, NetworkEntity


class NetworkIdsAdapter:
    """Adapter for Suricata, Snort, and Firewall intrusion alerts."""

    def adapter_name(self) -> str:
        return "firewall_ids"

    def can_adapt(self, raw_data: dict[str, Any] | str) -> bool:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                return False
        if not isinstance(raw_data, dict):
            return False

        if raw_data.get("source_type", "").lower() in ("firewall_ids", "suricata", "snort", "zeek", "firewall", "ids"):
            return True

        if raw_data.get("event_type") == "alert" and isinstance(raw_data.get("alert"), dict):
            return True

        return bool("signature" in raw_data and "src_ip" in raw_data and "dest_ip" in raw_data)

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

        alert_info = data.get("alert", {}) if isinstance(data.get("alert"), dict) else data

        signature = str(
            alert_info.get("signature")
            or data.get("signature")
            or data.get("threat_name")
            or "Network Intrusion Signature Detected"
        )
        sig_id = str(alert_info.get("signature_id") or data.get("signature_id") or data.get("rule_id") or "")
        sig_category = str(alert_info.get("category") or data.get("category") or "Network Anomaly")

        src_ip = str(data.get("src_ip") or data.get("source_ip") or "")
        dest_ip = str(data.get("dest_ip") or data.get("destination_ip") or "")
        proto = str(data.get("proto") or data.get("protocol") or "TCP").upper()
        app_proto = str(data.get("app_proto") or data.get("service") or "").lower()

        src_port: int | None = None
        if data.get("src_port") is not None:
            try:
                src_port = int(data["src_port"])
            except Exception:
                pass

        dest_port: int | None = None
        if data.get("dest_port") is not None:
            try:
                dest_port = int(data["dest_port"])
            except Exception:
                pass

        # Severity resolution:
        # In Suricata: 1 is High/Critical, 2 is Medium, 3 is Low/Info
        raw_sev = alert_info.get("severity") or data.get("severity")
        severity: AlertSeverity = "medium"
        if raw_sev in (1, "1", "critical", "Critical"):
            severity = "critical"
        elif raw_sev in (2, "2", "high", "High"):
            severity = "high"
        elif raw_sev in (3, "3", "medium", "Medium"):
            severity = "medium"
        elif raw_sev in (4, "4", "low", "Low"):
            severity = "low"

        # Timestamp
        ts_val = data.get("timestamp") or data.get("@timestamp")
        if ts_val:
            try:
                ts = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        # MITRE ATT&CK extraction
        mitre_list: list[MitreAttackReference] = []
        metadata = alert_info.get("metadata", {}) if isinstance(alert_info.get("metadata"), dict) else {}
        t_ids = metadata.get("mitre_technique_id", [])
        if isinstance(t_ids, str):
            t_ids = [t_ids]
        for t_id in t_ids:
            mitre_list.append(MitreAttackReference(technique_id=str(t_id)))

        if not mitre_list:
            if any(k in signature.lower() for k in ["c2", "cobalt", "beacon", "trojan", "meterpreter"]):
                mitre_list.append(
                    MitreAttackReference(
                        tactic_id="TA0011",
                        tactic_name="Command and Control",
                        technique_id="T1071.001",
                        technique_name="Web Protocols",
                    )
                )
            elif "scan" in signature.lower() or "sweep" in signature.lower():
                mitre_list.append(
                    MitreAttackReference(
                        tactic_id="TA0007",
                        tactic_name="Discovery",
                        technique_id="T1046",
                        technique_name="Network Service Discovery",
                    )
                )

        # Category resolution
        category: AlertCategory = "command_and_control"
        if any(k in signature.lower() for k in ["exploit", "cve-", "remote code"]):
            category = "initial_access"
        elif any(k in signature.lower() for k in ["scan", "sweep", "discovery"]):
            category = "discovery"
        elif any(k in signature.lower() for k in ["exfiltration", "upload", "leak"]):
            category = "exfiltration"

        # Entities & Observables
        entities: list[AlertEntity] = []
        observables: list[AlertObservable] = []

        if src_ip:
            entities.append(
                AlertEntity(
                    entity_type="ip",
                    entity_value=src_ip,
                    role="attacker" if severity in ("high", "critical") else "source",
                    attributes={"port": src_port, "protocol": proto},
                )
            )
            observables.append(AlertObservable(type="ip", value=src_ip, relevance="suspicious"))

        if dest_ip:
            entities.append(
                AlertEntity(
                    entity_type="ip",
                    entity_value=dest_ip,
                    role="target" if severity in ("high", "critical") else "destination",
                    attributes={"port": dest_port, "protocol": proto},
                )
            )
            observables.append(AlertObservable(type="ip", value=dest_ip, relevance="suspicious"))

        # Check HTTP / DNS context
        http_data = data.get("http", {}) if isinstance(data.get("http"), dict) else {}
        domain_name = http_data.get("hostname") or data.get("domain") or data.get("query_name")
        if domain_name:
            entities.append(
                AlertEntity(
                    entity_type="domain",
                    entity_value=str(domain_name),
                    role="destination",
                    attributes={"http_uri": http_data.get("url")},
                )
            )
            observables.append(AlertObservable(type="domain", value=str(domain_name), relevance="suspicious"))

        dns_entity: DnsEntity | None = None
        if domain_name:
            dns_entity = DnsEntity(query_name=str(domain_name))

        network_entity = NetworkEntity(
            source_ip=src_ip or None,
            source_port=src_port,
            destination_ip=dest_ip or None,
            destination_port=dest_port,
            protocol=proto.lower(),
            destination_hostname=str(domain_name) if domain_name else None,
        )

        return CanonicalAlert(
            id=uuid4(),
            source_type="firewall_ids",
            source_alert_id=str(data.get("flow_id") or sig_id or f"ids-{uuid4().hex[:8]}"),
            title=f"IDS Alert: {signature}",
            description=f"{signature} observed from {src_ip}:{src_port} to {dest_ip}:{dest_port} ({proto})",
            severity=severity,
            vendor_severity=str(raw_sev),
            category=category,
            provider="Suricata-IDS",
            timestamp=ts,
            mitre_attack=mitre_list,
            entities=entities,
            observables=observables,
            network=network_entity,
            dns=dns_entity,
            raw_ref=raw_ref,
            raw_payload_summary=f"{signature} [{src_ip} -> {dest_ip}]",
            custom_fields={
                "signature_id": sig_id,
                "category": sig_category,
                "app_proto": app_proto,
                "original_event": data,
            },
        )

