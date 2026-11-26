"""
AISOP Generic SIEM Correlation Alert Adapter.

Adapts correlation alerts and notable incidents from enterprise SIEM platforms
(e.g. Splunk ES Notable Events, Microsoft Sentinel Incidents, Elastic Security Alerts,
QRadar Offenses, and Wazuh alerts) into CanonicalAlert models.
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

SEVERITY_LOOKUP: dict[str, AlertSeverity] = {
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
    "urgent": "critical",
    "5": "critical",
    "high": "high",
    "4": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "3": "medium",
    "low": "low",
    "2": "low",
    "informational": "informational",
    "info": "informational",
    "1": "informational",
}


class GenericSiemAdapter:
    """Universal adapter for structured SIEM correlation alerts and incident findings."""

    def adapter_name(self) -> str:
        return "generic_siem"

    def can_adapt(self, raw_data: dict[str, Any] | str) -> bool:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                return False
        if not isinstance(raw_data, dict):
            return False

        if raw_data.get("source_type", "").lower() in ("generic_siem", "siem", "splunk", "sentinel", "qradar"):
            return True

        return bool(
            "rule_name" in raw_data
            or "rule_id" in raw_data
            or "incident_id" in raw_data
            or "search_name" in raw_data
            or "notable" in raw_data
        )

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

        rule_id = str(
            data.get("rule_id")
            or data.get("alert_id")
            or data.get("incident_id")
            or data.get("id")
            or f"siem-{uuid4().hex[:8]}"
        )
        title = str(
            data.get("rule_name")
            or data.get("alert_name")
            or data.get("title")
            or data.get("name")
            or "SIEM Correlation Alert"
        )
        description = str(
            data.get("description")
            or data.get("summary")
            or f"SIEM correlation alert triggered: {title}"
        )
        provider = str(
            data.get("provider")
            or data.get("siem")
            or data.get("source")
            or "Enterprise-SIEM"
        )

        # Severity resolution
        # A missing or unrecognised vendor severity stays "unknown", it is never defaulted to "medium"
        vendor_sev = data.get("severity") or data.get("urgency") or data.get("priority")
        severity: AlertSeverity = SEVERITY_LOOKUP.get(str(vendor_sev).lower(), "unknown") if vendor_sev else "unknown"

        # Timestamp
        ts_val = data.get("timestamp") or data.get("@timestamp") or data.get("created_at") or data.get("time")
        ts = require_event_time(ts_val)

        # Category resolution
        cat_str = str(data.get("category") or data.get("tactic") or "suspicious_activity").lower()
        category: AlertCategory = "suspicious_activity"
        valid_categories = {
            "malware", "initial_access", "execution", "persistence", "privilege_escalation",
            "defense_evasion", "credential_access", "discovery", "lateral_movement",
            "collection", "exfiltration", "command_and_control", "impact", "suspicious_activity",
            "policy_violation", "system_anomaly"
        }
        if cat_str in valid_categories:
            category = cat_str  # type: ignore[assignment]
        elif any(k in title.lower() for k in ["brute", "password", "credential"]):
            category = "credential_access"
        elif any(k in title.lower() for k in ["malware", "trojan", "ransomware"]):
            category = "malware"
        elif any(k in title.lower() for k in ["c2", "beacon", "tunnel"]):
            category = "command_and_control"

        # MITRE ATT&CK extraction
        mitre_list: list[MitreAttackReference] = []
        raw_techniques = data.get("mitre_techniques") or data.get("techniques") or []
        if isinstance(raw_techniques, str):
            raw_techniques = [raw_techniques]
        for t in raw_techniques:
            mitre_list.append(MitreAttackReference(technique_id=str(t)))

        raw_tactics = data.get("mitre_tactics") or data.get("tactics") or []
        if isinstance(raw_tactics, str):
            raw_tactics = [raw_tactics]
        for idx, tac in enumerate(raw_tactics):
            if idx < len(mitre_list):
                mitre_list[idx].tactic_name = str(tac)
            else:
                mitre_list.append(MitreAttackReference(tactic_name=str(tac)))

        # Entity extraction
        entities: list[AlertEntity] = []
        observables: list[AlertObservable] = []

        host_val = data.get("host") or data.get("hostname") or data.get("dest_host")
        if host_val:
            entities.append(
                AlertEntity(
                    entity_type="host",
                    entity_value=str(host_val),
                    role="target",
                    attributes={"hostname": str(host_val)},
                )
            )

        user_val = data.get("user") or data.get("username") or data.get("src_user")
        if user_val:
            entities.append(
                AlertEntity(
                    entity_type="user",
                    entity_value=str(user_val),
                    role="observed",
                    attributes={"username": str(user_val)},
                )
            )

        src_ip = data.get("src_ip") or data.get("source_ip")
        if src_ip:
            entities.append(
                AlertEntity(
                    entity_type="ip",
                    entity_value=str(src_ip),
                    role="attacker" if severity in ("high", "critical") else "source",
                )
            )
            observables.append(AlertObservable(type="ip", value=str(src_ip), relevance="suspicious"))

        dest_ip = data.get("dest_ip") or data.get("destination_ip")
        if dest_ip:
            entities.append(
                AlertEntity(
                    entity_type="ip",
                    entity_value=str(dest_ip),
                    role="target" if severity in ("high", "critical") else "destination",
                )
            )
            observables.append(AlertObservable(type="ip", value=str(dest_ip), relevance="suspicious"))

        sha256_val = data.get("sha256") or data.get("file_hash")
        if sha256_val:
            entities.append(
                AlertEntity(
                    entity_type="file_hash",
                    entity_value=str(sha256_val),
                    role="attacker",
                    attributes={"algorithm": "sha256"},
                )
            )
            observables.append(AlertObservable(type="sha256", value=str(sha256_val), relevance="suspicious"))

        # Explicit entity list in raw data
        explicit_entities = data.get("entities")
        if isinstance(explicit_entities, list):
            for item in explicit_entities:
                if isinstance(item, dict) and "type" in item and "value" in item:
                    entities.append(
                        AlertEntity(
                            entity_type=str(item["type"]),
                            entity_value=str(item["value"]),
                            role=str(item.get("role", "observed")),
                            attributes=item.get("attributes", {}),
                        )
                    )

        host_entity = HostEntity(hostname=str(host_val)) if host_val else None
        user_entity = UserEntity(username=str(user_val)) if user_val else None
        network_entity = (
            NetworkEntity(source_ip=str(src_ip) if src_ip else None, destination_ip=str(dest_ip) if dest_ip else None)
            if (src_ip or dest_ip)
            else None
        )

        return CanonicalAlert(
            id=uuid4(),
            source_type="generic_siem",
            source_alert_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            vendor_severity=str(vendor_sev) if vendor_sev else None,
            category=category,
            provider=provider,
            timestamp=ts,
            mitre_attack=mitre_list,
            entities=entities,
            observables=observables,
            host=host_entity,
            user=user_entity,
            network=network_entity,
            raw_ref=raw_ref,
            raw_payload_summary=f"{title} ({rule_id})",
            custom_fields={"original_event": data},
        )
