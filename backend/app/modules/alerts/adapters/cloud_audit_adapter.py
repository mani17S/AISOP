"""
AISOP Cloud Audit & IAM Alert Adapter.

Adapts cloud security findings and anomalous audit events
(e.g. AWS GuardDuty, AWS CloudTrail, Azure Entra ID Identity Protection, GCP Cloud Audit)
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
from app.schemas.entities import HostEntity, NetworkEntity, UserEntity


class CloudAuditAdapter:
    """Adapter for CloudTrail, GuardDuty, Entra ID, and GCP Cloud Audit logs."""

    def adapter_name(self) -> str:
        return "cloud_audit"

    def can_adapt(self, raw_data: dict[str, Any] | str) -> bool:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                return False
        if not isinstance(raw_data, dict):
            return False

        if raw_data.get("source_type", "").lower() in ("cloud_audit", "guardduty", "cloudtrail", "entra_id", "gcp_audit"):
            return True

        if "awsApiCallAction" in str(raw_data) or "GuardDuty" in str(raw_data):
            return True

        if "protoPayload" in raw_data or "riskEventType" in raw_data:
            return True

        return bool(
            raw_data.get("eventSource", "").endswith(".amazonaws.com")
            or "principalEmail" in str(raw_data)
            or "userPrincipalName" in raw_data
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

        finding_id = str(
            data.get("id")
            or data.get("finding_id")
            or data.get("eventID")
            or f"cloud-{uuid4().hex[:8]}"
        )
        provider = str(
            data.get("provider")
            or data.get("eventSource")
            or ("AWS-GuardDuty" if "service" in data else "Cloud-IAM-Audit")
        )

        title = str(
            data.get("title")
            or data.get("type")
            or data.get("eventName")
            or data.get("riskEventType")
            or "Suspicious Cloud Activity Detected"
        )
        description = str(
            data.get("description")
            or f"Anomalous cloud audit event: {title}"
        )

        # Extract timestamps
        ts_val = (
            data.get("createdAt")
            or data.get("eventTime")
            or data.get("timestamp")
            or data.get("createdDateTime")
        )
        ts = require_event_time(ts_val)

        # Unpack user identity & principal
        user_val = ""
        account_id = str(data.get("accountId") or data.get("recipientAccountId") or "")
        src_ip = ""
        user_agent = ""

        # AWS GuardDuty structure
        service_data = data.get("service", {}) if isinstance(data.get("service"), dict) else {}
        action_data = service_data.get("action", {}) if isinstance(service_data.get("action"), dict) else {}
        api_call = action_data.get("awsApiCallAction", {}) if isinstance(action_data.get("awsApiCallAction"), dict) else {}
        remote_ip_details = api_call.get("remoteIpDetails", {}) if isinstance(api_call.get("remoteIpDetails"), dict) else {}

        if remote_ip_details:
            src_ip = str(remote_ip_details.get("ipAddressV4") or remote_ip_details.get("ipAddress") or "")
        if api_call:
            user_agent = str(api_call.get("userAgent", ""))

        resource = data.get("resource", {}) if isinstance(data.get("resource"), dict) else {}
        access_keys = resource.get("accessKeyDetails", {}) if isinstance(resource.get("accessKeyDetails"), dict) else {}
        if access_keys.get("userName"):
            user_val = str(access_keys.get("userName"))

        # Fallback to CloudTrail / Azure / GCP
        if not user_val:
            # No principal in the record means no user: none is invented (and a dict without userName no longer yields the text "None").
            identity = data["userIdentity"] if isinstance(data.get("userIdentity"), dict) else {}
            user_val = str(
                identity.get("userName")
                or data.get("userPrincipalName")
                or data.get("user")
                or data.get("principalEmail")
                or ""
            ).strip()
        if not src_ip:
            src_ip = str(data.get("sourceIPAddress") or data.get("ipAddress") or data.get("caller_ip") or "")

        # Severity resolution
        # A missing or unrecognised vendor severity stays "unknown"; it is never defaulted to a mid score.
        raw_sev = data.get("severity")
        severity: AlertSeverity = "unknown"
        if raw_sev not in (None, ""):
            try:
                num_sev = float(raw_sev)
                if num_sev >= 7.0:
                    severity = "high"
                    if num_sev >= 8.5:
                        severity = "critical"
                elif num_sev <= 3.9:
                    severity = "low"
                else:
                    severity = "medium"
            except (ValueError, TypeError):
                sev_str = str(raw_sev).lower()
                if sev_str in ("critical", "high", "medium", "low", "informational"):
                    severity = sev_str  # type: ignore[assignment]

        # MITRE ATT&CK mapping
        mitre_list: list[MitreAttackReference] = [
            MitreAttackReference(
                tactic_id="TA0001",
                tactic_name="Initial Access",
                technique_id="T1078.004",
                technique_name="Cloud Accounts",
            )
        ]
        if any(k in title.lower() for k in ["credential", "exfiltration", "key"]):
            mitre_list.append(
                MitreAttackReference(
                    tactic_id="TA0006",
                    tactic_name="Credential Access",
                    technique_id="T1552",
                    technique_name="Unsecured Credentials",
                )
            )

        entities: list[AlertEntity] = []
        if user_val:
            entities.append(
                AlertEntity(
                    entity_type="user",
                    entity_value=user_val,
                    role="target",
                    attributes={"account_id": account_id, "user_agent": user_agent},
                )
            )
        observables: list[AlertObservable] = []

        if src_ip and src_ip not in ("-", "127.0.0.1"):
            entities.append(
                AlertEntity(
                    entity_type="ip",
                    entity_value=src_ip,
                    role="attacker",
                    attributes={"user_agent": user_agent},
                )
            )
            observables.append(AlertObservable(type="ip", value=src_ip, relevance="suspicious"))

        user_entity = UserEntity(username=user_val, domain=account_id or None) if user_val else None
        network_entity = NetworkEntity(source_ip=src_ip) if src_ip else None

        return CanonicalAlert(
            id=uuid4(),
            source_type="cloud_audit",
            source_alert_id=finding_id,
            title=f"Cloud Security Finding: {title}",
            description=description,
            severity=severity,
            vendor_severity=str(raw_sev) if raw_sev not in (None, "") else None,
            category="credential_access" if "credential" in title.lower() else "suspicious_activity",
            provider=provider,
            timestamp=ts,
            mitre_attack=mitre_list,
            entities=entities,
            observables=observables,
            user=user_entity,
            network=network_entity,
            raw_ref=raw_ref,
            raw_payload_summary=f"{title} [{user_val}]" if user_val else title,
            custom_fields={
                "account_id": account_id,
                "action_type": action_data.get("actionType"),
                "api": api_call.get("api"),
                "original_event": data,
            },
        )

