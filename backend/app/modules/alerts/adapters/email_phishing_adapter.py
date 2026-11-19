"""
AISOP Email Phishing & Gateway Alert Adapter.

Adapts email security gateway alerts (e.g. Proofpoint TAP, Microsoft Defender for Office 365,
Mimecast, Abnormal Security) into CanonicalAlert models.
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
from app.schemas.entities import FileEntity, UserEntity


class EmailPhishingAdapter:
    """Adapter for Email Security Gateways and Phishing detection alerts."""

    def adapter_name(self) -> str:
        return "email_phishing"

    def can_adapt(self, raw_data: dict[str, Any] | str) -> bool:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                return False
        if not isinstance(raw_data, dict):
            return False

        if raw_data.get("source_type", "").lower() in ("email_phishing", "email_security", "proofpoint", "mimecast", "o365_defender"):
            return True

        if "threat_type" in raw_data and ("sender" in raw_data or "recipient" in raw_data):
            return True

        return bool("sender" in raw_data and "recipient" in raw_data and "subject" in raw_data)

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

        msg_id = str(
            data.get("message_id")
            or data.get("id")
            or data.get("threat_id")
            or f"email-{uuid4().hex[:8]}"
        )
        provider = str(
            data.get("provider")
            or data.get("vendor")
            or "Email-Security-Gateway"
        )
        sender = str(data.get("sender") or data.get("from") or "unknown@external.com")
        recipient = str(data.get("recipient") or data.get("to") or "victim@internal.com")
        subject = str(data.get("subject") or "No Subject")
        threat_type = str(data.get("threat_type") or data.get("verdict") or "Phishing")

        # Timestamp
        ts_val = data.get("timestamp") or data.get("delivery_time") or data.get("date")
        if ts_val:
            try:
                ts = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        # Severity
        raw_sev = str(data.get("severity") or "high").lower()
        severity: AlertSeverity = "high"
        if raw_sev in ("critical", "high", "medium", "low", "informational"):
            severity = raw_sev  # type: ignore[assignment]

        entities: list[AlertEntity] = [
            AlertEntity(
                entity_type="email",
                entity_value=sender,
                role="attacker",
                attributes={"subject": subject},
            ),
            AlertEntity(
                entity_type="email",
                entity_value=recipient,
                role="victim",
                attributes={"subject": subject},
            ),
            AlertEntity(
                entity_type="user",
                entity_value=recipient.split("@")[0],
                role="victim",
                attributes={"email": recipient},
            ),
        ]
        observables: list[AlertObservable] = []

        # Extract domain from sender
        if "@" in sender:
            sender_domain = sender.split("@")[-1]
            entities.append(
                AlertEntity(
                    entity_type="domain",
                    entity_value=sender_domain,
                    role="attacker",
                    attributes={"source": "sender_domain"},
                )
            )
            observables.append(
                AlertObservable(type="domain", value=sender_domain, relevance="suspicious")
            )

        # Extract attachments
        attachment_data = data.get("attachment") or data.get("attachments")
        att_hashes: dict[str, str] = {}
        file_entity: FileEntity | None = None

        if isinstance(attachment_data, dict):
            att_name = attachment_data.get("name") or attachment_data.get("filename")
            att_sha = attachment_data.get("sha256")
            att_md5 = attachment_data.get("md5")
            if att_sha:
                att_hashes["sha256"] = str(att_sha)
                entities.append(
                    AlertEntity(
                        entity_type="file_hash",
                        entity_value=str(att_sha),
                        role="attacker",
                        attributes={"filename": att_name},
                    )
                )
                observables.append(
                    AlertObservable(type="sha256", value=str(att_sha), relevance="suspicious")
                )
            if att_md5:
                att_hashes["md5"] = str(att_md5)
                observables.append(
                    AlertObservable(type="md5", value=str(att_md5), relevance="suspicious")
                )
            if att_name:
                entities.append(
                    AlertEntity(
                        entity_type="file",
                        entity_value=str(att_name),
                        role="attacker",
                        attributes={"hashes": att_hashes},
                    )
                )
                observables.append(
                    AlertObservable(type="filename", value=str(att_name), relevance="suspicious")
                )
                file_entity = FileEntity(filename=str(att_name), hashes=att_hashes)

        # Extract URLs
        urls = data.get("urls") or data.get("malicious_urls") or []
        if isinstance(urls, str):
            urls = [urls]
        for item in urls:
            u_str = item.get("url") if isinstance(item, dict) else str(item)
            if u_str:
                entities.append(
                    AlertEntity(
                        entity_type="url",
                        entity_value=u_str,
                        role="attacker",
                        attributes={"threat_type": threat_type},
                    )
                )
                observables.append(AlertObservable(type="url", value=u_str, relevance="suspicious"))

        mitre_list: list[MitreAttackReference] = [
            MitreAttackReference(
                tactic_id="TA0001",
                tactic_name="Initial Access",
                technique_id="T1566.001" if attachment_data else "T1566.002",
                technique_name="Spearphishing Attachment" if attachment_data else "Spearphishing Link",
            )
        ]

        title = f"Phishing Alert: '{subject}' ({threat_type})"
        description = (
            f"Suspicious email detected from {sender} targeting {recipient}. "
            f"Subject: '{subject}'"
        )

        return CanonicalAlert(
            id=uuid4(),
            source_type="email_phishing",
            source_alert_id=msg_id,
            title=title,
            description=description,
            severity=severity,
            vendor_severity=str(data.get("severity") or raw_sev),
            category="initial_access",
            provider=provider,
            timestamp=ts,
            mitre_attack=mitre_list,
            entities=entities,
            observables=observables,
            user=UserEntity(username=recipient.split("@")[0]),
            file=file_entity,
            raw_ref=raw_ref,
            raw_payload_summary=f"Phishing: {subject[:80]} [{sender}]",
            custom_fields={
                "sender": sender,
                "recipient": recipient,
                "subject": subject,
                "threat_type": threat_type,
                "original_event": data,
            },
        )

