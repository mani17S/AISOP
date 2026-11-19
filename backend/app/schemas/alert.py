"""
AISOP Canonical Alert Schema & Taxonomy.

Governed by ADR-007 (Vendor-Neutral Alert Ingestion).
This module defines the architectural contract for security alerts ingested from
heterogeneous upstream tools (SIEM, EDR, Network IDS, Cloud Audit, Email Gateways,
Windows Security Events, and Linux Audit/Syslog).

Architectural distinction:
- Security Alert: High-level finding/detection emitted by an upstream security product.
- Raw Telemetry: Low-level event observations (e.g. Sysmon, process creation, network flows).
- Evidence: Cryptographically hashed (SHA-256) immutable artifact stored in the platform.
- Investigation: Analytical container linking alerts, evidence, entities, TI, and reports.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.schemas.entities import (
    DnsEntity,
    FileEntity,
    HostEntity,
    NetworkEntity,
    ProcessEntity,
    RegistryEntity,
    UserEntity,
)
from app.schemas.normalized_event import CanonicalEvent

# Canonical alert severity taxonomy
AlertSeverity = Literal[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
    "unknown",
]

# Canonical alert category taxonomy (aligned with OCSF & MITRE ATT&CK enterprise tactics)
AlertCategory = Literal[
    "malware",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "command_and_control",
    "impact",
    "suspicious_activity",
    "policy_violation",
    "system_anomaly",
    "other",
]

# Canonical alert triage lifecycle status
AlertStatus = Literal[
    "new",
    "triaged",
    "investigating",
    "closed",
    "suppressed",
]


class MitreAttackReference(BaseModel):
    """Structured MITRE ATT&CK enterprise reference."""

    tactic_id: str | None = Field(default=None, description="Tactic ID, e.g. TA0002")
    tactic_name: str | None = Field(default=None, description="Tactic name, e.g. Execution")
    technique_id: str | None = Field(
        default=None, description="Technique ID, e.g. T1059 or T1059.001"
    )
    technique_name: str | None = Field(
        default=None, description="Technique name, e.g. PowerShell"
    )


class AlertEntity(BaseModel):
    """
    Normalized atomic entity extracted from an alert.
    Forms graph nodes for cross-alert correlation, timeline assembly, and threat intelligence.
    """

    entity_type: str = Field(
        description="Entity type: host, user, ip, process, file_hash, domain, url, email"
    )
    entity_value: str = Field(description="Normalized string value of the entity")
    role: str = Field(
        default="observed",
        description="Role in alert: attacker, victim, target, source, destination, observed",
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual entity attributes (e.g. os, port, logon_id)",
    )


class AlertObservable(BaseModel):
    """Security observable or Indicator of Compromise (IOC) extracted from alert."""

    type: str = Field(
        description="Observable type: ip, domain, url, sha256, md5, filename, cmdline"
    )
    value: str = Field(description="Observable value")
    relevance: str | None = Field(
        default=None, description="Analytical relevance: suspicious, benign, context"
    )


class CanonicalAlert(BaseModel):
    """
    Vendor-Neutral Canonical Security Alert.

    Standardizes detection findings across heterogeneous tools while strictly preserving
    full vendor provenance, cryptographic raw hashes, and unmapped attributes.
    """

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique canonical alert identifier within AISOP",
    )
    source_type: str = Field(
        description="Originating source adapter: sysmon, windows_security, linux_auth, edr_malware, firewall_ids, cloud_audit, email_phishing, generic_siem",
    )
    source_alert_id: str = Field(
        description="Upstream vendor alert identifier, correlation ID, or event reference",
    )
    title: str = Field(
        description="Human-readable title or signature summary of the alert",
    )
    description: str | None = Field(
        default=None,
        description="Detailed alert description or trigger rationale",
    )
    severity: AlertSeverity = Field(
        default="medium",
        description="Standardized AISOP alert severity",
    )
    vendor_severity: str | None = Field(
        default=None,
        description="Original vendor severity string or score (e.g. Critical, 8.5, Tier 1)",
    )
    category: AlertCategory = Field(
        default="suspicious_activity",
        description="Standardized classification category",
    )
    provider: str = Field(
        default="generic",
        description="Upstream product/vendor name (e.g. Microsoft Defender, CrowdStrike, Suricata, AWS GuardDuty)",
    )
    status: AlertStatus = Field(
        default="new",
        description="Triage status of the alert",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time the security event/detection occurred on originating asset (UTC)",
    )
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time the alert was received and parsed by AISOP (UTC)",
    )

    # MITRE ATT&CK taxonomy
    mitre_attack: list[MitreAttackReference] = Field(
        default_factory=list,
        description="Associated MITRE ATT&CK tactics and techniques",
    )

    # Extracted graph entities & observables
    entities: list[AlertEntity] = Field(
        default_factory=list,
        description="Atomic entities extracted for correlation and investigation scoping",
    )
    observables: list[AlertObservable] = Field(
        default_factory=list,
        description="Extracted indicators of compromise (IOCs)",
    )

    # Normalized typed contextual models (compatible with CanonicalEvent)
    host: HostEntity | None = Field(default=None, description="Primary endpoint context")
    user: UserEntity | None = Field(default=None, description="Primary user context")
    process: ProcessEntity | None = Field(default=None, description="Primary process context")
    network: NetworkEntity | None = Field(default=None, description="Primary network flow context")
    file: FileEntity | None = Field(default=None, description="Primary file context")
    dns: DnsEntity | None = Field(default=None, description="Primary DNS query context")
    registry: RegistryEntity | None = Field(
        default=None, description="Primary registry context"
    )

    # Strict provenance and audit integrity
    raw_ref: str = Field(
        description="Cryptographic SHA-256 digest of original raw alert evidence payload",
    )
    raw_payload_summary: str | None = Field(
        default=None,
        description="Sanitized summary representation of original vendor alert",
    )
    custom_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Unmapped vendor-specific attributes preserved verbatim for full fidelity",
    )

    def to_canonical_event(self) -> CanonicalEvent:
        """
        Convert CanonicalAlert to CanonicalEvent for seamless persistence in existing
        NormalizedEventModel table and full interoperability with ContextBuilder,
        TimelineSynthesizer, and RAG knowledge retrieval.
        """
        event_severity: Literal["informational", "low", "medium", "high", "critical"]
        if self.severity in ("informational", "low", "medium", "high", "critical"):
            event_severity = self.severity  # type: ignore[assignment]
        else:
            event_severity = "informational"

        # Build custom fields preserving alert-specific metadata
        merged_custom_fields = dict(self.custom_fields)
        merged_custom_fields.update(
            {
                "is_alert": True,
                "alert_title": self.title,
                "alert_category": self.category,
                "vendor_severity": self.vendor_severity,
                "mitre_attack": [ref.model_dump() for ref in self.mitre_attack],
                "observables": [obs.model_dump() for obs in self.observables],
            }
        )

        return CanonicalEvent(
            id=self.id,
            event_id=self.source_alert_id,
            event_type=f"alert.{self.category}",
            timestamp=self.timestamp,
            provider=self.provider,
            action="alert_triggered",
            outcome="success",
            severity=event_severity,
            host=self.host,
            user=self.user,
            process=self.process,
            network=self.network,
            file=self.file,
            registry=self.registry,
            dns=self.dns,
            raw_ref=self.raw_ref,
            raw_payload_summary=self.raw_payload_summary or self.title,
            custom_fields=merged_custom_fields,
        )

