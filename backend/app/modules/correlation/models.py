"""
AISOP multi-source correlation: data models (Stage 3C-R vertical slice, ADR-009).

Immutable, source-neutral views produced by the normalizer and consumed by the correlator,
timeline builder, deterministic ATT&CK mapper and report renderer. Every event keeps the
SHA-256 of the raw record it came from, so any statement in a report can be traced back to
preserved evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class CorrelationEvent(BaseModel):
    """One normalized observation from any source (SIEM alert, identity, Sysmon, DNS, firewall...)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_key: uuid.UUID = Field(description="Deterministic id: uuid5(raw digest + record index)")
    record_index: int = Field(ge=0, description="Position of the raw record in the submitted batch")
    source_type: str = Field(description="Adapter that parsed the record (e.g. windows_security, sysmon)")
    provider: str
    timestamp: datetime
    title: str
    category: str
    severity: str
    outcome: str = Field(default="unknown", description="success | failure | unknown")
    host: Optional[str] = None
    host_source: str = Field(default="record", description="record | asset_inventory | none")
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    domain: Optional[str] = None
    process_name: Optional[str] = None
    process_guid: Optional[str] = None
    parent_process_guid: Optional[str] = None
    command_line: Optional[str] = None
    file_hashes: tuple[str, ...] = ()
    vendor_techniques: tuple[str, ...] = Field(default=(), description="ATT&CK ids ASSERTED by the source, not derived")
    source_event_id: str = Field(default="", description="Vendor event/signature id when present")
    native_event_id: str = Field(default="", max_length=64, description="Stage 7C/D2: the native id the SOURCE supplied (EDR detection id, Linux auth record id). Source-scoped provenance only (scope = source_type): never an identity, entity, correlation or independence key")
    time_assumed_utc: bool = Field(default=False, description="Stage 7B/D5: the source gave no time zone and UTC was ASSUMED (not documented by the source), so the event time is unverified")
    upstream_id: str = Field(default="", description="ADR-013/D5: source-declared underlying collection id; copies sharing it are one evidence unit")
    evidence_type: str = Field(default="", description="Canonical evidence type for source-agnostic observations (ADR-011); empty for SIEM/Sysmon alerts")
    raw_sha256: str = Field(min_length=64, max_length=64)
    entities: tuple[tuple[str, str], ...] = Field(default=(), description="(type, value) pairs used for linking")


class RejectedRecord(BaseModel):
    """A raw record that could not be normalized. Preserved, never silently dropped."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    record_index: int
    reason: str = Field(description="NO_ADAPTER | NOT_AN_OBJECT | ADAPTER_ERROR:<ExceptionType>")
    raw_sha256: str


class NormalizationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    events: list[CorrelationEvent]
    rejected: list[RejectedRecord]
    observations: list[Any] = Field(
        default_factory=list,
        description="Canonical observations (ADR-011) for aisop.evidence/1 records: ALL of them, including undated, analyst and unclassified ones that are not projected to events",
    )


class Link(BaseModel):
    """A relationship between two evidence clusters, with its strength and the reason for it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    cluster_a: int
    cluster_b: int
    strength: str = Field(description="strong | specific | weak (AiSOC link tiers)")
    shared_entities: tuple[tuple[str, str], ...]


class EvidenceCluster(BaseModel):
    """Duplicates, same-record and near-duplicate events collapsed into one evidence unit."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    cluster_id: int
    representative: uuid.UUID
    members: tuple[uuid.UUID, ...]
    first_seen: datetime
    last_seen: datetime


class Contradiction(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_keys: tuple[uuid.UUID, ...]
    reason: str


class Incident(BaseModel):
    """A group of evidence that belongs together, with the reason each part is included."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: uuid.UUID
    core_clusters: tuple[int, ...] = Field(description="joined by STRONG/SPECIFIC links")
    weak_context_clusters: tuple[int, ...] = Field(
        default=(), description="attached by weak host/user/internal-IP links only (context, not corroboration)"
    )
    event_keys: tuple[uuid.UUID, ...]
    first_seen: datetime
    last_seen: datetime
    hosts: tuple[str, ...]
    users: tuple[str, ...]
    severity: str
    stages: tuple[str, ...] = Field(default=(), description="kill-chain stages present, in order")
    escalated: bool = False
    link_counts: dict[str, int] = Field(default_factory=dict)
    weakly_related: tuple[uuid.UUID, ...] = Field(
        default=(), description="other incidents joined to this one only by weak links (reported, never merged)"
    )


class CorrelationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    events: list[CorrelationEvent]
    clusters: list[EvidenceCluster]
    links: list[Link]
    incidents: list[Incident]
    contradictions: list[Contradiction]


class TimelineEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    position: int
    timestamp: datetime
    source_type: str
    host: Optional[str]
    user: Optional[str]
    title: str
    stage: str
    severity: str
    outcome: str
    raw_sha256_prefix: str
    membership: str = Field(description="core | weak_context")
    duplicates_collapsed: int = 0
    contradicts: tuple[uuid.UUID, ...] = ()
    event_key: uuid.UUID


class MitreMapping(BaseModel):
    """Technique derived by a deterministic rule from evidence (not a probability, not a vendor claim)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str
    technique_name: str
    tactics: tuple[str, ...]
    rule_id: str
    evidence_keys: tuple[uuid.UUID, ...]
    independent_evidence_count: int
    vendor_asserted: bool = Field(description="True when a source also asserted this technique or its parent")
    limitation: str
