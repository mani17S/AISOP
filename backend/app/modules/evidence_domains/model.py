"""
AISOP source-agnostic evidence model (Stage 6, ADR-011).

An ``Observation`` is what an adapter extracts from ONE raw evidence record of ANY security domain: identity,
cloud audit, network, e-mail, forensic artefact, analyst statement. It is deliberately not an alert:
there is no required severity, no vendor alert id, and no required timestamp. What it always keeps:

* the evidence type and family (so a file artefact is never presented as an event alert),
* the source system and the collection method (provenance),
* the SHA-256 of the exact raw record (integrity),
* ``event_time`` separate from ``collected_at``, with an explicit ``time_status`` (a missing or invalid
  event time stays missing; the current time is never substituted),
* typed entities and the relationships the record itself directly states,
* the adapter name and version, and a trust class that says what kind of statement this is.

Pure data, no I/O. The raw record itself is stored unchanged by the application (``raw_evidence``); the
observation is a derived, re-computable view of it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

ENVELOPE_SCHEMA = "aisop.evidence/1"
MODEL_VERSION = "evidence-model-1"


class EvidenceFamily(StrEnum):
    IDENTITY = "identity"
    CLOUD = "cloud"
    NETWORK = "network"
    EMAIL = "email"
    FILE = "file"
    REGISTRY = "registry"
    MEMORY = "memory"
    PROCESS_ARTEFACT = "process_artefact"
    ANALYST = "analyst"
    UNCLASSIFIED = "unclassified"  # structurally valid envelope, evidence type not recognised: preserved, not interpreted


class TrustClass(StrEnum):
    """What kind of statement this is (never upgraded by repetition or by a model)."""

    RAW_OBSERVED = "raw_observed"            # a record produced by a collector/log source
    TOOL_ASSERTED = "tool_asserted"          # a forensic tool's interpretation (e.g. memory finding)
    ANALYST_OBSERVATION = "analyst_observation"  # a human statement; context, never corroboration
    DERIVED = "derived"                      # computed from observations (graph, hypotheses)
    TI_CONTEXT = "ti_context"                # threat intelligence: reference, not incident evidence
    MODEL_INFERENCE = "model_inference"      # LLM output
    ANALYST_CONFIRMED = "analyst_confirmed"  # reserved: set only by an explicit analyst decision


class TimeStatus(StrEnum):
    VALID = "valid"
    NAIVE_ASSUMED_UTC = "naive_assumed_utc"  # source gave no zone; UTC assumed and disclosed
    MISSING = "missing"
    INVALID = "invalid"
    OUT_OF_RANGE = "out_of_range"


def stored_event_time_unknown(normalized_payload: Optional[dict]) -> bool:
    """Stage 7A (owner decision D1): the same notion as ``bridge.is_dated`` is False, for a STORED normalized event.

    ``normalized_events.event_timestamp`` is NOT NULL, so for a record without a usable event time it holds the INGESTION time and
    the payload states ``event_timestamp_is_ingestion_time: true`` (set by the domain evidence service). Such a column value is
    never an event time. A non-dated ``time_status`` also counts as unknown. Legacy rows without these keys are treated as dated.
    """
    p = normalized_payload or {}
    if p.get("event_timestamp_is_ingestion_time") is True:
        return True
    status = p.get("time_status")
    return status is not None and status not in (TimeStatus.VALID.value, TimeStatus.NAIVE_ASSUMED_UTC.value)


class Predicate(StrEnum):
    """Relationship vocabulary (what a record directly states, or what the graph hypothesises)."""

    AUTHENTICATED_AS = "AUTHENTICATED_AS"      # user -> session
    AUTHENTICATED_FROM = "AUTHENTICATED_FROM"  # user -> ip
    EXECUTED_ON = "EXECUTED_ON"                # process -> host
    CREATED = "CREATED"                        # actor -> resource
    ACCESSED = "ACCESSED"                      # actor -> resource
    MODIFIED = "MODIFIED"                      # actor -> account/resource/registry key
    QUERIED = "QUERIED"                        # ip -> domain
    RESOLVED_TO = "RESOLVED_TO"                # domain -> ip
    CONNECTED_TO = "CONNECTED_TO"              # ip -> ip
    SENT_TO = "SENT_TO"                        # sender -> recipient
    CONTAINS = "CONTAINS"                      # e-mail message -> url / attachment hash
    HAS_HASH = "HAS_HASH"                      # file/process -> hash
    OBSERVED_IN = "OBSERVED_IN"                # artefact -> host
    DERIVED_FROM = "DERIVED_FROM"              # derived entity -> source entity (domain from URL)
    ASSOCIATED_WITH = "ASSOCIATED_WITH"        # hypothesis only: shared entity between independent evidence


class RelationSeed(BaseModel):
    """A relationship stated directly by one record."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: tuple[str, str]
    predicate: Predicate
    obj: tuple[str, str]


class Observation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    key: uuid.UUID = Field(description="Persisted evidence id when stored, else uuid5(raw digest + index)")
    record_index: int = Field(ge=0)
    evidence_id: Optional[str] = Field(default=None, description="Source-native id if the source supplied one (not required)")
    evidence_type: str = Field(description="e.g. identity.signin, cloud.api_call, network.dns, email.message, forensic.file")
    family: EvidenceFamily
    source_system: str
    source_category: str
    collection_method: str
    event_time: Optional[datetime] = None
    time_status: TimeStatus
    collected_at: Optional[datetime] = None
    raw_sha256: str = Field(min_length=64, max_length=64)
    integrity: str = Field(default="digest_computed", description="digest_attested (stored at ingestion) | digest_computed")
    title: str
    outcome: str = "unknown"
    host: Optional[str] = None
    entities: tuple[tuple[str, str], ...] = ()
    derived_entities: tuple[tuple[str, str], ...] = Field(default=(), description="entities computed from others (domain from URL)")
    relations: tuple[RelationSeed, ...] = ()
    attributes: dict[str, Any] = Field(default_factory=dict, description="source-specific fields, preserved (bounded view of the raw data)")
    adapter: str
    adapter_version: str
    trust_class: TrustClass = TrustClass.RAW_OBSERVED
    counts_for_corroboration: bool = Field(default=True, description="False for analyst statements: they never corroborate machine evidence")
    upstream_id: Optional[str] = Field(
        default=None,
        description="Source-declared id of the underlying collection event/feed this record derives from (forwarded, mirrored or replicated copies share it). Used only to decide evidence independence (ADR-013 / D5).",
    )
    classification: str = Field(
        default="normalized",
        description="normalized (adapter extracted entities) | partial (valid, but nothing linkable extracted) | unclassified (type not recognised)",
    )

    @property
    def dated(self) -> bool:
        return self.event_time is not None


__all__ = [
    "stored_event_time_unknown",
    "ENVELOPE_SCHEMA", "MODEL_VERSION", "EvidenceFamily", "Observation", "Predicate", "RelationSeed", "TimeStatus", "TrustClass",
]
