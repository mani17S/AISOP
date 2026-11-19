"""
Deterministic threat-intelligence enrichment (Stage 6, ADR-011).

Threat intelligence is REFERENCE CONTEXT about an indicator, never evidence that something happened in this
incident. An enrichment therefore (a) is produced only for entities that appear in observed evidence, (b) carries
``TrustClass.TI_CONTEXT``, (c) names the indicator source and the observed evidence it is attached to, and (d) never
changes corroboration, sufficiency or ATT&CK mapping (those use observed evidence only).

``IndicatorProvider`` is a synchronous, offline contract. ``StaticIndicatorSet`` serves synthetic and locally
curated indicators; the async ``LocalThreatIntelEngine`` (TI-2/TI-3) is NOT wired here (PARTIAL: it would be adapted
behind the same contract). No external API is called.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar, Iterable, Optional, Protocol

from app.modules.evidence.independence import canonical_entity_value
from app.modules.evidence_domains.model import Observation, TrustClass
from app.modules.threatintel.disclosure import ExternalDisclosurePolicy, evaluate_external_disclosure

ENRICHABLE_TYPES = frozenset({"ip", "domain", "file_hash", "url"})
MAX_ENRICHMENTS = 100
FRESHNESS_STATES = frozenset({"fresh", "cached", "stale"})
_MAX_LINEAGE = 10
_MAX_TEXT = 200


def _utc(value: Optional[datetime], name: str) -> Optional[datetime]:
    """Provenance timestamps are timezone-aware UTC or absent. A missing timestamp is never invented."""
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{name} must be a timezone-aware datetime or None")
    return value.astimezone(timezone.utc)


def _opt_text(value: Optional[str], name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT:
        raise ValueError(f"{name} must be a non-empty string of at most {_MAX_TEXT} characters or None")
    return value


@dataclass(frozen=True)
class IndicatorMatch:
    source: str
    description: str
    kind: str = "indicator"
    reference: Optional[str] = None
    # Provenance (Phase 4A). All optional: historical records have none and are never given any. The queried indicator
    # value is NOT repeated here (the Enrichment carries the entity and the observations it was seen in).
    source_id: Optional[str] = None  # stable registry ID; ``source`` stays the display name
    record_id: Optional[str] = None  # the provider's own record identifier, if it supplies one
    retrieved_at: Optional[datetime] = None  # when AISOP obtained the data (never the provider's time)
    source_observed_at: Optional[datetime] = None  # provider-reported observation time; stays None if not supplied
    source_updated_at: Optional[datetime] = None  # provider-reported record update time; stays None if not supplied
    dataset_version: Optional[str] = None  # feed/dataset version or digest for local sources
    lineage: tuple[str, ...] = ()  # declared upstream sources. Informational: it does not assert that sources are independent
    freshness: Optional[str] = None  # one of FRESHNESS_STATES

    def __post_init__(self) -> None:
        for name in ("retrieved_at", "source_observed_at", "source_updated_at"):
            object.__setattr__(self, name, _utc(getattr(self, name), name))
        for name in ("source_id", "record_id", "dataset_version"):
            _opt_text(getattr(self, name), name)
        if self.freshness is not None and self.freshness not in FRESHNESS_STATES:
            raise ValueError("freshness must be one of fresh, cached, stale or None")
        lineage = tuple(self.lineage)
        if len(lineage) > _MAX_LINEAGE or any(not isinstance(x, str) or not x.strip() or len(x) > _MAX_TEXT for x in lineage):
            raise ValueError("lineage must be a short tuple of non-empty strings")
        object.__setattr__(self, "lineage", lineage)

    def provenance_view(self) -> Optional[dict[str, Any]]:
        """Only the provenance that was actually recorded; ``None`` for a historical record with none."""
        out: dict[str, Any] = {}
        for name in ("source_id", "record_id", "dataset_version", "freshness"):
            if getattr(self, name) is not None:
                out[name] = getattr(self, name)
        for name in ("retrieved_at", "source_observed_at", "source_updated_at"):
            if getattr(self, name) is not None:
                out[name] = getattr(self, name).isoformat()
        if self.lineage:
            out["lineage"] = list(self.lineage)
        return out or None

    @classmethod
    def from_view(cls, view: dict[str, Any]) -> "IndicatorMatch":
        """Rebuild from ``Enrichment.view()`` output. Absent provenance stays absent (older records deserialize unchanged)."""
        prov = view.get("provenance") or {}

        def when(name: str) -> Optional[datetime]:
            raw = prov.get(name)
            return datetime.fromisoformat(raw) if raw else None

        return cls(
            source=view["source"], description=view["description"], kind=view.get("kind", "indicator"), reference=view.get("reference"),
            source_id=prov.get("source_id"), record_id=prov.get("record_id"), dataset_version=prov.get("dataset_version"), freshness=prov.get("freshness"),
            retrieved_at=when("retrieved_at"), source_observed_at=when("source_observed_at"), source_updated_at=when("source_updated_at"),
            lineage=tuple(prov.get("lineage") or ()),
        )


class IndicatorProvider(Protocol):
    """Synchronous indicator lookup. A provider that is not explicitly ``is_local_only = True`` is treated as EXTERNAL and
    is subject to the external-disclosure gate (fail closed): forgetting to declare locality can only make it stricter."""

    def lookup(self, entity_type: str, value: str) -> list[IndicatorMatch]: ...


@dataclass
class StaticIndicatorSet:
    """In-memory indicator table: {(type, value): [IndicatorMatch, ...]}. Deterministic and offline."""

    is_local_only: ClassVar[bool] = True
    indicators: dict[tuple[str, str], list[IndicatorMatch]] = field(default_factory=dict)

    def add(self, entity_type: str, value: str, match: IndicatorMatch) -> None:
        self.indicators.setdefault((entity_type, canonical_entity_value(entity_type, value)), []).append(match)

    def lookup(self, entity_type: str, value: str) -> list[IndicatorMatch]:
        return list(self.indicators.get((entity_type, canonical_entity_value(entity_type, value)), []))


@dataclass(frozen=True)
class Enrichment:
    entity: tuple[str, str]
    matches: tuple[IndicatorMatch, ...]
    observed_in: tuple[str, ...]  # observation keys the entity was OBSERVED in (the enrichment is attached to these)
    trust_class: str = TrustClass.TI_CONTEXT.value
    statement: str = "External intelligence about the indicator. It is not evidence that the indicator was malicious in this incident."

    def view(self) -> dict[str, Any]:
        def match_view(m: IndicatorMatch) -> dict[str, Any]:
            item: dict[str, Any] = {"source": m.source, "kind": m.kind, "description": m.description, "reference": m.reference}
            prov = m.provenance_view()
            if prov is not None:  # key absent when nothing was recorded, so historical views are unchanged
                item["provenance"] = prov
            return item

        return {
            "entity": f"{self.entity[0]}:{self.entity[1]}", "trust_class": self.trust_class, "observed_in": list(self.observed_in[:10]),
            "matches": [match_view(m) for m in self.matches],
            "statement": self.statement,
        }

    @classmethod
    def from_view(cls, view: dict[str, Any]) -> "Enrichment":
        """Rebuild from ``view()`` output. ``observed_in`` was truncated to 10 keys by ``view()``."""
        entity_type, _, value = str(view["entity"]).partition(":")
        return cls(
            entity=(entity_type, value), matches=tuple(IndicatorMatch.from_view(m) for m in view.get("matches", [])),
            observed_in=tuple(view.get("observed_in", [])), trust_class=view.get("trust_class", TrustClass.TI_CONTEXT.value),
            statement=view.get("statement", cls.statement),
        )


def _eligible(entity_type: str, value: str) -> bool:
    if entity_type not in ENRICHABLE_TYPES:
        return False
    if entity_type == "ip":  # private/reserved addresses are never looked up (and never leave the deployment)
        try:
            return ipaddress.ip_address(value).is_global
        except ValueError:
            return False
    return True


def enrich(observations: Iterable[Observation], provider: Optional[IndicatorProvider], policy: Optional[ExternalDisclosurePolicy] = None) -> list[Enrichment]:
    """Look up each distinct eligible entity once. A provider failure yields no enrichment (never an exception).

    A provider that is not ``is_local_only`` is external: before every ``lookup`` call the value must pass the external-
    disclosure gate (internal/private/reserved values, URLs, e-mails, malformed values and, by default, domains are
    never sent). The default policy is closed. The gate controls disclosure only; it never changes any assessment."""
    if provider is None:
        return []
    external = getattr(provider, "is_local_only", False) is not True
    policy = policy or ExternalDisclosurePolicy()
    shield = policy.build_shield() if external else None
    seen: dict[tuple[str, str], list[str]] = {}
    for o in observations:
        if not o.counts_for_corroboration:  # analyst statements are not observed evidence
            continue
        for ent in o.entities:
            if _eligible(*ent):
                seen.setdefault(ent, []).append(str(o.key))
    out: list[Enrichment] = []
    for ent in sorted(seen):
        if external and not evaluate_external_disclosure(ent[0], ent[1], policy, shield).eligible:
            continue  # last point before the provider call: nothing ineligible is ever passed to ``lookup``
        try:
            matches = provider.lookup(*ent)
        except Exception:  # noqa: BLE001 - enrichment is optional context
            continue
        if matches:
            out.append(Enrichment(entity=ent, matches=tuple(matches), observed_in=tuple(seen[ent])))
        if len(out) >= MAX_ENRICHMENTS:
            break
    return out


__all__ = ["Enrichment", "IndicatorMatch", "IndicatorProvider", "StaticIndicatorSet", "enrich"]
