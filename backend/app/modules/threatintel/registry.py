"""
AISOP threat-intelligence source registry (Phase 4A).

Stable source identity, declared capabilities and operator enablement for threat-intelligence sources. The registry
only DESCRIBES and GATES sources: it never constructs a provider, never performs I/O, never selects a different
source and never falls back to a remote one.

Defaults and rules:
* Every external source is disabled until the operator sets BOTH ``TI_EXTERNAL_ENABLED`` and lists the source ID in
  ``TI_ENABLED_SOURCES``. A configured API key never enables a source.
* Unknown source IDs fail closed (never enabled, never looked up).
* Distinct states: DISABLED, NOT_CONFIGURED (enabled but a required credential is absent), UNSUPPORTED (capability
  not declared), UNAVAILABLE (no operational implementation in this build), ENABLED.
* Descriptors make no claim that a source is free, licensed, privacy-safe or reachable: ``terms_status`` is
  ``unverified`` unless a source's terms were actually read, and ``implemented`` is true only when an adapter exists.
* The existing local feeds are described as they behave today (always on, offline); the registry does not toggle them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping, Optional

from app.modules.threatintel.models import ObservableType


class SourceKind(StrEnum):
    LOCAL_FEED = "local_feed"
    EXTERNAL_API = "external_api"


class SourceState(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    NOT_CONFIGURED = "not_configured"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"


class TermsStatus(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    UNVERIFIED = "unverified"
    VERIFIED = "verified"


class UnknownSourceError(KeyError):
    """Raised when a source ID is not registered. Never enables anything."""


@dataclass(frozen=True)
class SourceDescriptor:
    source_id: str
    display_name: str
    kind: SourceKind
    observable_types: frozenset[ObservableType]
    implemented: bool
    terms_status: TermsStatus
    requires_credential: bool = False
    credential_setting: Optional[str] = None  # name of the Settings field holding the key; the key is never copied here
    lineage: tuple[str, ...] = ()  # declared upstream; informational, does not assert independence
    note: str = ""


def _default_descriptors() -> tuple[SourceDescriptor, ...]:
    return (
        # Operational today (LocalThreatIntelEngine); offline.
        SourceDescriptor("feodo_tracker", "Feodo Tracker (abuse.ch)", SourceKind.LOCAL_FEED, frozenset({ObservableType.IPV4, ObservableType.IPV6}),
                         implemented=True, terms_status=TermsStatus.NOT_APPLICABLE, lineage=("abuse.ch",), note="Local feed file; always on; offline."),
        SourceDescriptor("tor_exit_nodes", "Tor exit nodes", SourceKind.LOCAL_FEED, frozenset({ObservableType.IPV4, ObservableType.IPV6}),
                         implemented=True, terms_status=TermsStatus.NOT_APPLICABLE, lineage=("torproject",), note="Local feed file; always on; offline."),
        # Candidates: config key fields or empty packages exist, but NO adapter is implemented. Non-operational.
        SourceDescriptor("abuseipdb", "AbuseIPDB", SourceKind.EXTERNAL_API, frozenset({ObservableType.IPV4, ObservableType.IPV6}), implemented=False,
                         terms_status=TermsStatus.UNVERIFIED, requires_credential=True, credential_setting="ABUSEIPDB_API_KEY", note="Candidate only; no adapter."),
        SourceDescriptor("alienvault_otx", "AlienVault OTX", SourceKind.EXTERNAL_API,
                         frozenset({ObservableType.IPV4, ObservableType.IPV6, ObservableType.DOMAIN, ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5}),
                         implemented=False, terms_status=TermsStatus.UNVERIFIED, requires_credential=True, credential_setting="ALIENVAULT_OTX_API_KEY",
                         note="Candidate only; no adapter; terms and limits unverified."),
        SourceDescriptor("virustotal", "VirusTotal", SourceKind.EXTERNAL_API,
                         frozenset({ObservableType.IPV4, ObservableType.IPV6, ObservableType.DOMAIN, ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5}),
                         implemented=False, terms_status=TermsStatus.UNVERIFIED, requires_credential=True, credential_setting="VIRUSTOTAL_API_KEY",
                         note="Deferred by the owner; no adapter; must not be used."),
    )


class SourceRegistry:
    def __init__(
        self,
        descriptors: Optional[Iterable[SourceDescriptor]] = None,
        *,
        external_enabled: bool = False,
        enabled_source_ids: Iterable[str] = (),
        credentials_present: Optional[Mapping[str, bool]] = None,
    ) -> None:
        items = tuple(descriptors) if descriptors is not None else _default_descriptors()
        self._by_id: dict[str, SourceDescriptor] = {}
        for d in items:
            if d.source_id in self._by_id:
                raise ValueError("duplicate source id in registry")
            self._by_id[d.source_id] = d
        self.external_enabled = bool(external_enabled)
        requested = {str(s).strip() for s in enabled_source_ids if str(s).strip()}
        self.enabled_source_ids: frozenset[str] = frozenset(s for s in requested if s in self._by_id)
        self.unknown_enabled_source_ids: frozenset[str] = frozenset(s for s in requested if s not in self._by_id)  # reported, never enabled
        self._credentials_present = dict(credentials_present or {})

    @classmethod
    def from_settings(cls, settings: Any, descriptors: Optional[Iterable[SourceDescriptor]] = None) -> "SourceRegistry":
        """Build from Settings. Reads only flags and whether a key is non-empty; the key value is never stored or logged."""
        items = tuple(descriptors) if descriptors is not None else _default_descriptors()
        present = {
            d.source_id: bool(str(getattr(settings, d.credential_setting, "") or "").strip())
            for d in items if d.credential_setting
        }
        return cls(items, external_enabled=bool(settings.TI_EXTERNAL_ENABLED), enabled_source_ids=settings.TI_ENABLED_SOURCES, credentials_present=present)

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_id))

    def get(self, source_id: str) -> SourceDescriptor:
        try:
            return self._by_id[source_id]
        except KeyError:
            raise UnknownSourceError("unknown threat-intelligence source") from None

    def state(self, source_id: str) -> SourceState:
        d = self.get(source_id)
        if d.kind is SourceKind.LOCAL_FEED:
            return SourceState.ENABLED if d.implemented else SourceState.UNAVAILABLE
        if not self.external_enabled or d.source_id not in self.enabled_source_ids:
            return SourceState.DISABLED
        if not d.implemented:
            return SourceState.UNAVAILABLE
        if d.requires_credential and not self._credentials_present.get(d.source_id, False):
            return SourceState.NOT_CONFIGURED
        return SourceState.ENABLED

    def external_lookup_permitted(self, source_id: str, observable_type: Any, allow_external: bool) -> tuple[bool, str]:
        """Dual opt-in plus capability check for an EXTERNAL source. Returns (permitted, non-sensitive reason code)."""
        if not allow_external:
            return False, "per_query_opt_in_missing"
        try:
            d = self.get(source_id)
        except UnknownSourceError:
            return False, "unknown_source"
        if d.kind is not SourceKind.EXTERNAL_API:
            return False, "not_external"
        state = self.state(source_id)
        if state is not SourceState.ENABLED:
            return False, state.value
        try:
            kind = observable_type if isinstance(observable_type, ObservableType) else ObservableType(str(observable_type).lower())
        except ValueError:
            return False, SourceState.UNSUPPORTED.value
        if kind not in d.observable_types:
            return False, SourceState.UNSUPPORTED.value
        return True, "permitted"


__all__ = ["SourceDescriptor", "SourceKind", "SourceRegistry", "SourceState", "TermsStatus", "UnknownSourceError"]
