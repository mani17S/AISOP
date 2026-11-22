"""
AISOP Alert Adapter Protocol & Registry.

Governed by ADR-007 (Vendor-Neutral Alert Ingestion).
Defines the architectural contract for adapters transforming vendor-specific
alert payloads into CanonicalAlert models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from app.schemas.alert import CanonicalAlert


@runtime_checkable
class BaseAlertAdapter(Protocol):
    """
    Interface contract for all vendor alert adapters in AISOP.
    """

    def adapter_name(self) -> str:
        """Unique identifier for this adapter (e.g. 'sysmon', 'edr_malware', 'firewall_ids')."""
        ...

    def can_adapt(self, raw_data: dict[str, Any] | str) -> bool:
        """Inspect raw payload structure to determine if this adapter can handle it."""
        ...

    def adapt(
        self,
        raw_data: dict[str, Any] | str,
        raw_ref: str | None = None,
    ) -> CanonicalAlert:
        """
        Transform raw vendor alert payload into a standardized CanonicalAlert.
        """
        ...


class AlertAdapterRegistry:
    """Registry managing available vendor alert adapters."""

    def __init__(self) -> None:
        self._adapters: dict[str, BaseAlertAdapter] = {}

    def register(self, adapter: BaseAlertAdapter) -> None:
        """Register an adapter under its normalized name."""
        self._adapters[adapter.adapter_name().lower()] = adapter

    def get(self, name: str) -> BaseAlertAdapter | None:
        """Retrieve an adapter by name (case-insensitive)."""
        return self._adapters.get(name.lower())

    def find_matching_adapter(
        self, raw_data: dict[str, Any] | str
    ) -> BaseAlertAdapter | None:
        """Inspect registered adapters in order to find one capable of parsing the payload."""
        for adapter in self._adapters.values():
            if adapter.can_adapt(raw_data):
                return adapter
        return None

    def list_adapters(self) -> list[str]:
        """Return a sorted list of registered adapter names."""
        return sorted(self._adapters.keys())


def get_default_registry() -> AlertAdapterRegistry:
    """
    Construct and return the default AlertAdapterRegistry pre-populated with all
    canonical built-in adapters.
    """
    from app.modules.alerts.adapters.cloud_audit_adapter import CloudAuditAdapter
    from app.modules.alerts.adapters.edr_malware_adapter import EdrMalwareAdapter
    from app.modules.alerts.adapters.email_phishing_adapter import EmailPhishingAdapter
    from app.modules.alerts.adapters.firewall_ids_adapter import NetworkIdsAdapter
    from app.modules.alerts.adapters.generic_siem_adapter import GenericSiemAdapter
    from app.modules.alerts.adapters.linux_auth_adapter import LinuxAuthAdapter
    from app.modules.alerts.adapters.sysmon_adapter import SysmonAlertAdapter
    from app.modules.alerts.adapters.windows_security_adapter import WindowsSecurityAdapter

    registry = AlertAdapterRegistry()
    registry.register(SysmonAlertAdapter())
    registry.register(WindowsSecurityAdapter())
    registry.register(LinuxAuthAdapter())
    registry.register(EdrMalwareAdapter())
    registry.register(NetworkIdsAdapter())
    registry.register(CloudAuditAdapter())
    registry.register(EmailPhishingAdapter())
    registry.register(GenericSiemAdapter())
    return registry



class AlertTimestampError(ValueError):
    """Raised when an alert carries no usable event time. The ingestion service reports it per alert; nothing is stored."""


def require_event_time(value: Any) -> "datetime":
    """Parse an alert's own event time. Never substitutes the ingestion time (project invariant: never invent a timestamp).

    A missing, non-string or unparseable value raises ``AlertTimestampError`` with a fixed message (the value is not echoed).
    """
    if not isinstance(value, str) or not value.strip():
        raise AlertTimestampError("ALERT_TIMESTAMP_MISSING_OR_INVALID: the alert has no usable event timestamp; it was not stored.")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        # A zoned time whose UTC conversion is out of range (year 1 with a positive offset, year 9999 with a negative one)
        # would store fine and then raise OverflowError in every investigation that converts it. Reject it here; times
        # that convert cleanly are kept exactly as supplied, never clamped or replaced.
        if parsed.tzinfo is not None:
            try:
                parsed.astimezone(timezone.utc)
            except OverflowError:
                raise ValueError("out of range") from None
        return parsed
    except ValueError:
        raise AlertTimestampError("ALERT_TIMESTAMP_MISSING_OR_INVALID: the alert has no usable event timestamp; it was not stored.") from None
