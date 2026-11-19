"""
AISOP external-disclosure eligibility gate (Phase 4A).

Decides whether an indicator value may be sent to an EXTERNAL threat-intelligence provider. It only controls
disclosure: it never changes detection, correlation, sufficiency or any verdict, and an ineligible value simply is
not sent.

Design rules:
* One policy system: the existing ``PrivateNetworkShield`` supplies the internal/private/reserved knowledge (built-in
  ranges and suffixes plus the operator's ``TI_INTERNAL_DOMAIN_SUFFIXES`` / ``TI_INTERNAL_NETWORKS``). This module adds
  only the fail-closed layer on top.
* No DNS and no network I/O: a domain cannot be proven public offline, so public-looking domains stay closed unless
  the operator sets ``TI_ALLOW_PUBLIC_DOMAIN_LOOKUPS``. Internal names that look ordinary are covered by the operator's
  suffix list; anything unclassifiable fails closed.
* URLs and e-mail addresses are never disclosed (no contract allows full URLs, credentials, queries or fragments).
* Reason codes are fixed non-sensitive strings. The shield's own reason text can contain the raw value, so it is never
  surfaced from here.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Optional

from app.modules.threatintel.shield import PrivateNetworkShield


class DisclosureReason(StrEnum):
    ELIGIBLE = "eligible"
    NON_PUBLIC_IP = "non_public_ip"
    INTERNAL_OR_RESERVED_DOMAIN = "internal_or_reserved_domain"
    DOMAIN_POLICY_CLOSED = "domain_policy_closed"
    URL_NOT_AUTHORISED = "url_not_authorised"
    EMAIL_NOT_AUTHORISED = "email_not_authorised"
    MALFORMED = "malformed"
    UNSUPPORTED_TYPE = "unsupported_type"


@dataclass(frozen=True)
class DisclosureDecision:
    eligible: bool
    reason: DisclosureReason


@dataclass(frozen=True)
class ExternalDisclosurePolicy:
    """Operator-maintained disclosure policy. The default is the closed policy."""

    internal_domain_suffixes: tuple[str, ...] = ()
    internal_networks: tuple[str, ...] = ()
    allow_public_domains: bool = False

    def __post_init__(self) -> None:
        suffixes = []
        for index, raw in enumerate(self.internal_domain_suffixes):
            norm = str(raw).strip().lower()
            if not norm or any(c in norm for c in " /\\@:") or any(ord(c) < 32 for c in norm):
                raise ValueError(f"invalid internal domain suffix at position {index}")
            suffixes.append(norm if norm.startswith(".") else "." + norm)
        networks = []
        for index, raw in enumerate(self.internal_networks):
            try:
                networks.append(str(ipaddress.ip_network(str(raw).strip(), strict=False)))
            except ValueError:
                raise ValueError(f"invalid internal network at position {index}") from None  # a bad entry must not silently leave a range unshielded
        object.__setattr__(self, "internal_domain_suffixes", tuple(suffixes))
        object.__setattr__(self, "internal_networks", tuple(networks))

    def build_shield(self) -> PrivateNetworkShield:
        return PrivateNetworkShield(
            custom_internal_suffixes=list(self.internal_domain_suffixes) or None,
            custom_internal_networks=list(self.internal_networks) or None,
        )

    @classmethod
    def from_settings(cls, settings: Any) -> "ExternalDisclosurePolicy":
        return cls(
            internal_domain_suffixes=tuple(settings.TI_INTERNAL_DOMAIN_SUFFIXES),
            internal_networks=tuple(settings.TI_INTERNAL_NETWORKS),
            allow_public_domains=bool(settings.TI_ALLOW_PUBLIC_DOMAIN_LOOKUPS),
        )


_URL_TYPES = frozenset({"url", "uri"})
_EMAIL_TYPES = frozenset({"email", "mail"})
_IP_TYPES = frozenset({"ip", "ipv4", "ipv6"})
_DOMAIN_TYPES = frozenset({"domain", "host", "hostname"})
_HASH_TYPES = frozenset({"file_hash", "hash", "md5", "sha1", "sha256"})
_HASH_LENGTHS = frozenset({32, 40, 64})
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_SYNTAX = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_MAX_VALUE_LENGTH = 2048


def _deny(reason: DisclosureReason) -> DisclosureDecision:
    return DisclosureDecision(False, reason)


def evaluate_external_disclosure(
    entity_type: Any,
    value: Any,
    policy: Optional[ExternalDisclosurePolicy] = None,
    shield: Optional[PrivateNetworkShield] = None,
) -> DisclosureDecision:
    """Return whether ``value`` of ``entity_type`` may be sent to an external provider. Fails closed; never raises for bad input."""
    policy = policy or ExternalDisclosurePolicy()
    shield = shield or policy.build_shield()
    kind = str(getattr(entity_type, "value", entity_type)).strip().lower()
    if not isinstance(value, str):
        return _deny(DisclosureReason.MALFORMED)
    text = value.strip()
    if not text or len(text) > _MAX_VALUE_LENGTH or any(ord(c) < 32 or ord(c) == 127 for c in text):
        return _deny(DisclosureReason.MALFORMED)

    if kind in _URL_TYPES or "://" in text:
        return _deny(DisclosureReason.URL_NOT_AUTHORISED)
    if kind in _EMAIL_TYPES or "@" in text:
        return _deny(DisclosureReason.EMAIL_NOT_AUTHORISED)

    if kind in _IP_TYPES:
        try:
            ipaddress.ip_address(text)
        except ValueError:
            return _deny(DisclosureReason.MALFORMED)  # non-canonical forms (integer, hex, octal, ports) are never forwarded
        shielded, _ = shield.shield_observable(text, "ip")
        return _deny(DisclosureReason.NON_PUBLIC_IP) if shielded else DisclosureDecision(True, DisclosureReason.ELIGIBLE)

    if kind in _DOMAIN_TYPES:
        shielded, _ = shield.shield_observable(text, "domain")
        if shielded:
            return _deny(DisclosureReason.INTERNAL_OR_RESERVED_DOMAIN)
        try:
            ascii_name = text.rstrip(".").lower().encode("idna").decode("ascii")
        except UnicodeError:
            return _deny(DisclosureReason.MALFORMED)
        if not _DOMAIN_SYNTAX.match(ascii_name):
            return _deny(DisclosureReason.MALFORMED)
        if not policy.allow_public_domains:
            return _deny(DisclosureReason.DOMAIN_POLICY_CLOSED)
        return DisclosureDecision(True, DisclosureReason.ELIGIBLE)

    if kind in _HASH_TYPES:
        if _HEX.match(text) and len(text) in _HASH_LENGTHS:
            return DisclosureDecision(True, DisclosureReason.ELIGIBLE)
        return _deny(DisclosureReason.MALFORMED)

    return _deny(DisclosureReason.UNSUPPORTED_TYPE)


__all__ = ["DisclosureDecision", "DisclosureReason", "ExternalDisclosurePolicy", "evaluate_external_disclosure"]
