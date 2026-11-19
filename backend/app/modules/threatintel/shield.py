"""
AISOP Threat Intelligence Private Network Shield.

In accordance with TI-3B Architectural Specification & Phase 1.2 Security Gate:
- Strict OPSEC privacy boundary separating internal/private assets from external lookup.
- Evaluates IP addresses, domains, hostnames, URLs, and email addresses.
- Crucial Semantic Invariant: Shielded observables return verdict=UNKNOWN with state=SHIELDED_INTERNAL.
  Never infer BENIGN from a blocked or shielded lookup.
- Policy-based boundary checks beyond basic is_private (CGNAT, loopback, link-local, multicast,
  documentation, benchmarking, reserved, broadcast, IPv4-mapped IPv6, integer/octal/hex notations).
- URL and email parser hardening: userinfo candidate extraction, multiple '@' rejection,
  control character / NUL rejection, IPv6 bracket handling, fail-closed on parsing uncertainty.
"""

from __future__ import annotations

import ipaddress
import logging
import urllib.parse
from typing import Any

from app.modules.threatintel.models import (
    ObservableType,
    ThreatIntelLookupStatus,
    ThreatIntelResult,
    ThreatVerdict,
)
from app.schemas.threatintel import InvestigationFindingState

logger = logging.getLogger(__name__)

# RFC-defined internal and special-use domain suffixes
_SHIELDED_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".internal",
    ".corp",
    ".lan",
    ".home",
    ".arpa",
    ".test",
    ".example",
    ".invalid",
    ".localhost",
)

# Additional networks beyond standard Python ipaddress.is_private
_EXTRA_SHIELDED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("100.64.0.0/10"),     # RFC 6598 Carrier-Grade NAT (CGNAT)
    ipaddress.ip_network("198.18.0.0/15"),     # RFC 2544 Benchmarking
    ipaddress.ip_network("192.0.2.0/24"),      # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # RFC 5737 TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),     # RFC 3849 IPv6 Documentation
    ipaddress.ip_network("240.0.0.0/4"),       # RFC 1112 Future use / reserved
    ipaddress.ip_network("0.0.0.0/8"),         # RFC 1122 This host / "this" network
)


class PrivateNetworkShield:
    """
    OPSEC privacy gate preventing internal, private, or special-use indicators
    from leaking to external threat intelligence providers.
    """

    def __init__(
        self,
        custom_internal_suffixes: list[str] | None = None,
        custom_internal_networks: list[str] | None = None,
    ) -> None:
        self._suffixes = list(_SHIELDED_DOMAIN_SUFFIXES)
        if custom_internal_suffixes:
            for s in custom_internal_suffixes:
                norm = s.lower().strip()
                if not norm.startswith("."):
                    norm = f".{norm}"
                if norm not in self._suffixes:
                    self._suffixes.append(norm)

        self._extra_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = list(_EXTRA_SHIELDED_NETWORKS)
        if custom_internal_networks:
            for cidr in custom_internal_networks:
                try:
                    self._extra_networks.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError as err:
                    logger.warning("Invalid custom internal network '%s': %s", cidr, err)

    def is_shielded(
        self,
        observable: Any,
        observable_type: Any = None,
    ) -> bool:
        """Return True if observable belongs to internal/private network space."""
        obs_val, obs_type = self._normalize_args(observable, observable_type)
        shielded, _ = self.shield_observable(obs_val, obs_type)
        return shielded

    def get_shield_reason(
        self,
        observable: Any,
        observable_type: Any = None,
    ) -> str | None:
        """Return human-readable rationale if observable is shielded, otherwise None."""
        obs_val, obs_type = self._normalize_args(observable, observable_type)
        _, reason = self.shield_observable(obs_val, obs_type)
        return reason

    def create_shielded_result(
        self,
        observable_value: str,
        observable_type: ObservableType | str,
        reason: str | None = None,
        provider_name: str = "private_network_shield",
    ) -> ThreatIntelResult:
        """
        Create a standardized ThreatIntelResult representing a shielded internal asset.

        Crucial Semantic Invariant:
        Shielded observables MUST return verdict=UNKNOWN with state=SHIELDED_INTERNAL.
        Never infer BENIGN from a blocked or shielded lookup.
        """
        if reason is None:
            reason = self.get_shield_reason(observable_value, observable_type) or "Shielded internal network resource"
        
        try:
            obs_type_enum = (
                observable_type
                if isinstance(observable_type, ObservableType)
                else ObservableType(str(observable_type).lower())
            )
        except ValueError:
            obs_type_enum = ObservableType.DOMAIN

        return ThreatIntelResult(
            provider_name=provider_name,
            observable_type=obs_type_enum,
            raw_observable=observable_value,
            normalized_observable=observable_value,
            status=ThreatIntelLookupStatus.SUCCESS,
            verdict=ThreatVerdict.UNKNOWN,  # NEVER BENIGN! Blocked lookups cannot be inferred safe
            tags=["shielded_internal"],
            raw_data={
                "shielded": True,
                "shielded_internal": True,
                "reason": reason,
                "state": InvestigationFindingState.SHIELDED_INTERNAL.value,
            },
            error_message=None,
        )

    def shield_observable(
        self,
        observable: str,
        observable_type: ObservableType | str,
    ) -> tuple[bool, str | None]:
        """
        Evaluate an observable for private/internal classification.

        Returns:
            tuple[bool, str | None]: (is_shielded, shield_reason)
        """
        if not observable:
            return False, None

        raw_str = str(observable).strip()
        type_str = (
            observable_type.value
            if hasattr(observable_type, "value")
            else str(observable_type).lower()
        )

        # Proactive URL parsing before type matching
        if "://" in raw_str or type_str in ("url", "uri"):
            return self._evaluate_url(raw_str)

        # Email parsing: either explicit email type or observable containing '@'
        if type_str in ("email", "mail") or ("@" in raw_str and type_str == "domain"):
            return self._evaluate_email(raw_str)

        # 1. IP Address Evaluation
        if type_str in ("ipv4", "ipv6", "ip"):
            return self._evaluate_ip(raw_str)

        # 2. Domain / Hostname Evaluation
        if type_str in ("domain", "host", "hostname"):
            return self._evaluate_domain(raw_str)

        # Hashes and other non-network observables are never shielded
        return False, None

    def _evaluate_ip(self, ip_str: str) -> tuple[bool, str | None]:
        """
        Evaluate IPv4 or IPv6 address against private, non-public, and reserved allocations.
        
        Explicitly evaluates specific RFC definitions rather than relying on a single
        generic `is_private` call. Fails closed on malformed or ambiguous IP representations.
        """
        cleaned = ip_str.strip()

        # Reject control characters or embedded NULs
        if any(ord(c) < 32 or ord(c) == 127 for c in cleaned):
            return True, f"Control characters or NUL in IP string '{ip_str}' (shielded conservatively)"

        # Strip trailing port if present (e.g. 192.168.1.1:80 or [fe80::1]:8080)
        if ":" in cleaned and not cleaned.startswith("::") and cleaned.count(":") == 1 and "." in cleaned:
            cleaned = cleaned.split(":", 1)[0]

        # Check for noncanonical integer, hex, or octal IPv4 notations
        # e.g., '2130706433' (127.0.0.1) or '0x7f000001'
        if cleaned.isdigit() and len(cleaned) >= 8:
            try:
                int_ip = ipaddress.IPv4Address(int(cleaned))
                return self._evaluate_ip(str(int_ip))
            except ValueError:
                return True, f"Malformed integer IP '{ip_str}' (shielded conservatively)"
        if cleaned.startswith("0x") and len(cleaned) == 10:
            try:
                hex_ip = ipaddress.IPv4Address(int(cleaned, 16))
                return self._evaluate_ip(str(hex_ip))
            except ValueError:
                return True, f"Malformed hex IP '{ip_str}' (shielded conservatively)"

        # Check octal component notation (e.g. 0177.0.0.1)
        if "." in cleaned:
            parts = cleaned.split(".")
            if len(parts) == 4 and any(p.startswith("0") and len(p) > 1 and p.isdigit() for p in parts):
                try:
                    oct_ip = ".".join(str(int(p, 8)) for p in parts)
                    return self._evaluate_ip(oct_ip)
                except ValueError:
                    return True, f"Malformed octal IP '{ip_str}' (shielded conservatively)"

        try:
            ip_obj = ipaddress.ip_address(cleaned)
        except ValueError:
            # Fails closed on unparseable IP input targeting an IP observable type
            return True, f"Malformed or ambiguous IP address '{ip_str}' (shielded conservatively)"

        # Check IPv4-Mapped IPv6 address (RFC 4291 section 2.5.5.2)
        # e.g., ::ffff:192.168.1.1 or ::ffff:100.64.0.1
        if ip_obj.version == 6 and ip_obj.ipv4_mapped is not None:
            return self._evaluate_ip(str(ip_obj.ipv4_mapped))

        # 1. Loopback addresses (RFC 1122 / RFC 4291)
        if ip_obj.is_loopback:
            return True, f"Loopback address ({ip_str}) - RFC 1122 / RFC 4291"

        # 2. Link-local addresses (RFC 3927 / RFC 4291)
        if ip_obj.is_link_local:
            return True, f"Link-local address ({ip_str}) - RFC 3927 / RFC 4291"

        # 3. Multicast addresses (RFC 1112 / RFC 5771 / RFC 4291)
        # Note: In Python ipaddress, 224.0.0.1 has is_private=False and is_global=True!
        if ip_obj.is_multicast:
            return True, f"Multicast address space ({ip_str}) - RFC 1112 / RFC 5771 / RFC 4291"

        # 4. Unspecified / current network (RFC 1122 / RFC 4291)
        if ip_obj.is_unspecified or (ip_obj.version == 4 and ip_obj in ipaddress.ip_network("0.0.0.0/8")):
            return True, f"Unspecified / this-network address ({ip_str}) - RFC 1122 / RFC 4291"

        # 5. Carrier-Grade NAT (RFC 6598) - Note: ip_obj.is_private is False in Python
        if ip_obj.version == 4 and ip_obj in ipaddress.ip_network("100.64.0.0/10"):
            return True, f"Carrier-Grade NAT address space ({ip_str}) - RFC 6598"

        # 6. Documentation / Test networks (RFC 5737 / RFC 3849)
        if ip_obj.version == 4:
            if ip_obj in ipaddress.ip_network("192.0.2.0/24") or \
               ip_obj in ipaddress.ip_network("198.51.100.0/24") or \
               ip_obj in ipaddress.ip_network("203.0.113.0/24"):
                return True, f"Documentation / test address space ({ip_str}) - RFC 5737"
        elif ip_obj.version == 6:
            if ip_obj in ipaddress.ip_network("2001:db8::/32"):
                return True, f"Documentation / test IPv6 space ({ip_str}) - RFC 3849"

        # 7. Benchmarking (RFC 2544 / RFC 6815)
        if ip_obj.version == 4 and ip_obj in ipaddress.ip_network("198.18.0.0/15"):
            return True, f"Benchmarking network space ({ip_str}) - RFC 2544 / RFC 6815"

        # 8. Reserved / broadcast / future use (RFC 1112)
        if ip_obj.is_reserved or (ip_obj.version == 4 and ip_obj in ipaddress.ip_network("240.0.0.0/4")) or cleaned == "255.255.255.255":
            return True, f"Reserved / broadcast address ({ip_str}) - RFC 1112"

        # 9. Private IP space (RFC 1918 / RFC 4193 ULA)
        if ip_obj.is_private:
            return True, f"Private IP address space ({ip_str}) - RFC 1918 / RFC 4193"

        # 10. Additional extra non-public networks
        for net in self._extra_networks:
            if ip_obj.version == net.version and ip_obj in net:
                return True, f"Reserved non-public network space ({net})"

        # 11. Catch-all for non-globally routable addresses
        if not ip_obj.is_global:
            return True, f"Non-globally-routable IP address ({ip_str})"

        # 12. Globally routable public unicast IP (allowed)
        return False, None

    def _evaluate_domain(self, domain_str: str) -> tuple[bool, str | None]:
        """Evaluate domain or hostname against internal and reserved name rules."""
        cleaned = domain_str.strip().rstrip(".")

        # Check for control characters or embedded NULs
        if any(ord(c) < 32 or ord(c) == 127 for c in cleaned):
            return True, f"Control characters or NUL in domain '{domain_str}' (shielded conservatively)"

        lowered = cleaned.lower()

        # Check if domain string is actually an IP literal
        try:
            ip_obj = ipaddress.ip_address(lowered.strip("[]"))
            is_priv, priv_reason = self._evaluate_ip(str(ip_obj))
            if is_priv:
                return True, f"Domain contains non-public IP literal: {priv_reason}"
        except ValueError:
            pass

        # Check single-label unqualified hostnames (e.g. WORKSTATION-01, DC-01, localhost)
        if "." not in lowered or lowered == "localhost":
            return True, f"Unqualified single-label internal hostname ({domain_str})"

        # Check internal / reserved domain suffixes
        for suffix in self._suffixes:
            if lowered.endswith(suffix) or lowered == suffix.lstrip("."):
                return True, f"Internal enterprise or reserved domain suffix '{suffix}' ({domain_str})"

        # Validate IDNA / Punycode decoding
        try:
            lowered.encode("idna").decode("ascii")
        except UnicodeError:
            return True, f"Invalid IDNA/Unicode domain '{domain_str}' (shielded conservatively)"

        return False, None

    def _evaluate_url(self, url_str: str) -> tuple[bool, str | None]:
        """
        Extract and evaluate candidate hosts from URL.
        
        Adheres to Phase D invariants:
        - Invariant 1: Extracted hosts normalized and validated.
        - Invariant 2: Parsing errors fail closed (shielded).
        - Invariant 3: URL userinfo is never mistaken for the hostname.
        - Invariant 4: Internal IP literals extracted from URL userinfo or netloc are shielded.
        - Invariant 5: Every candidate host evaluated; one safe host must not hide an unsafe host.
        - Invariant 6: Multiple '@' or userinfo ambiguity fails closed.
        """
        # Normalize backslashes (WHATWG URL compatibility)
        normalized = url_str.strip().replace("\\", "/")

        # Check for control characters or embedded NULs
        if any(ord(c) < 32 or ord(c) == 127 for c in normalized):
            return True, f"Control characters or NUL in URL '{url_str}' (shielded conservatively)"

        # Unquote percent-encoding
        unquoted = urllib.parse.unquote(normalized)

        try:
            parsed = urllib.parse.urlsplit(unquoted if "://" in unquoted else "//" + unquoted)
        except Exception:
            return True, f"Malformed URL syntax '{url_str}' (shielded conservatively)"

        # Check for userinfo ambiguity (multiple '@' symbols in netloc)
        if parsed.netloc.count("@") > 1:
            return True, f"Multiple '@' symbols in URL netloc '{url_str}' (shielded conservatively for ambiguity)"

        # Invariant 4: Check if userinfo contains an internal IP literal or internal domain
        if "@" in parsed.netloc:
            userinfo = parsed.netloc.rsplit("@", 1)[0]
            # Strip port from userinfo if present
            u_cand = userinfo.split(":")[0].strip("[]").rstrip(".")
            if u_cand:
                # Check if userinfo candidate is an IP
                try:
                    ip_obj = ipaddress.ip_address(u_cand)
                    is_ip, ip_reason = self._evaluate_ip(str(ip_obj))
                    if is_ip:
                        return True, f"URL userinfo contains non-public IP literal: {ip_reason}"
                except ValueError:
                    pass
                # Check if userinfo candidate has an internal suffix
                for suffix in self._suffixes:
                    if u_cand.lower().endswith(suffix) or u_cand.lower() == suffix.lstrip("."):
                        return True, f"URL userinfo contains internal domain suffix: {suffix}"

        # Evaluate the target hostname
        target_host = parsed.hostname
        if not target_host:
            return True, f"Malformed or empty host in URL '{url_str}' (shielded conservatively)"

        target_host = target_host.strip("[]").rstrip(".")

        # Check if target host has invalid bracket syntax remaining
        if "[" in target_host or "]" in target_host:
            return True, f"Malformed bracketed host in URL '{url_str}' (shielded conservatively)"

        # 1. Evaluate target host as IP
        try:
            ip_obj = ipaddress.ip_address(target_host)
            is_ip, ip_reason = self._evaluate_ip(str(ip_obj))
            if is_ip:
                return True, f"URL host is non-public/private IP: {ip_reason}"
            return False, None
        except ValueError:
            pass

        # 2. Evaluate target host as domain
        return self._evaluate_domain(target_host)

    def _evaluate_email(self, email_str: str) -> tuple[bool, str | None]:
        """
        Extract domain and userinfo candidate hosts from email and evaluate.
        
        Adheres to Phase D invariants:
        - Malformed email (missing '@') fails closed (shielded).
        - Multiple '@' symbols fail closed (shielded for ambiguity).
        - Bracketed IPv4 and IPv6 literals ([192.168.1.1], [::1]) evaluated as IPs.
        - Internal domain suffixes and single-label hostnames shielded.
        """
        cleaned = email_str.strip()

        # Check for control characters or NUL
        if any(ord(c) < 32 or ord(c) == 127 for c in cleaned):
            return True, f"Control characters or NUL in email '{email_str}' (shielded conservatively)"

        if "@" not in cleaned:
            return True, f"Malformed email address '{email_str}' (missing '@')"

        if cleaned.count("@") > 1:
            return True, f"Multiple '@' symbols in email '{email_str}' (shielded conservatively for ambiguity)"

        local_part, domain_part = cleaned.split("@", 1)
        if not local_part.strip():
            return True, f"Empty or whitespace-only local part in email '{email_str}' (shielded conservatively)"

        domain_part = domain_part.strip().strip("[]").rstrip(".")
        if not domain_part:
            return True, f"Empty domain part in email '{email_str}' (shielded conservatively)"

        # Check domain as IP literal (e.g. root@[192.168.1.1] or root@[::1])
        try:
            ip_obj = ipaddress.ip_address(domain_part)
            is_ip, ip_reason = self._evaluate_ip(str(ip_obj))
            if is_ip:
                return True, f"Email domain is non-public IP: {ip_reason}"
            return False, None
        except ValueError:
            pass

        return self._evaluate_domain(domain_part)

    def _normalize_args(
        self,
        observable: Any,
        observable_type: Any,
    ) -> tuple[str, ObservableType | str]:
        """Helper to extract raw string and type from various call signatures."""
        if hasattr(observable, "raw_observable") and hasattr(observable, "observable_type"):
            return str(observable.raw_observable), observable.observable_type
        if observable_type is None:
            # Fallback heuristic if type is omitted
            val = str(observable).strip()
            if "://" in val:
                return val, "url"
            if "@" in val and "/" not in val:
                return val, "email"
            return val, "domain"
        return str(observable).strip(), observable_type
