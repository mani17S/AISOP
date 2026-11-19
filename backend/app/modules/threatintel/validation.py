"""
AISOP Threat Intelligence Observable Normalization & Validation.

In accordance with ADR-001 (Direct Lightweight Abstraction) and strict validation rules:
- Validates IPv4 and IPv6 using standard library `ipaddress`.
- Validates domains using RFC 1035 / RFC 1123 syntactic rules without performing DNS lookups.
- Validates cryptographic hashes (MD5, SHA-1, SHA-256) by enforcing exact lengths and hexadecimal character sets.
- Guards against treating arbitrary extracted file_hash entities (e.g. imphash, corrupted hashes) as valid IOCs.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from app.modules.threatintel.exceptions import InvalidObservableError
from app.modules.threatintel.models import Observable, ObservableType

# Strictly matching hex characters
_HEX_RE = re.compile(r"^[0-9a-f]+$")

# RFC 1035 / RFC 1123 label: 1..63 alphanumeric with internal hyphens
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Prohibited domain characters (protocols, ports, paths, credentials)
_PROHIBITED_DOMAIN_CHARS = frozenset(
    {"/", ":", "@", "?", "#", "&", " ", "\t", "\r", "\n"}
)


def validate_ipv4(value: str) -> str:
    """
    Validate and normalize an IPv4 address.

    Args:
        value: Raw IPv4 address string.

    Returns:
        Canonical IPv4 address string (e.g. '192.168.1.1').

    Raises:
        InvalidObservableError: If value is not a valid IPv4 address.
    """
    cleaned = value.strip()
    try:
        addr = ipaddress.IPv4Address(cleaned)
        return str(addr)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise InvalidObservableError(
            f"Invalid IPv4 address '{value}': {exc}",
            observable=value,
            observable_type=ObservableType.IPV4.value,
        ) from exc


def validate_ipv6(value: str) -> str:
    """
    Validate and normalize an IPv6 address.

    Args:
        value: Raw IPv6 address string, optionally enclosed in brackets '[]'.

    Returns:
        Canonical compressed lowercase IPv6 address string (e.g. '2001:db8::1').

    Raises:
        InvalidObservableError: If value is not a valid IPv6 address.
    """
    cleaned = value.strip().strip("[]")
    try:
        addr = ipaddress.IPv6Address(cleaned)
        return str(addr)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise InvalidObservableError(
            f"Invalid IPv6 address '{value}': {exc}",
            observable=value,
            observable_type=ObservableType.IPV6.value,
        ) from exc


def validate_domain(value: str) -> str:
    """
    Validate and normalize a Fully Qualified Domain Name (FQDN) without DNS queries.

    Rules enforced:
    - Strips surrounding whitespace and trailing dots (e.g. 'example.com.' -> 'example.com').
    - Converts to lowercase.
    - Overall length between 1 and 253 characters.
    - Prohibits protocols, paths, colons/ports, and query parameters.
    - Prohibits raw IP addresses from masquerading as domains.
    - At least two labels (domain + TLD).
    - Each label 1..63 alphanumeric characters; hyphens allowed only internally.
    - TLD cannot be purely numeric and must be at least 2 characters.

    Args:
        value: Raw domain string.

    Returns:
        Normalized, lowercase domain string.

    Raises:
        InvalidObservableError: If value does not conform to FQDN syntax.
    """
    cleaned = value.strip().lower().rstrip(".")
    if not cleaned:
        raise InvalidObservableError(
            "Domain string cannot be empty",
            observable=value,
            observable_type=ObservableType.DOMAIN.value,
        )

    if len(cleaned) > 253:
        raise InvalidObservableError(
            f"Domain length ({len(cleaned)}) exceeds RFC 1035 limit (253 chars)",
            observable=value,
            observable_type=ObservableType.DOMAIN.value,
        )

    if any(c in cleaned for c in _PROHIBITED_DOMAIN_CHARS):
        raise InvalidObservableError(
            f"Domain '{value}' contains prohibited characters (protocol, port, path, or whitespace)",
            observable=value,
            observable_type=ObservableType.DOMAIN.value,
        )

    # Ensure IP addresses are rejected as domains
    try:
        ipaddress.ip_address(cleaned)
        raise InvalidObservableError(
            f"IP address '{value}' cannot be validated as a domain observable",
            observable=value,
            observable_type=ObservableType.DOMAIN.value,
        )
    except ValueError:
        pass

    labels = cleaned.split(".")
    if len(labels) < 2:
        raise InvalidObservableError(
            f"Domain '{value}' must contain at least a domain name and TLD",
            observable=value,
            observable_type=ObservableType.DOMAIN.value,
        )

    for label in labels:
        if not label:
            raise InvalidObservableError(
                f"Domain '{value}' contains empty label (consecutive dots)",
                observable=value,
                observable_type=ObservableType.DOMAIN.value,
            )
        if len(label) > 63:
            raise InvalidObservableError(
                f"Domain label '{label}' exceeds 63 character limit",
                observable=value,
                observable_type=ObservableType.DOMAIN.value,
            )
        if not _DOMAIN_LABEL_RE.match(label):
            raise InvalidObservableError(
                f"Domain label '{label}' contains invalid characters or illegal hyphens",
                observable=value,
                observable_type=ObservableType.DOMAIN.value,
            )

    tld = labels[-1]
    if tld.isdigit():
        raise InvalidObservableError(
            f"Domain TLD '{tld}' cannot be purely numeric",
            observable=value,
            observable_type=ObservableType.DOMAIN.value,
        )
    if len(tld) < 2:
        raise InvalidObservableError(
            f"Domain TLD '{tld}' must be at least 2 characters",
            observable=value,
            observable_type=ObservableType.DOMAIN.value,
        )

    return cleaned


def validate_hash(value: str, expected_len: int, algo_type: ObservableType) -> str:
    """
    Validate and normalize a cryptographic hash of specified length.

    Args:
        value: Raw hash string.
        expected_len: Required character length (32 for MD5, 40 for SHA-1, 64 for SHA-256).
        algo_type: ObservableType representing the algorithm.

    Returns:
        Canonical lowercase hexadecimal string.

    Raises:
        InvalidObservableError: If length is incorrect or characters are non-hexadecimal.
    """
    cleaned = value.strip().lower()
    algo_name = algo_type.value.upper()

    if len(cleaned) != expected_len:
        raise InvalidObservableError(
            f"Invalid {algo_name} hash length: expected {expected_len} hex characters, got {len(cleaned)}",
            observable=value,
            observable_type=algo_type.value,
        )

    if not _HEX_RE.match(cleaned):
        raise InvalidObservableError(
            f"Invalid {algo_name} hash '{value}': contains non-hexadecimal characters",
            observable=value,
            observable_type=algo_type.value,
        )

    return cleaned


def validate_md5(value: str) -> str:
    """Validate and normalize a 32-character MD5 hash."""
    return validate_hash(value, 32, ObservableType.MD5)


def validate_sha1(value: str) -> str:
    """Validate and normalize a 40-character SHA-1 hash."""
    return validate_hash(value, 40, ObservableType.SHA1)


def validate_sha256(value: str) -> str:
    """Validate and normalize a 64-character SHA-256 hash."""
    return validate_hash(value, 64, ObservableType.SHA256)


def detect_observable_type(value: str) -> ObservableType:
    """
    Attempt to auto-detect the observable type for an input string.

    Tries in priority order:
    1. IPv4 address
    2. IPv6 address
    3. Hashes by exact hex length (32 -> MD5, 40 -> SHA-1, 64 -> SHA-256)
    4. Domain syntax

    Raises:
        InvalidObservableError: If the input cannot be identified as any supported type.
    """
    cleaned = value.strip()

    # 1. IPv4
    try:
        ipaddress.IPv4Address(cleaned)
        return ObservableType.IPV4
    except ValueError:
        pass

    # 2. IPv6
    try:
        ipaddress.IPv6Address(cleaned.strip("[]"))
        return ObservableType.IPV6
    except ValueError:
        pass

    # 3. Hashes
    lower_val = cleaned.lower()
    if _HEX_RE.match(lower_val):
        if len(lower_val) == 64:
            return ObservableType.SHA256
        if len(lower_val) == 40:
            return ObservableType.SHA1
        if len(lower_val) == 32:
            return ObservableType.MD5

    # 4. Domain
    try:
        validate_domain(cleaned)
        return ObservableType.DOMAIN
    except InvalidObservableError:
        pass

    raise InvalidObservableError(
        f"Could not auto-detect a valid threat intelligence observable type for '{value}'",
        observable=value,
    )


def normalize_observable(
    value: str,
    observable_type: ObservableType | str | None = None,
) -> Observable:
    """
    Normalize and strictly validate an observable against a specified or detected type.

    Args:
        value: Raw observable string.
        observable_type: Explicit ObservableType enum, string identifier, or None to auto-detect.

    Returns:
        Observable model containing the validated type, raw value, and canonical normalized value.

    Raises:
        InvalidObservableError: If validation fails or observable is malformed.
    """
    raw = value
    clean_type: ObservableType

    if observable_type is None:
        clean_type = detect_observable_type(raw)
    elif isinstance(observable_type, ObservableType):
        clean_type = observable_type
    else:
        # String hint normalization
        str_type = str(observable_type).strip().lower()
        if str_type in ("ipv4", "ip_v4"):
            clean_type = ObservableType.IPV4
        elif str_type in ("ipv6", "ip_v6"):
            clean_type = ObservableType.IPV6
        elif str_type in ("domain", "hostname", "fqdn"):
            clean_type = ObservableType.DOMAIN
        elif str_type in ("md5",):
            clean_type = ObservableType.MD5
        elif str_type in ("sha1", "sha-1"):
            clean_type = ObservableType.SHA1
        elif str_type in ("sha256", "sha-256"):
            clean_type = ObservableType.SHA256
        elif str_type in ("ip",):
            # Generic IP hint: disambiguate v4 vs v6
            try:
                ip = ipaddress.ip_address(raw.strip().strip("[]"))
                clean_type = (
                    ObservableType.IPV4 if ip.version == 4 else ObservableType.IPV6
                )
            except ValueError as exc:
                raise InvalidObservableError(
                    f"Invalid IP address '{raw}': {exc}",
                    observable=raw,
                    observable_type="ip",
                ) from exc
        elif str_type in ("file_hash", "hash"):
            # Generic hash hint: determine algorithm by length
            stripped = raw.strip().lower()
            if not _HEX_RE.match(stripped):
                raise InvalidObservableError(
                    f"Hash observable '{raw}' contains non-hexadecimal characters",
                    observable=raw,
                    observable_type="file_hash",
                )
            if len(stripped) == 32:
                clean_type = ObservableType.MD5
            elif len(stripped) == 40:
                clean_type = ObservableType.SHA1
            elif len(stripped) == 64:
                clean_type = ObservableType.SHA256
            else:
                raise InvalidObservableError(
                    f"Unsupported or invalid hash length ({len(stripped)}) for '{raw}'. Expected 32 (MD5), 40 (SHA-1), or 64 (SHA-256)",
                    observable=raw,
                    observable_type="file_hash",
                )
        else:
            raise InvalidObservableError(
                f"Unsupported observable type hint '{observable_type}'",
                observable=raw,
                observable_type=str_type,
            )

    # Execute specific normalization
    normalized: str
    if clean_type == ObservableType.IPV4:
        normalized = validate_ipv4(raw)
    elif clean_type == ObservableType.IPV6:
        normalized = validate_ipv6(raw)
    elif clean_type == ObservableType.DOMAIN:
        normalized = validate_domain(raw)
    elif clean_type == ObservableType.MD5:
        normalized = validate_md5(raw)
    elif clean_type == ObservableType.SHA1:
        normalized = validate_sha1(raw)
    elif clean_type == ObservableType.SHA256:
        normalized = validate_sha256(raw)
    else:
        raise InvalidObservableError(
            f"Unhandled observable type '{clean_type}'",
            observable=raw,
            observable_type=str(clean_type),
        )

    return Observable(
        type=clean_type,
        raw_value=raw,
        normalized_value=normalized,
    )


def from_extracted_entity(record: Any) -> Observable:
    """
    Bridge function to convert an ExtractedEntityRecord from telemetry normalization
    into a strictly validated threat intelligence Observable.

    Guarantees:
    - Extracted 'file_hash' entities are NOT automatically trusted: length and hex characters
      are validated strictly according to algorithm or length.
    - IP entities are validated with `ipaddress`.
    - Domain entities are validated with RFC 1035 syntax rules without DNS lookups.

    Args:
        record: ExtractedEntityRecord instance or equivalent duck-typed object.

    Returns:
        Validated Observable model.

    Raises:
        InvalidObservableError: If the entity cannot be converted to a valid IOC observable.
    """
    entity_type = getattr(record, "entity_type", "")
    entity_value = getattr(record, "entity_value", "")
    attributes = getattr(record, "attributes", {}) or {}

    if entity_type == "ip":
        return normalize_observable(entity_value, "ip")
    elif entity_type == "domain":
        return normalize_observable(entity_value, ObservableType.DOMAIN)
    elif entity_type == "file_hash":
        algo = attributes.get("algorithm")
        if algo:
            algo_clean = str(algo).upper().replace("-", "")
            if algo_clean in ("MD5", "SHA1", "SHA256"):
                return normalize_observable(entity_value, algo_clean.lower())
            raise InvalidObservableError(
                f"Unsupported or non-standard file hash algorithm '{algo}'. Expected MD5, SHA-1, or SHA-256",
                observable=str(entity_value),
                observable_type="file_hash",
            )
        # If algorithm not specified, validate by length
        return normalize_observable(entity_value, "file_hash")
    else:
        raise InvalidObservableError(
            f"Entity type '{entity_type}' cannot be converted to a threat intelligence observable",
            observable=str(entity_value),
            observable_type=str(entity_type),
        )
