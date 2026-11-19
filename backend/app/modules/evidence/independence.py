"""
AISOP Evidence-Independence Primitives (Stage 3C-R, ADR-008 rule table ``suff-v2``).

Distinct events are not independent evidence. This module defines, once, the notions used by
the evidence-sufficiency gate, the claim validator and the multi-source correlator:

* **Evidence clusters**: events that are the same observation seen more than once collapse
  into one evidence unit: same event object, same attested raw-evidence digest (one raw
  record parsed into several events), identical content, or a *near-duplicate* (same identity
  and entities, within ``NEAR_DUPLICATE_WINDOW_SECONDS``). Unverifiable digests (missing,
  malformed or all-zero) never merge events by digest.
* **Link strength** of a shared entity (concept adapted from AiSOC's ``attack_chain_grouper``
  STRONG / SPECIFIC / WEAK link tiers): a *specific* link is a shared artefact that is not
  shared by accident (file hash, domain, file path, registry key, URL, e-mail address, public IP
  address). A *weak* link is a bare context string (host, user, process name, internal IP):
  it explains *where/who*, not *that two observations corroborate each other*.
* Independent corroboration therefore requires different evidence clusters (different attested
  raw records, not near-duplicates) joined by a specific link.

Pure functions, no I/O.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Hashable, Iterable, Optional

#: Same identity + same entities within this many seconds is one observation seen twice.
NEAR_DUPLICATE_WINDOW_SECONDS = 2.0

LINK_STRONG = "strong"
LINK_SPECIFIC = "specific"
LINK_WEAK = "weak"

#: Entity types whose shared value is evidence of a relationship rather than coincidence.
SPECIFIC_ENTITY_TYPES = frozenset({"file_hash", "domain", "file", "registry", "url", "email"})

#: One authenticated context / one process instance (AiSOC "STRONG" tier: session id, process GUID).
STRONG_ENTITY_TYPES = frozenset({"process_guid", "logon_session", "event_correlation"})  # event_correlation: issuer-scoped id of ONE underlying event (ADR-013)

_ZERO_DIGEST = "0" * 64


def is_unattested_digest(sha256_str: Optional[str]) -> bool:
    """True if the raw-evidence digest is missing, malformed or the all-zero sentinel."""
    if not sha256_str:
        return True
    clean = sha256_str.strip().lower()
    if clean == _ZERO_DIGEST or clean == "":
        return True
    return len(clean) != 64 or not all(c in "0123456789abcdef" for c in clean)


def normalize_digest(sha256_str: Optional[str]) -> Optional[str]:
    """Lower-cased attested digest, or None when unverifiable."""
    return None if is_unattested_digest(sha256_str) else sha256_str.strip().lower()  # type: ignore[union-attr]


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False


#: Values that carry no information: a producer (or an attacker) can emit them for any field, so sharing one
#: proves nothing (Stage 5 finding: ``unknown``/``-``/zero hashes were treated as shared artefacts).
PLACEHOLDER_VALUES = frozenset({
    "", "-", "--", "?", "unknown", "null", "none", "n/a", "na", "nil", "undefined", "(null)", "<null>",
    "<unknown>", "localhost", "anonymous", "default", "empty", "not available", "unspecified",
})
#: Logon sessions shared by every SYSTEM / service-account process: a shared value is not one authenticated context.
WELL_KNOWN_LOGON_SESSIONS = frozenset({"0x0", "0x3e7", "0x3e4", "0x3e5", "0x3e6"})
_HASH_LENGTHS = frozenset({32, 40, 64, 128})
_HEX = frozenset("0123456789abcdef")


def fold_mailbox(value: str) -> str:
    """
    Stage 7C (D3). RFC 5321 section 2.4: the DOMAIN of an address is case-insensitive, the LOCAL PART is case-sensitive, so only the part after the
    last ``@`` is folded. A value without ``@`` is returned unchanged. The same rule serves message ids (``<left@right>``): only ``right`` is folded.
    """
    left, at, right = value.rpartition("@")
    if not at:
        return value
    if right.endswith(">"):
        return f"{left}@{right[:-1].lower()}>"
    return f"{left}@{right.lower()}"


def canonical_entity_value(entity_type: str, entity_value: str) -> str:
    """
    Comparison form of an entity value, per type and component (Stage 7C, D3; every other type keeps the source value's case):
      domain, file_hash, ip, process_guid : case-insensitive by definition (DNS names RFC 4343, hexadecimal digits, IP text) -> folded
      email                               : domain part folded, LOCAL PART PRESERVED (RFC 5321)
      logon_session                       : opaque session id: case PRESERVED (legacy host-scoped Windows/Sysmon hexadecimal logon ids are
                                            lower-cased by their own producer, because hexadecimal digits are case-insensitive)
    """
    t = entity_type.strip().lower()
    v = entity_value.strip()
    if t in ("domain", "file_hash", "ip", "process_guid"):
        v = v.lower()
    elif t == "email":
        v = fold_mailbox(v)
    if t == "domain":
        v = v.rstrip(".")
    return v


def is_informative_value(entity_type: str, entity_value: str) -> bool:
    """False for placeholders and structurally impossible values of a specific/strong entity type."""
    t = entity_type.strip().lower()
    v = entity_value.strip().lower()
    if v in PLACEHOLDER_VALUES:
        return False
    if t == "file_hash":
        return len(v) in _HASH_LENGTHS and set(v) <= _HEX and len(set(v)) > 1
    if t == "domain":
        return "." in v.strip(".") and " " not in v
    if t == "email":
        return "@" in v
    if t == "process_guid":
        return len(set(v.strip("{}").replace("-", ""))) > 1
    if t == "logon_session":
        return v.rsplit(":", 1)[-1] not in WELL_KNOWN_LOGON_SESSIONS  # normalised form is "<host>:<id>"
    if t == "url":
        return "://" in v or "/" in v
    return True


def entity_link_strength(entity_type: str, entity_value: str) -> str:
    """Strength of the relationship implied by sharing this entity (see module docstring).

    A strong/specific type whose value is a placeholder or structurally invalid is only WEAK.
    """
    t = entity_type.strip().lower()
    if t in STRONG_ENTITY_TYPES:
        return LINK_STRONG if is_informative_value(t, entity_value) else LINK_WEAK
    if t in SPECIFIC_ENTITY_TYPES:
        return LINK_SPECIFIC if is_informative_value(t, entity_value) else LINK_WEAK
    if t == "ip":
        return LINK_SPECIFIC if is_public_ip(canonical_entity_value(t, entity_value)) else LINK_WEAK
    return LINK_WEAK


def specific_entities(entities: Iterable[tuple[str, str]]) -> set[tuple[str, str]]:
    """Entities whose sharing is corroborating (strong or specific tier)."""
    return {e for e in entities if entity_link_strength(e[0], e[1]) in (LINK_STRONG, LINK_SPECIFIC)}


@dataclass(frozen=True)
class EvidenceItem:
    """Minimal, schema-independent view of one observation for clustering."""

    key: Hashable
    timestamp: datetime
    digest: Optional[str]  # attested raw digest or None
    identity: tuple  # e.g. (host, event id/signature, event type, action, outcome)
    entities: frozenset  # frozenset[(type, value)]
    content: str = ""  # canonical content discriminator (attributes), exact-duplicate test


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def cluster_evidence(
    items: list[EvidenceItem],
    window_seconds: float = NEAR_DUPLICATE_WINDOW_SECONDS,
) -> dict[Hashable, int]:
    """
    Map each item key to a cluster id (the index of the cluster's first item).

    Merge rules (any one suffices): identical key; identical attested digest; identical
    (identity, content, timestamp); same identity and same entities within the window.
    Deterministic for a given item order.
    """
    n = len(items)
    uf = _UnionFind(n)
    first_by_key: dict[Hashable, int] = {}
    first_by_digest: dict[str, int] = {}
    first_by_content: dict[tuple, int] = {}
    for i, it in enumerate(items):
        if it.key in first_by_key:
            uf.union(first_by_key[it.key], i)
        else:
            first_by_key[it.key] = i
        if it.digest:
            if it.digest in first_by_digest:
                uf.union(first_by_digest[it.digest], i)
            else:
                first_by_digest[it.digest] = i
        ckey = (it.identity, it.content, it.timestamp)
        if ckey in first_by_content:
            uf.union(first_by_content[ckey], i)
        else:
            first_by_content[ckey] = i
    by_identity: dict[tuple, list[int]] = {}
    for i, it in enumerate(items):
        by_identity.setdefault((it.identity, it.entities), []).append(i)
    for idxs in by_identity.values():
        idxs.sort(key=lambda j: items[j].timestamp)
        for a, b in zip(idxs, idxs[1:]):
            if abs((items[b].timestamp - items[a].timestamp).total_seconds()) <= window_seconds:
                uf.union(a, b)
    return {it.key: uf.find(i) for i, it in enumerate(items)}


def independent_groups(keys: Iterable[Hashable], clusters: dict[Hashable, int]) -> int:
    """Number of distinct evidence clusters among the given keys (unknown keys are ignored)."""
    return len({clusters[k] for k in keys if k in clusters})


def explain_clusters(
    items: list[EvidenceItem],
    clusters: dict[Hashable, int],
    window_seconds: float = NEAR_DUPLICATE_WINDOW_SECONDS,
) -> list[dict]:
    """
    TRACE ONLY (analyst rationale, Sprint 1). Observes WHY items share a cluster; it never decides membership and ``cluster_evidence`` is not
    changed or called here. For every non-first member of a multi-member cluster it reports which of the existing merge predicates holds
    DIRECTLY between that member and the cluster's first item (the representative): ``same_key``, ``same_upstream_id`` (the item digest is an
    ``upstream:`` key), ``same_digest``, ``same_content`` (identity, content and timestamp equal) and ``near_duplicate_within_window`` (same
    identity and entities within the window). If none holds directly the member was merged through other members: ``transitive_chain``.
    The conditions are the ones ``cluster_evidence`` applies; results are deterministic for a given item order.
    """
    by_cluster: dict[int, list[int]] = {}
    for i, it in enumerate(items):
        if it.key in clusters:
            by_cluster.setdefault(clusters[it.key], []).append(i)
    out: list[dict] = []
    for cid in sorted(by_cluster):
        idxs = by_cluster[cid]
        if len(idxs) < 2:
            continue
        rep = items[idxs[0]]
        for j in idxs[1:]:
            m = items[j]
            basis: list[str] = []
            if m.key == rep.key:
                basis.append("same_key")
            if m.digest and m.digest == rep.digest:
                basis.append("same_upstream_id" if str(m.digest).startswith("upstream:") else "same_digest")
            if (m.identity, m.content, m.timestamp) == (rep.identity, rep.content, rep.timestamp):
                basis.append("same_content")
            if (m.identity, m.entities) == (rep.identity, rep.entities) and abs((m.timestamp - rep.timestamp).total_seconds()) <= window_seconds:
                basis.append("near_duplicate_within_window")
            out.append({"into": rep.key, "duplicate": m.key, "basis": basis or ["transitive_chain"], "direct": bool(basis)})
    return out
