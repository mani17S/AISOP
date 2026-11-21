"""
AISOP multi-source normalization (Stage 3C-R vertical slice, ADR-009).

Turns heterogeneous raw records (SIEM alerts, Windows identity events, Sysmon, DNS/firewall/IDS
...) into source-neutral ``CorrelationEvent`` objects by reusing the existing vendor-neutral
adapter registry (ADR-007) and adding only what correlation needs: identity/host normalization,
ATT&CK ids *asserted by the source* (kept separate from derived mappings), Sysmon process and DNS
identifiers that the alert adapters do not surface (read from the raw record), and an optional
asset inventory to attribute network-only records to a host.

AiSOC concept adapted: connector -> canonical event normalization with provenance preserved
(``services/fusion/app/services/provenance.py`` and the OCSF ingest envelope). Here the
provenance is the SHA-256 of the exact raw record, kept on every event.

Failure handling: a record that cannot be normalized is recorded in ``rejected`` with a fixed
reason code (never the exception text) and never silently dropped; one bad record does not stop
the batch. No I/O, no network.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.modules.alerts.adapter_protocol import AlertAdapterRegistry, AlertTimestampError, get_default_registry
from app.modules.correlation.models import CorrelationEvent, NormalizationResult, RejectedRecord
from app.modules.evidence_domains.adapters import EvidenceFormatError, is_domain_record, parse_record
from app.modules.evidence_domains.bridge import is_projectable, observation_to_event
from app.schemas.alert import CanonicalAlert

EVENT_NAMESPACE = uuid.UUID("0d1c7e44-52a9-4a53-8a67-3b2f6b9d4e11")

_OUTCOME_BY_WINDOWS_EVENT = {"4624": "success", "4625": "failure"}

#: Bounds on untrusted raw records (Stage 5). A record deeper than this cannot be a real vendor event and would
#: exhaust the interpreter stack when hashed; a record larger than this (canonical JSON) is rejected rather than
#: parsed. 1 MiB is far above any single Windows/Sysmon/SIEM/IDS event while keeping per-record work bounded.
MAX_RECORD_NESTING_DEPTH = 32
MAX_RECORD_BYTES = 1_048_576

#: Placeholder digest recorded for a record that cannot be hashed at all (too deep / not serialisable). It is a
#: sentinel, not provenance: ``is_unattested_digest`` treats it like the all-zero value, so it never merges events.
_UNHASHABLE = "0" * 64


def _exceeds_depth(obj: Any, limit: int = MAX_RECORD_NESTING_DEPTH) -> bool:
    """Iterative (stack-safe) check that no container is nested deeper than ``limit``."""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if isinstance(cur, dict):
            children: Any = cur.values()
        elif isinstance(cur, (list, tuple)):
            children = cur
        else:
            continue
        if depth > limit:
            return True
        stack.extend((c, depth + 1) for c in children if isinstance(c, (dict, list, tuple)))
    return False


def raw_digest(record: Any) -> str:
    """SHA-256 of the canonical JSON of the raw record (stable key order)."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def normalize_user(value: Optional[str]) -> Optional[str]:
    """``CORP\\JDoe`` and ``jdoe@corp.local`` both become ``jdoe`` (identity across sources)."""
    if not value:
        return None
    v = value.strip()
    if "\\" in v:
        v = v.rsplit("\\", 1)[1]
    if "@" in v:
        v = v.split("@", 1)[0]
    v = v.strip().lower()
    return v or None


def _event_data(raw: dict[str, Any]) -> dict[str, Any]:
    ev = raw.get("Event")
    if isinstance(ev, dict) and isinstance(ev.get("EventData"), dict):
        return ev["EventData"]
    if isinstance(raw.get("EventData"), dict):
        return raw["EventData"]
    return {}


def _sysmon_event_id(raw: dict[str, Any]) -> str:
    ev = raw.get("Event")
    if isinstance(ev, dict):
        return str(ev.get("System", {}).get("EventID", ""))
    return str(raw.get("EventID", ""))


def _first_public_ip(text: str) -> Optional[str]:
    for part in str(text).replace(",", ";").split(";"):
        part = part.strip()
        try:
            if part and ipaddress.ip_address(part).is_global:
                return part
        except ValueError:
            continue
    return None


def _guid(value: Any) -> Optional[str]:
    if not value:
        return None
    g = str(value).strip().strip("{}").lower()
    return g or None


_NATIVE_ID_SOURCES = frozenset({"edr_malware", "linux_auth"})


def _supplied_native_id(alert: CanonicalAlert, raw: Any) -> str:
    """
    Stage 7C (D2). EDR and Linux auth adapters keep the source's id in ``source_alert_id`` but fall back to a random synthetic id when the source
    supplied none. The id is returned ONLY if the raw record itself carries exactly that value (top level or one nested object), so a generated
    id is never presented as native. Provenance only: it is not put in ``source_event_id`` (which feeds duplicate identity and observation class).
    """
    if alert.source_type not in _NATIVE_ID_SOURCES or not isinstance(raw, dict):
        return ""
    candidate = str(alert.source_alert_id or "")
    if not candidate:
        return ""
    pools = [raw] + [v for v in raw.values() if isinstance(v, dict)]
    for pool in pools:
        for v in pool.values():
            if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v) == candidate:
                return candidate[:64]
    return ""


_DOCUMENTED_UTC_SOURCES = frozenset({"sysmon", "windows_security"})


def _time_assumed_utc(alert: CanonicalAlert, raw: dict[str, Any]) -> bool:
    """
    Stage 7B (D5). A time without an offset is NOT silently reliable UTC. The only exception is where the SOURCE FORMAT defines UTC: Sysmon
    ``EventData.UtcTime`` and the Windows event ``System.TimeCreated.@SystemTime`` are UTC by definition of those formats. For every other
    adapter (or a Sysmon/Windows record that fell back to a generic ``timestamp`` field) a naive time is flagged as an assumption.
    """
    if alert.timestamp.tzinfo is not None:
        return False
    if alert.source_type in _DOCUMENTED_UTC_SOURCES:
        system_time = ((raw.get("Event") or {}).get("System") or {}).get("TimeCreated") if isinstance(raw.get("Event"), dict) else None
        if (isinstance(system_time, dict) and system_time.get("@SystemTime")) or _event_data(raw).get("UtcTime"):
            return False
    return True


def _to_event(
    alert: CanonicalAlert,
    raw: dict[str, Any],
    index: int,
    digest: str,
    assets: dict[str, str],
    event_key: Optional[uuid.UUID] = None,
) -> CorrelationEvent:
    src_ip: Optional[str] = alert.network.source_ip if alert.network and alert.network.source_ip else None
    dst_ip: Optional[str] = alert.network.destination_ip if alert.network and alert.network.destination_ip else None
    if src_ip is None or dst_ip is None:
        for ent in alert.entities:
            if ent.entity_type != "ip":
                continue
            if ent.role in ("attacker", "source") and src_ip is None:
                src_ip = ent.entity_value
            elif ent.role in ("target", "destination") and dst_ip is None:
                dst_ip = ent.entity_value

    host = alert.host.hostname if alert.host and alert.host.hostname else None
    if host is None:
        host = next((e.entity_value for e in alert.entities if e.entity_type == "host"), None)
    host_source = "record" if host else "none"
    if host is None:
        for ip in (src_ip, dst_ip):
            if ip and ip in assets:
                host, host_source = assets[ip], "asset_inventory"
                break
    host = host.strip().lower() if host else None

    user = normalize_user(
        (alert.user.username if alert.user and alert.user.username else None)
        or next((e.entity_value for e in alert.entities if e.entity_type == "user"), None)
        or (alert.process.user if alert.process else None)
    )

    domain = alert.dns.query_name if alert.dns and alert.dns.query_name else None
    if domain is None:
        domain = next((e.entity_value for e in alert.entities if e.entity_type == "domain"), None)

    process_name = None
    process_guid = None
    parent_guid = None
    command_line = None
    hashes: set[str] = set()
    if alert.process:
        process_name = (alert.process.process_name or (alert.process.image_path or "").replace("\\", "/").rsplit("/", 1)[-1] or None)
        command_line = alert.process.command_line
        for k, v in (alert.process.hashes or {}).items():
            if k.lower() == "sha256" and len(v) == 64:
                hashes.add(v.lower())
    for obs in alert.observables:
        if obs.type in ("hash_sha256", "sha256") and len(obs.value) == 64:
            hashes.add(obs.value.lower())
    if alert.file:
        for k, v in (alert.file.hashes or {}).items():
            if k.lower() == "sha256" and len(v) == 64:
                hashes.add(v.lower())

    # Identifiers the alert adapters do not surface, read from the preserved raw record.
    source_event_id = str(alert.custom_fields.get("event_id", "") or "")
    outcome = "unknown"
    if alert.source_type == "windows_security":
        outcome = _OUTCOME_BY_WINDOWS_EVENT.get(source_event_id, "unknown")
    elif isinstance(raw.get("outcome"), str) and raw["outcome"].lower() in ("success", "failure"):
        outcome = raw["outcome"].lower()
    if alert.source_type == "sysmon":
        ed = _event_data(raw)
        sid = _sysmon_event_id(raw)
        source_event_id = sid
        process_guid = _guid(ed.get("ProcessGuid"))
        parent_guid = _guid(ed.get("ParentProcessGuid"))
        if sid == "22":
            domain = domain or ed.get("QueryName")
            dst_ip = dst_ip or _first_public_ip(ed.get("QueryResults", ""))
        if sid == "3":
            domain = domain or ed.get("DestinationHostname")
    elif alert.source_type in ("firewall_ids", "generic_siem"):
        source_event_id = str(raw.get("signature_id") or raw.get("rule_id") or raw.get("incident_id") or source_event_id)

    # Logon session (AiSOC STRONG tier: one authenticated context). Windows 4624 TargetLogonId and
    # Sysmon LogonId are the same host-local session id; scoped by host so ids cannot collide.
    ed_all = _event_data(raw)
    logon_id = ed_all.get("TargetLogonId") if alert.source_type == "windows_security" and source_event_id == "4624" else (
        ed_all.get("LogonId") if alert.source_type == "sysmon" else None
    )
    logon_session = f"{host}:{str(logon_id).strip().lower()}" if (logon_id and host) else None

    domain = domain.strip().lower() if domain else None
    entity_set: set[tuple[str, str]] = set()
    if logon_session:
        entity_set.add(("logon_session", logon_session))
    if host:
        entity_set.add(("host", host))
    if user:
        entity_set.add(("user", user))
    for ip in (src_ip, dst_ip):
        if ip:
            entity_set.add(("ip", ip))
    if domain:
        entity_set.add(("domain", domain))
    if process_name:
        entity_set.add(("process", process_name.lower()))
    for g in (process_guid, parent_guid):
        if g:
            entity_set.add(("process_guid", g))
    for h in hashes:
        entity_set.add(("file_hash", h))

    severity = alert.severity if alert.severity in ("informational", "low", "medium", "high", "critical") else "informational"
    vendor_techniques = tuple(sorted({m.technique_id for m in alert.mitre_attack if m.technique_id}))
    ts = alert.timestamp if alert.timestamp.tzinfo else alert.timestamp.replace(tzinfo=timezone.utc)
    return CorrelationEvent(
        event_key=event_key or uuid.uuid5(EVENT_NAMESPACE, f"{digest}:{index}"),
        record_index=index,
        source_type=alert.source_type,
        provider=alert.provider,
        timestamp=ts.astimezone(timezone.utc),
        title=alert.title[:200],
        category=alert.category,
        severity=severity,
        outcome=outcome,
        host=host,
        host_source=host_source,
        user=user,
        src_ip=src_ip,
        dst_ip=dst_ip,
        domain=domain,
        process_name=process_name.lower() if process_name else None,
        process_guid=process_guid,
        parent_process_guid=parent_guid,
        command_line=(command_line[:500] if command_line else None),
        file_hashes=tuple(sorted(hashes)),
        vendor_techniques=vendor_techniques,
        source_event_id=source_event_id[:64],
        native_event_id=_supplied_native_id(alert, raw),
        time_assumed_utc=_time_assumed_utc(alert, raw),
        raw_sha256=digest,
        entities=tuple(sorted(entity_set)),
    )


def normalize_records(
    records: list[Any],
    registry: Optional[AlertAdapterRegistry] = None,
    assets: Optional[dict[str, str]] = None,
    digests: Optional[list[Optional[str]]] = None,
    event_keys: Optional[list[Optional[uuid.UUID]]] = None,
) -> NormalizationResult:
    """
    Normalize a batch. ``assets`` optionally maps an IP address to a host name (asset inventory);
    it is only used to attribute a record that carries no host, and is recorded as
    ``host_source = asset_inventory``.

    Application integration (Stage 4): when the records come from stored evidence, ``digests`` supplies
    the SHA-256 already recorded at ingestion (preserving the stored provenance instead of recomputing it)
    and ``event_keys`` supplies the persisted normalized-event ids so every correlated event keeps the id
    of the evidence row it came from. Both are positional; invalid or missing entries fall back to the
    computed digest / derived key.
    """
    reg = registry or get_default_registry()
    asset_map = {k: v for k, v in (assets or {}).items()}
    events: list[CorrelationEvent] = []
    rejected: list[RejectedRecord] = []
    observations: list[Any] = []
    for index, record in enumerate(records):
        obj: Any = record
        if isinstance(record, str):
            try:
                obj = json.loads(record)
            except Exception:  # noqa: BLE001
                obj = None
        supplied = digests[index] if digests and index < len(digests) else None
        target = obj if obj is not None else record
        if _exceeds_depth(target):
            rejected.append(RejectedRecord(record_index=index, reason="RECORD_TOO_DEEP", raw_sha256=_UNHASHABLE))
            continue
        try:
            canonical_size = len(json.dumps(target, sort_keys=True, separators=(",", ":"), default=str))
            digest = (
                supplied.strip().lower()
                if isinstance(supplied, str) and len(supplied.strip()) == 64 and all(c in "0123456789abcdefABCDEF" for c in supplied.strip())
                else raw_digest(target)
            )
        except (TypeError, ValueError, RecursionError, OverflowError):
            rejected.append(RejectedRecord(record_index=index, reason="RECORD_NOT_SERIALIZABLE", raw_sha256=_UNHASHABLE))
            continue
        if canonical_size > MAX_RECORD_BYTES:
            rejected.append(RejectedRecord(record_index=index, reason="RECORD_TOO_LARGE", raw_sha256=digest))
            continue
        key = event_keys[index] if event_keys and index < len(event_keys) else None
        if not isinstance(obj, dict):
            rejected.append(RejectedRecord(record_index=index, reason="NOT_AN_OBJECT", raw_sha256=digest))
            continue
        if isinstance(obj.get("schema"), str) and obj["schema"].startswith("aisop.evidence/") and not is_domain_record(obj):
            rejected.append(RejectedRecord(record_index=index, reason="SCHEMA_VERSION_UNSUPPORTED", raw_sha256=digest))
            continue
        if is_domain_record(obj):  # ADR-011: source-agnostic evidence envelope; never treated as an alert
            try:
                obs = parse_record(
                    obj, key=key or uuid.uuid5(EVENT_NAMESPACE, f"{digest}:{index}"), record_index=index, raw_sha256=digest,
                    integrity="digest_attested" if supplied else "digest_computed",
                )
            except EvidenceFormatError as exc:
                rejected.append(RejectedRecord(record_index=index, reason=exc.code, raw_sha256=digest))
                continue
            observations.append(obs)
            if is_projectable(obs):
                events.append(observation_to_event(obs))
            continue
        adapter = reg.find_matching_adapter(obj)
        if adapter is None:
            rejected.append(RejectedRecord(record_index=index, reason="NO_ADAPTER", raw_sha256=digest))
            continue
        try:
            before = datetime.now(timezone.utc)
            alert = adapter.adapt(obj, raw_ref=digest)
            after = datetime.now(timezone.utc)
            adapted_ts = alert.timestamp if alert.timestamp.tzinfo else alert.timestamp.replace(tzinfo=timezone.utc)
            if before <= adapted_ts <= after:
                # The ADR-007 adapters substitute "now" for a missing or unparseable timestamp. An invented time
                # would place the record on the timeline (and in time-windowed correlation) as if observed then.
                rejected.append(RejectedRecord(record_index=index, reason="TIMESTAMP_MISSING_OR_INVALID", raw_sha256=digest))
                continue
            events.append(_to_event(alert, obj, index, digest, asset_map, key))
        except AlertTimestampError:
            rejected.append(RejectedRecord(record_index=index, reason="TIMESTAMP_MISSING_OR_INVALID", raw_sha256=digest))
        except Exception as exc:  # noqa: BLE001 - classify, never leak the message
            rejected.append(RejectedRecord(record_index=index, reason=f"ADAPTER_ERROR:{type(exc).__name__}", raw_sha256=digest))
    return NormalizationResult(events=events, rejected=rejected, observations=observations)
