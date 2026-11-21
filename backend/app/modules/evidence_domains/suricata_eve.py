"""
Suricata EVE JSON -> ``aisop.evidence/1`` envelopes (ADR-011 source-format adapter; PROPOSED in the adapters module docstring).

This is a pure translator: it reads Suricata's native EVE records and emits the same envelopes the other sources use, so everything
downstream (independence, sufficiency gate, ATT&CK rules, report escaping, lead review) applies unchanged. It adds no second ingestion path
and no new corroboration rule.

Supported EVE ``event_type`` values and what they become (nothing else is interpreted; other types are counted as skipped, never guessed):
* ``alert`` -> ``network.ids``   (signature, signature id, category and Suricata severity are kept as attributes only; the severity is
                                  never turned into an AISOP verdict or an ATT&CK technique)
* ``dns``   -> ``network.dns``   (query name; answers only when they parse as IP addresses)
* ``flow``  -> ``network.flow``  (recorded with action ``observed``: a flow record states that traffic was seen, not that a firewall allowed it,
                                  so no CONNECTED_TO relationship is asserted)

Rules (each is tested):
* The event time is taken only from ``timestamp``. Missing or unparseable stays missing or invalid; the current time is never substituted.
* Records from ONE sensor that share a ``flow_id`` describe the same observed traffic, so they get one shared ``source.upstream_id``
  (``suricata:<sensor>:<flow_id>``) and count as one piece of evidence, not as corroboration of each other. The sensor name is required
  because ``flow_id`` is only unique per sensor. A Suricata record and a firewall record of the same flow remain independent sources.
* A record that is not a JSON object, has no usable source address, or is of the wrong shape is rejected with a FIXED code, never with the
  exception text. Bounded: size and record count are limited like the other file imports.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Optional

from app.modules.evidence_domains.adapters import EvidenceFormatError
from app.modules.evidence_domains.model import ENVELOPE_SCHEMA

SUPPORTED = {"alert": "network.ids", "dns": "network.dns", "flow": "network.flow"}
_SENSOR_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_FLOW_ID_RE = re.compile(r"^[0-9]{1,24}$")
MAX_FILE_BYTES = 5 * 1024 * 1024


def _addr(value: Any) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _put(out: dict[str, Any], key: str, value: Any) -> None:
    if isinstance(value, (str, int, float, bool)) and value != "":
        out[key] = value


def eve_to_envelope(record: Any, *, sensor: str) -> Optional[dict[str, Any]]:
    """One EVE record -> one envelope, or None for an event type that is not supported (skipped, not interpreted)."""
    if not isinstance(sensor, str) or not _SENSOR_RE.match(sensor):
        raise EvidenceFormatError("SENSOR_NAME_INVALID")
    if not isinstance(record, dict):
        raise EvidenceFormatError("RECORD_MALFORMED")
    etype = SUPPORTED.get(str(record.get("event_type", "")))
    if etype is None:
        return None
    src = _addr(record.get("src_ip"))
    if src is None:
        raise EvidenceFormatError("FIELD_INVALID:src_ip")
    data: dict[str, Any] = {"src_ip": src}
    if etype == "network.dns":
        dns = record.get("dns")
        if not isinstance(dns, dict) or not isinstance(dns.get("rrname"), str) or not dns["rrname"].strip():
            raise EvidenceFormatError("FIELD_MISSING:dns.rrname")
        data["query"] = dns["rrname"]
        _put(data, "rcode", dns.get("rcode"))
        answers: list[str] = []
        raw_answers = dns.get("answers")
        if isinstance(raw_answers, list):
            answers += [str(a.get("rdata")) for a in raw_answers if isinstance(a, dict) and a.get("rdata") is not None]
        grouped = dns.get("grouped")
        if isinstance(grouped, dict):
            for kind in ("A", "AAAA"):
                if isinstance(grouped.get(kind), list):
                    answers += [str(x) for x in grouped[kind]]
        ips = [a for a in (_addr(x) for x in answers) if a]
        if ips:
            data["answers"] = ips[:20]
    else:
        dst = _addr(record.get("dest_ip"))
        if dst is None:
            raise EvidenceFormatError("FIELD_INVALID:dest_ip")
        data["dst_ip"] = dst
        _put(data, "dst_port", record.get("dest_port"))
        _put(data, "src_port", record.get("src_port"))
        _put(data, "proto", record.get("proto"))
        _put(data, "app_proto", record.get("app_proto"))
        if etype == "network.ids":
            alert = record.get("alert")
            if not isinstance(alert, dict) or not isinstance(alert.get("signature"), str) or not alert["signature"].strip():
                raise EvidenceFormatError("FIELD_MISSING:alert.signature")
            data["signature"] = alert["signature"]
            _put(data, "signature_id", alert.get("signature_id"))
            _put(data, "category", alert.get("category"))
            _put(data, "suricata_severity", alert.get("severity"))
            _put(data, "suricata_action", alert.get("action"))
        else:
            data["action"] = "observed"
    _put(data, "in_iface", record.get("in_iface"))
    source: dict[str, Any] = {"system": "suricata", "category": "network", "collection_method": "eve_json"}
    flow_id = record.get("flow_id")
    if flow_id is not None and _FLOW_ID_RE.match(str(flow_id)):
        source["upstream_id"] = f"suricata:{sensor}:{flow_id}"
        data["flow_id"] = str(flow_id)
    envelope: dict[str, Any] = {"schema": ENVELOPE_SCHEMA, "evidence_type": etype, "source": source, "data": data}
    if record.get("timestamp") is not None:
        envelope["event_time"] = record["timestamp"]
    return envelope


def eve_file_to_envelopes(path: str | Path, *, sensor: str, max_records: int = 1000) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Read an EVE JSON Lines file. Returns (envelopes, counts) where counts has read, converted, skipped_unsupported and rejected."""
    p = Path(path)
    if not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
        raise EvidenceFormatError("FILE_UNREADABLE_OR_TOO_LARGE")
    envelopes: list[dict[str, Any]] = []
    counts = {"read": 0, "converted": 0, "skipped_unsupported": 0, "rejected": 0}
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        counts["read"] += 1
        if counts["read"] > max_records:
            raise EvidenceFormatError("FILE_BAD_STRUCTURE_OR_TOO_MANY_RECORDS")
        try:
            env = eve_to_envelope(json.loads(line), sensor=sensor)
        except json.JSONDecodeError:
            counts["rejected"] += 1
            continue
        except EvidenceFormatError as exc:
            if str(exc).startswith("SENSOR_NAME_INVALID"):
                raise
            counts["rejected"] += 1
            continue
        if env is None:
            counts["skipped_unsupported"] += 1
        else:
            envelopes.append(env)
            counts["converted"] += 1
    return envelopes, counts


__all__ = ["SUPPORTED", "eve_file_to_envelopes", "eve_to_envelope"]
