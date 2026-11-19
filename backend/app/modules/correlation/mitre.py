"""
AISOP deterministic MITRE ATT&CK mapping (Stage 3C-R vertical slice, ADR-009).

Maps *evidence* to ATT&CK techniques with an explicit, versioned rule table. A mapping is NOT a
probability and NOT a vendor claim: it states "rule R fired on these independent evidence items".
Techniques that a source merely asserted (``vendor_techniques``) are reported separately as
asserted-only unless a rule also derives them.

Each rule inspects de-duplicated evidence (one representative per raw record) so duplicates cannot
inflate counts. Rules are small pure predicates; adding a rule means adding one entry to ``RULES``
and a test.

AiSOC concept adapted: Sigma/detection content carrying ATT&CK tags, evaluated by a deterministic
rule engine (``packages/aisoc-detections``, ``windowed_detection``). AISOP keeps the table in code,
with technique names and tactics, and does not ship third-party rule content.

Limitations (IMPLEMENTED scope): six rules; PowerShell command-line patterns are heuristics; the
network rule relies on the destination address being public and the process being a scripting
host; the table is not the full matrix.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable, Optional

from app.modules.correlation.models import CorrelationEvent, MitreMapping

MAPPING_VERSION = "attack-map-v1"

_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_ENCODED = re.compile(r"(?i)(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{8,}")
_HIDDEN = re.compile(r"(?i)(?:^|\s)-(?:w|win|window|windowstyle)\s+hidden")
_SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
FAILED_LOGON_THRESHOLD = 3
LOGON_WINDOW = timedelta(minutes=10)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    technique_id: str
    technique_name: str
    tactics: tuple[str, ...]
    limitation: str
    match: Callable[[list[CorrelationEvent]], list[CorrelationEvent]]


def _is_public(ip: Optional[str]) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global  # type: ignore[arg-type]
    except ValueError:
        return False


def _failed_logon_burst(evs: list[CorrelationEvent]) -> list[CorrelationEvent]:
    fails = sorted(
        (e for e in evs if e.source_type == "windows_security" and e.outcome == "failure"),
        key=lambda e: e.timestamp,
    )
    by_origin: dict[tuple, list[CorrelationEvent]] = {}
    for e in fails:
        by_origin.setdefault((e.host, e.src_ip or e.user), []).append(e)
    for group in by_origin.values():
        for i, first in enumerate(group):
            window = [g for g in group[i:] if g.timestamp - first.timestamp <= LOGON_WINDOW]
            if len(window) >= FAILED_LOGON_THRESHOLD:
                return window
    return []


def _success_after_failures(evs: list[CorrelationEvent]) -> list[CorrelationEvent]:
    """A successful logon preceded, within 10 minutes and from the same origin, by a failed-logon burst."""
    fails = [e for e in evs if e.source_type == "windows_security" and e.outcome == "failure"]
    for success in sorted((e for e in evs if e.source_type == "windows_security" and e.outcome == "success"), key=lambda x: x.timestamp):
        origin = (success.host, success.src_ip or success.user)
        prior = sorted(
            (f for f in fails
             if (f.host, f.src_ip or f.user) == origin and timedelta(0) <= success.timestamp - f.timestamp <= LOGON_WINDOW),
            key=lambda f: f.timestamp,
        )
        if len(prior) >= FAILED_LOGON_THRESHOLD:
            return [*prior, success]
    return []


def _powershell_encoded(evs: list[CorrelationEvent]) -> list[CorrelationEvent]:
    return [
        e for e in evs
        if e.process_name in ("powershell.exe", "pwsh.exe") and e.command_line and _ENCODED.search(e.command_line)
    ]


def _powershell_hidden_window(evs: list[CorrelationEvent]) -> list[CorrelationEvent]:
    return [
        e for e in evs
        if e.process_name in ("powershell.exe", "pwsh.exe") and e.command_line and _HIDDEN.search(e.command_line)
    ]


def _script_host_outbound(evs: list[CorrelationEvent]) -> list[CorrelationEvent]:
    return [
        e for e in evs
        if e.source_type == "sysmon" and e.source_event_id == "3" and e.process_name in _SCRIPT_HOSTS and _is_public(e.dst_ip)
    ]


RULES: tuple[Rule, ...] = (
    Rule("MAP-T1110-REPEATED-FAILED-LOGON", "T1110", "Brute Force", ("credential-access",),
         f"At least {FAILED_LOGON_THRESHOLD} failed Windows logons (distinct records) from one origin within 10 minutes; "
         "cannot distinguish brute force from a misconfigured service.", _failed_logon_burst),
    Rule("MAP-T1078-SUCCESS-AFTER-FAILURES", "T1078", "Valid Accounts",
         ("initial-access", "persistence", "privilege-escalation", "defense-evasion"),
         "A successful logon from the same origin within 10 minutes after a failed-logon burst; does not prove the "
         "credentials were stolen.", _success_after_failures),
    Rule("MAP-T1059.001-POWERSHELL-ENCODED", "T1059.001", "Command and Scripting Interpreter: PowerShell", ("execution",),
         "PowerShell started with an encoded-command argument; legitimate management tools also do this.",
         _powershell_encoded),
    Rule("MAP-T1027-ENCODED-COMMAND", "T1027", "Obfuscated Files or Information", ("defense-evasion",),
         "Encoded PowerShell command line (base64-like argument); the decoded content was not analysed.",
         _powershell_encoded),
    Rule("MAP-T1564.003-POWERSHELL-HIDDEN-WINDOW", "T1564.003", "Hide Artifacts: Hidden Window", ("defense-evasion",),
         "PowerShell started with a hidden window style; some automation uses it legitimately.",
         _powershell_hidden_window),
    Rule("MAP-T1071-SCRIPT-HOST-OUTBOUND", "T1071", "Application Layer Protocol", ("command-and-control",),
         "A scripting host opened an outbound connection to a public address (Sysmon event 3); the protocol and the "
         "remote party's intent are not established.", _script_host_outbound),
)


def _parent(technique_id: str) -> str:
    return technique_id.split(".")[0]


def map_techniques(events: list[CorrelationEvent]) -> list[MitreMapping]:
    """Apply every rule to the de-duplicated evidence; returns mappings in rule order."""
    seen: set[str] = set()
    unique: list[CorrelationEvent] = []
    for e in sorted(events, key=lambda x: (x.timestamp, x.record_index)):
        if e.raw_sha256 in seen:  # same raw record: one piece of evidence
            continue
        seen.add(e.raw_sha256)
        unique.append(e)
    vendor = {t for e in unique for t in e.vendor_techniques}
    vendor_parents = {_parent(t) for t in vendor}
    out: list[MitreMapping] = []
    for rule in RULES:
        if not _TECHNIQUE_ID.match(rule.technique_id):  # pragma: no cover - table integrity guard
            raise ValueError(f"invalid technique id in rule {rule.rule_id}")
        matched = rule.match(unique)
        if not matched:
            continue
        keys: tuple[uuid.UUID, ...] = tuple(e.event_key for e in matched)
        out.append(
            MitreMapping(
                technique_id=rule.technique_id,
                technique_name=rule.technique_name,
                tactics=rule.tactics,
                rule_id=rule.rule_id,
                evidence_keys=keys,
                independent_evidence_count=len({e.raw_sha256 for e in matched}),
                vendor_asserted=rule.technique_id in vendor or _parent(rule.technique_id) in vendor_parents,
                limitation=rule.limitation,
            )
        )
    return out


def asserted_only_techniques(events: list[CorrelationEvent], mappings: list[MitreMapping]) -> list[str]:
    """Technique ids a source asserted but no deterministic rule derived (reported, not trusted)."""
    derived = {m.technique_id for m in mappings} | {_parent(m.technique_id) for m in mappings}
    asserted = {t for e in events for t in e.vendor_techniques if _TECHNIQUE_ID.match(t)}
    return sorted(t for t in asserted if t not in derived and _parent(t) not in derived)


__all__ = ["MAPPING_VERSION", "RULES", "asserted_only_techniques", "map_techniques"]
