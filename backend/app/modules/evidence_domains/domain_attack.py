r"""
Deterministic ATT&CK rules over canonical observations (Stage 6, ADR-011).

Same contract as ``app.modules.correlation.mitre``: a rule fires only when its structural conditions hold on
de-duplicated, machine-observed evidence, and the result is "rule R fired on these evidence items", not a probability.
There is NO keyword matching: each rule checks typed fields (an action name from a fixed set, a registry path
structure, a hash shared by two independent records, a count within a window). Analyst statements and threat
intelligence never satisfy a rule.

Rules (table ``domain-attack-v1``):
* MAP-T1098.003-CLOUD-ROLE-ASSIGNED   successful cloud role/policy assignment call that names a role or target.
* MAP-T1136.003-CLOUD-ACCOUNT-CREATED successful cloud user-creation call.
* MAP-T1621-MFA-PUSH-BURST            >= 5 denied/unanswered MFA challenges for one user within 10 minutes.
* MAP-T1566.002-LINK-THEN-DNS         e-mail URL domain queried (DNS) AFTER delivery: two independent records.
* MAP-T1566.001-ATTACHMENT-ON-HOST    e-mail attachment hash found as a file artefact on a host: two independent records,
                                      and the artefact must not be timestamped before the e-mail (ADR-013, ordering).
* MAP-T1547.001-REGISTRY-RUN-KEY      registry artefact under a ...\CurrentVersion\Run / RunOnce key.
* MAP-T1055-TOOL-ASSERTED-INJECTION   forensic memory tool reports injected code / hollowing (marked tool-asserted).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Callable

from app.modules.correlation.models import MitreMapping
from app.modules.evidence_domains.contradictions import attachment_precedes_delivery
from app.modules.evidence_domains.model import Observation, TrustClass

DOMAIN_MAPPING_VERSION = "domain-attack-v1"
_ROLE_ACTIONS = frozenset({"attachuserpolicy", "attachrolepolicy", "putuserpolicy", "addroleassignment", "createroleassignment",
                           "add member to role", "add role assignment", "setiampolicy", "createaccesskey"})
_CREATE_USER = frozenset({"createuser", "add user", "create user", "adduser"})
_RUN_KEY = re.compile(r"(?i)\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\run(?:once)?(?:ex)?(?:\\|$)")
_INJECTION = frozenset({"injected_code", "process_hollowing", "reflective_dll"})
MFA_BURST = 5
MFA_WINDOW = timedelta(minutes=10)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _t(o: Observation) -> datetime:
    return o.event_time or _EPOCH


def _action(o: Observation) -> str:
    return str(o.attributes.get("action", "")).strip().lower()


def _success(o: Observation) -> bool:
    return o.outcome == "success"


def _cloud_role(obs: list[Observation]) -> list[Observation]:
    return [o for o in obs if o.evidence_type.startswith("cloud.") and _success(o) and _action(o) in _ROLE_ACTIONS
            and (o.attributes.get("role") or o.attributes.get("target_principal") or o.attributes.get("resource"))]


def _cloud_user(obs: list[Observation]) -> list[Observation]:
    return [o for o in obs if o.evidence_type.startswith("cloud.") and _success(o) and _action(o) in _CREATE_USER]


def _mfa_burst(obs: list[Observation]) -> list[Observation]:
    by_user: dict[str, list[Observation]] = {}
    for o in obs:
        if o.evidence_type == "identity.mfa" and o.event_time and o.outcome == "failure":
            by_user.setdefault(str(o.attributes.get("user", "")).lower(), []).append(o)
    for items in by_user.values():
        items.sort(key=_t)
        for i, first in enumerate(items):
            win = [x for x in items[i:] if _t(x) - _t(first) <= MFA_WINDOW]
            if len(win) >= MFA_BURST:
                return win
    return []


def _link_then_dns(obs: list[Observation]) -> list[Observation]:
    out: list[Observation] = []
    mails = [o for o in obs if o.evidence_type == "email.message" and o.event_time]
    dns = [o for o in obs if o.evidence_type == "network.dns" and o.event_time]
    for m in mails:
        derived_domains = {e for e in m.derived_entities if e[0] == "domain"}
        for d in dns:
            if derived_domains & set(d.entities) and _t(d) >= _t(m) and d.raw_sha256 != m.raw_sha256:
                out.extend(x for x in (m, d) if x not in out)
    return out


def _attachment_on_host(obs: list[Observation]) -> list[Observation]:
    out: list[Observation] = []
    mails = [o for o in obs if o.evidence_type == "email.message"]
    files = [o for o in obs if o.evidence_type == "forensic.file"]
    for m in mails:
        hashes = {e for e in m.entities if e[0] == "file_hash"}
        for f in files:
            if hashes & set(f.entities) and f.raw_sha256 != m.raw_sha256:
                if attachment_precedes_delivery(m, f):
                    continue  # ADR-013: an artefact older than the e-mail cannot support "attachment delivered"; the pair is a contradiction
                out.extend(x for x in (m, f) if x not in out)
    return out


def _run_key(obs: list[Observation]) -> list[Observation]:
    return [o for o in obs if o.evidence_type == "forensic.registry" and _RUN_KEY.search(str(o.attributes.get("key", "")))]


def _injection(obs: list[Observation]) -> list[Observation]:
    return [o for o in obs if o.evidence_type == "forensic.memory_finding" and str(o.attributes.get("finding_type", "")).lower() in _INJECTION]


class _Rule:
    def __init__(self, rule_id: str, tid: str, name: str, tactics: tuple[str, ...], limitation: str,
                 match: Callable[[list[Observation]], list[Observation]], tool_asserted: bool = False) -> None:
        self.rule_id, self.tid, self.name, self.tactics = rule_id, tid, name, tactics
        self.limitation, self.match, self.tool_asserted = limitation, match, tool_asserted


RULES: tuple[_Rule, ...] = (
    _Rule("MAP-T1098.003-CLOUD-ROLE-ASSIGNED", "T1098.003", "Account Manipulation: Additional Cloud Roles", ("persistence", "privilege-escalation"),
          "A successful role/policy assignment call; it may be an authorised administrative change.", _cloud_role),
    _Rule("MAP-T1136.003-CLOUD-ACCOUNT-CREATED", "T1136.003", "Create Account: Cloud Account", ("persistence",),
          "A successful cloud user-creation call; it may be an authorised onboarding action.", _cloud_user),
    _Rule("MAP-T1621-MFA-PUSH-BURST", "T1621", "Multi-Factor Authentication Request Generation", ("credential-access",),
          f"At least {MFA_BURST} denied or unanswered MFA challenges for one user within 10 minutes (distinct records); may be a faulty device.", _mfa_burst),
    _Rule("MAP-T1566.002-LINK-THEN-DNS", "T1566.002", "Phishing: Spearphishing Link", ("initial-access",),
          "An e-mail URL's domain was queried after delivery; shows a lookup, not that a user clicked or what was loaded.", _link_then_dns),
    _Rule("MAP-T1566.001-ATTACHMENT-ON-HOST", "T1566.001", "Phishing: Spearphishing Attachment", ("initial-access",),
          "An attachment hash matches a file artefact on a host; does not show how the file arrived or that it was opened.", _attachment_on_host),
    _Rule("MAP-T1547.001-REGISTRY-RUN-KEY", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", ("persistence", "privilege-escalation"),
          "A registry artefact exists under a Run/RunOnce key; legitimate software also uses these keys.", _run_key),
    _Rule("MAP-T1055-TOOL-ASSERTED-INJECTION", "T1055", "Process Injection", ("defense-evasion", "privilege-escalation"),
          "Asserted by a forensic memory tool (interpretation not independently verified by AISOP).", _injection, tool_asserted=True),
)


def map_domain_techniques(observations: list[Observation]) -> list[MitreMapping]:
    """Apply the rule table to machine-observed, de-duplicated evidence (analyst statements are excluded)."""
    seen: set[str] = set()
    unique: list[Observation] = []
    for o in sorted(observations, key=lambda x: (_t(x), x.record_index)):
        if not o.counts_for_corroboration or o.trust_class in (TrustClass.ANALYST_OBSERVATION, TrustClass.TI_CONTEXT, TrustClass.MODEL_INFERENCE):
            continue
        if o.raw_sha256 in seen:
            continue
        seen.add(o.raw_sha256)
        unique.append(o)
    out: list[MitreMapping] = []
    for r in RULES:
        matched = r.match(unique)
        if not matched:
            continue
        out.append(MitreMapping(
            technique_id=r.tid, technique_name=r.name, tactics=r.tactics, rule_id=r.rule_id,
            evidence_keys=tuple(o.key for o in matched), independent_evidence_count=len({o.raw_sha256 for o in matched}),
            vendor_asserted=r.tool_asserted, limitation=r.limitation,
        ))
    return out


__all__ = ["DOMAIN_MAPPING_VERSION", "RULES", "map_domain_techniques"]
