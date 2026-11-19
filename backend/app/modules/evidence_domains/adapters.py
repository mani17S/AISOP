"""
AISOP evidence-domain adapters (Stage 6, ADR-011): identity, cloud audit, network, e-mail, forensic and analyst evidence.

Contract (``DomainAdapter``): an adapter declares its name, version, the evidence types it parses and their
family; ``parse`` validates one envelope and returns an ``Observation`` or raises ``EvidenceFormatError`` with a
FIXED code (never the exception text). Input is the AISOP evidence envelope (JSON object):

    {"schema": "aisop.evidence/1", "evidence_type": "identity.signin", "evidence_id": "<optional source id>",
     "source": {"system": "entra", "category": "identity", "collection_method": "api_export"},
     "event_time": "<ISO-8601, optional>", "collected_at": "<ISO-8601, optional>", "data": {...type specific...}}

Design rules (each tested in ``test_evidence_domains.py``):
* No alert needed: no severity, no vendor alert id, no timestamp required.
* The event time is never invented. Missing -> ``TimeStatus.MISSING``; unparseable -> ``INVALID``; a naive
  time is accepted as UTC and disclosed (``NAIVE_ASSUMED_UTC``). ``collected_at`` is kept apart.
* Source-specific fields are preserved in ``attributes`` (bounded, scalar view); the whole raw record is
  preserved unchanged elsewhere.
* Link-capable entities are normalised and scoped so that sharing them means something: files and registry
  keys are scoped to the host (``host:path``), sessions to the issuing system (``system:id``), bare file
  names and placeholders are not emitted as link entities.
* AiSOC concept adapted (``services/connectors/app/connectors/azure_entra.py:439``): a *session id* and a
  *correlation id* are different things; only the session id becomes a session entity.

Optional, SOURCE-STATED provenance and linkage fields (ADR-013 Revision 2). Nothing is guessed: when a field is absent the relationship is
simply not established, and every one of these fields is additive (existing records parse exactly as before):
* ``source.upstream_id``          id of the underlying collection event/feed the record derives from (forwarded, mirrored or replicated copies
                                  share it). Decides evidence independence only; never a payload field.
* ``correlation: {issuer, id}``   an ISSUER-SCOPED id that two sources state they share for ONE underlying event (becomes the
                                  ``event_correlation`` entity). Source-native event ids are never comparable across sources and are not used.
* ``data.session_issuer``         names the system that issued ``session_id``; without it a session id is local to the record's own system.
* ``data.canonical_id`` + ``data.canonical_id_issuer``  the canonical principal from a named directory (both or neither); a local user name
                                  is never a canonical principal.
* ``forensic.file`` ``data.origin_message_id`` + ``data.timestamp_semantics`` (``arrival|creation|modification|collection``)  which e-mail the
                                  artefact came from and what the record's event time MEANS; only an arrival or creation time with a stated
                                  origin forms a verified causal-ordering relationship.

Source-format coverage: the envelope (structured JSON, analyst-supplied evidence, file import through
``import_file``). Native vendor formats (CloudTrail, Entra, Zeek...) are PROPOSED: each would be a new adapter
that emits the same ``Observation``.
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from app.modules.evidence_domains.model import (
    ENVELOPE_SCHEMA,
    EvidenceFamily,
    Observation,
    Predicate,
    RelationSeed,
    TimeStatus,
    TrustClass,
)
from app.modules.evidence.independence import PLACEHOLDER_VALUES, canonical_entity_value, fold_mailbox, is_informative_value

ADAPTER_VERSION = "domain-adapters-1"
MAX_STR = 300
MAX_LIST = 50
MAX_STATEMENT = 2000
_EPOCH_MIN = datetime(1990, 1, 1, tzinfo=timezone.utc)
_EPOCH_MAX = datetime(2100, 1, 1, tzinfo=timezone.utc)
_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ENTITY_TYPES_FOR_ANALYST = frozenset({"user", "host", "ip", "domain", "url", "email", "file_hash"})


class EvidenceFormatError(Exception):
    """Fixed-vocabulary parse failure: ``code`` is e.g. ``FIELD_MISSING:user`` (never free text)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# ── primitive validators ─────────────────────────────────────────────────────
def parse_time(value: Any) -> tuple[Optional[datetime], TimeStatus]:
    """Strict time parse. Never returns the current time."""
    if value is None or value == "":
        return None, TimeStatus.MISSING
    dt: Optional[datetime] = None
    naive = False
    try:
        if isinstance(value, bool):
            return None, TimeStatus.INVALID
        if isinstance(value, (int, float)):
            if value != value or abs(value) > 4_102_444_800:
                return None, TimeStatus.INVALID
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        elif isinstance(value, str):
            s = value.strip()
            if len(s) > 64:
                return None, TimeStatus.INVALID
            dt = datetime.fromisoformat(s.replace("Z", "+00:00").replace("z", "+00:00"))
            if dt.tzinfo is None:
                naive = True
                dt = dt.replace(tzinfo=timezone.utc)
        else:
            return None, TimeStatus.INVALID
    except (ValueError, OverflowError, OSError):
        return None, TimeStatus.INVALID
    dt = dt.astimezone(timezone.utc)
    if not (_EPOCH_MIN <= dt <= _EPOCH_MAX):
        return None, TimeStatus.OUT_OF_RANGE
    return dt, (TimeStatus.NAIVE_ASSUMED_UTC if naive else TimeStatus.VALID)


def _s(value: Any, name: str, *, required: bool = False, limit: int = MAX_STR) -> Optional[str]:
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise EvidenceFormatError(f"FIELD_MISSING:{name}")
        return None
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise EvidenceFormatError(f"FIELD_INVALID:{name}")
    text = str(value).strip()
    if len(text) > limit:
        raise EvidenceFormatError(f"FIELD_TOO_LONG:{name}")
    return text


def _ip(value: Any, name: str, *, required: bool = False) -> Optional[str]:
    text = _s(value, name, required=required)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise EvidenceFormatError(f"FIELD_INVALID:{name}") from None


def _list(value: Any, name: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_LIST:
        raise EvidenceFormatError(f"FIELD_INVALID:{name}")
    return value


def _sha256(value: Any, name: str, *, required: bool = False) -> Optional[str]:
    text = _s(value, name, required=required)
    if text is None:
        return None
    if not _HASH_RE.match(text):
        raise EvidenceFormatError(f"FIELD_INVALID:{name}")
    return text.lower()


def _host(value: Any, name: str = "host", *, required: bool = False) -> Optional[str]:
    text = _s(value, name, required=required)
    return text.lower() if text else None


_UPSTREAM_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_TIME_SEMANTICS = frozenset({"arrival", "creation", "modification", "collection"})


_UUID_SHAPE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _issuer_id(issuer: Any, ident: Any, name: str) -> Optional[str]:
    """
    Issuer-scoped identifier ``issuer:id``. Both parts or neither: a bare id is source-local and is never made global.

    Case (Stage 7B, D4): the ISSUER is a system/directory name and is lower-cased, like ``source.system`` it is compared with. The IDENTIFIER keeps
    its case: directories may be case-sensitive, so ``AbC`` and ``abc`` must not become one principal. The single explicit exception is a
    namespace whose comparison form is defined as case-insensitive by its format: a canonical UUID (RFC 4122 hexadecimal digits) is folded.
    """
    i, v = _s(issuer, f"{name}_issuer"), _s(ident, name)
    if i is None and v is None:
        return None
    if i is None or v is None:
        raise EvidenceFormatError(f"FIELD_INVALID:{name}")
    return f"{i.lower()}:{v.lower() if _UUID_SHAPE.match(v) else v}"


def _scalar_attrs(data: dict[str, Any]) -> dict[str, Any]:
    """Bounded, scalar-flattened view of the source-specific fields (the raw record is preserved elsewhere)."""
    out: dict[str, Any] = {}

    def put(prefix: str, v: Any, depth: int) -> None:
        if len(out) >= 60:
            return
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[prefix] = v[:MAX_STR] if isinstance(v, str) else v
        elif isinstance(v, dict) and depth < 2:
            for k, vv in list(v.items())[:20]:
                put(f"{prefix}.{str(k)[:40]}", vv, depth + 1)
        elif isinstance(v, list):
            out[prefix] = [x[:MAX_STR] if isinstance(x, str) else x for x in v[:10] if isinstance(x, (str, int, float, bool))]

    for k, v in list(data.items())[:40]:
        put(str(k)[:40], v, 0)
    return out


class _Build:
    """Accumulates entities and relations while keeping their normalisation in one place."""

    def __init__(self) -> None:
        self.entities: dict[tuple[str, str], None] = {}
        self.derived: dict[tuple[str, str], None] = {}
        self.relations: list[RelationSeed] = []
        self.system = ""  # issuing source system; scopes session ids

    def ent(self, etype: str, value: Optional[str], *, derived: bool = False) -> Optional[tuple[str, str]]:
        if not value:
            return None
        v = canonical_entity_value(etype, value)
        if not v or v.lower() in PLACEHOLDER_VALUES or (etype in ("domain", "file_hash", "email", "url") and not is_informative_value(etype, v)):
            return None
        key = (etype, v)
        self.entities[key] = None
        if derived:
            self.derived[key] = None
        return key

    def rel(self, a: Optional[tuple[str, str]], pred: Predicate, b: Optional[tuple[str, str]]) -> None:
        if a and b and a != b and len(self.relations) < 100:
            self.relations.append(RelationSeed(subject=a, predicate=pred, obj=b))

    def url(self, raw: str) -> Optional[tuple[str, str]]:
        u = raw.strip()
        if len(u) > 1000 or "://" not in u:
            return None
        try:
            parts = urlsplit(u)
        except ValueError:
            return None
        host = (parts.hostname or "").lower()
        if not host or parts.scheme.lower() not in ("http", "https", "ftp"):
            return None
        url_key = self.ent("url", f"{parts.scheme.lower()}://{host}{parts.path}{'?' + parts.query if parts.query else ''}")
        try:
            ipaddress.ip_address(host)
            h = self.ent("ip", host, derived=True)
        except ValueError:
            h = self.ent("domain", host, derived=True)
        self.rel(h, Predicate.DERIVED_FROM, url_key)
        return url_key

    def file_scoped(self, host: Optional[str], path: Optional[str]) -> Optional[tuple[str, str]]:
        """Paths are only link entities when scoped to a host and when they carry a directory part."""
        if not host or not path or not re.search(r"[\\/]", path):
            return None
        return self.ent("file", f"{host}:{path.lower()}")


# ── adapter contract ─────────────────────────────────────────────────────────
class DomainAdapter:
    """Contract for an evidence-domain adapter (see module docstring). Subclasses implement ``_extract``."""

    adapter_name = "base"
    version = ADAPTER_VERSION
    family = EvidenceFamily.IDENTITY
    evidence_types: tuple[str, ...] = ()
    trust_class = TrustClass.RAW_OBSERVED
    counts_for_corroboration = True
    input_format = "aisop.evidence/1 envelope (JSON object)"

    def _extract(self, etype: str, data: dict[str, Any], b: _Build) -> tuple[str, str, Optional[str]]:
        raise NotImplementedError

    def parse(
        self, envelope: dict[str, Any], *, key: uuid.UUID, record_index: int, raw_sha256: str, integrity: str = "digest_computed"
    ) -> Observation:
        etype = envelope["evidence_type"]
        data = envelope.get("data")
        if not isinstance(data, dict):
            raise EvidenceFormatError("FIELD_INVALID:data")
        src = envelope.get("source")
        if not isinstance(src, dict):
            raise EvidenceFormatError("FIELD_MISSING:source")
        system = _s(src.get("system"), "source.system", required=True)
        category = _s(src.get("category"), "source.category") or self.family.value
        method = _s(src.get("collection_method"), "source.collection_method") or "unspecified"
        event_time, time_status = parse_time(envelope.get("event_time"))
        collected, _ = parse_time(envelope.get("collected_at"))
        b = _Build()
        b.system = (system or "").lower()
        upstream = _s(src.get("upstream_id"), "source.upstream_id")
        if upstream is not None and not _UPSTREAM_RE.match(upstream):
            raise EvidenceFormatError("FIELD_INVALID:source.upstream_id")
        title, outcome, host = self._extract(etype, data, b)
        corr = envelope.get("correlation")
        if corr is not None and self.family != EvidenceFamily.UNCLASSIFIED:
            if not isinstance(corr, dict):
                raise EvidenceFormatError("FIELD_INVALID:correlation")
            corr_key = _issuer_id(corr.get("issuer"), corr.get("id"), "correlation")
            if corr_key is None:
                raise EvidenceFormatError("FIELD_MISSING:correlation")
            b.ent("event_correlation", corr_key)  # issuer-scoped: the only way two sources state they describe the SAME underlying event
        return Observation(
            key=key,
            record_index=record_index,
            evidence_id=_s(envelope.get("evidence_id"), "evidence_id"),
            evidence_type=etype,
            family=self.family,
            source_system=(system or "").lower(),
            source_category=(category or "").lower(),
            collection_method=(method or "").lower(),
            event_time=event_time,
            time_status=time_status,
            collected_at=collected,
            raw_sha256=raw_sha256,
            integrity=integrity,
            title=title[:200],
            outcome=outcome,
            host=host,
            entities=tuple(sorted(b.entities)),
            derived_entities=tuple(sorted(b.derived)),
            relations=tuple(b.relations),
            attributes=_scalar_attrs(data),
            adapter=self.adapter_name,
            adapter_version=self.version,
            trust_class=self.trust_class,
            counts_for_corroboration=self.counts_for_corroboration,
            upstream_id=upstream.lower() if upstream else None,
        )


_OUTCOMES = {"success": "success", "succeeded": "success", "allow": "success", "allowed": "success", "approved": "success",
             "failure": "failure", "failed": "failure", "deny": "failure", "denied": "failure", "blocked": "failure",
             "no_response": "failure", "interrupted": "unknown"}


def _outcome(value: Any) -> str:
    return _OUTCOMES.get(str(value or "").strip().lower(), "unknown")


class IdentityAdapter(DomainAdapter):
    adapter_name = "identity"
    family = EvidenceFamily.IDENTITY
    evidence_types = ("identity.signin", "identity.mfa", "identity.privilege_change", "identity.account_change")

    def _extract(self, etype: str, d: dict[str, Any], b: _Build) -> tuple[str, str, Optional[str]]:
        if etype in ("identity.signin", "identity.mfa"):
            user = _s(d.get("user"), "user", required=True).lower()
            ip = _ip(d.get("ip"), "ip")
            session = _s(d.get("session_id"), "session_id")
            u = b.ent("user", user)
            b.rel(u, Predicate.AUTHENTICATED_FROM, b.ent("ip", ip))
            if session:
                # A session id is source-local unless the record names the issuing system (session_issuer); only then is it comparable.
                issuer = (_s(d.get("session_issuer"), "session_issuer") or b.system).lower()
                b.rel(u, Predicate.AUTHENTICATED_AS, b.ent("logon_session", f"{issuer}:{session}"))
            principal = _issuer_id(d.get("canonical_id_issuer"), d.get("canonical_id"), "canonical_id")
            if principal:
                b.ent("principal", principal)  # canonical identity from a named directory; local user names never equal a principal
            mfa = d.get("mfa") if isinstance(d.get("mfa"), dict) else {}
            result = _outcome(d.get("result") or mfa.get("result"))
            what = "MFA challenge" if etype == "identity.mfa" else "Sign-in"
            return f"{what} for {user}: {str(d.get('result') or mfa.get('result') or 'unknown')[:40]}", result, None
        if etype == "identity.privilege_change":
            actor = _s(d.get("actor"), "actor", required=True).lower()
            target = _s(d.get("target_user"), "target_user", required=True).lower()
            role = _s(d.get("role"), "role", required=True)
            action = (_s(d.get("action"), "action") or "add").lower()
            ip = _ip(d.get("ip"), "ip")
            a, t = b.ent("user", actor), b.ent("user", target)
            b.rel(a, Predicate.MODIFIED, t)
            b.ent("ip", ip)
            b.rel(a, Predicate.AUTHENTICATED_FROM, b.ent("ip", ip))
            return f"Privilege change: {actor} {action} role {role[:80]} for {target}", "success", None
        actor = _s(d.get("actor"), "actor", required=True).lower()
        target = _s(d.get("target_user"), "target_user", required=True).lower()
        change = _s(d.get("change"), "change", required=True)
        ip = _ip(d.get("ip"), "ip")
        b.rel(b.ent("user", actor), Predicate.MODIFIED, b.ent("user", target))
        b.ent("ip", ip)
        return f"Account change by {actor} on {target}: {change[:80]}", "success", None


class CloudAdapter(DomainAdapter):
    adapter_name = "cloud_audit"
    family = EvidenceFamily.CLOUD
    evidence_types = ("cloud.api_call", "cloud.config_change", "cloud.object_access")

    def _extract(self, etype: str, d: dict[str, Any], b: _Build) -> tuple[str, str, Optional[str]]:
        actor = _s(d.get("actor"), "actor", required=True).lower()
        action = _s(d.get("action"), "action", required=True)
        resource = _s(d.get("resource"), "resource")
        account = _s(d.get("account"), "account")
        ip = _ip(d.get("source_ip"), "source_ip")
        a = b.ent("user", actor)
        b.ent("cloud_account", account)
        r = b.ent("cloud_resource", resource)
        b.rel(a, Predicate.AUTHENTICATED_FROM, b.ent("ip", ip))
        low = action.lower()
        pred = Predicate.ACCESSED if etype == "cloud.object_access" else (
            Predicate.CREATED if low.startswith(("create", "run", "launch")) else Predicate.MODIFIED)
        b.rel(a, pred, r)
        session = _s(d.get("session_id"), "session_id")
        if session:
            issuer = (_s(d.get("session_issuer"), "session_issuer") or b.system).lower()
            b.rel(a, Predicate.AUTHENTICATED_AS, b.ent("logon_session", f"{issuer}:{session}"))
        principal = _issuer_id(d.get("canonical_id_issuer"), d.get("canonical_id"), "canonical_id")
        if principal:
            b.ent("principal", principal)
        role = _s(d.get("role"), "role")
        target = _s(d.get("target_principal"), "target_principal")
        if target:
            b.rel(a, Predicate.MODIFIED, b.ent("user", target.lower()))
        return f"Cloud {action[:80]} by {actor}" + (f" on {resource[:80]}" if resource else "") + (f" (role {role[:60]})" if role else ""), _outcome(d.get("outcome", "success")), None


class NetworkAdapter(DomainAdapter):
    adapter_name = "network"
    family = EvidenceFamily.NETWORK
    evidence_types = ("network.dns", "network.flow", "network.firewall", "network.ids")

    def _extract(self, etype: str, d: dict[str, Any], b: _Build) -> tuple[str, str, Optional[str]]:
        host = _host(d.get("host"))
        src = _ip(d.get("src_ip"), "src_ip", required=True)
        s = b.ent("ip", src)
        b.ent("host", host)  # the record names the observed host: a (weak) context entity, never an inferred relationship
        if etype == "network.dns":
            q = _s(d.get("query"), "query", required=True).lower().rstrip(".")
            dom = b.ent("domain", q)
            b.rel(s, Predicate.QUERIED, dom)
            for ans in _list(d.get("answers"), "answers"):
                try:
                    a_ip = str(ipaddress.ip_address(str(ans)))
                except ValueError:
                    continue
                b.rel(dom, Predicate.RESOLVED_TO, b.ent("ip", a_ip))
            return f"DNS query {q[:120]} from {src}", _outcome("success" if str(d.get("rcode", "NOERROR")).upper() == "NOERROR" else "failure"), host
        dst = _ip(d.get("dst_ip"), "dst_ip", required=True)
        dd = b.ent("ip", dst)
        if etype == "network.ids":
            sig = _s(d.get("signature"), "signature", required=True)
            b.rel(s, Predicate.CONNECTED_TO, dd)
            return f"IDS signature {sig[:120]}: {src} -> {dst}", "unknown", host
        action = (_s(d.get("action"), "action") or "allow").lower()
        if action in ("allow", "allowed", "permit", "accept"):
            b.rel(s, Predicate.CONNECTED_TO, dd)
        port = _s(d.get("dst_port"), "dst_port")
        return f"{'Flow' if etype == 'network.flow' else 'Firewall'} {action} {src} -> {dst}" + (f":{port}" if port else ""), _outcome(action), host


class EmailAdapter(DomainAdapter):
    adapter_name = "email"
    family = EvidenceFamily.EMAIL
    evidence_types = ("email.message",)

    def _extract(self, etype: str, d: dict[str, Any], b: _Build) -> tuple[str, str, Optional[str]]:
        mid = fold_mailbox(_s(d.get("message_id"), "message_id", required=True))
        sender = _s(d.get("from"), "from", required=True)
        m = b.ent("email_message", mid)
        s = b.ent("email", sender)
        for rcpt in _list(d.get("to"), "to"):
            r = b.ent("email", str(rcpt).strip())
            b.rel(s, Predicate.SENT_TO, r)
            if r:
                b.ent("user", str(rcpt).split("@")[0].strip().lower())
        for u in _list(d.get("urls"), "urls"):
            b.rel(m, Predicate.CONTAINS, b.url(str(u)))
        for att in _list(d.get("attachments"), "attachments"):
            if not isinstance(att, dict):
                raise EvidenceFormatError("FIELD_INVALID:attachments")
            h = _sha256(att.get("sha256"), "attachments.sha256")
            b.rel(m, Predicate.CONTAINS, b.ent("file_hash", h))
        ip = _ip(d.get("received_from_ip"), "received_from_ip")
        b.ent("ip", ip)
        subject = _s(d.get("subject"), "subject") or ""
        return f"E-mail from {sender[:100]}: {subject[:100]}", "unknown", None


class ForensicAdapter(DomainAdapter):
    adapter_name = "forensic"
    family = EvidenceFamily.FILE
    evidence_types = ("forensic.file", "forensic.registry", "forensic.memory_finding", "forensic.process_artifact")

    def _extract(self, etype: str, d: dict[str, Any], b: _Build) -> tuple[str, str, Optional[str]]:
        host = _host(d.get("host"), required=True)
        h = b.ent("host", host)
        if etype == "forensic.file":
            path = _s(d.get("path"), "path", required=True)
            f = b.file_scoped(host, path)
            digest = _sha256(d.get("sha256"), "sha256")
            b.rel(f, Predicate.OBSERVED_IN, h)
            b.rel(f, Predicate.HAS_HASH, b.ent("file_hash", digest))
            # Optional, source-stated: which e-mail this artefact came from, and what the record's event time MEANS (ADR-013, D6). Without
            # both, an artefact timestamped before an e-mail is just an earlier timestamp, not a causal-ordering violation.
            origin = _s(d.get("origin_message_id"), "origin_message_id")
            if origin:
                b.rel(b.ent("file_hash", digest), Predicate.DERIVED_FROM, b.ent("email_message", fold_mailbox(origin)))
            sem = _s(d.get("timestamp_semantics"), "timestamp_semantics")
            if sem is not None and sem.lower() not in _TIME_SEMANTICS:
                raise EvidenceFormatError("FIELD_INVALID:timestamp_semantics")
            return f"File artefact {path[:150]}", "unknown", host
        if etype == "forensic.registry":
            key = _s(d.get("key"), "key", required=True)
            r = b.ent("registry", f"{host}:{key.lower()}")
            b.rel(r, Predicate.OBSERVED_IN, h)
            proc = _s(d.get("process"), "process")
            b.rel(b.ent("process", proc.lower() if proc else None), Predicate.MODIFIED, r)
            return f"Registry artefact {key[:150]}", "unknown", host
        if etype == "forensic.memory_finding":
            tool = _s(d.get("tool"), "tool", required=True)
            ftype = _s(d.get("finding_type"), "finding_type", required=True)
            pname = _s(d.get("process_name"), "process_name")
            p = b.ent("process", pname.lower() if pname else None)
            b.rel(p, Predicate.EXECUTED_ON, h)
            b.rel(p, Predicate.HAS_HASH, b.ent("file_hash", _sha256(d.get("sha256"), "sha256")))
            b.rel(p, Predicate.CONNECTED_TO, b.ent("ip", _ip(d.get("remote_ip"), "remote_ip")))
            return f"Memory finding ({tool[:40]}): {ftype[:80]}" + (f" in {pname[:60]}" if pname else ""), "unknown", host
        image = _s(d.get("image"), "image", required=True)
        base = re.split(r"[\\/]", image)[-1].lower()
        p = b.ent("process", base)
        b.rel(p, Predicate.EXECUTED_ON, h)
        b.rel(p, Predicate.HAS_HASH, b.ent("file_hash", _sha256(d.get("sha256"), "sha256")))
        b.file_scoped(host, image)
        b.rel(p, Predicate.CONNECTED_TO, b.ent("ip", _ip(d.get("remote_ip"), "remote_ip")))
        b.ent("user", (_s(d.get("user"), "user") or "").lower() or None)
        return f"Process artefact {image[:150]} ({str(d.get('source_artifact', 'artefact'))[:40]})", "unknown", host

    def parse(self, envelope: dict[str, Any], **kw: Any) -> Observation:  # type: ignore[override]
        obs = super().parse(envelope, **kw)
        fam = {"forensic.file": EvidenceFamily.FILE, "forensic.registry": EvidenceFamily.REGISTRY,
               "forensic.memory_finding": EvidenceFamily.MEMORY, "forensic.process_artifact": EvidenceFamily.PROCESS_ARTEFACT}[obs.evidence_type]
        update: dict[str, Any] = {"family": fam}
        if obs.evidence_type == "forensic.memory_finding":
            update["trust_class"] = TrustClass.TOOL_ASSERTED
        return obs.model_copy(update=update)


class AnalystAdapter(DomainAdapter):
    adapter_name = "analyst"
    family = EvidenceFamily.ANALYST
    evidence_types = ("analyst.observation",)
    trust_class = TrustClass.ANALYST_OBSERVATION
    counts_for_corroboration = False

    def _extract(self, etype: str, d: dict[str, Any], b: _Build) -> tuple[str, str, Optional[str]]:
        analyst = _s(d.get("analyst"), "analyst", required=True)
        statement = _s(d.get("statement"), "statement", required=True, limit=MAX_STATEMENT)
        for item in _list(d.get("entities"), "entities"):
            if not isinstance(item, dict) or item.get("type") not in _ENTITY_TYPES_FOR_ANALYST:
                raise EvidenceFormatError("FIELD_INVALID:entities")
            val = _s(item.get("value"), "entities.value", required=True).lower()
            b.ent(item["type"], val)
        return f"Analyst observation by {analyst[:60]}: {statement[:120]}", "unknown", None


class UnclassifiedAdapter(DomainAdapter):
    """
    Structurally valid envelope whose ``evidence_type`` no adapter recognises. The record is PRESERVED (raw payload,
    digest, source identity, event time, bounded attribute view) but not interpreted: no entities, no relationships,
    no classification. It can appear on the timeline only as unclassified and can never corroborate anything.
    """

    adapter_name = "unclassified"
    family = EvidenceFamily.UNCLASSIFIED
    evidence_types = ()
    counts_for_corroboration = False

    def _extract(self, etype: str, data: dict[str, Any], b: _Build) -> tuple[str, str, Optional[str]]:
        return f"Unclassified evidence ({etype[:60]})", "unknown", None


_UNCLASSIFIED = UnclassifiedAdapter()
_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}(\.[a-z0-9_]{1,32}){0,3}$")
ADAPTERS: tuple[DomainAdapter, ...] = (IdentityAdapter(), CloudAdapter(), NetworkAdapter(), EmailAdapter(), ForensicAdapter(), AnalystAdapter())
_BY_TYPE: dict[str, DomainAdapter] = {t: a for a in ADAPTERS for t in a.evidence_types}


def is_domain_record(record: Any) -> bool:
    """True when the record declares the AISOP evidence envelope (it is then NEVER treated as an alert)."""
    return isinstance(record, dict) and record.get("schema") == ENVELOPE_SCHEMA


def parse_record(
    record: Any, *, key: uuid.UUID, record_index: int, raw_sha256: str, integrity: str = "digest_computed"
) -> Observation:
    """Validate one envelope and parse it with the adapter for its evidence type. Raises ``EvidenceFormatError``."""
    if not is_domain_record(record):
        raise EvidenceFormatError("SCHEMA_VERSION_UNSUPPORTED")
    etype = record.get("evidence_type")
    if not isinstance(etype, str) or not _TYPE_RE.match(etype):
        raise EvidenceFormatError("EVIDENCE_TYPE_INVALID")
    adapter = _BY_TYPE.get(etype) or _UNCLASSIFIED
    try:
        obs = adapter.parse(record, key=key, record_index=record_index, raw_sha256=raw_sha256, integrity=integrity)
    except EvidenceFormatError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise EvidenceFormatError("RECORD_MALFORMED") from None
    if obs.family != EvidenceFamily.UNCLASSIFIED and not obs.entities:
        obs = obs.model_copy(update={"classification": "partial"})
    elif obs.family == EvidenceFamily.UNCLASSIFIED:
        obs = obs.model_copy(update={"classification": "unclassified"})
    return obs


def import_file(path: str | Path, max_records: int = 1000) -> list[dict[str, Any]]:
    """
    Documented file-import path: a JSON array, a JSON object with an ``evidence`` array, or JSON Lines. Returns the
    envelope dictionaries unchanged (they are preserved byte-for-byte by the application as raw evidence).
    Bounded (size 5 MiB, ``max_records``); raises ``EvidenceFormatError`` with a fixed code.
    """
    p = Path(path)
    if not p.is_file() or p.stat().st_size > 5 * 1024 * 1024:
        raise EvidenceFormatError("FILE_UNREADABLE_OR_TOO_LARGE")
    text = p.read_text(encoding="utf-8")
    try:
        doc = json.loads(text)
        items = doc.get("evidence") if isinstance(doc, dict) else doc
    except json.JSONDecodeError:
        try:
            items = [json.loads(line) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError:
            raise EvidenceFormatError("FILE_NOT_JSON") from None
    if not isinstance(items, list) or len(items) > max_records:
        raise EvidenceFormatError("FILE_BAD_STRUCTURE_OR_TOO_MANY_RECORDS")
    return items


__all__ = [
    "ADAPTERS", "ADAPTER_VERSION", "DomainAdapter", "UnclassifiedAdapter", "EvidenceFormatError", "import_file", "is_domain_record", "parse_record", "parse_time",
]
