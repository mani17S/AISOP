"""
AISOP case-scoped source-agnostic evidence import (Stage 6, ADR-011).

Accepts ``aisop.evidence/1`` envelopes (identity, cloud audit, network, e-mail, forensic, analyst, or unrecognised but
structurally valid types) for ONE case and stores them in the EXISTING evidence tables, so every downstream feature
(case evidence listing, the multi-source investigation, audit trail) works unchanged and no migration is needed:

  record -> SHA-256 -> validate with the domain adapters
         -> malformed:            QUARANTINED (reported with a fixed code + hash prefix, NOT stored)
         -> already stored:       reused (idempotent); linked to this case if it is not linked yet
         -> valid / unrecognised: ``raw_evidence`` (payload unchanged) + ``normalized_events`` (derived summary)
                                  + ``case_evidence`` link
  one append-only ``case_audit_events`` row (action ``case_domain_evidence_imported``): counts and hashes, no payloads.

Design points:
* Raw payload and SHA-256 are preserved exactly as submitted; the observation is a re-computable derived view.
* ``normalized_events.event_timestamp`` is NOT NULL in the existing schema. For a record WITHOUT a usable event time
  the column holds the ingestion time purely so the row can be stored, and the row's ``normalized_payload`` states
  ``event_time: null`` and ``event_timestamp_is_ingestion_time: true``. The investigation never reads that column
  for domain evidence: it re-derives the time from the preserved raw payload (so it cannot be mistaken for event time).
* Case isolation: the case row is checked first (404 for unknown cases; the router already enforces case roles);
  a record already stored for another case is linked here only by this request, never exposed from the other case.
* Atomic: any storage failure rolls the whole request back and nothing (including the audit row) is kept.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from loguru import logger
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import AuthenticatedAnalyst
from app.models.case import CaseAuditEventModel, CaseEvidenceModel, CaseModel, CaseStatus
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.correlation.normalize import MAX_RECORD_BYTES, _exceeds_depth
from app.modules.evidence.hasher import canonicalize_payload, compute_sha256
from app.modules.evidence_domains.adapters import EvidenceFormatError, is_domain_record, parse_record
from app.modules.evidence_domains.model import ENVELOPE_SCHEMA, MODEL_VERSION
from app.services.multisource_investigation_service import CaseClosed, CaseNotFound, MultiSourceError, PersistenceFailed

svc_logger = logger.bind(component="domain_evidence_service")

IMPORT_ACTION = "case_domain_evidence_imported"
MAX_RECORDS_PER_REQUEST = 500


class ImportTooLarge(MultiSourceError):
    code = "evidence_too_large"


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None


class _LostRace(Exception):
    """Internal signal: a concurrent import won the unique-hash race; the attempt was rolled back."""


def _has_nul(obj: Any) -> bool:
    """Iterative scan for a NUL character in any string or key (stack-safe; depth is already bounded by the caller)."""
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            if "\x00" in cur:
                return True
        elif isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str) and "\x00" in k:
                    return True
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return False


class DomainEvidenceService:
    @staticmethod
    async def _create(session: AsyncSession, record: dict, digest: str, obs: Any, now: datetime) -> uuid.UUID:
        """Insert the raw record (unchanged) and its derived normalized event; returns the normalized event id."""
        raw = RawEvidence(source_type="aisop_evidence", source_identifier=obs.source_system[:255], sha256_hash=digest, raw_payload=record)
        session.add(raw)
        await session.flush()
        event = NormalizedEventModel(
            raw_evidence_id=raw.id,
            event_id=(obs.evidence_id or digest[:16])[:50],
            event_type=obs.evidence_type[:100],
            event_timestamp=obs.event_time or now,
            provider=obs.source_system[:100],
            action="observed",
            outcome=obs.outcome if obs.outcome in ("success", "failure") else "unknown",
            severity="informational",
            normalized_payload={
                "aisop_domain": True, "schema": ENVELOPE_SCHEMA, "model_version": MODEL_VERSION,
                "classification": obs.classification, "family": obs.family.value, "trust_class": obs.trust_class.value,
                "source_system": obs.source_system, "collection_method": obs.collection_method,
                "time_status": obs.time_status.value, "event_time": _iso(obs.event_time),
                "event_timestamp_is_ingestion_time": obs.event_time is None,
                "title": obs.title, "adapter": f"{obs.adapter}@{obs.adapter_version}",
                "entities": [[t, v] for t, v in obs.entities][:50],
                **({"upstream_id": obs.upstream_id} if obs.upstream_id else {}),
            },
        )
        session.add(event)
        await session.flush()
        return event.id

    async def import_records(
        self, *, session: AsyncSession, case_id: uuid.UUID, actor: AuthenticatedAnalyst, records: list[Any]
    ) -> dict[str, Any]:
        """Import is idempotent by SHA-256, so a lost insert race is handled by rolling back and retrying once (portable across
        databases: no savepoint, whose behaviour differs between SQLite and PostgreSQL)."""
        try:
            return await self._import_once(session=session, case_id=case_id, actor=actor, records=records)
        except _LostRace:
            try:
                return await self._import_once(session=session, case_id=case_id, actor=actor, records=records)
            except _LostRace:
                raise PersistenceFailed("The evidence could not be stored; nothing was imported.") from None

    async def _import_once(
        self, *, session: AsyncSession, case_id: uuid.UUID, actor: AuthenticatedAnalyst, records: list[Any]
    ) -> dict[str, Any]:
        if len(records) > MAX_RECORDS_PER_REQUEST:
            raise ImportTooLarge(f"At most {MAX_RECORDS_PER_REQUEST} records per request.")
        case = (await session.execute(select(CaseModel).where(CaseModel.id == case_id))).scalars().first()
        if case is None:
            raise CaseNotFound("Case not found or access denied.")
        if case.status in (CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value):
            raise CaseClosed("The case is closed or archived; evidence cannot be added.")

        now = datetime.now(timezone.utc)
        stored: list[dict[str, Any]] = []
        quarantined: list[dict[str, Any]] = []
        seen_in_request: dict[str, uuid.UUID] = {}
        linked_event_ids = set(
            (await session.execute(select(CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case_id))).scalars().all()
        )
        try:
            for index, record in enumerate(records):
                if not isinstance(record, dict) or _exceeds_depth(record):
                    quarantined.append({"record_index": index, "reason": "NOT_AN_OBJECT_OR_TOO_DEEP", "sha256_prefix": None})
                    continue
                try:
                    canonical = canonicalize_payload(record)
                    digest = compute_sha256(record)
                except (TypeError, ValueError, RecursionError):
                    quarantined.append({"record_index": index, "reason": "RECORD_NOT_SERIALIZABLE", "sha256_prefix": None})
                    continue
                if len(canonical.encode("utf-8")) > MAX_RECORD_BYTES:  # bytes, not characters: multi-byte text must not slip under the cap
                    quarantined.append({"record_index": index, "reason": "RECORD_TOO_LARGE", "sha256_prefix": digest[:12]})
                    continue
                if _has_nul(record):  # PostgreSQL JSON cannot store U+0000; refuse it up front instead of failing the whole batch
                    quarantined.append({"record_index": index, "reason": "CONTROL_CHARACTER", "sha256_prefix": digest[:12]})
                    continue
                if not is_domain_record(record):
                    quarantined.append({"record_index": index, "reason": "SCHEMA_VERSION_UNSUPPORTED", "sha256_prefix": digest[:12]})
                    continue
                try:
                    obs = parse_record(record, key=uuid.uuid5(uuid.NAMESPACE_URL, digest), record_index=index, raw_sha256=digest, integrity="digest_attested")
                except EvidenceFormatError as exc:
                    quarantined.append({"record_index": index, "reason": exc.code, "sha256_prefix": digest[:12]})
                    continue

                raw = (await session.execute(select(RawEvidence).where(RawEvidence.sha256_hash == digest))).scalars().first()
                duplicate = raw is not None or digest in seen_in_request
                if raw is None and digest not in seen_in_request:
                    event_id = await self._create(session, record, digest, obs, now)
                    seen_in_request[digest] = event_id
                else:
                    event_id = seen_in_request.get(digest)
                    if event_id is None:
                        event_id = (await session.execute(
                            select(NormalizedEventModel.id).where(NormalizedEventModel.raw_evidence_id == raw.id).limit(1)  # type: ignore[union-attr]
                        )).scalars().first()
                    if event_id is None:  # raw record stored by another path without a normalized event: not ours to interpret
                        quarantined.append({"record_index": index, "reason": "RAW_WITHOUT_NORMALIZED_EVENT", "sha256_prefix": digest[:12]})
                        continue
                if event_id not in linked_event_ids:
                    session.add(CaseEvidenceModel(id=uuid.uuid4(), case_id=case_id, evidence_id=event_id,
                                                  linked_by_analyst_id=actor.analyst_id, linked_at=now))
                    linked_event_ids.add(event_id)
                stored.append({"record_index": index, "evidence_id": str(event_id), "sha256": digest, "evidence_type": obs.evidence_type,
                               "classification": obs.classification, "time_status": obs.time_status.value, "duplicate": duplicate})

            summary = {
                "schema": "domain-import-v1", "received": len(records), "accepted": len(stored),
                "duplicates": sum(1 for s in stored if s["duplicate"]), "quarantined": len(quarantined),
                "unclassified": sum(1 for s in stored if s["classification"] == "unclassified"),
                "undated": sum(1 for s in stored if s["time_status"] not in ("valid", "naive_assumed_utc")),
                "sha256": [s["sha256"] for s in stored][:100],
                "quarantine": [{"record_index": q["record_index"], "reason": q["reason"]} for q in quarantined][:100],
            }
            session.add(CaseAuditEventModel(
                id=uuid.uuid4(), case_id=case_id, actor_analyst_id=actor.analyst_id, actor_username=actor.username,
                action=IMPORT_ACTION, context_sha256=None, details=summary, created_at=now,
            ))
            await session.commit()
        except MultiSourceError:
            await session.rollback()
            raise
        except IntegrityError:
            # A concurrent request stored the same record between our existence check and our insert (unique sha256_hash).
            # Nothing of this attempt is kept; the caller retries once, and the retry takes the ordinary duplicate path.
            await session.rollback()
            raise _LostRace from None
        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            svc_logger.error("Domain evidence import failed: nothing stored", error_type=type(exc).__name__)
            raise PersistenceFailed("The evidence could not be stored; nothing was imported.") from None
        return {**{k: v for k, v in summary.items() if k not in ("sha256", "quarantine")}, "evidence": stored, "quarantined_records": quarantined}


__all__ = ["DomainEvidenceService", "IMPORT_ACTION", "ImportTooLarge", "MAX_RECORDS_PER_REQUEST"]
