"""
AISOP Alert Ingestion Service.

Orchestrates the vendor-neutral alert ingestion workflow:
1. Validates and hashes raw alert payloads (SHA-256).
2. Performs batched/chunked database existence lookup for all unique hashes.
3. Classifies alerts into existing duplicates vs new unique alerts in memory.
4. Normalizes new vendor alerts into CanonicalAlerts via registered adapters.
5. Projects CanonicalAlerts into CanonicalEvents and extracts graph entities.
6. Atomically persists RawEvidence, NormalizedEvents, and ExtractedEntities.

Persistence has two paths with identical results. The fast path (default) runs the pure per-record work for a chunk of alerts
without touching the database, then stores the whole chunk under ONE savepoint with three flushes. If that chunk savepoint fails
for any reason, the chunk is rolled back and every alert of that chunk is re-processed one by one through the per-alert path,
which is also the reference path (one savepoint per alert, its own race recovery and error recording).
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.core.errors import safe_exception_text
from app.core.logging import redact_sensitive_data
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.alerts.adapter_protocol import AlertAdapterRegistry, get_default_registry
from app.modules.evidence.entity_extractor import extract_entities
from app.modules.evidence.hasher import compute_sha256
from app.schemas.alert import CanonicalAlert
from app.schemas.alert_ingest import (
    AlertIngestError,
    AlertIngestRequest,
    AlertIngestResponse,
)
from loguru import logger
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

DEFAULT_CHUNK_SIZE: int = 1000


def _safe_sample(data: Any, max_len: int = 100) -> str:
    """Safely produce a truncated, sanitized string representation of a raw payload without raising exceptions."""
    try:
        sanitized = redact_sensitive_data(data)
        if isinstance(sanitized, (dict, list)):
            return json.dumps(sanitized, default=str)[:max_len]
        return str(sanitized)[:max_len]
    except Exception:
        return "<unserializable payload>"


@dataclass
class _BatchState:
    """Mutable per-batch accounting shared by the per-alert path and the chunked fast path."""

    hashes: list[str]
    existing_map: dict[str, uuid.UUID]
    errors: list[AlertIngestError]
    seen_in_batch: dict[str, uuid.UUID] = field(default_factory=dict)
    existing_evidence_ids: list[uuid.UUID] = field(default_factory=list)
    existing_evidence_seen: set[uuid.UUID] = field(default_factory=set)
    alert_ids: list[uuid.UUID] = field(default_factory=list)
    total_normalized: int = 0
    total_entities: int = 0
    total_skipped_duplicates: int = 0

    def note_existing(self, ev_id: uuid.UUID) -> None:
        """Record a referenced existing evidence id once, in first-seen order (set for the test, list for the response)."""
        if ev_id not in self.existing_evidence_seen:
            self.existing_evidence_seen.add(ev_id)
            self.existing_evidence_ids.append(ev_id)


@dataclass
class _Prepared:
    """A record that passed every pure step. Holds what the database phase needs; touches no database."""

    idx: int
    sha256_hash: str
    raw_alert: Any
    event_kwargs: dict[str, Any]
    entity_specs: list[tuple[str, str, str, Any]]
    raw_id: uuid.UUID | None = None
    event_id: uuid.UUID | None = None


def _event_timestamp(canonical_alert: CanonicalAlert) -> datetime:
    # A time with a zone is stored as the same instant in UTC, so the result does not depend on how the
    # database handles zones (SQLite drops the offset). A zone-less time is left exactly as supplied:
    # Stage 7B assumes and flags it, and this code does not decide a zone.
    return (
        canonical_alert.timestamp.astimezone(timezone.utc)
        if canonical_alert.timestamp.tzinfo is not None
        else canonical_alert.timestamp
    )


def _entity_specs(canonical_alert: CanonicalAlert, canonical_event: Any) -> list[tuple[str, str, str, Any]]:
    """Entities from the canonical event and the explicit alert entities, de-duplicated by (type, value), in the stored order."""
    seen_entities: set[tuple[str, str]] = set()
    specs: list[tuple[str, str, str, Any]] = []
    for ent in extract_entities(canonical_event):
        key = (ent.entity_type, ent.entity_value)
        if key not in seen_entities:
            seen_entities.add(key)
            specs.append((ent.entity_type, ent.entity_value, ent.role, ent.attributes))
    for alert_ent in canonical_alert.entities:
        key = (alert_ent.entity_type, alert_ent.entity_value)
        if key not in seen_entities:
            seen_entities.add(key)
            specs.append((alert_ent.entity_type, alert_ent.entity_value, alert_ent.role, alert_ent.attributes))
    return specs


class AlertIngestionService:
    """Service handling multi-source vendor-neutral alert ingestion and normalization."""

    # Alerts per database phase on the fast path: 1 savepoint + 3 flushes + 1 release per chunk instead of 5 statements per alert.
    # Measured: smaller chunks bound the synchronous ORM flush work per event-loop turn (worst stall 74-89 ms at 50, 11-27 ms at 20).
    FAST_CHUNK_SIZE: int = 20

    def __init__(
        self,
        registry: AlertAdapterRegistry | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        chunked: bool = True,
    ) -> None:
        if registry is None:
            registry = get_default_registry()
        self.registry = registry
        self.chunk_size = chunk_size
        self.chunked = chunked

    async def ingest_batch(
        self,
        session: Any,
        request: AlertIngestRequest,
    ) -> AlertIngestResponse:
        """
        Process and atomically persist a batch of raw vendor alerts.
        Enforces idempotent deduplication with batched existence lookup.
        """
        batch_id = uuid.uuid4()
        start_time = time.perf_counter()
        b_logger = logger.bind(
            component="alert_ingestion_service",
            batch_id=str(batch_id),
            source_type=request.source_type,
            source_identifier=request.source_identifier,
        )
        b_logger.info(
            "Received alert ingestion batch",
            total_alerts=len(request.alerts),
        )

        errors: list[AlertIngestError] = []

        if not request.alerts:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            b_logger.info(
                "Alert ingestion batch completed (empty batch)",
                total_received=0,
                duration_ms=duration_ms,
            )
            return AlertIngestResponse(
                batch_id=batch_id,
                source_type=request.source_type,
                total_received=0,
                total_normalized=0,
                total_entities_extracted=0,
                total_skipped_duplicates=0,
                existing_evidence_ids=[],
                alert_ids=[],
                errors=[],
            )

        # 1. Resolve adapter for batch
        adapter = self.registry.get(request.source_type)

        # 2. Hash incoming alert payloads and record indices
        hashes: list[str] = []
        hash_to_indices: dict[str, list[int]] = {}
        for idx, alert in enumerate(request.alerts):
            try:
                h = compute_sha256(alert)
                hashes.append(h)
                hash_to_indices.setdefault(h, []).append(idx)
            except Exception as exc:
                errors.append(
                    AlertIngestError(
                        alert_index=idx,
                        error=f"Failed to hash alert: {exc}",
                        raw_sample=_safe_sample(alert),
                    )
                )

        unique_hashes = list(hash_to_indices.keys())

        # 3. Batched existence query in database
        existing_map: dict[str, uuid.UUID] = {}
        for i in range(0, len(unique_hashes), self.chunk_size):
            chunk = unique_hashes[i : i + self.chunk_size]
            stmt = select(RawEvidence.sha256_hash, RawEvidence.id).where(
                RawEvidence.sha256_hash.in_(chunk)
            )
            result = await session.execute(stmt)
            for row in result:
                existing_map[row[0]] = row[1]

        # 4. Classify and process items
        st = _BatchState(hashes=hashes, existing_map=existing_map, errors=errors)
        total = len(request.alerts)
        if self.chunked:
            for start in range(0, total, self.FAST_CHUNK_SIZE):
                await self._ingest_chunk(session, request, adapter, st, start, min(start + self.FAST_CHUNK_SIZE, total), b_logger)
        else:
            for idx in range(total):
                await self._ingest_one_per_alert(session, request, adapter, st, idx)

        await session.commit()
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        b_logger.info(
            "Alert ingestion batch completed",
            total_received=len(request.alerts),
            total_normalized=st.total_normalized,
            total_entities_extracted=st.total_entities,
            total_skipped_duplicates=st.total_skipped_duplicates,
            total_errors=len(st.errors),
            duration_ms=duration_ms,
        )

        return AlertIngestResponse(
            batch_id=batch_id,
            source_type=request.source_type,
            total_received=len(request.alerts),
            total_normalized=st.total_normalized,
            total_entities_extracted=st.total_entities,
            total_skipped_duplicates=st.total_skipped_duplicates,
            existing_evidence_ids=st.existing_evidence_ids,
            alert_ids=st.alert_ids,
            errors=st.errors,
        )

    def _select_adapter(
        self,
        request: AlertIngestRequest,
        adapter: Any,
        idx: int,
        raw_alert: Any,
    ) -> tuple[Any, AlertIngestError | None]:
        """Pick the adapter for one record, or return the per-record error. Never raises (hostile record shapes)."""
        # Use the declared adapter only when it can actually parse this alert; otherwise detect one. There is no silent
        # fallback to generic_siem: provenance must name the adapter that really parsed the record (review finding D-4).
        # Adapters inspect attacker-controlled fields; a wrongly typed value must reject this one record, never the batch.
        try:
            if adapter is not None and adapter.can_adapt(raw_alert):
                active_adapter = adapter
            else:
                active_adapter = self.registry.find_matching_adapter(raw_alert)
        except Exception:  # noqa: BLE001 - hostile record shape; reported per alert with a fixed message
            return None, AlertIngestError(
                alert_index=idx,
                error="The alert has an unexpected structure and could not be matched to an adapter.",
                raw_sample=_safe_sample(raw_alert),
            )

        if active_adapter is None:
            return None, AlertIngestError(
                alert_index=idx,
                error=f"No suitable alert adapter found for source_type='{request.source_type}'",
                raw_sample=_safe_sample(raw_alert),
            )
        return active_adapter, None

    # --- Per-alert path (reference and fallback): one savepoint per alert ---

    async def _ingest_one_per_alert(
        self,
        session: Any,
        request: AlertIngestRequest,
        adapter: Any,
        st: _BatchState,
        idx: int,
    ) -> None:
        if idx >= len(st.hashes):
            return
        raw_alert = request.alerts[idx]
        h = st.hashes[idx]

        # Case A: Already in DB
        if h in st.existing_map:
            st.total_skipped_duplicates += 1
            st.note_existing(st.existing_map[h])
            return

        # Case B: Intra-batch duplicate
        if h in st.seen_in_batch:
            st.total_skipped_duplicates += 1
            st.note_existing(st.seen_in_batch[h])
            return

        # Case C: New unique alert to normalize and persist
        active_adapter, select_error = self._select_adapter(request, adapter, idx, raw_alert)
        if select_error is not None:
            st.errors.append(select_error)
            return

        # Run normalization under a savepoint
        try:
            async with session.begin_nested():
                canonical_alert: CanonicalAlert = active_adapter.adapt(raw_alert, raw_ref=h)
                canonical_event = canonical_alert.to_canonical_event()

                # Persist RawEvidence
                db_raw = RawEvidence(
                    source_type=request.source_type,
                    source_identifier=request.source_identifier,
                    sha256_hash=h,
                    raw_payload=raw_alert,
                )
                session.add(db_raw)
                await session.flush()

                # Persist NormalizedEvent
                db_event = NormalizedEventModel(
                    raw_evidence_id=db_raw.id,
                    event_id=canonical_alert.source_alert_id,
                    event_type=canonical_event.event_type,
                    event_timestamp=_event_timestamp(canonical_alert),
                    provider=canonical_alert.provider,
                    action="alert_triggered",
                    outcome="success",
                    severity=canonical_event.severity,
                    normalized_payload=canonical_alert.model_dump(mode="json"),
                )
                session.add(db_event)
                await session.flush()

                # Extract entities from both canonical event and explicit alert entities
                db_entities = [
                    ExtractedEntityModel(
                        event_id=db_event.id,
                        raw_evidence_id=db_raw.id,
                        entity_type=entity_type,
                        entity_value=entity_value,
                        role=role,
                        attributes=attributes,
                    )
                    for entity_type, entity_value, role, attributes in _entity_specs(canonical_alert, canonical_event)
                ]

                if db_entities:
                    session.add_all(db_entities)
                    await session.flush()

                st.seen_in_batch[h] = db_raw.id
                st.total_normalized += 1
                st.total_entities += len(db_entities)
                st.alert_ids.append(db_event.id)

        except IntegrityError as ie:
            # Concurrency race: check if raw evidence was inserted concurrently
            stmt = select(RawEvidence.id).where(RawEvidence.sha256_hash == h)
            race_check = await session.execute(stmt)
            race_id = race_check.scalar_one_or_none()
            if race_id is not None:
                st.total_skipped_duplicates += 1
                st.note_existing(race_id)
            else:
                st.errors.append(
                    AlertIngestError(
                        alert_index=idx,
                        error=safe_exception_text(ie, "A database integrity error occurred while storing this alert."),
                        raw_sample=_safe_sample(raw_alert),
                    )
                )
        except Exception as exc:
            st.errors.append(
                AlertIngestError(
                    alert_index=idx,
                    error="Error processing alert: " + safe_exception_text(exc, "the alert could not be processed."),
                    raw_sample=_safe_sample(raw_alert),
                )
            )

    # --- Chunked fast path ---

    def _prepare(
        self,
        request: AlertIngestRequest,
        active_adapter: Any,
        idx: int,
        raw_alert: Any,
        h: str,
    ) -> _Prepared | AlertIngestError:
        """The pure steps of the per-alert path, in the same order and with the same error text. No database access."""
        try:
            canonical_alert: CanonicalAlert = active_adapter.adapt(raw_alert, raw_ref=h)
            canonical_event = canonical_alert.to_canonical_event()
            event_kwargs = dict(
                event_id=canonical_alert.source_alert_id,
                event_type=canonical_event.event_type,
                event_timestamp=_event_timestamp(canonical_alert),
                provider=canonical_alert.provider,
                action="alert_triggered",
                outcome="success",
                severity=canonical_event.severity,
                normalized_payload=canonical_alert.model_dump(mode="json"),
            )
            entity_specs = _entity_specs(canonical_alert, canonical_event)
        except Exception as exc:
            return AlertIngestError(
                alert_index=idx,
                error="Error processing alert: " + safe_exception_text(exc, "the alert could not be processed."),
                raw_sample=_safe_sample(raw_alert),
            )
        return _Prepared(idx=idx, sha256_hash=h, raw_alert=raw_alert, event_kwargs=event_kwargs, entity_specs=entity_specs)

    async def _ingest_chunk(
        self,
        session: Any,
        request: AlertIngestRequest,
        adapter: Any,
        st: _BatchState,
        start: int,
        end: int,
        b_logger: Any,
    ) -> None:
        # PHASE 1 (no database): classify in input order and run the pure steps. Outcomes are only planned here; nothing in
        # the shared state changes until the chunk is stored, so a failed chunk can be replayed through the per-alert path.
        plan: list[tuple[str, Any]] = []
        pending: dict[str, _Prepared] = {}
        for idx in range(start, end):
            if idx >= len(st.hashes):
                continue
            raw_alert = request.alerts[idx]
            h = st.hashes[idx]
            if h in st.existing_map:
                plan.append(("duplicate", st.existing_map[h]))
                continue
            if h in st.seen_in_batch:
                plan.append(("duplicate", st.seen_in_batch[h]))
                continue
            if h in pending:
                # Same hash as an earlier record of this chunk: one piece of evidence, never stored twice.
                plan.append(("duplicate_pending", pending[h]))
                continue
            active_adapter, select_error = self._select_adapter(request, adapter, idx, raw_alert)
            if select_error is not None:
                plan.append(("error", select_error))
                continue
            prepared = self._prepare(request, active_adapter, idx, raw_alert, h)
            if isinstance(prepared, AlertIngestError):
                plan.append(("error", prepared))
                continue
            pending[h] = prepared
            plan.append(("new", prepared))

        # Keep the event loop responsive: the pure phase above ran without an await.
        await asyncio.sleep(0)

        # PHASE 2 (database): one savepoint, three flushes, for the records that survived phase 1.
        new_records = list(pending.values())
        if new_records:
            try:
                async with session.begin_nested():
                    raws = [
                        RawEvidence(
                            source_type=request.source_type,
                            source_identifier=request.source_identifier,
                            sha256_hash=p.sha256_hash,
                            raw_payload=p.raw_alert,
                        )
                        for p in new_records
                    ]
                    session.add_all(raws)
                    await session.flush()

                    events = [
                        NormalizedEventModel(raw_evidence_id=raw.id, **p.event_kwargs)
                        for raw, p in zip(raws, new_records)
                    ]
                    session.add_all(events)
                    await session.flush()

                    entities = [
                        ExtractedEntityModel(
                            event_id=event.id,
                            raw_evidence_id=raw.id,
                            entity_type=entity_type,
                            entity_value=entity_value,
                            role=role,
                            attributes=attributes,
                        )
                        for raw, event, p in zip(raws, events, new_records)
                        for entity_type, entity_value, role, attributes in p.entity_specs
                    ]
                    if entities:
                        session.add_all(entities)
                        await session.flush()

                    for raw, event, p in zip(raws, events, new_records):
                        p.raw_id = raw.id
                        p.event_id = event.id
            except Exception as exc:  # noqa: BLE001 - ANY failure: the savepoint is already rolled back; replay one by one
                b_logger.warning(
                    "Chunk savepoint failed; re-processing the chunk through the per-alert path",
                    chunk_start=start,
                    chunk_end=end,
                    error_type=type(exc).__name__,
                )
                for idx in range(start, end):
                    await self._ingest_one_per_alert(session, request, adapter, st, idx)
                return

        # Merge the planned outcomes in input order: identical accounting to the per-alert path.
        for kind, item in plan:
            if kind == "duplicate":
                st.total_skipped_duplicates += 1
                st.note_existing(item)
            elif kind == "duplicate_pending":
                st.total_skipped_duplicates += 1
                st.note_existing(item.raw_id)
            elif kind == "error":
                st.errors.append(item)
            else:
                st.seen_in_batch[item.sha256_hash] = item.raw_id
                st.total_normalized += 1
                st.total_entities += len(item.entity_specs)
                st.alert_ids.append(item.event_id)
