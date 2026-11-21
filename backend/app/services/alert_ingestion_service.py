"""
AISOP Alert Ingestion Service.

Orchestrates the vendor-neutral alert ingestion workflow:
1. Validates and hashes raw alert payloads (SHA-256).
2. Performs batched/chunked database existence lookup for all unique hashes.
3. Classifies alerts into existing duplicates vs new unique alerts in memory.
4. Normalizes new vendor alerts into CanonicalAlerts via registered adapters.
5. Projects CanonicalAlerts into CanonicalEvents and extracts graph entities.
6. Atomically persists RawEvidence, NormalizedEvents, and ExtractedEntities.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

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


class AlertIngestionService:
    """Service handling multi-source vendor-neutral alert ingestion and normalization."""

    def __init__(
        self,
        registry: AlertAdapterRegistry | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        if registry is None:
            registry = get_default_registry()
        self.registry = registry
        self.chunk_size = chunk_size

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

        total_normalized = 0
        total_entities = 0
        total_skipped_duplicates = 0
        existing_evidence_ids: list[uuid.UUID] = []
        alert_ids: list[uuid.UUID] = []
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
        seen_in_batch: dict[str, uuid.UUID] = {}

        for idx, raw_alert in enumerate(request.alerts):
            if idx >= len(hashes):
                continue
            h = hashes[idx]

            # Case A: Already in DB
            if h in existing_map:
                total_skipped_duplicates += 1
                ev_id = existing_map[h]
                if ev_id not in existing_evidence_ids:
                    existing_evidence_ids.append(ev_id)
                continue

            # Case B: Intra-batch duplicate
            if h in seen_in_batch:
                total_skipped_duplicates += 1
                ev_id = seen_in_batch[h]
                if ev_id not in existing_evidence_ids:
                    existing_evidence_ids.append(ev_id)
                continue

            # Case C: New unique alert to normalize and persist
            # Use the declared adapter only when it can actually parse this alert; otherwise detect one. There is no silent
            # fallback to generic_siem: provenance must name the adapter that really parsed the record (review finding D-4).
            if adapter is not None and adapter.can_adapt(raw_alert):
                active_adapter = adapter
            else:
                active_adapter = self.registry.find_matching_adapter(raw_alert)

            if active_adapter is None:
                errors.append(
                    AlertIngestError(
                        alert_index=idx,
                        error=f"No suitable alert adapter found for source_type='{request.source_type}'",
                        raw_sample=_safe_sample(raw_alert),
                    )
                )
                continue

            # Run normalization under a savepoint
            try:
                async with session.begin_nested():
                    canonical_alert: CanonicalAlert = active_adapter.adapt(
                        raw_alert, raw_ref=h
                    )
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
                        event_timestamp=canonical_alert.timestamp,
                        provider=canonical_alert.provider,
                        action="alert_triggered",
                        outcome="success",
                        severity=canonical_event.severity,
                        normalized_payload=canonical_alert.model_dump(mode="json"),
                    )
                    session.add(db_event)
                    await session.flush()

                    # Extract entities from both canonical event and explicit alert entities
                    extracted_records = extract_entities(canonical_event)
                    seen_entities: set[tuple[str, str]] = set()
                    db_entities: list[ExtractedEntityModel] = []

                    for ent in extracted_records:
                        key = (ent.entity_type, ent.entity_value)
                        if key not in seen_entities:
                            seen_entities.add(key)
                            db_entities.append(
                                ExtractedEntityModel(
                                    event_id=db_event.id,
                                    raw_evidence_id=db_raw.id,
                                    entity_type=ent.entity_type,
                                    entity_value=ent.entity_value,
                                    role=ent.role,
                                    attributes=ent.attributes,
                                )
                            )

                    for alert_ent in canonical_alert.entities:
                        key = (alert_ent.entity_type, alert_ent.entity_value)
                        if key not in seen_entities:
                            seen_entities.add(key)
                            db_entities.append(
                                ExtractedEntityModel(
                                    event_id=db_event.id,
                                    raw_evidence_id=db_raw.id,
                                    entity_type=alert_ent.entity_type,
                                    entity_value=alert_ent.entity_value,
                                    role=alert_ent.role,
                                    attributes=alert_ent.attributes,
                                )
                            )

                    if db_entities:
                        session.add_all(db_entities)
                        await session.flush()

                    seen_in_batch[h] = db_raw.id
                    total_normalized += 1
                    total_entities += len(db_entities)
                    alert_ids.append(db_event.id)

            except IntegrityError as ie:
                # Concurrency race: check if raw evidence was inserted concurrently
                stmt = select(RawEvidence.id).where(RawEvidence.sha256_hash == h)
                race_check = await session.execute(stmt)
                race_id = race_check.scalar_one_or_none()
                if race_id is not None:
                    total_skipped_duplicates += 1
                    if race_id not in existing_evidence_ids:
                        existing_evidence_ids.append(race_id)
                else:
                    errors.append(
                        AlertIngestError(
                            alert_index=idx,
                            error=f"IntegrityError during alert ingestion: {ie}",
                            raw_sample=_safe_sample(raw_alert),
                        )
                    )
            except Exception as exc:
                errors.append(
                    AlertIngestError(
                        alert_index=idx,
                        error=f"Error processing alert: {exc}",
                        raw_sample=_safe_sample(raw_alert),
                    )
                )

        await session.commit()
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        b_logger.info(
            "Alert ingestion batch completed",
            total_received=len(request.alerts),
            total_normalized=total_normalized,
            total_entities_extracted=total_entities,
            total_skipped_duplicates=total_skipped_duplicates,
            total_errors=len(errors),
            duration_ms=duration_ms,
        )

        return AlertIngestResponse(
            batch_id=batch_id,
            source_type=request.source_type,
            total_received=len(request.alerts),
            total_normalized=total_normalized,
            total_entities_extracted=total_entities,
            total_skipped_duplicates=total_skipped_duplicates,
            existing_evidence_ids=existing_evidence_ids,
            alert_ids=alert_ids,
            errors=errors,
        )
