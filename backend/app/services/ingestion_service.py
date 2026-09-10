"""
AISOP Telemetry Ingestion Service.

Orchestrates the Evidence-First ingestion workflow:
1. Validates and hashes raw telemetry payloads (SHA-256).
2. Performs batched/chunked database existence lookup for all unique hashes.
3. Classifies events into existing duplicates vs new unique events in memory.
4. Normalizes new telemetry into CanonicalEvents.
5. Extracts atomic entities (IP, host, user, process, file_hash, domain).
6. Atomically persists RawEvidence, NormalizedEvents, and ExtractedEntities.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.evidence.entity_extractor import extract_entities
from app.modules.evidence.hasher import compute_sha256
from app.modules.evidence.parser_protocol import ParserRegistry
from app.modules.evidence.sysmon_parser import SysmonParser
from app.schemas.ingest import IngestError, IngestRequest, IngestResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

DEFAULT_CHUNK_SIZE: int = 1000


def _safe_sample(data: Any, max_len: int = 100) -> str:
    """Safely produce a truncated string representation of a raw payload without raising exceptions."""
    try:
        if isinstance(data, (dict, list)):
            return json.dumps(data, default=str)[:max_len]
        return str(data)[:max_len]
    except Exception:
        return "<unserializable payload>"


class IngestionService:
    """Service handling evidence ingestion and normalization."""

    def __init__(
        self,
        registry: ParserRegistry | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        if registry is None:
            registry = ParserRegistry()
            registry.register(SysmonParser())
        self.registry = registry
        self.chunk_size = chunk_size

    async def ingest_batch(
        self,
        session: Any,
        request: IngestRequest,
    ) -> IngestResponse:
        """
        Process and atomically persist a batch of raw telemetry events.
        Enforces Option A idempotent deduplication with batched existence lookup:
        - Hashes for all incoming events are computed.
        - Existing records are queried in chunks of size `self.chunk_size`.
        - Incoming events are classified in memory.
        - Intra-batch duplicates are deduplicated in memory upon insertion of the
          first occurrence.
        - Concurrency races and per-event failures are guarded via nested SAVEPOINT
          rollback and recovery, ensuring zero orphaned raw records.
        """
        batch_id = uuid.uuid4()
        total_normalized = 0
        total_entities = 0
        total_skipped_duplicates = 0
        existing_evidence_ids: list[uuid.UUID] = []
        errors: list[IngestError] = []

        if not request.events:
            return IngestResponse(
                batch_id=batch_id,
                source_type=request.source_type,
                total_received=0,
                total_normalized=0,
                total_entities_extracted=0,
                total_skipped_duplicates=0,
                existing_evidence_ids=[],
                errors=[],
            )

        parser = self.registry.get(request.source_type)

        # 1. Precompute cryptographic integrity hashes for all incoming events
        event_hashes: list[str | None] = []
        for raw_event in request.events:
            try:
                event_hashes.append(compute_sha256(raw_event))
            except Exception:
                event_hashes.append(None)

        # 2. Extract unique hashes preserving insertion order
        unique_hashes = list(dict.fromkeys(h for h in event_hashes if h is not None))

        # 3. Batched existence query in chunks
        existing_records: dict[str, RawEvidence] = {}
        if unique_hashes:
            for i in range(0, len(unique_hashes), self.chunk_size):
                chunk = unique_hashes[i : i + self.chunk_size]
                stmt = select(RawEvidence).where(RawEvidence.sha256_hash.in_(chunk))
                result = await session.execute(stmt)
                for record in result.scalars().all():
                    existing_records[record.sha256_hash] = record

        # 4. Process each event with full atomic savepoint isolation
        for idx, raw_event in enumerate(request.events):
            try:
                sha256_hash = event_hashes[idx]
                if sha256_hash is None:
                    # Retry hashing if precomputation failed to capture exact error
                    sha256_hash = compute_sha256(raw_event)

                # Check if raw evidence already exists (from batched DB query or intra-batch previous event)
                existing_raw = existing_records.get(sha256_hash)
                if existing_raw:
                    total_skipped_duplicates += 1
                    existing_evidence_ids.append(existing_raw.id)
                    continue

                # Select parser
                event_parser = parser or self.registry.find_matching_parser(raw_event)
                if not event_parser:
                    errors.append(
                        IngestError(
                            event_index=idx,
                            error=f"No parser available for source_type '{request.source_type}'",
                            raw_sample=_safe_sample(raw_event),
                        )
                    )
                    continue

                # Parse into canonical event(s)
                canonical_events = event_parser.parse(raw_event, raw_ref=sha256_hash)
                if not canonical_events:
                    errors.append(
                        IngestError(
                            event_index=idx,
                            error="Parser produced zero events for this payload",
                            raw_sample=_safe_sample(raw_event),
                        )
                    )
                    continue

                # Prepare raw evidence record
                raw_record = RawEvidence(
                    id=uuid.uuid4(),
                    source_type=request.source_type,
                    source_identifier=request.source_identifier,
                    sha256_hash=sha256_hash,
                    raw_payload=(
                        raw_event
                        if isinstance(raw_event, dict)
                        else {"raw": str(raw_event)}
                    ),
                )

                # Atomic per-event transaction isolation via SAVEPOINT
                is_duplicate_race = False
                event_norm_count = 0
                event_entity_count = 0

                try:
                    async with session.begin_nested():
                        # 1. Insert and flush raw evidence record
                        session.add(raw_record)
                        await session.flush()
                        existing_records[sha256_hash] = raw_record

                        # 2. Process each normalized event and extracted entities
                        for canonical in canonical_events:
                            norm_model = NormalizedEventModel(
                                id=canonical.id,
                                raw_evidence_id=raw_record.id,
                                event_id=canonical.event_id,
                                event_type=canonical.event_type,
                                event_timestamp=canonical.timestamp,
                                provider=canonical.provider,
                                action=canonical.action,
                                outcome=canonical.outcome,
                                severity=canonical.severity,
                                normalized_payload=canonical.model_dump(mode="json"),
                            )
                            session.add(norm_model)
                            event_norm_count += 1

                            # Extract and persist atomic entities
                            entities = extract_entities(canonical)
                            for entity in entities:
                                ent_model = ExtractedEntityModel(
                                    id=uuid.uuid4(),
                                    event_id=canonical.id,
                                    raw_evidence_id=raw_record.id,
                                    entity_type=entity.entity_type,
                                    entity_value=entity.entity_value,
                                    role=entity.role,
                                    attributes=entity.attributes,
                                )
                                session.add(ent_model)
                                event_entity_count += 1
                except IntegrityError as exc:
                    # Clean up optimistic in-memory registration on insert conflict
                    if (
                        sha256_hash in existing_records
                        and existing_records[sha256_hash] is raw_record
                    ):
                        del existing_records[sha256_hash]

                    err_str = str(exc).lower()
                    # Distinguish SHA-256 uniqueness conflict from unrelated database integrity errors
                    if "sha256_hash" in err_str or (
                        "unique" in err_str and "raw_evidence" in err_str
                    ):
                        re_stmt = select(RawEvidence).where(
                            RawEvidence.sha256_hash == sha256_hash
                        )
                        re_res = await session.execute(re_stmt)
                        winner_raw = re_res.scalars().first()
                        if winner_raw:
                            existing_records[sha256_hash] = winner_raw
                            total_skipped_duplicates += 1
                            existing_evidence_ids.append(winner_raw.id)
                            is_duplicate_race = True
                        else:
                            raise
                    else:
                        raise
                except Exception:
                    # Clean up in-memory registration if child processing threw an error
                    if (
                        sha256_hash in existing_records
                        and existing_records[sha256_hash] is raw_record
                    ):
                        del existing_records[sha256_hash]
                    raise

                if is_duplicate_race:
                    continue

                # Event completed successfully: apply counters
                total_normalized += event_norm_count
                total_entities += event_entity_count

            except Exception as exc:
                errors.append(
                    IngestError(
                        event_index=idx,
                        error=f"Ingestion failed: {str(exc)}",
                        raw_sample=_safe_sample(raw_event),
                    )
                )

        await session.commit()

        return IngestResponse(
            batch_id=batch_id,
            source_type=request.source_type,
            total_received=len(request.events),
            total_normalized=total_normalized,
            total_entities_extracted=total_entities,
            total_skipped_duplicates=total_skipped_duplicates,
            existing_evidence_ids=existing_evidence_ids,
            errors=errors,
        )
