"""
AISOP Telemetry Ingestion Service.

Orchestrates the Evidence-First ingestion workflow:
1. Validates and hashes raw telemetry payloads (SHA-256).
2. Selects appropriate parser from ParserRegistry.
3. Normalizes telemetry into CanonicalEvents.
4. Extracts atomic entities (IP, host, user, process, file_hash, domain).
5. Atomically persists RawEvidence, NormalizedEvents, and ExtractedEntities.
"""

from __future__ import annotations

import json
from typing import Any
import uuid

from sqlalchemy import select

from app.modules.evidence.entity_extractor import extract_entities
from app.modules.evidence.hasher import compute_sha256
from app.modules.evidence.parser_protocol import ParserRegistry
from app.modules.evidence.sysmon_parser import SysmonParser
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.schemas.ingest import IngestError, IngestRequest, IngestResponse


class IngestionService:
    """Service handling evidence ingestion and normalization."""

    def __init__(self, registry: ParserRegistry | None = None) -> None:
        if registry is None:
            registry = ParserRegistry()
            registry.register(SysmonParser())
        self.registry = registry

    async def ingest_batch(
        self,
        session: Any,
        request: IngestRequest,
    ) -> IngestResponse:
        """
        Process and atomically persist a batch of raw telemetry events.
        """
        batch_id = uuid.uuid4()
        total_normalized = 0
        total_entities = 0
        errors: list[IngestError] = []

        parser = self.registry.get(request.source_type)

        for idx, raw_event in enumerate(request.events):
            try:
                # Compute cryptographic integrity hash
                sha256_hash = compute_sha256(raw_event)

                # Select parser
                event_parser = parser or self.registry.find_matching_parser(raw_event)
                if not event_parser:
                    errors.append(
                        IngestError(
                            event_index=idx,
                            error=f"No parser available for source_type '{request.source_type}'",
                            raw_sample=json.dumps(raw_event)[:100],
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
                            raw_sample=json.dumps(raw_event)[:100],
                        )
                    )
                    continue

                # Check if raw evidence already exists (deduplication)
                stmt = select(RawEvidence).where(RawEvidence.sha256_hash == sha256_hash)
                result = await session.execute(stmt)
                existing_raw = result.scalars().first()

                if existing_raw:
                    raw_record = existing_raw
                else:
                    raw_record = RawEvidence(
                        id=uuid.uuid4(),
                        source_type=request.source_type,
                        source_identifier=request.source_identifier,
                        sha256_hash=sha256_hash,
                        raw_payload=raw_event if isinstance(raw_event, dict) else {"raw": str(raw_event)},
                    )
                    session.add(raw_record)
                    await session.flush()

                # Process each normalized event
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
                    total_normalized += 1

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
                        total_entities += 1

            except Exception as exc:
                errors.append(
                    IngestError(
                        event_index=idx,
                        error=f"Ingestion failed: {str(exc)}",
                        raw_sample=str(raw_event)[:100],
                    )
                )

        await session.commit()

        return IngestResponse(
            batch_id=batch_id,
            source_type=request.source_type,
            total_received=len(request.events),
            total_normalized=total_normalized,
            total_entities_extracted=total_entities,
            errors=errors,
        )
