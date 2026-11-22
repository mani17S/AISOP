"""
AISOP SOC Investigation Query Service.

Implements deterministic retrieval, multi-dimensional filtering,
time-window boundary queries, IOC correlation lookups, and bounded pagination.
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.schemas.query import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    ExtractedEntityItem,
    NormalizedEventDetail,
    NormalizedEventSummary,
    PaginatedResponse,
    RawEvidenceDetailResponse,
    RawEvidenceEventSummary,
)
from app.modules.threatintel.exceptions import InvalidObservableError
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.modules.threatintel.models import (
    ObservableType,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatVerdict,
)
from app.modules.threatintel.validation import from_extracted_entity
from app.schemas.threatintel import InvestigationFindingState, ThreatIntelFindingItem

from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload

q_logger = logger.bind(component="query_service")


class InvestigationQueryService:
    """Service providing deterministic querying across evidence, events, and entities."""

    def __init__(self, threat_intel_engine: Any | None = None) -> None:
        self.threat_intel_engine = threat_intel_engine

    @staticmethod
    def _normalize_datetime(dt: datetime | None) -> datetime | None:
        """Ensure datetimes are timezone-aware in UTC to prevent offset comparison errors."""
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @classmethod
    def validate_time_range(
        cls,
        start_time: datetime | None,
        end_time: datetime | None,
    ) -> tuple[datetime | None, datetime | None]:
        """Validate and normalize start_time and end_time filters."""
        norm_start = cls._normalize_datetime(start_time)
        norm_end = cls._normalize_datetime(end_time)

        if norm_start is not None and norm_end is not None:
            if norm_start > norm_end:
                raise ValueError("start_time cannot be after end_time")

        return norm_start, norm_end

    async def query_events(
        self,
        session: Any,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        event_type: str | None = None,
        source_type: str | None = None,
        source_identifier: str | None = None,
        severity: str | None = None,
        outcome: str | None = None,
        entity_type: str | None = None,
        entity_value: str | None = None,
        page: int = 1,
        limit: int = DEFAULT_PAGE_SIZE,
    ) -> PaginatedResponse[NormalizedEventSummary]:
        """
        Deterministic, paginated query for normalized security events with multi-field filtering.
        """
        if page < 1:
            q_logger.warning("Event query rejected: invalid page", page=page)
            raise ValueError("page must be greater than or equal to 1")
        if limit < 1 or limit > MAX_PAGE_SIZE:
            q_logger.warning("Event query rejected: invalid limit", limit=limit)
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")

        try:
            norm_start, norm_end = self.validate_time_range(start_time, end_time)
        except ValueError as exc:
            q_logger.warning("Event query rejected: invalid time range", error=str(exc))
            raise

        q_logger.debug(
            "Executing events query",
            event_type=event_type,
            source_type=source_type,
            source_identifier=source_identifier,
            severity=severity,
            outcome=outcome,
            entity_type=entity_type,
            has_start_time=bool(norm_start),
            has_end_time=bool(norm_end),
            page=page,
            limit=limit,
        )

        conditions: list[Any] = []
        needs_raw_join = False

        if norm_start is not None:
            conditions.append(NormalizedEventModel.event_timestamp >= norm_start)
        if norm_end is not None:
            conditions.append(NormalizedEventModel.event_timestamp <= norm_end)
        if event_type is not None:

            conditions.append(NormalizedEventModel.event_type == event_type)
        if severity is not None:
            conditions.append(NormalizedEventModel.severity == severity)
        if outcome is not None:
            conditions.append(NormalizedEventModel.outcome == outcome)

        if source_type is not None:
            needs_raw_join = True
            conditions.append(RawEvidence.source_type == source_type)
        if source_identifier is not None:
            needs_raw_join = True
            conditions.append(RawEvidence.source_identifier == source_identifier)

        # Entity/IOC filtering via correlated subquery (avoids row multiplication)
        if entity_type is not None or entity_value is not None:
            subq = select(ExtractedEntityModel.event_id)
            if entity_type is not None:
                subq = subq.where(ExtractedEntityModel.entity_type == entity_type)
            if entity_value is not None:
                subq = subq.where(ExtractedEntityModel.entity_value == entity_value)
            conditions.append(NormalizedEventModel.id.in_(subq))

        # 1. Total count query
        count_stmt = select(func.count()).select_from(NormalizedEventModel)
        if needs_raw_join:
            count_stmt = count_stmt.join(
                RawEvidence, NormalizedEventModel.raw_evidence_id == RawEvidence.id
            )
        for cond in conditions:
            count_stmt = count_stmt.where(cond)

        count_res = await session.execute(count_stmt)
        total = count_res.scalar() or 0

        # Pagination bounds
        total_pages = math.ceil(total / limit) if total > 0 else 0
        has_next = (page * limit) < total
        has_previous = (page > 1) and ((page - 1) * limit < total)

        # If requested page is beyond available results, return empty items quickly
        offset = (page - 1) * limit
        if total == 0 or offset >= total:
            return PaginatedResponse[NormalizedEventSummary](
                items=[],
                total=total,
                page=page,
                limit=limit,
                total_pages=total_pages,
                has_next=has_next,
                has_previous=has_previous,
            )

        # 2. Data query with deterministic ordering
        data_stmt = select(NormalizedEventModel).options(
            joinedload(NormalizedEventModel.raw_evidence)
        )
        if needs_raw_join:
            data_stmt = data_stmt.join(
                RawEvidence, NormalizedEventModel.raw_evidence_id == RawEvidence.id
            )
        for cond in conditions:
            data_stmt = data_stmt.where(cond)

        data_stmt = (
            data_stmt.order_by(
                NormalizedEventModel.event_timestamp.desc(),
                NormalizedEventModel.id.desc(),
            )
            .limit(limit)
            .offset(offset)
        )

        res = await session.execute(data_stmt)
        events = res.scalars().unique().all()

        items = [
            NormalizedEventSummary(
                id=e.id,
                raw_evidence_id=e.raw_evidence_id,
                event_id=e.event_id,
                event_type=e.event_type,
                event_timestamp=e.event_timestamp,
                provider=e.provider,
                action=e.action,
                outcome=e.outcome,
                severity=e.severity,
                source_type=e.raw_evidence.source_type if e.raw_evidence else None,
                source_identifier=(
                    e.raw_evidence.source_identifier if e.raw_evidence else None
                ),
                raw_ingested_at=e.raw_evidence.ingested_at if e.raw_evidence else None,
                normalized_payload=e.normalized_payload,
            )
            for e in events
        ]

        return PaginatedResponse[NormalizedEventSummary](
            items=items,
            total=total,
            page=page,
            limit=limit,
            total_pages=total_pages,
            has_next=has_next,
            has_previous=has_previous,
        )

    async def get_event_by_id(
        self,
        session: Any,
        event_id: uuid.UUID,
        enrich_threat_intel: bool = False,
        engine: Any | None = None,
    ) -> NormalizedEventDetail | None:
        """
        Fetch a single normalized event by UUID, including extracted entities, provenance,
        and optional local threat intelligence enrichment.
        """
        q_logger.debug("Fetching normalized event by ID", event_id=str(event_id), enrich_threat_intel=enrich_threat_intel)
        stmt = (
            select(NormalizedEventModel)
            .options(
                joinedload(NormalizedEventModel.raw_evidence),
                joinedload(NormalizedEventModel.entities),
            )
            .where(NormalizedEventModel.id == event_id)
        )
        res = await session.execute(stmt)
        event = res.scalars().unique().first()
        if not event:
            q_logger.debug("Normalized event not found", event_id=str(event_id))
            return None

        entities = [
            ExtractedEntityItem(
                id=ent.id,
                event_id=ent.event_id,
                raw_evidence_id=ent.raw_evidence_id,
                entity_type=ent.entity_type,
                entity_value=ent.entity_value,
                role=ent.role,
                attributes=ent.attributes,
            )
            for ent in (event.entities or [])
        ]

        threat_intel_findings: list[ThreatIntelFindingItem] = []
        if enrich_threat_intel:
            threat_intel_findings = await self.enrich_entities_with_threat_intel(
                event.entities or [], engine=engine
            )

        return NormalizedEventDetail(
            id=event.id,
            raw_evidence_id=event.raw_evidence_id,
            event_id=event.event_id,
            event_type=event.event_type,
            event_timestamp=event.event_timestamp,
            provider=event.provider,
            action=event.action,
            outcome=event.outcome,
            severity=event.severity,
            source_type=event.raw_evidence.source_type if event.raw_evidence else None,
            source_identifier=(
                event.raw_evidence.source_identifier if event.raw_evidence else None
            ),
            normalized_payload=event.normalized_payload,
            raw_sha256_hash=(
                event.raw_evidence.sha256_hash if event.raw_evidence else None
            ),
            raw_ingested_at=(
                event.raw_evidence.ingested_at if event.raw_evidence else None
            ),
            entities=entities,
            threat_intel=threat_intel_findings,
        )

    async def enrich_entities_with_threat_intel(
        self,
        entities: list[Any],
        engine: Any | None = None,
    ) -> list[ThreatIntelFindingItem]:
        """
        Enrich extracted entities with deterministic threat intelligence findings.

        Guarantees:
        - Non-IOC entities (host, user, process) are safely ignored.
        - Invalid observables produce an INVALID_OBSERVABLE item without aborting the batch.
        - Provenance (entity_id, event_id, raw_evidence_id, source attribution) is fully preserved.
        - Distinct operational states are categorized: FRESH_MATCH, STALE_MATCH,
          VALID_UNMATCHED, ENGINE_UNAVAILABLE, INVALID_OBSERVABLE, LOOKUP_ERROR.
        - Per-observable failures do not abort remaining lookups.
        """
        ti_engine = engine or self.threat_intel_engine
        findings: list[ThreatIntelFindingItem] = []
        ioc_types = {"ip", "domain", "file_hash"}

        for ent in entities:
            ent_type = getattr(ent, "entity_type", None) or (ent.get("entity_type") if isinstance(ent, dict) else None)
            if not ent_type or ent_type not in ioc_types:
                continue

            ent_id = getattr(ent, "id", None) or (ent.get("id") if isinstance(ent, dict) else None)
            event_id = getattr(ent, "event_id", None) or (ent.get("event_id") if isinstance(ent, dict) else None)
            raw_ev_id = getattr(ent, "raw_evidence_id", None) or (ent.get("raw_evidence_id") if isinstance(ent, dict) else None)
            raw_val = str(getattr(ent, "entity_value", None) or (ent.get("entity_value") if isinstance(ent, dict) else ""))

            # 1. Parse and validate observable using from_extracted_entity bridge
            try:
                obs = from_extracted_entity(ent)
            except InvalidObservableError as val_err:
                findings.append(
                    ThreatIntelFindingItem(
                        entity_id=ent_id,
                        event_id=event_id,
                        raw_evidence_id=raw_ev_id,
                        observable_type=ObservableType.DOMAIN,
                        raw_observable=raw_val,
                        normalized_observable=raw_val,
                        status=ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE,
                        verdict=ThreatVerdict.UNKNOWN,
                        integration_state=InvestigationFindingState.INVALID_OBSERVABLE,
                        error_message=f"Observable validation rejected: {val_err.message}",
                    )
                )
                continue
            except Exception as exc:
                findings.append(
                    ThreatIntelFindingItem(
                        entity_id=ent_id,
                        event_id=event_id,
                        raw_evidence_id=raw_ev_id,
                        observable_type=ObservableType.DOMAIN,
                        raw_observable=raw_val,
                        normalized_observable=raw_val,
                        status=ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE,
                        verdict=ThreatVerdict.UNKNOWN,
                        integration_state=InvestigationFindingState.INVALID_OBSERVABLE,
                        error_message=f"Observable parsing failure: {exc}",
                    )
                )
                continue

            # 2. Check engine availability
            if ti_engine is None:
                findings.append(
                    ThreatIntelFindingItem(
                        entity_id=ent_id,
                        event_id=event_id,
                        raw_evidence_id=raw_ev_id,
                        observable_type=obs.type,
                        raw_observable=obs.raw_value,
                        normalized_observable=obs.normalized_value,
                        status=ThreatIntelLookupStatus.PROVIDER_FAILURE,
                        verdict=ThreatVerdict.UNKNOWN,
                        integration_state=InvestigationFindingState.ENGINE_UNAVAILABLE,
                        error_message="Threat intelligence engine is not initialized or unavailable",
                    )
                )
                continue

            # 3. Query threat intelligence engine
            try:
                res = await ti_engine.lookup(
                    ThreatIntelRequest(
                        observable=obs.normalized_value,
                        observable_type=obs.type,
                    )
                )
            except Exception as exc:
                findings.append(
                    ThreatIntelFindingItem(
                        entity_id=ent_id,
                        event_id=event_id,
                        raw_evidence_id=raw_ev_id,
                        observable_type=obs.type,
                        raw_observable=obs.raw_value,
                        normalized_observable=obs.normalized_value,
                        status=ThreatIntelLookupStatus.PROVIDER_FAILURE,
                        verdict=ThreatVerdict.UNKNOWN,
                        integration_state=InvestigationFindingState.LOOKUP_ERROR,
                        error_message=f"Engine execution error: {exc}",
                    )
                )
                continue

            # 3. Categorize operational integration state
            raw_data = res.raw_data or {}
            is_stale = bool(raw_data.get("is_stale", False) or "stale_feed" in res.tags)
            stale_feeds = raw_data.get("stale_feeds", [])
            sources = raw_data.get("sources", [])

            if res.status == ThreatIntelLookupStatus.SUCCESS:
                state = (
                    InvestigationFindingState.STALE_MATCH
                    if is_stale
                    else InvestigationFindingState.FRESH_MATCH
                )
            elif res.status == ThreatIntelLookupStatus.NOT_FOUND:
                state = InvestigationFindingState.VALID_UNMATCHED
            elif res.status == ThreatIntelLookupStatus.PROVIDER_FAILURE:
                state = InvestigationFindingState.ENGINE_UNAVAILABLE
            elif res.status == ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE:
                state = InvestigationFindingState.INVALID_OBSERVABLE
            else:
                state = InvestigationFindingState.LOOKUP_ERROR

            findings.append(
                ThreatIntelFindingItem(
                    entity_id=ent_id,
                    event_id=event_id,
                    raw_evidence_id=raw_ev_id,
                    observable_type=obs.type,
                    raw_observable=obs.raw_value,
                    normalized_observable=obs.normalized_value,
                    status=res.status,
                    verdict=res.verdict,
                    integration_state=state,
                    is_stale=is_stale,
                    stale_feeds=stale_feeds,
                    tags=res.tags,
                    sources=sources,
                    error_message=res.error_message,
                    timestamp=res.timestamp,
                )
            )

        return findings


    async def query_entities(
        self,
        session: Any,
        entity_type: str | None = None,
        entity_value: str | None = None,
        role: str | None = None,
        page: int = 1,
        limit: int = DEFAULT_PAGE_SIZE,
    ) -> PaginatedResponse[ExtractedEntityItem]:
        """
        Deterministic, paginated query for extracted entities / IOCs.
        """
        if page < 1:
            q_logger.warning("Entity query rejected: invalid page", page=page)
            raise ValueError("page must be greater than or equal to 1")
        if limit < 1 or limit > MAX_PAGE_SIZE:
            q_logger.warning("Entity query rejected: invalid limit", limit=limit)
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")

        q_logger.debug(
            "Executing entities query",
            entity_type=entity_type,
            role=role,
            page=page,
            limit=limit,
        )

        conditions: list[Any] = []
        if entity_type is not None:
            conditions.append(ExtractedEntityModel.entity_type == entity_type)
        if entity_value is not None:

            conditions.append(ExtractedEntityModel.entity_value == entity_value)
        if role is not None:
            conditions.append(ExtractedEntityModel.role == role)

        count_stmt = select(func.count()).select_from(ExtractedEntityModel)
        for cond in conditions:
            count_stmt = count_stmt.where(cond)

        count_res = await session.execute(count_stmt)
        total = count_res.scalar() or 0

        total_pages = math.ceil(total / limit) if total > 0 else 0
        has_next = (page * limit) < total
        has_previous = (page > 1) and ((page - 1) * limit < total)

        offset = (page - 1) * limit
        if total == 0 or offset >= total:
            return PaginatedResponse[ExtractedEntityItem](
                items=[],
                total=total,
                page=page,
                limit=limit,
                total_pages=total_pages,
                has_next=has_next,
                has_previous=has_previous,
            )

        data_stmt = select(ExtractedEntityModel)
        for cond in conditions:
            data_stmt = data_stmt.where(cond)

        data_stmt = (
            data_stmt.order_by(
                ExtractedEntityModel.entity_type.asc(),
                ExtractedEntityModel.entity_value.asc(),
                ExtractedEntityModel.id.desc(),
            )
            .limit(limit)
            .offset(offset)
        )

        res = await session.execute(data_stmt)
        entities = res.scalars().all()

        items = [
            ExtractedEntityItem(
                id=ent.id,
                event_id=ent.event_id,
                raw_evidence_id=ent.raw_evidence_id,
                entity_type=ent.entity_type,
                entity_value=ent.entity_value,
                role=ent.role,
                attributes=ent.attributes,
            )
            for ent in entities
        ]

        return PaginatedResponse[ExtractedEntityItem](
            items=items,
            total=total,
            page=page,
            limit=limit,
            total_pages=total_pages,
            has_next=has_next,
            has_previous=has_previous,
        )

    def _build_raw_detail(self, raw: RawEvidence) -> RawEvidenceDetailResponse:
        """Construct a RawEvidenceDetailResponse from an ORM model."""
        norm_events = [
            RawEvidenceEventSummary(
                id=e.id,
                event_id=e.event_id,
                event_type=e.event_type,
                event_timestamp=e.event_timestamp,
                severity=e.severity,
                action=e.action,
                outcome=e.outcome,
            )
            for e in (raw.normalized_events or [])
        ]
        return RawEvidenceDetailResponse(
            id=raw.id,
            source_type=raw.source_type,
            source_identifier=raw.source_identifier,
            sha256_hash=raw.sha256_hash,
            ingested_at=raw.ingested_at,
            raw_payload=raw.raw_payload,
            normalized_events=norm_events,
        )

    async def get_evidence_by_id(
        self,
        session: Any,
        evidence_id: uuid.UUID,
    ) -> RawEvidenceDetailResponse | None:
        """
        Fetch a raw evidence record and its child normalized events by UUID.
        """
        q_logger.debug("Fetching raw evidence by ID", evidence_id=str(evidence_id))
        stmt = (
            select(RawEvidence)
            .options(joinedload(RawEvidence.normalized_events))
            .where(RawEvidence.id == evidence_id)
        )
        res = await session.execute(stmt)
        raw = res.scalars().unique().first()
        if not raw:
            q_logger.debug("Raw evidence not found by ID", evidence_id=str(evidence_id))
            return None
        return self._build_raw_detail(raw)

    async def get_evidence_by_hash(
        self,
        session: Any,
        sha256_hash: str,
    ) -> RawEvidenceDetailResponse | None:
        """
        Fetch a raw evidence record and its child normalized events by cryptographic SHA-256 hash.
        """
        q_logger.debug("Fetching raw evidence by hash", sha256_hash=sha256_hash)
        stmt = (
            select(RawEvidence)
            .options(joinedload(RawEvidence.normalized_events))
            .where(RawEvidence.sha256_hash == sha256_hash)
        )
        res = await session.execute(stmt)
        raw = res.scalars().unique().first()
        if not raw:
            q_logger.debug("Raw evidence not found by hash", sha256_hash=sha256_hash)
            return None
        return self._build_raw_detail(raw)
