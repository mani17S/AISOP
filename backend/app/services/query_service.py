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
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload


class InvestigationQueryService:
    """Service providing deterministic querying across evidence, events, and entities."""

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
            raise ValueError("page must be greater than or equal to 1")
        if limit < 1 or limit > MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")

        norm_start, norm_end = self.validate_time_range(start_time, end_time)

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
    ) -> NormalizedEventDetail | None:
        """
        Fetch a single normalized event by UUID, including extracted entities and provenance.
        """
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
        )

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
            raise ValueError("page must be greater than or equal to 1")
        if limit < 1 or limit > MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")

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
        stmt = (
            select(RawEvidence)
            .options(joinedload(RawEvidence.normalized_events))
            .where(RawEvidence.id == evidence_id)
        )
        res = await session.execute(stmt)
        raw = res.scalars().unique().first()
        if not raw:
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
        stmt = (
            select(RawEvidence)
            .options(joinedload(RawEvidence.normalized_events))
            .where(RawEvidence.sha256_hash == sha256_hash)
        )
        res = await session.execute(stmt)
        raw = res.scalars().unique().first()
        if not raw:
            return None
        return self._build_raw_detail(raw)
