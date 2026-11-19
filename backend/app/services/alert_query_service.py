"""
AISOP Alert Query Service.

Provides deterministic, paginated querying and detail retrieval across persisted security alerts.
Governed by ADR-007 (Vendor-Neutral Alert Ingestion) and Decision 1A (Sanitized Projections).
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.case import CaseEvidenceModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.schemas.alert import (
    AlertCategory,
    AlertObservable,
    AlertSeverity,
    AlertStatus,
    MitreAttackReference,
)
from app.schemas.alert_query import AlertDetailResponse, AlertSummaryItem
from app.schemas.entities import (
    DnsEntity,
    FileEntity,
    HostEntity,
    NetworkEntity,
    ProcessEntity,
    RegistryEntity,
    UserEntity,
)
from app.schemas.query import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, PaginatedResponse
from loguru import logger
from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

q_logger = logger.bind(component="alert_query_service")


class AlertQueryService:
    """Service providing query and detail retrieval for persisted security alerts."""

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

    async def list_alerts(
        self,
        session: AsyncSession,
        page: int = 1,
        limit: int = 20,
        source_type: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        provider: str | None = None,
        source_identifier: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        search: str | None = None,
    ) -> PaginatedResponse[AlertSummaryItem]:
        """
        Deterministic, paginated query for security alerts with multi-dimensional filtering.
        Strictly restricts results to alert records (action='alert_triggered').
        """
        if page < 1:
            q_logger.warning("Alert query rejected: invalid page", page=page)
            raise ValueError("page must be greater than or equal to 1")
        if limit < 1 or limit > MAX_PAGE_SIZE:
            q_logger.warning("Alert query rejected: invalid limit", limit=limit)
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")

        norm_start, norm_end = self.validate_time_range(start_time, end_time)

        conditions: list[Any] = [
            NormalizedEventModel.action == "alert_triggered",
        ]
        needs_raw_join = False

        if norm_start is not None:
            conditions.append(NormalizedEventModel.event_timestamp >= norm_start)
        if norm_end is not None:
            conditions.append(NormalizedEventModel.event_timestamp <= norm_end)
        if severity is not None and severity.strip():
            conditions.append(
                NormalizedEventModel.severity == severity.strip().lower()
            )
        if category is not None and category.strip():
            cat = category.strip().lower()
            conditions.append(NormalizedEventModel.event_type == f"alert.{cat}")
        if provider is not None and provider.strip():
            conditions.append(
                NormalizedEventModel.provider == provider.strip().lower()
            )

        if source_type is not None and source_type.strip():
            needs_raw_join = True
            conditions.append(
                RawEvidence.source_type == source_type.strip().lower()
            )
        if source_identifier is not None and source_identifier.strip():
            needs_raw_join = True
            conditions.append(
                RawEvidence.source_identifier == source_identifier.strip()
            )

        if search is not None and search.strip():
            s = f"%{search.strip()}%"
            search_cond = (
                NormalizedEventModel.event_id.ilike(s)
                | NormalizedEventModel.provider.ilike(s)
                | cast(NormalizedEventModel.normalized_payload, String).ilike(s)
            )
            conditions.append(search_cond)

        # 1. Total count query
        count_stmt = select(func.count()).select_from(NormalizedEventModel)
        if needs_raw_join:
            count_stmt = count_stmt.join(
                RawEvidence,
                NormalizedEventModel.raw_evidence_id == RawEvidence.id,
            )
        for cond in conditions:
            count_stmt = count_stmt.where(cond)

        count_res = await session.execute(count_stmt)
        total = count_res.scalar() or 0

        # Pagination metadata
        total_pages = math.ceil(total / limit) if total > 0 else 0
        has_next = (page * limit) < total
        has_previous = (page > 1) and ((page - 1) * limit < total)
        offset = (page - 1) * limit

        if total == 0 or offset >= total:
            return PaginatedResponse[AlertSummaryItem](
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
                RawEvidence,
                NormalizedEventModel.raw_evidence_id == RawEvidence.id,
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

        data_res = await session.execute(data_stmt)
        events = list(data_res.scalars().all())

        # 3. Batch case linkage resolution
        alert_ids = [e.id for e in events]
        cases_map: dict[uuid.UUID, list[uuid.UUID]] = {}
        if alert_ids:
            case_stmt = select(
                CaseEvidenceModel.evidence_id, CaseEvidenceModel.case_id
            ).where(CaseEvidenceModel.evidence_id.in_(alert_ids))
            case_res = await session.execute(case_stmt)
            for ev_id, cid in case_res:
                cases_map.setdefault(ev_id, []).append(cid)

        # 4. Project into AlertSummaryItem
        items: list[AlertSummaryItem] = []
        for e in events:
            p = e.normalized_payload or {}
            associated = cases_map.get(e.id, [])

            # Mitre attack parsing
            mitre_list: list[MitreAttackReference] = []
            for m in p.get("mitre_attack", []):
                if isinstance(m, dict):
                    try:
                        mitre_list.append(MitreAttackReference(**m))
                    except Exception:
                        pass
                elif isinstance(m, MitreAttackReference):
                    mitre_list.append(m)

            # Top observables parsing
            obs_list: list[AlertObservable] = []
            for obs in p.get("observables", []):
                if isinstance(obs, dict):
                    try:
                        obs_list.append(AlertObservable(**obs))
                    except Exception:
                        pass
                elif isinstance(obs, AlertObservable):
                    obs_list.append(obs)

            # Derive category
            cat = p.get("category")
            if not cat:
                if "." in e.event_type:
                    cat = e.event_type.split(".", 1)[1]
                else:
                    cat = "suspicious_activity"

            # Derive severity
            sev = p.get("severity") or e.severity or "medium"

            # Derive title
            title = (
                p.get("title")
                or p.get("alert_title")
                or f"Security Alert: {e.event_id}"
            )

            # Description (safe truncation at 500 chars for listing)
            desc = p.get("description")
            if desc and len(desc) > 500:
                desc = desc[:497] + "..."

            items.append(
                AlertSummaryItem(
                    id=e.id,
                    source_alert_id=e.event_id,
                    source_type=(
                        e.raw_evidence.source_type
                        if e.raw_evidence
                        else p.get("source_type", "unknown")
                    ),
                    provider=e.provider,
                    source_identifier=(
                        e.raw_evidence.source_identifier
                        if e.raw_evidence
                        else None
                    ),
                    title=title,
                    description=desc,
                    category=cat,  # type: ignore[arg-type]
                    severity=sev,  # type: ignore[arg-type]
                    vendor_severity=p.get("vendor_severity"),
                    status=p.get("status", "new"),  # type: ignore[arg-type]
                    timestamp=e.event_timestamp,
                    ingested_at=(
                        e.raw_evidence.ingested_at
                        if e.raw_evidence
                        else e.event_timestamp
                    ),
                    mitre_attack=mitre_list,
                    top_observables=obs_list[:5],  # Cap top 5 for listing
                    has_case=len(associated) > 0,
                    case_count=len(associated),
                )
            )

        return PaginatedResponse[AlertSummaryItem](
            items=items,
            total=total,
            page=page,
            limit=limit,
            total_pages=total_pages,
            has_next=has_next,
            has_previous=has_previous,
        )

    async def get_alert_detail(
        self,
        session: AsyncSession,
        alert_id: uuid.UUID,
    ) -> AlertDetailResponse | None:
        """
        Retrieve complete canonical alert detail for triage inspection.
        Returns None if record does not exist or is NOT an alert (action != 'alert_triggered').
        """
        stmt = (
            select(NormalizedEventModel)
            .options(joinedload(NormalizedEventModel.raw_evidence))
            .where(
                NormalizedEventModel.id == alert_id,
                NormalizedEventModel.action == "alert_triggered",
            )
        )
        res = await session.execute(stmt)
        event = res.scalars().first()
        if event is None:
            return None

        # Fetch associated case IDs
        case_stmt = select(CaseEvidenceModel.case_id).where(
            CaseEvidenceModel.evidence_id == alert_id
        )
        case_res = await session.execute(case_stmt)
        associated_case_ids = list(case_res.scalars().all())

        p = event.normalized_payload or {}
        raw_ref = (
            p.get("raw_ref")
            or (event.raw_evidence.sha256_hash if event.raw_evidence else None)
            or ""
        )

        # Mitre attack parsing
        mitre_list: list[MitreAttackReference] = []
        for m in p.get("mitre_attack", []):
            if isinstance(m, dict):
                try:
                    mitre_list.append(MitreAttackReference(**m))
                except Exception:
                    pass
            elif isinstance(m, MitreAttackReference):
                mitre_list.append(m)

        # Observables parsing
        obs_list: list[AlertObservable] = []
        for obs in p.get("observables", []):
            if isinstance(obs, dict):
                try:
                    obs_list.append(AlertObservable(**obs))
                except Exception:
                    pass
            elif isinstance(obs, AlertObservable):
                obs_list.append(obs)

        # Entities parsing
        entities = p.get("entities", [])

        # Parse contextual entities safely
        host = HostEntity(**p["host"]) if isinstance(p.get("host"), dict) else None
        user = UserEntity(**p["user"]) if isinstance(p.get("user"), dict) else None
        process = (
            ProcessEntity(**p["process"])
            if isinstance(p.get("process"), dict)
            else None
        )
        network = (
            NetworkEntity(**p["network"])
            if isinstance(p.get("network"), dict)
            else None
        )
        file = FileEntity(**p["file"]) if isinstance(p.get("file"), dict) else None
        dns = DnsEntity(**p["dns"]) if isinstance(p.get("dns"), dict) else None
        registry = (
            RegistryEntity(**p["registry"])
            if isinstance(p.get("registry"), dict)
            else None
        )

        cat = p.get("category")
        if not cat:
            if "." in event.event_type:
                cat = event.event_type.split(".", 1)[1]
            else:
                cat = "suspicious_activity"

        sev = p.get("severity") or event.severity or "medium"
        title = (
            p.get("title")
            or p.get("alert_title")
            or f"Security Alert: {event.event_id}"
        )

        return AlertDetailResponse(
            id=event.id,
            source_alert_id=event.event_id,
            source_type=(
                event.raw_evidence.source_type
                if event.raw_evidence
                else p.get("source_type", "unknown")
            ),
            provider=event.provider,
            source_identifier=(
                event.raw_evidence.source_identifier
                if event.raw_evidence
                else None
            ),
            title=title,
            description=p.get("description"),
            category=cat,  # type: ignore[arg-type]
            severity=sev,  # type: ignore[arg-type]
            vendor_severity=p.get("vendor_severity"),
            status=p.get("status", "new"),  # type: ignore[arg-type]
            timestamp=event.event_timestamp,
            ingested_at=(
                event.raw_evidence.ingested_at
                if event.raw_evidence
                else event.event_timestamp
            ),
            raw_ref=raw_ref,
            mitre_attack=mitre_list,
            entities=entities,
            observables=obs_list,
            host=host,
            user=user,
            process=process,
            network=network,
            file=file,
            dns=dns,
            registry=registry,
            custom_fields=p.get("custom_fields", {}),
            associated_case_ids=associated_case_ids,
            has_case=len(associated_case_ids) > 0,
        )

