"""
AISOP Case-Scoped Multi-Source Investigation Service (Stage 4, ADR-010).

Integrates the multi-source engine (``app.modules.correlation``) with the existing case, evidence and
audit architecture:

  case evidence (existing ``case_evidence`` -> ``normalized_events`` -> ``raw_evidence``)
    -> re-normalization of the PRESERVED raw payloads through the ADR-007 adapters
    -> correlation, timeline, deterministic ATT&CK mapping, sufficiency gate (ADR-008)
    -> optional gated LLM + claim verification
    -> analyst report
    -> one append-only ``case_audit_events`` row (action ``case_multisource_investigation``) whose
       ``details`` JSON holds the result (no new table, no migration).

Design points (all verified by tests in ``test_multisource_api.py``):
* Case isolation: evidence is read only through ``case_evidence`` for the given case id; callers are
  authorized by the router's existing ``require_case_role`` dependencies.
* Provenance: the stored SHA-256 of each raw record is used as the event digest and the persisted
  normalized-event id is the correlated event id, so every timeline row maps to a stored evidence row.
* Idempotency: a run is identified by a fingerprint of (evidence ids, stored raw hashes, options,
  engine versions). Repeating the request for the same evidence returns the stored result and writes
  nothing; ``force`` appends a new audit row. Evidence that changes while the engine runs aborts with
  a conflict (mirrors the SEC-D24 mutation checks of case synthesis).
* The database transaction is ended before any LLM call (no connection held during inference).
* The result carries no raw payloads or command lines; errors surfaced to callers are generic.
* The audit row is the persistence layer: PARTIAL by design (not queryable by section, one row per run,
  size-capped); see ADR-010 for the migration alternative that was deliberately not executed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.core.rbac import AuthenticatedAnalyst
from app.models.case import CaseAuditEventModel, CaseEvidenceModel, CaseModel, CaseStatus
from app.models.evidence import NormalizedEventModel
from app.modules.ai.guardrails.sufficiency_trace import RATIONALE_SCHEMA, build_rationale
from app.modules.correlation.mitre import MAPPING_VERSION
from app.modules.correlation.report import REASON_EXPLANATIONS
from app.modules.correlation.workflow import WORKFLOW_VERSION, IncidentAnalysis, WorkflowResult, run_workflow
from app.services.attack_reference_service import resolve_attack_reference
from app.modules.correlation.mitre import MAPPING_VERSION as _LEGACY_MAPPING_VERSION  # noqa: F401
from app.modules.evidence_domains.bridge import is_dated, is_machine
from app.modules.evidence_domains.domain_attack import DOMAIN_MAPPING_VERSION
from app.schemas.multisource import MultiSourceSection
from app.modules.correlation.management_view import management_view
from app.modules.correlation.report import non_weak_links
from app.schemas.sufficiency import SUFFICIENCY_RULE_VERSION

svc_logger = logger.bind(component="multisource_investigation_service")

MULTISOURCE_ACTION = "case_multisource_investigation"
MULTISOURCE_REVIEW_ACTION = "case_multisource_review"   # append-only analyst review of one stored investigation (human approval record)
MAX_REVIEW_NOTE_CHARS = 500
MULTISOURCE_EXPORT_ACTION = "case_multisource_export"
PAYLOAD_SCHEMA = "multisource-v1"
MAX_TIMELINE_ENTRIES = 200
MAX_LINKS = 100
MAX_REPORT_CHARS = 60_000
MAX_EVIDENCE_IDS = 100
MAX_OBSERVATIONS_LISTED = 500
#: Stage 5 bounds (measured with ``backend/scripts/benchmark_investigation.py``): correlation is quadratic in
#: evidence clusters; 1,000 events took about 2.5 s and 155 MB in the worst (single large incident) shape and the
#: cost grows roughly four-fold per doubling, so larger case evidence sets are refused rather than risking memory
#: exhaustion. The stored-result caps keep one audit row (and the activity feed that lists it) bounded.
MAX_EVIDENCE_PER_RUN = 1000
MAX_STORED_INCIDENTS = 25
MAX_REJECTED_LISTED = 200
MAX_CONTRADICTIONS_LISTED = 200

#: One investigation per case at a time (in-process). A second concurrent request waits, then finds the stored
#: result by fingerprint and reuses it instead of running and storing a duplicate. Does not coordinate separate
#: worker processes (a PostgreSQL advisory lock would; PROPOSED, not validated).
_CASE_LOCKS: dict[uuid.UUID, asyncio.Lock] = {}


class MultiSourceError(Exception):
    """Base class: ``code`` is mapped to an HTTP status by the router; messages are safe to return."""

    code = "error"


class CaseNotFound(MultiSourceError):
    code = "not_found"


class CaseClosed(MultiSourceError):
    code = "conflict_closed"


class EvidenceChanged(MultiSourceError):
    code = "conflict_evidence_changed"


class EvidenceTooLarge(MultiSourceError):
    code = "evidence_too_large"


class PersistenceFailed(MultiSourceError):
    code = "persistence_failed"


class NoInvestigation(MultiSourceError):
    code = "no_investigation"


class ExportNotApproved(MultiSourceError):
    """The export is released only for a result the case lead has approved and whose evidence has not changed since."""

    code = "export_requires_approval"


class InvestigationMismatch(MultiSourceError):
    """The reviewer saw a different investigation than the current stored one (or the evidence changed since the run)."""

    code = "conflict_investigation_changed"


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


class MultiSourceInvestigationService:
    """Stateless service; all state lives in the case evidence tables and the audit trail."""

    # ── evidence ────────────────────────────────────────────────────────────
    async def _load_rows(self, session: AsyncSession, case_id: uuid.UUID) -> list[NormalizedEventModel]:
        stmt = (
            select(NormalizedEventModel)
            .join(CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id)
            .options(joinedload(NormalizedEventModel.raw_evidence))
            .where(CaseEvidenceModel.case_id == case_id)
            .order_by(NormalizedEventModel.event_timestamp.asc(), NormalizedEventModel.id.asc())
        )
        return list((await session.execute(stmt)).unique().scalars().all())

    @staticmethod
    def _inputs(rows: list[NormalizedEventModel]) -> tuple[list[Any], list[Optional[str]], list[uuid.UUID]]:
        records: list[Any] = []
        digests: list[Optional[str]] = []
        keys: list[uuid.UUID] = []
        for ev in rows:
            raw = ev.raw_evidence
            payload = raw.raw_payload if raw is not None else None
            records.append(payload if isinstance(payload, dict) else None)
            digests.append(raw.sha256_hash if raw is not None else None)
            keys.append(ev.id)
        return records, digests, keys

    @staticmethod
    def fingerprint(rows: list[NormalizedEventModel], use_llm: bool) -> str:
        items = sorted((str(ev.id), (ev.raw_evidence.sha256_hash if ev.raw_evidence else "") or "") for ev in rows)
        blob = json.dumps(
            {"evidence": items, "use_llm": use_llm, "workflow": WORKFLOW_VERSION, "mapping": MAPPING_VERSION,
             "rules": SUFFICIENCY_RULE_VERSION},
            sort_keys=True,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    async def _latest(self, session: AsyncSession, case_id: uuid.UUID) -> Optional[CaseAuditEventModel]:
        stmt = (
            select(CaseAuditEventModel)
            .where(CaseAuditEventModel.case_id == case_id, CaseAuditEventModel.action == MULTISOURCE_ACTION)
            .order_by(CaseAuditEventModel.created_at.desc())
            .limit(1)
        )
        return (await session.execute(stmt)).scalars().first()

    # ── start ───────────────────────────────────────────────────────────────
    async def start(
        self,
        *,
        session: AsyncSession,
        case_id: uuid.UUID,
        actor: AuthenticatedAnalyst,
        use_llm: bool,
        force: bool,
        llm_provider: Any,
    ) -> tuple[bool, dict[str, Any]]:
        """Run (or reuse) the investigation. Returns (created, stored payload). Serialised per case in-process."""
        lock = _CASE_LOCKS.setdefault(case_id, asyncio.Lock())
        try:
            async with lock:
                return await self._start_locked(
                    session=session, case_id=case_id, actor=actor, use_llm=use_llm, force=force, llm_provider=llm_provider
                )
        finally:
            if not lock.locked() and not getattr(lock, "_waiters", None):
                _CASE_LOCKS.pop(case_id, None)

    async def _start_locked(
        self,
        *,
        session: AsyncSession,
        case_id: uuid.UUID,
        actor: AuthenticatedAnalyst,
        use_llm: bool,
        force: bool,
        llm_provider: Any,
    ) -> tuple[bool, dict[str, Any]]:
        case = (await session.execute(select(CaseModel).where(CaseModel.id == case_id))).scalars().first()
        if case is None:
            raise CaseNotFound("Case not found or access denied.")
        if case.status in (CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value):
            raise CaseClosed("The case is closed or archived; a new investigation cannot be started.")

        linked = (await session.execute(
            select(func.count()).select_from(CaseEvidenceModel).where(CaseEvidenceModel.case_id == case_id)
        )).scalar_one()
        if linked > MAX_EVIDENCE_PER_RUN:
            raise EvidenceTooLarge(f"The case has {linked} evidence items; the limit per investigation is {MAX_EVIDENCE_PER_RUN}.")

        rows = await self._load_rows(session, case_id)
        records, digests, keys = self._inputs(rows)
        fp = self.fingerprint(rows, use_llm)

        latest = await self._latest(session, case_id)
        if latest is not None and not force and (latest.details or {}).get("evidence_fingerprint") == fp:
            payload = dict(latest.details)
            payload["created_at"] = _iso(latest.created_at)
            payload["reused"] = True
            return False, payload

        await session.rollback()  # end the read transaction: no connection is held during inference

        # The optional local ATT&CK catalogue is only needed when a model is invoked; resolved lazily, loaded at most once.
        result = await run_workflow(records, None, llm_provider if use_llm else None, digests, keys,
                                    attack_reference=resolve_attack_reference() if use_llm else None)

        if self.fingerprint(await self._load_rows(session, case_id), use_llm) != fp:
            await session.rollback()
            raise EvidenceChanged("Case evidence changed while the investigation was running; the result was discarded.")

        payload = self.build_payload(result, fp, use_llm)
        now = datetime.now(timezone.utc)
        payload["created_at"] = _iso(now)
        payload["started_by"] = actor.username
        first_context = next((i["context_sha256"] for i in payload["incidents"]), None)
        audit = CaseAuditEventModel(
            id=uuid.uuid4(),
            case_id=case_id,
            actor_analyst_id=actor.analyst_id,
            actor_username=actor.username,
            action=MULTISOURCE_ACTION,
            context_sha256=first_context,
            details=payload,
            created_at=now,
        )
        session.add(audit)
        try:
            await session.commit()
        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            svc_logger.error("Multi-source audit write failed: result suppressed", error_type=type(exc).__name__)
            raise PersistenceFailed("Audit logging failed; the investigation result was not stored.") from None
        payload["reused"] = False
        return True, payload

    # ── retrieval ───────────────────────────────────────────────────────────
    async def get_section(
        self, *, session: AsyncSession, case_id: uuid.UUID, section: MultiSourceSection
    ) -> dict[str, Any]:
        latest = await self._latest(session, case_id)
        if latest is None:
            raise NoInvestigation("No multi-source investigation has been started for this case.")
        payload = dict(latest.details or {})
        payload["created_at"] = _iso(latest.created_at)
        current = self.fingerprint(await self._load_rows(session, case_id), bool(payload.get("use_llm")))
        stale = current != payload.get("evidence_fingerprint")
        view = self.section_view(payload, section, stale)
        if section in (MultiSourceSection.STATUS, MultiSourceSection.REPORT):
            view["review"] = await self._review_view(session, case_id, latest, stale)
        return view

    # ── analyst review (human approval record) ──────────────────────────────
    async def _review_view(self, session: AsyncSession, case_id: uuid.UUID, latest: CaseAuditEventModel, stale: bool) -> dict[str, Any]:
        """Review state of the CURRENT stored investigation: not_reviewed, approved, rejected, or stale (evidence changed since the run)."""
        rows = (await session.execute(
            select(CaseAuditEventModel)
            .where(CaseAuditEventModel.case_id == case_id, CaseAuditEventModel.action == MULTISOURCE_REVIEW_ACTION)
            .order_by(CaseAuditEventModel.created_at.desc())
            .limit(25)
        )).scalars().all()
        mine = next((r for r in rows if (r.details or {}).get("investigation_audit_id") == str(latest.id)), None)
        if mine is None:
            return {"state": "stale" if stale else "not_reviewed", "decision": None, "reviewed_by": None, "reviewed_at": None, "note": None}
        d = mine.details or {}
        return {"state": "stale" if stale else d.get("decision"), "decision": d.get("decision"), "reviewed_by": mine.actor_username,
                "reviewed_at": _iso(mine.created_at), "note": d.get("note")}

    async def review(
        self,
        *,
        session: AsyncSession,
        case_id: uuid.UUID,
        actor: AuthenticatedAnalyst,
        decision: str,
        evidence_fingerprint: str,
        note: Optional[str],
    ) -> dict[str, Any]:
        """Record the lead's decision on the latest stored investigation. Append-only; never edits the investigation itself."""
        case = (await session.execute(select(CaseModel).where(CaseModel.id == case_id))).scalars().first()
        if case is None:
            raise CaseNotFound("Case not found or access denied.")
        if case.status in (CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value):
            raise CaseClosed("The case is closed or archived; it can no longer be reviewed.")
        latest = await self._latest(session, case_id)
        if latest is None:
            raise NoInvestigation("No multi-source investigation has been started for this case.")
        stored_fp = (latest.details or {}).get("evidence_fingerprint")
        current_fp = self.fingerprint(await self._load_rows(session, case_id), bool((latest.details or {}).get("use_llm")))
        if evidence_fingerprint != stored_fp or current_fp != stored_fp:
            raise InvestigationMismatch("The investigation or its evidence changed; reload it and review the current result.")
        clean_note = None
        if note:
            clean_note = "".join(ch for ch in note if ch.isprintable() or ch in " \n")[:MAX_REVIEW_NOTE_CHARS].strip() or None
        now = datetime.now(timezone.utc)
        session.add(CaseAuditEventModel(
            id=uuid.uuid4(), case_id=case_id, actor_analyst_id=actor.analyst_id, actor_username=actor.username,
            action=MULTISOURCE_REVIEW_ACTION, context_sha256=latest.context_sha256,
            details={"decision": decision, "note": clean_note, "evidence_fingerprint": stored_fp, "investigation_audit_id": str(latest.id)},
            created_at=now,
        ))
        try:
            await session.commit()
        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            svc_logger.error("Multi-source review audit write failed", error_type=type(exc).__name__)
            raise PersistenceFailed("Audit logging failed; the review was not stored.") from None
        return await self._review_view(session, case_id, latest, False)

    async def export_report(self, *, session: AsyncSession, case_id: uuid.UUID, actor: AuthenticatedAnalyst) -> dict[str, Any]:
        """
        Released report bundle (markdown) for the latest stored investigation. Refused unless the case lead has APPROVED this exact result
        and the evidence is unchanged. Each release is an append-only audit row. The markdown is the stored deterministic report; the
        approval header only states who approved what, it adds no claim.
        """
        latest = await self._latest(session, case_id)
        if latest is None:
            raise NoInvestigation("No multi-source investigation has been started for this case.")
        payload = dict(latest.details or {})
        stored_fp = payload.get("evidence_fingerprint")
        stale = self.fingerprint(await self._load_rows(session, case_id), bool(payload.get("use_llm"))) != stored_fp
        review = await self._review_view(session, case_id, latest, stale)
        if review["state"] != "approved":
            raise ExportNotApproved(f"Export refused: review state is {review['state']}.")
        parts = [
            "# AISOP investigation report (approved)",
            f"Approved by {review['reviewed_by']} at {review['reviewed_at']}. Evidence fingerprint {stored_fp}.",
            "The approval records a human decision about this result. It does not make any claim in the report more certain.",
        ]
        if review.get("note"):
            parts.append("Reviewer note: " + str(review["note"]).replace("\n", " "))
        if payload.get("batch_report_markdown"):
            parts.append(str(payload["batch_report_markdown"])[:MAX_REPORT_CHARS])
        for inc in payload.get("incidents", []):
            parts.append(str(inc.get("report_markdown", ""))[:MAX_REPORT_CHARS])
        session.add(CaseAuditEventModel(
            id=uuid.uuid4(), case_id=case_id, actor_analyst_id=actor.analyst_id, actor_username=actor.username,
            action=MULTISOURCE_EXPORT_ACTION, context_sha256=latest.context_sha256,
            details={"evidence_fingerprint": stored_fp, "investigation_audit_id": str(latest.id), "approved_by": review["reviewed_by"]},
            created_at=datetime.now(timezone.utc),
        ))
        try:
            await session.commit()
        except Exception as exc:  # noqa: BLE001
            await session.rollback()
            svc_logger.error("Multi-source export audit write failed", error_type=type(exc).__name__)
            raise PersistenceFailed("Audit logging failed; the report was not released.") from None
        return {"filename": f"aisop-report-{str(case_id)[:8]}.md", "markdown": "\n\n".join(parts), "evidence_fingerprint": stored_fp, "review": review}

    @staticmethod
    def _observation_view(o: Any, placed: set[Any]) -> dict[str, Any]:
        return {
            "evidence_id": str(o.key), "record_index": o.record_index, "source_evidence_id": o.evidence_id,
            "evidence_type": o.evidence_type, "family": o.family.value, "classification": o.classification,
            "source_system": o.source_system, "source_category": o.source_category, "collection_method": o.collection_method,
            "adapter": f"{o.adapter}@{o.adapter_version}", "time_status": o.time_status.value, "event_time": _iso(o.event_time),
            "collected_at": _iso(o.collected_at), "raw_sha256": o.raw_sha256, "integrity": o.integrity,
            "trust_class": o.trust_class.value, "counts_for_corroboration": o.counts_for_corroboration, "outcome": o.outcome,
            "title": o.title, "on_timeline": o.key in placed, "entity_count": len(o.entities), "relationship_count": len(o.relations),
        }

    @staticmethod
    def _domain_payload(result: WorkflowResult) -> dict[str, Any]:
        placed = {e.event_key for e in result.normalization.events}
        views = [MultiSourceInvestigationService._observation_view(o, placed) for o in result.observations]
        classes: dict[str, int] = {}
        for o in result.observations:
            classes[o.classification] = classes.get(o.classification, 0) + 1
        return {
            "observations": views[:MAX_OBSERVATIONS_LISTED],
            "observation_counts": {"total": len(views), "listed": min(len(views), MAX_OBSERVATIONS_LISTED), "by_classification": classes,
                                   "undated": sum(1 for o in result.observations if is_machine(o) and not is_dated(o)),
                                   "analyst_statements": sum(1 for o in result.observations if not o.counts_for_corroboration and o.family.value == "analyst")},
            "batch_graph": result.batch_graph.to_view() if (result.batch_graph is not None and not result.incidents) else None,
            "domain_attack_rules": DOMAIN_MAPPING_VERSION,
        }

    @staticmethod
    def section_view(payload: dict[str, Any], section: MultiSourceSection, stale: bool) -> dict[str, Any]:
        inc = payload.get("incidents", [])
        head = {"status": payload.get("status"), "created_at": payload.get("created_at"), "stale_evidence": stale}
        if section == MultiSourceSection.GRAPH:
            return {**head, "batch_graph": payload.get("batch_graph"),
                    "incidents": [{"incident_id": i["incident_id"], "graph": i.get("graph"), "enrichments": i.get("enrichments", []),
                                   "analyst_statements": i.get("analyst_statements", [])} for i in inc]}
        if section == MultiSourceSection.EVIDENCE:
            return {**head, "observation_counts": payload.get("observation_counts"), "observations": payload.get("observations", []),
                    "rejected": payload.get("rejected")}
        if section == MultiSourceSection.STATUS:
            return {
                **head, "use_llm": payload.get("use_llm"), "workflow_version": payload.get("workflow_version"),
                "evidence_fingerprint": payload.get("evidence_fingerprint"), "counts": payload.get("counts"),
                "sources": payload.get("sources"), "ledger": payload.get("ledger"),
                "incidents": [{k: i[k] for k in ("incident_id", "severity", "event_count", "llm_status")}
                              | {"verdict": i["sufficiency"]["verdict"]} for i in inc],
                "batch_sufficiency": payload.get("batch_sufficiency"), "rejected": payload.get("rejected"),
                "truncation": payload.get("truncation"),
            }
        if section == MultiSourceSection.TIMELINE:
            return {**head, "incidents": [{"incident_id": i["incident_id"], "timeline": i["timeline"]} for i in inc]}
        if section == MultiSourceSection.CORRELATION:
            return {
                **head, "sources": payload.get("sources"), "contradictions": payload.get("contradictions"),
                "rejected": payload.get("rejected"), "counts": payload.get("counts"),
                "incidents": [{k: i[k] for k in ("incident_id", "severity", "hosts", "users", "stages", "escalated",
                                                  "link_counts", "weakly_related", "links", "weak_link_count")} for i in inc],
            }
        if section == MultiSourceSection.ATTACK:
            return {**head, "mapping_version": payload.get("mapping_version"),
                    "incidents": [{"incident_id": i["incident_id"], "mitre": i["mitre"], "asserted_only": i["asserted_only"]} for i in inc]}
        if section == MultiSourceSection.SUFFICIENCY:
            return {**head, "rule_version": payload.get("rule_version"), "batch_sufficiency": payload.get("batch_sufficiency"),
                    "incidents": [{"incident_id": i["incident_id"], "sufficiency": i["sufficiency"], "llm_status": i["llm_status"],
                           "contradictions": i.get("contradictions", [])} for i in inc]}
        return {  # REPORT
            **head, "batch_report_markdown": payload.get("batch_report_markdown"), "ledger": payload.get("ledger"),
            "incidents": [{"incident_id": i["incident_id"], "verdict": i["sufficiency"]["verdict"], "llm_status": i["llm_status"],
                           "llm": i["llm"], "report_markdown": i["report_markdown"]} for i in inc],
        }

    # ── payload ─────────────────────────────────────────────────────────────
    @staticmethod
    def _assessment_view(a: Any) -> dict[str, Any]:
        return {
            "verdict": a.verdict.value,
            "rule_version": a.rule_version,
            "reason_codes": list(a.reason_codes),
            "reasons": [{"code": c, "meaning": REASON_EXPLANATIONS.get(c.split(":")[0], c)} for c in a.reason_codes],
            "assessment_sha256": a.assessment_sha256,
            "abstain": a.abstain,
            "counts": {"events": a.total_events, "evidence_units": a.effective_events, "relevant": a.relevant_events,
                       "attested": a.attested_events, "corroborating": a.corroborating_events},
            "evidence_ids": list(a.evidence_ids)[:MAX_EVIDENCE_IDS],
        }

    @staticmethod
    def _sufficiency_view(a: Any, trace: Any, llm_status: str) -> dict[str, Any]:
        """
        Sprint 1: the existing assessment view plus the additive same-pass ``rationale``. ONE canonical serialiser (``build_rationale``) feeds both
        the run response and the stored audit document, because ``build_payload`` is what is returned and what is stored. A rationale failure
        degrades only the rationale (disclosed), never the verdict or the persistence of the result. Entity values are never part of it.
        """
        view = MultiSourceInvestigationService._assessment_view(a)
        try:
            if trace is None:
                view["rationale"] = {"schema": RATIONALE_SCHEMA, "completeness": "unavailable", "trace_error": None}
            else:
                view["rationale"] = build_rationale(trace, a, llm_status=llm_status)
        except Exception as exc:  # noqa: BLE001 - never break the result for an explanation
            view["rationale"] = {"schema": RATIONALE_SCHEMA, "completeness": "unavailable", "trace_error": type(exc).__name__}
        return view

    @staticmethod
    def _contradiction_view(c: Any) -> dict[str, Any]:
        """ADR-013 finding as stored/returned: fixed vocabulary, evidence ids, source names and times only (no payload text)."""
        from app.modules.evidence_domains.contradictions import HINT_TEXT

        return {
            "kind": c.kind.value, "proposition": c.proposition, "materiality": c.materiality.value, "relation": c.relation.value,
            "affects_verdict": c.affects_verdict, "evidence_ids": [str(i) for i in c.evidence_ids], "sources": list(c.sources),
            "times": [_iso(t) for t in c.times], "time_quality": list(c.time_quality), "claims": list(c.claims),
            "link_strength": c.link_strength, "independence": c.independence, "overlap_seconds": c.overlap_seconds,
            "reliability": list(c.reliability), "explanation": c.explanation.value if c.explanation else None,
            "resolution_hint": c.resolution_hint, "resolution_text": HINT_TEXT.get(c.resolution_hint, ""),
        }

    def _incident_view(self, result: WorkflowResult, a: IncidentAnalysis) -> dict[str, Any]:
        inc = a.incident
        members = {*inc.core_clusters, *inc.weak_context_clusters}
        links = sorted(
            (lk for lk in non_weak_links(result)
             if lk.cluster_a in members and lk.cluster_b in members),
            key=lambda lk: (lk.strength != "strong", lk.cluster_a, lk.cluster_b),
        )
        llm = None
        if a.llm_result is not None:
            out = a.llm_result.output
            llm = {
                "decision": a.llm_result.decision.value, "is_valid": a.llm_result.is_valid,
                "summary": out.investigation_summary, "grounding_score": out.overall_grounding_score,
                "claims": [{"claim_id": str(c.claim_id), "text": c.claim_text, "category": c.category.value,
                            "grounding": c.grounding_status.value, "confidence": c.confidence,
                            "supporting_event_ids": [str(u) for u in c.supporting_evidence_ids],
                            # Task 1: additive. Absent for claims without structured assertions (= not machine-verifiable).
                            "verification": c.verification.model_dump(mode="json") if c.verification is not None else None} for c in out.claims],
                "uncertainty_and_data_gaps": list(out.uncertainty_and_data_gaps),
                "violations": [v.rule_id for v in a.llm_result.violations],
            }
        return {
            "incident_id": str(inc.incident_id),
            "severity": inc.severity,
            "event_count": len(a.events),
            "first_seen": _iso(inc.first_seen), "last_seen": _iso(inc.last_seen),
            "hosts": list(inc.hosts), "users": list(inc.users), "stages": list(inc.stages), "escalated": inc.escalated,
            "link_counts": dict(inc.link_counts),
            "weakly_related": [str(i) for i in inc.weakly_related],
            "context_sha256": a.context.reproducibility.context_sha256,
            "sufficiency": self._sufficiency_view(a.assessment, a.trace, a.llm_status),
            "contradictions": [self._contradiction_view(c) for c in a.assessment.contradictions[:50]],
            "timeline": [
                {"position": t.position, "timestamp": _iso(t.timestamp), "source_type": t.source_type, "host": t.host,
                 "user": t.user, "title": t.title, "stage": t.stage, "severity": t.severity, "outcome": t.outcome,
                 "raw_sha256_prefix": t.raw_sha256_prefix, "membership": t.membership,
                 "duplicates_collapsed": t.duplicates_collapsed, "event_id": str(t.event_key),
                 "contradicts": [str(x) for x in t.contradicts]}
                for t in a.timeline[:MAX_TIMELINE_ENTRIES]
            ],
            "links": [{"strength": lk.strength, "clusters": [lk.cluster_a, lk.cluster_b],
                       "entities": [[t, v] for t, v in lk.shared_entities[:4]]} for lk in links[:MAX_LINKS]],
            "weak_link_count": inc.link_counts.get("weak", 0),
            "mitre": [{"technique_id": m.technique_id, "technique_name": m.technique_name, "tactics": list(m.tactics),
                       "rule_id": m.rule_id, "independent_evidence_count": m.independent_evidence_count,
                       "vendor_asserted": m.vendor_asserted, "limitation": m.limitation,
                       "evidence_event_ids": [str(k) for k in m.evidence_keys][:MAX_EVIDENCE_IDS]} for m in a.mitre],
            "asserted_only": list(a.asserted_only),
            "llm_status": a.llm_status,
            "llm": llm,
            "report_markdown": a.markdown[:MAX_REPORT_CHARS],
            "graph": a.graph.to_view() if a.graph is not None else None,
            "enrichments": [en.view() for en in a.enrichments],
            "analyst_statements": [
                {"evidence_id": str(n.key), "time": _iso(n.event_time), "statement": str(n.attributes.get("statement", n.title))[:500],
                 "analyst": str(n.attributes.get("analyst", ""))[:60], "entities": [f"{t}:{v}" for t, v in n.entities[:6]],
                 "trust_class": n.trust_class.value, "counts_for_corroboration": False}
                for n in a.analyst_notes[:50]
            ],
        }

    def build_payload(self, result: WorkflowResult, fingerprint: str, use_llm: bool) -> dict[str, Any]:
        by_source: dict[str, dict[str, Any]] = {}
        for e in result.normalization.events:
            s = by_source.setdefault(e.source_type, {"source_type": e.source_type, "events": 0, "raws": set()})
            s["events"] += 1
            s["raws"].add(e.raw_sha256)
        summary = result.summary()
        batch = result.batch_assessment
        payload: dict[str, Any] = {
            "schema": PAYLOAD_SCHEMA,
            "status": "completed",
            "workflow_version": WORKFLOW_VERSION,
            "mapping_version": MAPPING_VERSION,
            "rule_version": SUFFICIENCY_RULE_VERSION,
            "evidence_fingerprint": fingerprint,
            "use_llm": use_llm,
            "counts": {"records_normalized": summary["records_normalized"], "records_rejected": summary["records_rejected"],
                       "evidence_clusters": summary["evidence_clusters"], "duplicates_collapsed": summary["duplicates_collapsed"],
                       "contradictions": len(result.correlation.contradictions), "incidents": len(result.incidents)},
            "management": management_view(result),
            "sources": [{"source_type": k, "events": v["events"], "distinct_raw_records": len(v["raws"])}
                        for k, v in sorted(by_source.items())],
            "rejected": [{"record_index": r.record_index, "reason": r.reason, "raw_sha256_prefix": r.raw_sha256[:12]}
                         for r in result.normalization.rejected[:MAX_REJECTED_LISTED]],
            "contradictions": [{"event_ids": [str(k) for k in c.event_keys], "reason": c.reason}
                               for c in result.correlation.contradictions[:MAX_CONTRADICTIONS_LISTED]],
            "truncation": {
                "incidents_total": len(result.incidents),
                "incidents_listed": min(len(result.incidents), MAX_STORED_INCIDENTS),
                "rejected_total": len(result.normalization.rejected),
                "rejected_listed": min(len(result.normalization.rejected), MAX_REJECTED_LISTED),
                "contradictions_total": len(result.correlation.contradictions),
                "contradictions_listed": min(len(result.correlation.contradictions), MAX_CONTRADICTIONS_LISTED),
            },
            "batch_sufficiency": self._sufficiency_view(batch, result.batch_trace, "not_requested") if batch is not None else None,
            "batch_report_markdown": result.batch_markdown[:MAX_REPORT_CHARS] if result.batch_markdown else None,
            "incidents": [self._incident_view(result, a) for a in result.incidents[:MAX_STORED_INCIDENTS]],
            **self._domain_payload(result),
            "ledger": {"head": result.ledger_head, "verified": result.ledger_ok,
                       "steps": [{"seq": e["seq"], "step": e["step"], "entry_hash": e["entry_hash"]} for e in result.ledger]},
        }
        return json.loads(json.dumps(payload, default=str))


def activity_summary(details: dict[str, Any]) -> dict[str, Any]:
    """
    Bounded view of a stored result for the case activity feed (which any case role may list). The full document
    is available only through the section endpoints; the feed must not carry up to megabytes per run.
    """
    incidents = details.get("incidents") if isinstance(details.get("incidents"), list) else []
    batch = details.get("batch_sufficiency") if isinstance(details.get("batch_sufficiency"), dict) else None
    ledger = details.get("ledger") if isinstance(details.get("ledger"), dict) else {}
    return {
        "summary_only": True,
        "schema": details.get("schema"),
        "evidence_fingerprint": details.get("evidence_fingerprint"),
        "use_llm": details.get("use_llm"),
        "counts": details.get("counts"),
        "verdicts": [
            {"incident_id": i.get("incident_id"), "verdict": (i.get("sufficiency") or {}).get("verdict"),
             "reason_codes": (i.get("sufficiency") or {}).get("reason_codes")}
            for i in incidents if isinstance(i, dict)
        ] or ([{"incident_id": None, "verdict": batch.get("verdict"), "reason_codes": batch.get("reason_codes")}] if batch else []),
        "ledger_head": ledger.get("head"),
        "ledger_verified": ledger.get("verified"),
    }


__all__ = [
    "EvidenceTooLarge", "activity_summary",
    "CaseClosed", "CaseNotFound", "EvidenceChanged", "MULTISOURCE_ACTION", "MultiSourceError",
    "MultiSourceInvestigationService", "NoInvestigation", "PersistenceFailed",
]
