"""
AISOP Investigation Pipeline Service.

Orchestrates the complete AI-assisted incident investigation lifecycle:
1. Validates scope parameters and time-window boundaries.
2. Queries normalized security telemetry and atomic entities from the database.
3. Enriches observables with local threat intelligence findings and reference knowledge.
4. Assembles canonical, reproducible InvestigationContext enforcing CJSON-1.0 and MAX_CONTEXT_CHARS.
5. Constructs defensive, role-separated LLM prompts enforcing 'The Untrusted Data Axiom'.
6. Dispatches inference to the approved local Ollama provider.
7. Parses raw LLM response into StructuredInvestigationOutput with truncation detection.
8. Enforces output guardrails and 3-tier claim grounding via InvestigationOutputValidator.
9. Employs deterministic factual fallbacks on provider failure, timeout, or parsing rejection.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.models.evidence import NormalizedEventModel
from app.modules.ai.context_builder import (
    IncompleteContextOverflowError,
    InvestigationContextBuilder,
)
from app.modules.ai.guardrails import (
    GuardrailDecision,
    InvestigationOutputValidator,
    InvestigationValidationResult,
)
from app.modules.ai.knowledge.retriever import KnowledgeRetriever
from app.modules.ai.llm.exceptions import (
    LLMConnectionError,
    LLMError,
    LLMTimeoutError,
)
from app.modules.ai.guardrails.gated_generation import GatedGenerator
from app.modules.ai.guardrails.sufficiency_gate import apply_sufficiency_disclosure, evaluate_sufficiency
from app.modules.ai.llm.manager import get_llm_provider
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.ai.prompt_builder import InvestigationPromptBuilder
from app.modules.ai.response_parser import (
    InvestigationResponseParser,
    ResponseParsingError,
)
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.schemas.investigation import (
    ContextEntityItem,
    ContextEventItem,
    ContextKnowledgeChunkItem,
    InvestigationContext,
    InvestigationScopeType,
    InvestigationSynthesizeRequest,
    StructuredInvestigationOutput,
)
from app.schemas.knowledge import RetrievalRequest
from app.schemas.query import ExtractedEntityItem
from app.services.query_service import InvestigationQueryService

inv_logger = logger.bind(component="investigation_pipeline")


def _is_unlinked_or_missing_hash(sha256_str: Optional[str]) -> bool:
    """
    Deterministic predicate: returns True if raw evidence hash is None, empty,
    whitespace, malformed (not 64 hex characters), or the 64-zero sentinel ('0' * 64).

    Scope & Semantics:
    - Returns True: Telemetry lacks cryptographic binding to raw source evidence.
      This indicates an ingestion limitation, detached mode, or unlinked database record.
      It does NOT prove that tampering occurred, and does NOT imply the event payload is fabricated.
    - Returns False: Telemetry possesses a structurally valid, non-zero SHA-256 hex digest.
    """
    if not sha256_str:
        return True
    clean = sha256_str.strip().lower()
    if clean == ("0" * 64) or clean == "":
        return True
    return len(clean) != 64 or not all(c in "0123456789abcdef" for c in clean)


class InvestigationPipelineService:
    """
    Authoritative orchestration service for the AISOP investigation synthesis workflow.
    """

    def __init__(
        self,
        llm_provider: LLMProvider | None = None,
        threat_intel_engine: LocalThreatIntelEngine | None = None,
        knowledge_retriever: KnowledgeRetriever | None = None,
        validator: InvestigationOutputValidator | None = None,
        context_builder: InvestigationContextBuilder | None = None,
        response_parser: InvestigationResponseParser | None = None,
        prompt_builder: InvestigationPromptBuilder | None = None,
    ) -> None:
        self._llm_provider = llm_provider
        self._threat_intel_engine = threat_intel_engine
        self._knowledge_retriever = knowledge_retriever
        self._validator = validator or InvestigationOutputValidator()
        self._context_builder = context_builder or InvestigationContextBuilder()
        self._response_parser = response_parser or InvestigationResponseParser()
        self._prompt_builder = prompt_builder

    @property
    def llm_provider(self) -> LLMProvider:
        if self._llm_provider is None:
            self._llm_provider = get_llm_provider()
        return self._llm_provider

    async def synthesize_investigation(
        self,
        session: AsyncSession,
        request: InvestigationSynthesizeRequest,
    ) -> InvestigationValidationResult:
        """
        Execute the end-to-end investigation synthesis pipeline.
        Preserves backward compatibility for callers expecting InvestigationValidationResult.
        """
        result, _ = await self.synthesize_investigation_with_context(session, request)
        return result

    async def synthesize_investigation_with_context(
        self,
        session: AsyncSession,
        request: InvestigationSynthesizeRequest,
    ) -> tuple[InvestigationValidationResult, InvestigationContext]:
        """
        Execute the end-to-end investigation synthesis pipeline and return both
        the validated result and the fully assembled, canonical InvestigationContext.
        """
        start_time = request.time_window_start
        end_time = request.time_window_end

        if start_time >= end_time:
            inv_logger.warning(
                "Investigation synthesis rejected: invalid time window",
                start=start_time.isoformat(),
                end=end_time.isoformat(),
            )
            raise ValueError(f"time_window_start ({start_time}) must be strictly before time_window_end ({end_time})")

        inv_logger.info(
            "Starting investigation synthesis",
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            root_event_id=str(request.root_event_id) if request.root_event_id else None,
            model_override=request.model_override,
        )

        # ── 1. RETRIEVE TELEMETRY AND ENTITIES ──────────────────────────────
        stmt = (
            select(NormalizedEventModel)
            .options(
                joinedload(NormalizedEventModel.entities),
                joinedload(NormalizedEventModel.raw_evidence),
            )
            .where(
                NormalizedEventModel.event_timestamp >= start_time,
                NormalizedEventModel.event_timestamp < end_time,
            )
            .order_by(NormalizedEventModel.event_timestamp.asc())
        )
        res = await session.execute(stmt)
        orm_events = res.scalars().unique().all()

        context_events: list[ContextEventItem] = []
        extracted_entities_for_ti: list[ExtractedEntityItem] = []
        target_hosts_set: set[str] = set()

        for ev in orm_events:
            raw_hash = (
                ev.raw_evidence.sha256_hash
                if ev.raw_evidence and ev.raw_evidence.sha256_hash
                else ("0" * 64)
            )
            source_id = (
                ev.raw_evidence.source_identifier
                if ev.raw_evidence and ev.raw_evidence.source_identifier
                else (getattr(ev, "source_identifier", None) or ev.provider or "unknown")
            )
            target_hosts_set.add(source_id)
            summary = f"{ev.event_type} {ev.action} on {source_id}"


            ts = ev.event_timestamp
            if ts is not None and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            elif ts is not None:
                ts = ts.astimezone(timezone.utc)

            c_ev = ContextEventItem(
                event_uuid=ev.id,
                raw_evidence_sha256=raw_hash,
                event_id=str(ev.event_id),
                event_type=ev.event_type,
                timestamp_utc=ts,
                action=ev.action,
                outcome=ev.outcome or "unknown",
                severity=ev.severity or "informational",
                source_identifier=source_id,
                summary=summary,
                attributes=dict(ev.normalized_payload or {}),
            )
            context_events.append(c_ev)

            for ent in ev.entities or []:
                extracted_entities_for_ti.append(
                    ExtractedEntityItem(
                        id=ent.id,
                        event_id=ent.event_id,
                        raw_evidence_id=ent.raw_evidence_id,
                        entity_type=ent.entity_type,
                        entity_value=ent.entity_value,
                        role=ent.role or "associated",
                        attributes=dict(ent.attributes or {}),
                    )
                )

        # ── 2. ENRICH WITH LOCAL THREAT INTEL ────────────────────────────────
        ti_findings: list[Any] = []
        if self._threat_intel_engine and extracted_entities_for_ti:
            try:
                query_svc = InvestigationQueryService(threat_intel_engine=self._threat_intel_engine)
                ti_findings = await query_svc.enrich_entities_with_threat_intel(extracted_entities_for_ti)
            except Exception as exc:
                inv_logger.warning("Local threat intelligence enrichment failed", error=str(exc))

        # ── 3. RETRIEVE KNOWLEDGE CHUNKS (RAG) ──────────────────────────────
        knowledge_chunks: list[ContextKnowledgeChunkItem] = []
        retrieval_uncertainty: Optional[str] = None

        if self._knowledge_retriever is None:
            retrieval_uncertainty = (
                "RETRIEVER_UNAVAILABLE: Semantic knowledge retrieval component is not initialized."
            )
        elif not request.query_filter or len(request.query_filter.strip()) < 3:
            retrieval_uncertainty = (
                "SKIPPED_SHORT_OR_MISSING_QUERY: Semantic knowledge retrieval skipped due to absent or short query filter (<3 chars)."
            )
        else:
            try:
                retrieval_res = await self._knowledge_retriever.retrieve(
                    session=session,
                    request=RetrievalRequest(query=request.query_filter.strip(), top_k=5),
                )
                if retrieval_res:
                    for chunk in retrieval_res:
                        knowledge_chunks.append(
                            ContextKnowledgeChunkItem(
                                chunk_id=chunk.id,
                                source_document=chunk.source_document,
                                section_title=chunk.section_title or "General",
                                chunk_index=chunk.chunk_index,
                                similarity_score=round(chunk.similarity_score, 4),
                                content=chunk.content,
                            )
                        )
                else:
                    retrieval_uncertainty = (
                        "RETRIEVED_NO_MATCH: Semantic knowledge retrieval executed but returned zero matching chunks."
                    )
            except Exception as exc:
                inv_logger.warning(
                    "Semantic knowledge retrieval encountered operational failure",
                    error_type=type(exc).__name__,
                )
                retrieval_uncertainty = (
                    "RETRIEVAL_FAILED: Semantic knowledge retrieval encountered operational failure during query execution."
                )

        # ── 4. ASSEMBLE CANONICAL INVESTIGATION CONTEXT ──────────────────────
        uncertainty_flags: list[str] = []
        if not context_events:
            uncertainty_flags.append("NO_TELEMETRY_IN_SCOPE: No security events recorded in the specified time window")
        if retrieval_uncertainty:
            uncertainty_flags.append(retrieval_uncertainty)

        has_unlinked_events = any(
            _is_unlinked_or_missing_hash(e.raw_evidence_sha256)
            for e in context_events
        )
        if has_unlinked_events:
            uncertainty_flags.append(
                "PROVENANCE_LIMITATION: One or more telemetry events lack cryptographic raw-evidence bindings; raw source integrity unverified."
            )
        if (
            request.root_event_id
            and not any(e.event_uuid == request.root_event_id for e in context_events)
        ):
            uncertainty_flags.append(
                "ROOT_ANCHOR_FALLBACK_APPLIED: Caller-specified root_event_id was absent from queried telemetry; context anchor designated via chronological/severity fallback."
            )
        elif (
            request.root_event_id
            and any(
                e.event_uuid == request.root_event_id and _is_unlinked_or_missing_hash(e.raw_evidence_sha256)
                for e in context_events
            )
        ):
            uncertainty_flags.append(
                "ROOT_PROVENANCE_MISSING: Root anchor event lacks cryptographic raw-evidence binding."
            )

        scope_type = (
            InvestigationScopeType.SINGLE_EVENT
            if len(context_events) == 1
            else InvestigationScopeType.INCIDENT_TIMELINE
        )

        provider_inst = self.llm_provider
        default_model = getattr(provider_inst, "model_name", "llama3.1:8b")
        target_model = request.model_override or default_model

        context = self._context_builder.build_structured_context(
            events=context_events,
            investigation_id=uuid.uuid4(),
            root_event_id=request.root_event_id,
            scope_type=scope_type,
            time_window_start=start_time,
            time_window_end=end_time,
            target_hosts=sorted(target_hosts_set) if target_hosts_set else None,
            entities=extracted_entities_for_ti if extracted_entities_for_ti else None,
            threat_intel=ti_findings,
            knowledge_chunks=knowledge_chunks,
            query_filter=request.query_filter,
            llm_provider="ollama",
            model_name=target_model,
            uncertainty_flags=uncertainty_flags,
        )

        inv_logger.info(
            "InvestigationContext assembled",
            investigation_id=str(context.investigation_id),
            context_sha256=context.reproducibility.context_sha256,
            events_count=len(context.events),
            omitted_events=context.budget_metrics.events_omitted_count,
        )

        def _build_fallback_result(reason: str, sufficiency: Any = None) -> InvestigationValidationResult:
            fallback = self._response_parser.build_deterministic_fallback(context, reason, sufficiency)
            validated = self._validator.validate(fallback, context)
            return InvestigationValidationResult(
                decision=GuardrailDecision.REJECT_TO_FALLBACK,
                is_valid=False,
                output=validated.output,
                violations=validated.violations,
                context_sha256=context.reproducibility.context_sha256,
                validated_at_utc=datetime.now(timezone.utc),
            )

        # ── 4b. DETERMINISTIC EVIDENCE-SUFFICIENCY GATE (Stage 3C, ADR-008) ──
        # Runs before ANY model invocation. Fails closed: an exception inside the gate yields
        # INSUFFICIENT, which forbids the model call. INSUFFICIENT (including the former
        # "zero events" branch) returns an auditable abstention without touching the provider.
        assessment = evaluate_sufficiency(context)
        inv_logger.info(
            "Evidence sufficiency assessed",
            investigation_id=str(context.investigation_id),
            verdict=assessment.verdict.value,
            reason_codes=assessment.reason_codes,
            assessment_sha256=assessment.assessment_sha256,
        )
        if assessment.abstain:
            return _build_fallback_result(
                "Evidence assessed INSUFFICIENT: " + ", ".join(assessment.reason_codes),
                assessment,
            ), context
        sufficiency_note = assessment.limitation_note()

        # ── 5. BUILD DEFENSIVE PROMPT & EXECUTE WITH BOUNDED RETRY ────────────
        prompt_builder = self._prompt_builder or InvestigationPromptBuilder(default_model=default_model, structured_assertions=True)
        max_attempts = 2
        raw_response = None
        validation_result = None
        fallback_reason = ""

        for attempt in range(max_attempts):
            if attempt == 0:
                llm_request = prompt_builder.build_request(
                    context,
                    model_override=request.model_override,
                    sufficiency_note=sufficiency_note,
                )
            else:
                inv_logger.info(
                    "Executing bounded retry for truncated investigation synthesis",
                    attempt=attempt,
                    investigation_id=str(context.investigation_id),
                )
                llm_request = prompt_builder.build_retry_request(
                    context,
                    model_override=request.model_override,
                    sufficiency_note=sufficiency_note,
                )

            raw_response = None
            try:
                raw_response = await GatedGenerator.generate(provider_inst, llm_request, assessment, context)
            except LLMTimeoutError as exc:
                inv_logger.warning("LLM generation timed out", error=str(exc))
                fallback_reason = f"LLM inference timed out: {exc}"
                break
            except LLMConnectionError as exc:
                inv_logger.warning("LLM connection failed", error=str(exc))
                fallback_reason = f"LLM provider unavailable: {exc}"
                break
            except LLMError as exc:
                inv_logger.warning("LLM provider execution error", error=str(exc))
                fallback_reason = f"LLM provider failure: {exc}"
                break
            except Exception as exc:
                inv_logger.error("Unexpected error during LLM invocation", error=str(exc))
                fallback_reason = f"Internal inference execution failure: {exc}"
                break

            if raw_response is None:
                break

            is_length_truncated = getattr(raw_response, "finish_reason", None) == "length"

            try:
                parsed_output = self._response_parser.parse(raw_response, context)
                validation_result = self._validator.validate(parsed_output, context, assessment)
                inv_logger.info(
                    "Investigation guardrails evaluated",
                    investigation_id=str(context.investigation_id),
                    decision=validation_result.decision.value,
                    is_valid=validation_result.is_valid,
                    violations_count=len(validation_result.violations),
                    grounding_score=validation_result.output.overall_grounding_score,
                )
                break
            except ResponseParsingError as exc:
                err_msg = str(exc).lower()
                is_truncated_parse = (
                    is_length_truncated
                    or "truncated" in err_msg
                    or "length" in err_msg
                    or "unterminated" in err_msg
                )
                if attempt == 0 and is_truncated_parse:
                    inv_logger.warning(
                        "Synthesis output was truncated, triggering bounded retry",
                        error=str(exc),
                        attempt=attempt,
                    )
                    continue
                inv_logger.warning("Failed to parse structured LLM response", error=str(exc))
                fallback_reason = f"Response parsing failure: {exc}"
                validation_result = _build_fallback_result(fallback_reason)
                break

        if validation_result is None:
            validation_result = _build_fallback_result(fallback_reason or "Inference failed without producing valid output")

        # 3C-R: the sufficiency verdict must reach the analyst-facing output, not only the prompt.
        validation_result = apply_sufficiency_disclosure(validation_result, assessment)
        return validation_result, context
