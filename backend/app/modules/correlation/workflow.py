"""
AISOP multi-source investigation workflow (Stage 3C-R vertical slice, ADR-009).

Orchestrates, in this order:

  raw records -> normalize (adapters, provenance) -> correlate (typed links, dedup)
  -> per incident: timeline, deterministic ATT&CK mapping, InvestigationContext,
     evidence-sufficiency assessment (ADR-008) -> [optional LLM through the gate]
     -> claim verification (existing validator) -> analyst-facing report
  with every step recorded in a hash-chained ledger.

The deterministic path (``analyze``) is complete without an LLM. The LLM step is optional and can
only be reached through ``GatedGenerator`` after an assessment that permits it; an INSUFFICIENT
assessment produces an auditable abstention and no provider call; any LLM or parsing failure falls
back to deterministic output.

AiSOC concepts adapted: fusion spine ordering (ingest -> normalize -> fuse/correlate -> agents),
investigation ledger, deterministic narrative that works without an LLM, verdict gate. AISOP differs
deliberately: the gate is deterministic and fails closed (AiSOC's verdict gate fails open).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Optional

from app.modules.ai.llm.exceptions import LLMDisabledError
from app.modules.ai.guardrails.attack_policy import AttackReferenceSource
from app.modules.ai.guardrails.gated_generation import GatedGenerator
from app.modules.ai.guardrails.sufficiency_gate import apply_sufficiency_disclosure, evaluate_sufficiency
from app.modules.ai.guardrails.sufficiency_trace import SufficiencyTrace
from app.modules.ai.guardrails.validator import (
    GuardrailDecision,
    InvestigationOutputValidator,
    InvestigationValidationResult,
)
from app.modules.ai.context_builder.hasher import compute_context_sha256
from app.modules.ai.prompt_builder.builder import BOUNDED_MAX_TOKENS, InvestigationPromptBuilder
from app.modules.ai.response_parser.parser import InvestigationResponseParser
from app.modules.correlation.correlator import correlate, first_event_of_max_severity
from app.modules.correlation.ledger import Ledger, verify_chain
from app.modules.correlation.mitre import MAPPING_VERSION, asserted_only_techniques, map_techniques
from app.modules.correlation.models import (
    Contradiction,
    CorrelationEvent,
    CorrelationResult,
    Incident,
    MitreMapping,
    NormalizationResult,
    TimelineEntry,
)
from app.modules.correlation.normalize import normalize_records
from app.modules.correlation.timeline import build_timeline
from app.modules.evidence_domains.bridge import is_dated, is_machine, is_projectable
from app.modules.evidence_domains.contradictions import detect_contradictions
from app.modules.evidence_domains.domain_attack import DOMAIN_MAPPING_VERSION, map_domain_techniques
from app.modules.evidence_domains.graph import InvestigationGraph, build_graph
from app.modules.evidence_domains.model import EvidenceFamily, Observation
from app.modules.evidence_domains.ti import Enrichment, IndicatorProvider, enrich
from app.schemas.investigation import (
    BudgetMetrics,
    ContextEntityItem,
    ContextEventItem,
    InvestigationContext,
    InvestigationScopeType,
    ReproducibilityRecord,
)
from app.schemas.sufficiency import EvidenceSufficiencyAssessment

MAX_CONTEXT_EVENTS = 200
WORKFLOW_VERSION = "multi-source-v2"  # v2: ADR-011 source-agnostic observations, graph, domain ATT&CK rules

_EVENT_TYPE_BY_SYSMON = {"1": "process_creation", "3": "network_connection", "22": "dns_query"}
_ACTION_BY_SYSMON = {"1": "start", "3": "connect", "22": "query"}


@dataclass
class IncidentAnalysis:
    incident: Incident
    events: list[CorrelationEvent]
    timeline: list[TimelineEntry]
    mitre: list[MitreMapping]
    asserted_only: list[str]
    context: InvestigationContext
    assessment: EvidenceSufficiencyAssessment
    llm_status: str = "not_requested"  # not_requested | abstained | validated | fallback:<reason>
    llm_result: Optional[InvestigationValidationResult] = None
    markdown: str = ""
    observations: list[Observation] = field(default_factory=list)  # ADR-011 canonical observations in this incident
    graph: Optional[InvestigationGraph] = None
    enrichments: list[Enrichment] = field(default_factory=list)  # TI context: reference, never observed evidence
    analyst_notes: list[Observation] = field(default_factory=list)  # analyst statements touching this incident: context only
    trace: Optional[SufficiencyTrace] = None  # Sprint 1: same-pass explanation of ``assessment`` (ids, codes, entity type/strength only)


@dataclass
class WorkflowResult:
    normalization: NormalizationResult
    correlation: CorrelationResult
    incidents: list[IncidentAnalysis] = field(default_factory=list)
    ledger: list[dict[str, Any]] = field(default_factory=list)
    ledger_ok: bool = True
    ledger_head: str = ""
    batch_assessment: Optional[EvidenceSufficiencyAssessment] = None  # set when no incident could be formed
    batch_markdown: str = ""
    observations: list[Observation] = field(default_factory=list)  # ALL canonical observations (ADR-011), incl. undated/analyst/unclassified
    batch_graph: Optional[InvestigationGraph] = None  # graph of all machine observations (shown when no incident formed)
    batch_trace: Optional[SufficiencyTrace] = None  # Sprint 1: same-pass explanation of ``batch_assessment``

    def summary(self) -> dict[str, Any]:
        return {
            "workflow_version": WORKFLOW_VERSION,
            "records_normalized": len(self.normalization.events),
            "domain_observations": len(self.observations),
            "records_rejected": len(self.normalization.rejected),
            "evidence_clusters": len(self.correlation.clusters),
            "duplicates_collapsed": len(self.normalization.events) - len(self.correlation.clusters),
            "incidents": [
                {
                    "incident_id": str(a.incident.incident_id),
                    "events": len(a.incident.event_keys),
                    "severity": a.incident.severity,
                    "verdict": a.assessment.verdict.value,
                    "reason_codes": a.assessment.reason_codes,
                    "techniques": [m.technique_id for m in a.mitre],
                    "llm_status": a.llm_status,
                }
                for a in self.incidents
            ],
            "ledger_head": self.ledger_head,
            "ledger_verified": self.ledger_ok,
        }


def _event_type(e: CorrelationEvent) -> str:
    if e.evidence_type:  # ADR-011 source-agnostic observation: the canonical type is the event type
        return e.evidence_type
    if e.source_type == "sysmon":
        return _EVENT_TYPE_BY_SYSMON.get(e.source_event_id, "sysmon_event")
    if e.source_type == "windows_security":
        return "authentication"
    if e.source_type == "generic_siem":
        return "siem_alert"
    if e.domain and e.source_type == "firewall_ids":
        return "dns_query"
    return "ids_alert" if e.source_type == "firewall_ids" else e.category


def _action(e: CorrelationEvent) -> str:
    if e.evidence_type:
        return "observed"
    if e.source_type == "sysmon":
        return _ACTION_BY_SYSMON.get(e.source_event_id, "observed")
    if e.source_type == "windows_security":
        return "logon"
    return "alert"


def build_incident_context(
    result: CorrelationResult,
    incident: Incident,
    rejected_count: int = 0,
    extra_flags: Optional[list[str]] = None,
) -> tuple[InvestigationContext, list[CorrelationEvent]]:
    """
    Build the canonical InvestigationContext (existing schema, real context SHA-256) for one incident.
    Anchor (root event) = earliest event of the highest severity inside the strongly linked core.
    """
    by_key = {e.event_key: e for e in result.events}
    events = sorted((by_key[k] for k in incident.event_keys), key=lambda e: (e.timestamp, e.record_index))
    core_keys = {k for i in incident.core_clusters for k in result.clusters[i].members}
    anchor = first_event_of_max_severity(events, core_keys)
    included = events[:MAX_CONTEXT_EVENTS]
    omitted = len(events) - len(included)

    items = [
        ContextEventItem(
            event_uuid=e.event_key,
            raw_evidence_sha256=e.raw_sha256,
            # Logical event id: all Windows logon records share "logon" so a success and a failure for the
            # same actors can be recognised as a contradiction; the vendor id stays in the attributes.
            event_id="logon" if e.source_type == "windows_security" else (e.source_event_id or e.source_type),
            event_type=_event_type(e),
            timestamp_utc=e.timestamp,
            action=_action(e),
            outcome=e.outcome,
            severity=e.severity,
            source_identifier=e.host or f"sensor:{e.source_type}",
            summary=e.title or "event",
            attributes={
                k: v for k, v in {
                    "source_type": e.source_type, "source_event_id": e.source_event_id, "user": e.user, "src_ip": e.src_ip, "dst_ip": e.dst_ip,
                    "domain": e.domain, "process": e.process_name, "upstream_id": e.upstream_id, "native_event_id": e.native_event_id, "time_assumed_utc": e.time_assumed_utc,
                    "command_line": (e.command_line[:200] if e.command_line else None),
                }.items() if v
            },
        )
        for e in included
    ]
    ent_map: dict[tuple[str, str], list[uuid.UUID]] = {}
    for e in included:
        for t, v in e.entities:
            ent_map.setdefault((t, v), []).append(e.event_key)
    entities = [
        ContextEntityItem(entity_type=t, entity_value=v, roles=[], occurrence_count=len(ids), associated_event_uuids=ids)
        for (t, v), ids in sorted(ent_map.items())
    ]
    w_start = included[0].timestamp
    w_end = included[-1].timestamp + timedelta(seconds=1)
    assembled = w_end + timedelta(hours=1)  # deterministic assembly time (reproducible assessment)
    flags = []
    if omitted:
        flags.append("CONTEXT_TRUNCATED_TO_BUDGET")
    if rejected_count:
        flags.append(f"INGEST_REJECTED_RECORDS: {rejected_count} record(s) could not be normalized")
    flags.extend(extra_flags or [])
    assumed = sum(1 for e in included if e.time_assumed_utc)
    if assumed:
        flags.append(f"NAIVE_TIMESTAMPS_ASSUMED_UTC: {assumed} record(s) carried no time zone and UTC was assumed by AISOP, so their event times are unverified")
    budget = BudgetMetrics(
        total_events_in_scope=len(events),
        events_included=len(included),
        events_omitted_count=omitted,
        omitted_event_ids_summary=[e.event_key for e in events[MAX_CONTEXT_EVENTS:]][:omitted],
        total_entities_in_scope=len(entities),
        entities_included=len(entities),
        context_truncated=omitted > 0,
    )

    def make(sha: str) -> InvestigationContext:
        return InvestigationContext(
            investigation_id=incident.incident_id,
            scope_type=InvestigationScopeType.SINGLE_EVENT if len(items) == 1 else InvestigationScopeType.INCIDENT_TIMELINE,
            time_window_start=w_start,
            time_window_end=w_end,
            target_hosts=sorted({e.host for e in included if e.host}),
            events=items,
            entities=entities,
            budget_metrics=budget,
            reproducibility=ReproducibilityRecord(
                request_id=uuid.uuid5(incident.incident_id, "request"),
                time_window_start=w_start,
                time_window_end=w_end,
                root_event_id=anchor.event_key,
                selected_event_uuids=[i.event_uuid for i in items],
                context_sha256=sha,
                created_at_utc=assembled,
            ),
            uncertainty_flags=flags,
            assembled_at=assembled,
        )

    return make(compute_context_sha256(make("a" * 64))), included


def _abstention_context(rejected_count: int) -> InvestigationContext:
    """Placeholder context for a batch with no usable evidence (so the gate still runs and abstains)."""
    base = uuid.uuid5(uuid.NAMESPACE_URL, "aisop:no-usable-evidence")
    from datetime import datetime, timezone

    t0 = datetime(2000, 1, 1, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=1)

    def make(sha: str) -> InvestigationContext:
        return InvestigationContext(
            investigation_id=base,
            scope_type=InvestigationScopeType.INCIDENT_TIMELINE,
            time_window_start=t0,
            time_window_end=t1,
            events=[],
            entities=[],
            budget_metrics=BudgetMetrics(total_events_in_scope=0, events_included=0, events_omitted_count=0),
            reproducibility=ReproducibilityRecord(
                time_window_start=t0, time_window_end=t1, context_sha256=sha, created_at_utc=t1,
            ),
            uncertainty_flags=[f"INGEST_REJECTED_RECORDS: {rejected_count} record(s) could not be normalized"] if rejected_count else [],
            assembled_at=t1,
        )

    return make(compute_context_sha256(make("a" * 64)))


def _with_candidate_contradictions(corr: CorrelationResult, candidates: tuple[Any, ...]) -> CorrelationResult:
    """Add detector findings to the correlator's contradiction list, skipping pairs the correlator already reported."""
    existing = {frozenset(c.event_keys) for c in corr.contradictions}
    extra = [
        Contradiction(event_keys=tuple(c.evidence_ids), reason=f"{c.kind.value.upper()}_CONFLICT")
        for c in candidates if frozenset(c.evidence_ids) not in existing
    ]
    return corr.model_copy(update={"contradictions": [*corr.contradictions, *extra]}) if extra else corr


def _domain_flags(observations: list[Observation]) -> list[str]:
    """Disclosures for evidence that exists but could not take part in correlation (never silently dropped)."""
    machine = [o for o in observations if is_machine(o)]
    flags: list[str] = []
    undated = sum(1 for o in machine if not is_dated(o))
    if undated:
        flags.append(f"UNDATED_OBSERVATIONS: {undated} observation(s) have no usable event time and were not placed on the timeline")
    unclassified = sum(1 for o in machine if o.family == EvidenceFamily.UNCLASSIFIED)
    if unclassified:
        flags.append(f"UNCLASSIFIED_EVIDENCE: {unclassified} observation(s) were preserved but not interpreted")
    return flags


def analyze(
    records: list[Any],
    assets: Optional[dict[str, str]] = None,
    digests: Optional[list[Optional[str]]] = None,
    event_keys: Optional[list[Optional[uuid.UUID]]] = None,
    indicators: Optional[IndicatorProvider] = None,
) -> WorkflowResult:
    """Deterministic workflow: no LLM, no network, no I/O. Fully usable on its own."""
    from app.modules.correlation.report import render_abstention_report, render_incident_report  # local: report uses these types

    ledger = Ledger()
    norm = normalize_records(records, assets=assets, digests=digests, event_keys=event_keys)
    ledger.append("NORMALIZE", {
        "records_in": len(records),
        "events_normalized": len(norm.events),
        "rejected": [{"index": r.record_index, "reason": r.reason, "raw_sha256": r.raw_sha256} for r in norm.rejected],
        "sources": sorted({e.source_type for e in norm.events}),
        "raw_digests": sorted({e.raw_sha256 for e in norm.events}),
    })
    observations: list[Observation] = list(norm.observations)
    machine_obs = [o for o in observations if is_machine(o)]
    analyst_obs = [o for o in observations if o.family == EvidenceFamily.ANALYST]
    if observations:
        ledger.append("DOMAIN_EVIDENCE", {
            "observations": len(observations), "machine": len(machine_obs), "analyst_context": len(analyst_obs),
            "undated": sum(1 for o in machine_obs if not is_dated(o)),
            "unclassified": sum(1 for o in machine_obs if o.family == EvidenceFamily.UNCLASSIFIED),
            "adapters": sorted({o.adapter + "@" + o.adapter_version for o in observations}),
            "attack_rules": DOMAIN_MAPPING_VERSION,
        })
    corr = correlate(norm.events)
    # ADR-013: the pure detector runs ONCE over all machine observations. Its findings are also surfaced as correlator contradictions (so the
    # graph, timeline and counts show them) and each incident passes ITS findings to the single gate, which alone decides the verdict.
    all_candidates = detect_contradictions(machine_obs)
    corr = _with_candidate_contradictions(corr, all_candidates)
    ledger.append("CORRELATE", {
        "evidence_clusters": len(corr.clusters),
        "duplicates_collapsed": len(norm.events) - len(corr.clusters),
        "links": {s: sum(1 for lk in corr.links if lk.strength == s) for s in ("strong", "specific", "weak")},
        "incidents": [str(i.incident_id) for i in corr.incidents],
        "contradictions": len(corr.contradictions),
    })
    link_index: dict[int, list[int]] = {}
    for li, lk in enumerate(corr.links):
        link_index.setdefault(lk.cluster_a, []).append(li)
        if lk.cluster_b != lk.cluster_a:
            link_index.setdefault(lk.cluster_b, []).append(li)
    result = WorkflowResult(normalization=norm, correlation=corr, observations=observations)
    domain_flags = _domain_flags(observations)
    if observations:
        result.batch_graph = build_graph(machine_obs, corr, analyst_obs, len(norm.rejected))

    if not corr.incidents:
        ctx = _abstention_context(len(norm.rejected))
        batch_trace = SufficiencyTrace()
        assessment = evaluate_sufficiency(ctx, trace=batch_trace)
        result.batch_assessment = assessment
        result.batch_trace = batch_trace
        ledger.append("SUFFICIENCY", {"incident": None, "verdict": assessment.verdict.value,
                                      "reason_codes": assessment.reason_codes, "assessment_sha256": assessment.assessment_sha256})
    for incident in corr.incidents:
        context, included = build_incident_context(corr, incident, len(norm.rejected), domain_flags)
        keys_in = {e.event_key for e in included}
        obs_in = [o for o in machine_obs if o.key in keys_in]
        # ADR-013 (suff-v4): contradiction FACTS from the pure detector go to the single gate, which alone decides the verdict.
        incident_candidates = tuple(c for c in all_candidates if c.evidence_ids[0] in keys_in and c.evidence_ids[1] in keys_in)
        trace = SufficiencyTrace()
        assessment = evaluate_sufficiency(context, incident_candidates, trace=trace)
        timeline = build_timeline(corr, incident)
        mappings = map_techniques(included) + map_domain_techniques(obs_in)
        ents_in = {e for o in obs_in for e in o.entities}
        notes = [a for a in analyst_obs if ents_in & set(a.entities)]
        analysis = IncidentAnalysis(
            incident=incident, events=included, timeline=timeline, mitre=mappings,
            asserted_only=asserted_only_techniques(included, mappings), context=context, assessment=assessment,
            observations=obs_in, analyst_notes=notes,
            graph=build_graph(obs_in, corr, notes, len(norm.rejected), link_index=link_index) if obs_in else None,
            enrichments=enrich(obs_in, indicators),
            trace=trace,
        )
        result.incidents.append(analysis)
        ledger.append("SUFFICIENCY", {
            "incident": str(incident.incident_id), "verdict": assessment.verdict.value,
            "reason_codes": assessment.reason_codes, "assessment_sha256": assessment.assessment_sha256,
            "context_sha256": context.reproducibility.context_sha256,
        })
        ledger.append("MITRE_MAP", {
            "incident": str(incident.incident_id), "mapping_version": MAPPING_VERSION,
            "techniques": [{"id": m.technique_id, "rule": m.rule_id, "evidence": len(m.evidence_keys)} for m in mappings],
            "asserted_only": analysis.asserted_only,
        })
        ledger.append("LLM", {"incident": str(incident.incident_id), "status": "not_requested"})
    _finalize(result, ledger)
    for analysis in result.incidents:
        analysis.markdown = render_incident_report(result, analysis)
    if result.batch_assessment is not None:
        result.batch_markdown = render_abstention_report(result)
    return result


def _finalize(result: WorkflowResult, ledger: Ledger) -> None:
    ledger.append("REPORT", {"incidents": len(result.incidents), "workflow_version": WORKFLOW_VERSION})
    result.ledger = ledger.export()
    result.ledger_head = ledger.head
    result.ledger_ok, _ = verify_chain(result.ledger)


async def _llm_for_incident(analysis: IncidentAnalysis, provider: Any, attack_reference: AttackReferenceSource = None) -> None:
    context, assessment = analysis.context, analysis.assessment
    # ``attack_reference`` is the optional local ATT&CK catalogue (or None = not configured), injected by the caller.
    parser, validator = InvestigationResponseParser(), InvestigationOutputValidator(attack_reference=attack_reference)

    def fallback(reason: str, sufficiency: Optional[EvidenceSufficiencyAssessment] = None) -> InvestigationValidationResult:
        fb = parser.build_deterministic_fallback(context, reason, sufficiency)
        validated = validator.validate(fb, context)
        return InvestigationValidationResult(
            decision=GuardrailDecision.REJECT_TO_FALLBACK, is_valid=False, output=validated.output,
            violations=validated.violations, context_sha256=context.reproducibility.context_sha256,
            validated_at_utc=validated.validated_at_utc,
        )

    if assessment.abstain:
        analysis.llm_result = fallback("Evidence assessed INSUFFICIENT: " + ", ".join(assessment.reason_codes), assessment)
        analysis.llm_status = "abstained"
        return
    builder = InvestigationPromptBuilder(default_model=getattr(provider, "model_name", "llama3.1:8b"), structured_assertions=True)
    try:
        request = builder.build_request(
            context,
            sufficiency_note=assessment.limitation_note(),
            model_override=getattr(provider, "model_name", None),  # use the configured model, not the context's recorded default
            max_tokens=BOUNDED_MAX_TOKENS,  # the bounded schema keeps a valid answer far below this; see docs/06_AI/AI_Latency.md
        )
        raw = await GatedGenerator.generate(provider, request, assessment, context)
    except Exception as exc:  # noqa: BLE001 - provider failure or gate refusal: deterministic fallback
        analysis.llm_result = apply_sufficiency_disclosure(fallback(f"LLM invocation failed ({type(exc).__name__})"), assessment)
        # AI switched off by configuration is a deliberate state, not a failure: report it as such (Task 2).
        analysis.llm_status = "disabled" if isinstance(exc, LLMDisabledError) else f"fallback:{type(exc).__name__}"
        return
    try:
        parsed = parser.parse(raw, context)
        analysis.llm_result = apply_sufficiency_disclosure(validator.validate(parsed, context, assessment), assessment)
        analysis.llm_status = "validated"
    except Exception as exc:  # noqa: BLE001
        analysis.llm_result = apply_sufficiency_disclosure(fallback(f"Response parsing failed ({type(exc).__name__})"), assessment)
        analysis.llm_status = f"fallback:{type(exc).__name__}"


#: Upper bound on model invocations per run (Stage 5): inference is sequential and each call may take up to the
#: provider timeout, so an evidence set that forms many incidents must not translate into unbounded inference.
#: Incidents beyond the limit keep their deterministic analysis with ``llm_status = "skipped:llm_incident_limit"``.
MAX_LLM_INCIDENTS = 5


async def run_workflow(
    records: list[Any],
    assets: Optional[dict[str, str]] = None,
    provider: Any = None,
    digests: Optional[list[Optional[str]]] = None,
    event_keys: Optional[list[Optional[uuid.UUID]]] = None,
    max_llm_incidents: Optional[int] = None,
    indicators: Optional[IndicatorProvider] = None,
    attack_reference: AttackReferenceSource = None,
) -> WorkflowResult:
    """``analyze`` plus the optional gated LLM investigation and claim verification per incident."""
    from app.modules.correlation.report import render_incident_report

    result = analyze(records, assets, digests, event_keys, indicators)
    if provider is None:
        return result
    ledger = Ledger()
    for entry in result.ledger[:-1]:  # replay the chain up to (not including) REPORT, then extend it
        ledger.append(entry["step"], entry["details"])
    limit = MAX_LLM_INCIDENTS if max_llm_incidents is None else max_llm_incidents
    for position, analysis in enumerate(result.incidents):
        if position >= limit:
            analysis.llm_status = "skipped:llm_incident_limit"
        else:
            await _llm_for_incident(analysis, provider, attack_reference)
        out = analysis.llm_result.output if analysis.llm_result else None
        ledger.append("LLM_GATE", {
            "incident": str(analysis.incident.incident_id), "verdict": analysis.assessment.verdict.value,
            "provider_invoked": analysis.llm_status in ("validated",) or analysis.llm_status.startswith("fallback:"),
            "status": analysis.llm_status,
        })
        ledger.append("CLAIM_VERIFY", {
            "incident": str(analysis.incident.incident_id),
            "decision": analysis.llm_result.decision.value if analysis.llm_result else None,
            "claims": [
                {"id": str(c.claim_id), "category": c.category.value, "grounding": c.grounding_status.value}
                for c in (out.claims if out else [])
            ],
            "violations": [v.rule_id for v in (analysis.llm_result.violations if analysis.llm_result else [])],
        })
    _finalize(result, ledger)
    for analysis in result.incidents:
        analysis.markdown = render_incident_report(result, analysis)
    return result


def workflow_audit_details(analysis: IncidentAnalysis, result: WorkflowResult) -> dict[str, Any]:
    """Fixed-shape, payload-free dictionary fitting ``case_audit_events.details`` (DB write not wired: PARTIAL)."""
    details = analysis.assessment.audit_details()
    details.update({
        "workflow": WORKFLOW_VERSION,
        "incident_id": str(analysis.incident.incident_id),
        "context_sha256": analysis.context.reproducibility.context_sha256,
        "llm_status": analysis.llm_status,
        "techniques": [m.technique_id for m in analysis.mitre],
        "ledger_head": result.ledger_head,
    })
    return details


__all__ = [
    "IncidentAnalysis",
    "WORKFLOW_VERSION",
    "WorkflowResult",
    "analyze",
    "build_incident_context",
    "run_workflow",
    "workflow_audit_details",
]
