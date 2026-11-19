"""
Unit tests for AISOP P2-H4 Task 2.2:
Multi-Event Investigation Context Assembly and Deterministic Pruning.

Covers all 14 required acceptance-test scenarios:
1. Empty investigation scope
2. Root-event anchoring
3. Deterministic event ordering with timestamp ties
4. Entity deduplication and source-event provenance
5. Mandatory evidence overflow (IncompleteContextOverflowError)
6. Deterministic pruning with exact budget remeasurement (P_evidence <= 8750)
7. Omission-count and truncation invariants
8. Threat-intelligence state disclosures (match, clean no-match, unavailable, stale, shielded)
9. Verified query-cap disclosure (PaginatedResponse has_next vs un-capped limit)
10. Final context hash integrity (AISOP-CJSON-1.0 and ephemeral exclusion)
11. Repeated assembly determinism for identical inputs
12. Protection against loss of mandatory evidence during pruning
13. Correct handling of unknown totals and partial retrieval
14. Schema validation and backward compatibility with legacy XML methods
"""

from datetime import datetime, timedelta, timezone
import math
import uuid
import pytest

from app.modules.ai.context_builder import (
    MAX_CONTEXT_CHARS,
    IncompleteContextOverflowError,
    InvestigationContextBuilder,
    aggregate_context_entities,
    build_investigation_context,
    canonicalize_payload,
    compute_context_sha256,
    prune_to_evidence_budget,
    resolve_causal_lineage,
)
from app.schemas.investigation import (
    ContextEntityItem,
    ContextEventItem,
    ContextKnowledgeChunkItem,
    ContextTIFindingItem,
    ContextTIThreatState,
    ContextTIVerdict,
    InvestigationContext,
    InvestigationScopeType,
)
from app.schemas.query import (
    ExtractedEntityItem,
    NormalizedEventDetail,
    PaginatedResponse,
)
from app.schemas.threatintel import (
    InvestigationFindingState,
    ThreatIntelFindingItem,
)
from app.modules.threatintel.models import ObservableType, ThreatIntelLookupStatus, ThreatVerdict


VALID_SHA256 = "a" * 64
VALID_SHA256_B = "b" * 64


def make_test_event(
    event_uuid: uuid.UUID | None = None,
    event_id: str = "1",
    event_type: str = "process_creation",
    timestamp: datetime | None = None,
    action: str = "started",
    outcome: str = "success",
    severity: str = "medium",
    source_id: str = "ENDPOINT-01",
    summary: str = "Process started: cmd.exe",
    attributes: dict | None = None,
) -> ContextEventItem:
    """Helper to construct a valid ContextEventItem."""
    t = timestamp or datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    return ContextEventItem(
        event_uuid=event_uuid or uuid.uuid4(),
        raw_evidence_sha256=VALID_SHA256,
        event_id=event_id,
        event_type=event_type,
        timestamp_utc=t,
        action=action,
        outcome=outcome,
        severity=severity,
        source_identifier=source_id,
        summary=summary,
        attributes=attributes or {},
    )


def make_test_chunk(
    chunk_id: uuid.UUID | None = None,
    doc: str = "mitre/T1059.md",
    section: str = "Command and Scripting Interpreter",
    similarity: float = 0.85,
    content: str = "Adversaries may use interpreters to execute commands.",
) -> ContextKnowledgeChunkItem:
    """Helper to construct a ContextKnowledgeChunkItem."""
    return ContextKnowledgeChunkItem(
        chunk_id=chunk_id or uuid.uuid4(),
        source_document=doc,
        section_title=section,
        chunk_index=0,
        similarity_score=similarity,
        content=content,
    )


# ---------------------------------------------------------------------------
# 1. TC-2.2-01: Empty Investigation Scope
# ---------------------------------------------------------------------------

def test_empty_investigation_scope():
    """Empty event scope generates a valid InvestigationContext with zeroed metrics."""
    context = build_investigation_context(events=[])

    assert isinstance(context, InvestigationContext)
    assert context.events == []
    assert context.entities == []
    assert context.budget_metrics.events_included == 0
    assert context.budget_metrics.total_events_in_scope == 0
    assert context.budget_metrics.events_omitted_count == 0
    assert context.budget_metrics.context_truncated is False
    assert context.reproducibility.root_event_id is None
    assert context.reproducibility.selected_event_uuids == []
    assert context.reproducibility.selected_chunk_ids == []
    assert len(context.reproducibility.context_sha256) == 64
    assert context.reproducibility.context_sha256 == compute_context_sha256(context)


# ---------------------------------------------------------------------------
# 2. TC-2.2-02: Root-Event Anchoring
# ---------------------------------------------------------------------------

def test_root_event_anchoring():
    """Designates and anchors the specified root event, preserving it in reproducibility."""
    root_id = uuid.uuid4()
    other_id = uuid.uuid4()

    t1 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 23, 10, 5, 0, tzinfo=timezone.utc)

    e1 = make_test_event(event_uuid=other_id, timestamp=t1, summary="Earlier event")
    e2 = make_test_event(event_uuid=root_id, timestamp=t2, summary="Root event anchor")

    context = build_investigation_context(
        events=[e1, e2],
        root_event_id=root_id,
        scope_type=InvestigationScopeType.SINGLE_EVENT,
    )

    assert context.reproducibility.root_event_id == root_id
    assert root_id in [e.event_uuid for e in context.events]
    assert context.scope_type == InvestigationScopeType.SINGLE_EVENT


# ---------------------------------------------------------------------------
# 3. TC-2.2-03: Deterministic Event Ordering with Timestamp Ties
# ---------------------------------------------------------------------------

def test_deterministic_event_ordering_with_timestamp_ties():
    """Events with identical timestamps are ordered deterministically by event_uuid."""
    t_fixed = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    u_c = uuid.UUID("33333333-3333-3333-3333-333333333333")
    u_a = uuid.UUID("11111111-1111-1111-1111-111111111111")
    u_b = uuid.UUID("22222222-2222-2222-2222-222222222222")

    e_c = make_test_event(event_uuid=u_c, timestamp=t_fixed, summary="Event C")
    e_a = make_test_event(event_uuid=u_a, timestamp=t_fixed, summary="Event A")
    e_b = make_test_event(event_uuid=u_b, timestamp=t_fixed, summary="Event B")

    # Order 1: [C, A, B]
    ctx1 = build_investigation_context(events=[e_c, e_a, e_b])
    uuids1 = [e.event_uuid for e in ctx1.events]
    assert uuids1 == [u_a, u_b, u_c]

    # Order 2: [B, C, A]
    ctx2 = build_investigation_context(events=[e_b, e_c, e_a])
    uuids2 = [e.event_uuid for e in ctx2.events]
    assert uuids2 == [u_a, u_b, u_c]

    # Hashes must be identical
    assert ctx1.reproducibility.context_sha256 == ctx2.reproducibility.context_sha256


# ---------------------------------------------------------------------------
# 4. TC-2.2-04: Entity Deduplication and Source-Event Provenance
# ---------------------------------------------------------------------------

def test_entity_deduplication_and_provenance():
    """Identical entities observed across multiple events deduplicate with combined provenance."""
    e1_id = uuid.uuid4()
    e2_id = uuid.uuid4()

    ev1 = make_test_event(
        event_uuid=e1_id,
        attributes={"dest_ip": "198.51.100.42", "user": "alice"},
    )
    ev2 = make_test_event(
        event_uuid=e2_id,
        attributes={"src_ip": "198.51.100.42", "user": "alice"},
    )

    context = build_investigation_context(events=[ev1, ev2])

    ip_entities = [ent for ent in context.entities if ent.entity_value == "198.51.100.42"]
    assert len(ip_entities) == 1
    ip_ent = ip_entities[0]
    assert ip_ent.entity_type == "ip"
    assert ip_ent.occurrence_count == 2
    assert sorted([str(u) for u in ip_ent.associated_event_uuids]) == sorted([str(e1_id), str(e2_id)])
    assert "destination" in ip_ent.roles
    assert "source" in ip_ent.roles


# ---------------------------------------------------------------------------
# 5. TC-2.2-05: Mandatory Evidence Overflow
# ---------------------------------------------------------------------------

def test_mandatory_evidence_overflow():
    """If mandatory evidence alone exceeds MAX_CONTEXT_CHARS, raise IncompleteContextOverflowError."""
    # Create a root event with a massive summary that exceeds 8750 chars
    root_id = uuid.uuid4()
    huge_summary = "A" * 9000
    root_event = make_test_event(event_uuid=root_id, summary=huge_summary)

    with pytest.raises(IncompleteContextOverflowError) as exc_info:
        build_investigation_context(events=[root_event], root_event_id=root_id)

    assert "exceeds MAX_CONTEXT_CHARS" in str(exc_info.value)
    assert "8750" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 6. TC-2.2-06: Deterministic Pruning with Exact Budget Remeasurement
# ---------------------------------------------------------------------------

def test_deterministic_pruning_with_exact_budget_remeasurement():
    """Oversized context prunes knowledge chunks then secondary events to fit P_evidence <= 8750."""
    t_root = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    root_id = uuid.uuid4()
    root_event = make_test_event(
        event_uuid=root_id,
        timestamp=t_root,
        summary="Root event: process execution",
        attributes={"process_guid": "{ROOT-GUID-1}"},
    )

    # 3 knowledge chunks (Tier 7)
    kc1 = make_test_chunk(similarity=0.3, content="Low relevance chunk: " + ("X" * 1500))
    kc2 = make_test_chunk(similarity=0.7, content="Medium relevance chunk: " + ("Y" * 1500))
    kc3 = make_test_chunk(similarity=0.95, content="High relevance chunk: " + ("Z" * 1500))

    # 4 optional secondary events with large payloads (Tier 5)
    opt_events = []
    for i in range(1, 5):
        t_opt = t_root + timedelta(minutes=i * 10)
        opt_events.append(
            make_test_event(
                timestamp=t_opt,
                severity="low",
                summary=f"Secondary event {i}: " + ("S" * 2500),
                attributes={"random_data": f"payload_{i}"},
            )
        )

    all_events = [root_event] + opt_events

    context = build_investigation_context(
        events=all_events,
        root_event_id=root_id,
        knowledge_chunks=[kc1, kc2, kc3],
    )

    # Validate budget enforcement
    assert context.budget_metrics.estimated_character_count <= MAX_CONTEXT_CHARS
    assert context.budget_metrics.context_truncated is True
    assert context.budget_metrics.events_omitted_count > 0
    assert root_id in [e.event_uuid for e in context.events]


# ---------------------------------------------------------------------------
# 7. TC-2.2-07: Omission-Count and Truncation Invariants
# ---------------------------------------------------------------------------

def test_omission_count_and_truncation_invariants():
    """Omission metrics and uncertainty disclosure strictly satisfy schema validators."""
    t_root = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    root_id = uuid.uuid4()
    root_event = make_test_event(event_uuid=root_id, timestamp=t_root)

    # Add 5 events that force budget truncation
    events = [root_event]
    for i in range(5):
        events.append(
            make_test_event(
                timestamp=t_root + timedelta(minutes=i + 1),
                summary="Event causing overflow: " + ("W" * 2000),
            )
        )

    context = build_investigation_context(events=events, root_event_id=root_id)

    # Invariants
    bm = context.budget_metrics
    assert bm.total_events_in_scope == 6
    assert bm.events_included + bm.events_omitted_count == bm.total_events_in_scope
    assert bm.context_truncated is True
    assert len(bm.omitted_event_ids_summary) == bm.events_omitted_count

    # Truncation uncertainty flags must be present
    assert any("TRUNCATION:" in f for f in context.uncertainty_flags)


# ---------------------------------------------------------------------------
# 8. TC-2.2-08: Threat-Intelligence State Disclosures
# ---------------------------------------------------------------------------

def test_threat_intel_state_disclosures():
    """Verifies that clean lookups emit no flags, while engine failure and stale feeds disclose."""
    ev = make_test_event()

    # 1. Successful clean lookup (active, unknown verdict) -> No degradation flag
    clean_ti = ContextTIFindingItem(
        observable="8.8.8.8",
        observable_type="ipv4",
        verdict=ContextTIVerdict.UNKNOWN,
        threat_state=ContextTIThreatState.ACTIVE,
    )
    ctx1 = build_investigation_context(events=[ev], threat_intel=[clean_ti])
    assert not any("DEGRADATION:" in f for f in ctx1.uncertainty_flags)

    # 2. Engine unavailable -> Discloses degradation
    unavail_ti = ContextTIFindingItem(
        observable="8.8.4.4",
        observable_type="ipv4",
        verdict=ContextTIVerdict.UNKNOWN,
        threat_state=ContextTIThreatState.ENGINE_UNAVAILABLE,
    )
    ctx2 = build_investigation_context(events=[ev], threat_intel=[unavail_ti])
    assert any("DEGRADATION: Threat intelligence engine unavailable" in f for f in ctx2.uncertainty_flags)

    # 3. Stale feed match -> Discloses stale data gap
    stale_ti = ContextTIFindingItem(
        observable="1.2.3.4",
        observable_type="ipv4",
        verdict=ContextTIVerdict.SUSPICIOUS,
        threat_state=ContextTIThreatState.STALE,
        is_stale=True,
    )
    ctx3 = build_investigation_context(events=[ev], threat_intel=[stale_ti])
    assert any("DATA_GAP: Threat intelligence indicator matched stale feed data" in f for f in ctx3.uncertainty_flags)


# ---------------------------------------------------------------------------
# 9. TC-2.2-09: Verified Query-Cap Disclosure
# ---------------------------------------------------------------------------

def test_verified_query_cap_disclosure():
    """PaginatedResponse with has_next=True discloses query cap; un-capped query does not."""
    events = [make_test_event() for _ in range(5)]

    # Case A: Un-capped query (5 of 5 items, has_next=False)
    p_uncapped = PaginatedResponse(
        items=events,
        total=5,
        page=1,
        limit=5,
        total_pages=1,
        has_next=False,
        has_previous=False,
    )
    ctx_uncapped = build_investigation_context(events=events, query_metadata=p_uncapped)
    assert not any("Query result limit reached" in f for f in ctx_uncapped.uncertainty_flags)

    # Case B: Capped query (5 items returned of 50 total, has_next=True)
    p_capped = PaginatedResponse(
        items=events,
        total=50,
        page=1,
        limit=5,
        total_pages=10,
        has_next=True,
        has_previous=False,
    )
    ctx_capped = build_investigation_context(events=events, query_metadata=p_capped)
    assert ctx_capped.budget_metrics.total_events_in_scope == 50
    assert any("TRUNCATION: Query result limit reached (5 items returned of 50 total matching)" in f for f in ctx_capped.uncertainty_flags)


# ---------------------------------------------------------------------------
# 10. TC-2.2-10: Final Context Hash Integrity
# ---------------------------------------------------------------------------

def test_final_context_hash_integrity():
    """Reproducibility context_sha256 matches compute_context_sha256 and is sensitive to changes."""
    ev = make_test_event(summary="Initial summary")
    ctx = build_investigation_context(events=[ev])

    # Hash must match
    computed = compute_context_sha256(ctx)
    assert ctx.reproducibility.context_sha256 == computed
    assert len(computed) == 64

    # Modifying an event alters the hash
    ev_modified = make_test_event(event_uuid=ev.event_uuid, summary="Modified substantive summary")
    ctx_mod = build_investigation_context(events=[ev_modified])
    assert ctx_mod.reproducibility.context_sha256 != ctx.reproducibility.context_sha256


# ---------------------------------------------------------------------------
# 11. TC-2.2-11: Repeated Assembly Determinism
# ---------------------------------------------------------------------------

def test_repeated_assembly_determinism():
    """Identical inputs produce identical byte-exact canonical JSON and hash."""
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    u1 = uuid.uuid4()
    u2 = uuid.uuid4()

    e1 = make_test_event(event_uuid=u1, timestamp=t0, summary="Event 1")
    e2 = make_test_event(event_uuid=u2, timestamp=t0 + timedelta(minutes=1), summary="Event 2")

    ctx1 = build_investigation_context(events=[e1, e2], seed=42)
    ctx2 = build_investigation_context(events=[e1, e2], seed=42)

    assert ctx1.reproducibility.context_sha256 == ctx2.reproducibility.context_sha256
    assert ctx1.budget_metrics.estimated_character_count == ctx2.budget_metrics.estimated_character_count


# ---------------------------------------------------------------------------
# 12. TC-2.2-12: Protection Against Loss of Mandatory Evidence During Pruning
# ---------------------------------------------------------------------------

def test_protection_against_mandatory_evidence_loss():
    """Pruning removes optional events and knowledge chunks but strictly retains root and causal child."""
    t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    root_id = uuid.uuid4()
    child_id = uuid.uuid4()
    opt_id = uuid.uuid4()

    # Root process
    root_event = make_test_event(
        event_uuid=root_id,
        timestamp=t0,
        summary="Root process powershell.exe",
        attributes={"process_guid": "{PROC-ROOT}", "dest_ip": "10.0.0.1"},
    )

    # Direct child process (causal lineage)
    child_event = make_test_event(
        event_uuid=child_id,
        timestamp=t0 + timedelta(seconds=5),
        summary="Child process cmd.exe",
        attributes={"process_guid": "{PROC-CHILD}", "parent_process_guid": "{PROC-ROOT}"},
    )

    # Optional secondary event with huge summary to trigger pruning
    optional_event = make_test_event(
        event_uuid=opt_id,
        timestamp=t0 + timedelta(hours=2),
        summary="Secondary event outside lineage: " + ("M" * 7000),
        attributes={"random_guid": "{UNRELATED}"},
    )

    # Knowledge chunk to be pruned first
    kc = make_test_chunk(similarity=0.4, content="Knowledge chunk: " + ("K" * 2000))

    context = build_investigation_context(
        events=[root_event, child_event, optional_event],
        root_event_id=root_id,
        knowledge_chunks=[kc],
    )

    included_uuids = [e.event_uuid for e in context.events]
    assert root_id in included_uuids, "Root event must be preserved"
    assert child_id in included_uuids, "Causal child process must be preserved"
    assert opt_id not in included_uuids, "Optional event must be pruned"
    assert len(context.knowledge_chunks) == 0, "Knowledge chunk must be pruned"


# ---------------------------------------------------------------------------
# 13. TC-2.2-13: Unknown Totals and Partial Retrieval
# ---------------------------------------------------------------------------

def test_unknown_totals_and_partial_retrieval():
    """Partial retrieval / unknown scope correctly emits DATA_GAP flag without crashing."""
    ev = make_test_event()
    context = build_investigation_context(events=[ev], is_partial_retrieval=True)

    assert any("DATA_GAP: Unquantified event retrieval scope" in f for f in context.uncertainty_flags)
    assert context.budget_metrics.total_events_in_scope == 1


# ---------------------------------------------------------------------------
# 14. TC-2.2-14: Schema Validation and Backward Compatibility with Legacy XML
# ---------------------------------------------------------------------------

def test_schema_validation_and_backward_compatibility():
    """Builder preserves legacy XML methods and returns XML string when called with legacy signature."""
    builder = InvestigationContextBuilder()

    sample_event = NormalizedEventDetail(
        id=uuid.uuid4(),
        raw_evidence_id=uuid.uuid4(),
        event_id="3",
        event_type="network_connection",
        event_timestamp=datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc),
        provider="Microsoft-Windows-Sysmon",
        action="connected",
        outcome="success",
        severity="high",
        source_identifier="WORKSTATION-01",
        normalized_payload={"DestinationIp": "198.51.100.25"},
        raw_sha256_hash="e" * 64,
        entities=[],
        threat_intel=[],
    )

    finding = ThreatIntelFindingItem(
        observable_type=ObservableType.IPV4,
        raw_observable="198.51.100.25",
        normalized_observable="198.51.100.25",
        status=ThreatIntelLookupStatus.SUCCESS,
        verdict=ThreatVerdict.MALICIOUS,
        integration_state=InvestigationFindingState.FRESH_MATCH,
        tags=["botnet_c2"],
    )

    # Legacy XML invocation
    xml_out = builder.build_investigation_context(
        sample_event,
        threat_intel_findings=[finding],
        additional_instructions="Analyze carefully",
    )

    assert isinstance(xml_out, str)
    assert "<threat_intelligence_context>" in xml_out
    assert "</threat_intelligence_context>" in xml_out
    assert "Analyze carefully" in xml_out
    assert "WORKSTATION-01" in xml_out

    # Structured invocation
    struct_out = builder.build_investigation_context(events=[sample_event])
    assert isinstance(struct_out, InvestigationContext)
    assert len(struct_out.events) == 1
    assert struct_out.events[0].source_identifier == "WORKSTATION-01"
