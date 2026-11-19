"""
Unit tests for AISOP P2-H4 typed investigation schemas and domain contracts.

Tests cover:
1. Valid minimal investigation context.
2. Valid fully populated context.
3. Missing required fields across all models.
4. Invalid UUID validation.
5. Invalid SHA-256 formatting and case normalization.
6. UTC timestamp normalization, non-UTC offsets, and timezone-awareness enforcement (F-01).
7. Invalid confidence and similarity ranges.
8. Negative counts and inconsistent budget metrics.
9. Empty investigation scope.
10. Missing or unavailable threat-intelligence data.
11. Valid and invalid claim categories.
12. Valid and invalid grounding statuses.
13. Incomplete-context and omission metadata consistency for events AND entities (F-02).
14. Structured output with valid evidence references and grounding score consistency.
15. Empty uncertainty and data-gap collections where permitted.
16. Independent mutable defaults across model instances.
17. Serialization and deserialization round trips (JSON & dict).
18. Unknown-field handling (extra="forbid" project policy enforcement).
19. Strict time-window rules across request, reproducibility, and context (F-03).
20. Meaningful non-whitespace summaries for events and structured output (F-04).
"""

from datetime import datetime, timedelta, timezone
import json
import uuid

from pydantic import ValidationError
import pytest

from app.schemas.investigation import (
    BudgetMetrics,
    ClaimCategory,
    ContextEntityItem,
    ContextEventItem,
    ContextKnowledgeChunkItem,
    ContextTIFindingItem,
    ContextTIThreatState,
    ContextTIVerdict,
    FactualClaimItem,
    GroundingStatus,
    InvestigationContext,
    InvestigationScopeType,
    InvestigationSynthesizeRequest,
    MitreAttackHypothesis,
    ReproducibilityRecord,
    StructuredInvestigationOutput,
)


# ---------------------------------------------------------------------------
# Test Fixtures & Helpers
# ---------------------------------------------------------------------------

VALID_SHA256_A = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
VALID_SHA256_B = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


def make_test_event(
    event_uuid: uuid.UUID | None = None,
    ts: datetime | None = None,
    sha256: str = VALID_SHA256_A,
    summary: str = "Process powershell.exe created by explorer.exe",
) -> ContextEventItem:
    return ContextEventItem(
        event_uuid=event_uuid or uuid.uuid4(),
        raw_evidence_sha256=sha256,
        event_id="1",
        event_type="process_creation",
        timestamp_utc=ts or datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc),
        action="created",
        outcome="success",
        severity="medium",
        source_identifier="WORKSTATION-01",
        summary=summary,
        attributes={"process_name": "powershell.exe", "pid": 4120},
    )


def make_test_entity(
    event_uuids: list[uuid.UUID] | None = None,
) -> ContextEntityItem:
    return ContextEntityItem(
        entity_type="process",
        entity_value="powershell.exe",
        roles=["executed"],
        occurrence_count=len(event_uuids) if event_uuids else 1,
        associated_event_uuids=event_uuids or [uuid.uuid4()],
        attributes={"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
    )


def make_test_chunk() -> ContextKnowledgeChunkItem:
    return ContextKnowledgeChunkItem(
        chunk_id=uuid.uuid4(),
        source_document="mitre/T1059.001.md",
        section_title="PowerShell Execution Overview",
        chunk_index=0,
        similarity_score=0.88,
        content="Adversaries may use PowerShell to execute arbitrary commands and scripts.",
    )


# ---------------------------------------------------------------------------
# 1. Valid Minimal Investigation Context
# ---------------------------------------------------------------------------

def test_valid_minimal_investigation_context():
    start = datetime(2026, 10, 23, 8, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)

    budget = BudgetMetrics(
        total_events_in_scope=0,
        events_included=0,
        events_omitted_count=0,
        context_truncated=False,
    )
    repro = ReproducibilityRecord(
        time_window_start=start,
        time_window_end=end,
        context_sha256=VALID_SHA256_A,
        selected_event_uuids=[],
        selected_chunk_ids=[],
    )

    ctx = InvestigationContext(
        scope_type=InvestigationScopeType.INCIDENT_TIMELINE,
        time_window_start=start,
        time_window_end=end,
        budget_metrics=budget,
        reproducibility=repro,
    )

    assert ctx.schema_version == "1.0.0"
    assert isinstance(ctx.investigation_id, uuid.UUID)
    assert ctx.events == []
    assert ctx.entities == []
    assert ctx.threat_intel == []
    assert ctx.knowledge_chunks == []
    assert ctx.target_hosts == []
    assert ctx.uncertainty_flags == []
    assert ctx.assembled_at.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# 2. Valid Fully Populated Context
# ---------------------------------------------------------------------------

def test_valid_fully_populated_context():
    start = datetime(2026, 10, 23, 8, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)

    event1_id = uuid.uuid4()
    event2_id = uuid.uuid4()
    event1 = make_test_event(event_uuid=event1_id, ts=start + timedelta(minutes=10))
    event2 = make_test_event(event_uuid=event2_id, ts=start + timedelta(minutes=20))

    entity1 = ContextEntityItem(
        entity_type="ip",
        entity_value="198.51.100.10",
        roles=["destination"],
        occurrence_count=2,
        associated_event_uuids=[event1_id, event2_id],
    )
    entity2 = make_test_entity(event_uuids=[event1_id])

    ti1 = ContextTIFindingItem(
        observable="198.51.100.10",
        observable_type="ipv4",
        verdict=ContextTIVerdict.MALICIOUS,
        threat_state=ContextTIThreatState.ACTIVE,
        is_shielded=False,
        is_stale=False,
        tags=["c2", "cobalt_strike"],
        source_feeds=["abuse_ch"],
        confidence=0.95,
    )
    ti2 = ContextTIFindingItem(
        observable="10.0.0.5",
        observable_type="ipv4",
        verdict=ContextTIVerdict.BENIGN,
        threat_state=ContextTIThreatState.SHIELDED_INTERNAL,
        is_shielded=True,
        confidence=1.0,
    )

    chunk = make_test_chunk()

    budget = BudgetMetrics(
        total_events_in_scope=2,
        events_included=2,
        events_omitted_count=0,
        total_entities_in_scope=2,
        entities_included=2,
        knowledge_chunks_included=1,
        estimated_character_count=3500,
        estimated_tokens=1000,
        context_truncated=False,
    )

    repro = ReproducibilityRecord(
        time_window_start=start,
        time_window_end=end,
        root_event_id=event1_id,
        query_filter="powershell",
        selected_event_uuids=[event1_id, event2_id],
        selected_chunk_ids=[chunk.chunk_id],
        context_sha256=VALID_SHA256_B,
    )

    ctx = InvestigationContext(
        scope_type=InvestigationScopeType.SINGLE_EVENT,
        time_window_start=start,
        time_window_end=end,
        target_hosts=["WORKSTATION-01"],
        events=[event1, event2],
        entities=[entity1, entity2],
        threat_intel=[ti1, ti2],
        knowledge_chunks=[chunk],
        budget_metrics=budget,
        reproducibility=repro,
        uncertainty_flags=["INFO: Test investigation complete"],
    )

    assert len(ctx.events) == 2
    assert len(ctx.entities) == 2
    assert len(ctx.threat_intel) == 2
    assert len(ctx.knowledge_chunks) == 1
    assert ctx.reproducibility.root_event_id == event1_id
    assert ctx.target_hosts == ["WORKSTATION-01"]


# ---------------------------------------------------------------------------
# 3. Missing Required Fields
# ---------------------------------------------------------------------------

def test_missing_required_fields_raises_validation_error():
    # ContextEventItem missing raw_evidence_sha256 and event_type
    with pytest.raises(ValidationError) as exc:
        ContextEventItem(
            event_uuid=uuid.uuid4(),
            event_id="1",
            timestamp_utc=datetime.now(timezone.utc),
            action="executed",
            source_identifier="host1",
            summary="test",
        )
    errors = str(exc.value)
    assert "raw_evidence_sha256" in errors
    assert "event_type" in errors

    # BudgetMetrics missing total_events_in_scope
    with pytest.raises(ValidationError):
        BudgetMetrics(events_included=0, events_omitted_count=0)

    # FactualClaimItem missing claim_text and category
    with pytest.raises(ValidationError):
        FactualClaimItem(
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
            confidence=0.9,
        )


# ---------------------------------------------------------------------------
# 4. Invalid UUID Validation
# ---------------------------------------------------------------------------

def test_invalid_uuid_rejected():
    with pytest.raises(ValidationError) as exc:
        ContextEventItem(
            event_uuid="not-a-valid-uuid",  # type: ignore[arg-type]
            raw_evidence_sha256=VALID_SHA256_A,
            event_id="1",
            event_type="test",
            timestamp_utc=datetime.now(timezone.utc),
            action="test",
            source_identifier="host",
            summary="test",
        )
    assert "event_uuid" in str(exc.value)

    with pytest.raises(ValidationError):
        FactualClaimItem(
            claim_text="Valid claim",
            category=ClaimCategory.OBSERVED_FACT,
            supporting_evidence_ids=["malformed-uuid"],  # type: ignore[list-item]
            references_exist=True,
            grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED,
            confidence=0.8,
        )


# ---------------------------------------------------------------------------
# 5. Invalid SHA-256 Formatting & Normalization
# ---------------------------------------------------------------------------

def test_sha256_validation_length_and_hex():
    # Too short (63 chars)
    with pytest.raises(ValidationError) as exc:
        ContextEventItem(
            event_uuid=uuid.uuid4(),
            raw_evidence_sha256="a" * 63,
            event_id="1",
            event_type="test",
            timestamp_utc=datetime.now(timezone.utc),
            action="test",
            source_identifier="host",
            summary="test",
        )
    assert "raw_evidence_sha256" in str(exc.value)

    # Too long (65 chars)
    with pytest.raises(ValidationError):
        ContextEventItem(
            event_uuid=uuid.uuid4(),
            raw_evidence_sha256="a" * 65,
            event_id="1",
            event_type="test",
            timestamp_utc=datetime.now(timezone.utc),
            action="test",
            source_identifier="host",
            summary="test",
        )

    # Non-hex characters
    with pytest.raises(ValidationError):
        ContextEventItem(
            event_uuid=uuid.uuid4(),
            raw_evidence_sha256="g" * 64,
            event_id="1",
            event_type="test",
            timestamp_utc=datetime.now(timezone.utc),
            action="test",
            source_identifier="host",
            summary="test",
        )

    # Uppercase hex is accepted and normalized to lowercase
    event = ContextEventItem(
        event_uuid=uuid.uuid4(),
        raw_evidence_sha256=VALID_SHA256_A.upper(),
        event_id="1",
        event_type="test",
        timestamp_utc=datetime.now(timezone.utc),
        action="test",
        source_identifier="host",
        summary="test",
    )
    assert event.raw_evidence_sha256 == VALID_SHA256_A.lower()


# ---------------------------------------------------------------------------
# 6. UTC Timestamp Normalization & Timezone Handling (F-01)
# ---------------------------------------------------------------------------

def test_utc_normalization_and_timezone_handling():
    # 1. Naive datetime must be rejected
    naive_dt = datetime(2026, 10, 23, 10, 0, 0)
    with pytest.raises(ValidationError) as exc:
        ContextEventItem(
            event_uuid=uuid.uuid4(),
            raw_evidence_sha256=VALID_SHA256_A,
            event_id="1",
            event_type="test",
            timestamp_utc=naive_dt,
            action="test",
            source_identifier="host",
            summary="test action",
        )
    assert "timestamp_utc must be timezone-aware" in str(exc.value)

    # 2. Non-UTC offset (+05:30) is normalized to UTC
    ist = timezone(timedelta(hours=5, minutes=30))
    dt_ist = datetime(2026, 10, 23, 10, 0, 0, tzinfo=ist)
    event_ist = ContextEventItem(
        event_uuid=uuid.uuid4(),
        raw_evidence_sha256=VALID_SHA256_A,
        event_id="1",
        event_type="test",
        timestamp_utc=dt_ist,
        action="test",
        source_identifier="host",
        summary="test action",
    )
    assert event_ist.timestamp_utc.tzinfo == timezone.utc
    assert event_ist.timestamp_utc == datetime(2026, 10, 23, 4, 30, 0, tzinfo=timezone.utc)

    # 3. Non-UTC offset (-04:00) is normalized to UTC
    edt = timezone(timedelta(hours=-4))
    dt_edt = datetime(2026, 10, 23, 0, 30, 0, tzinfo=edt)
    event_edt = ContextEventItem(
        event_uuid=uuid.uuid4(),
        raw_evidence_sha256=VALID_SHA256_A,
        event_id="1",
        event_type="test",
        timestamp_utc=dt_edt,
        action="test",
        source_identifier="host",
        summary="test action",
    )
    assert event_edt.timestamp_utc.tzinfo == timezone.utc
    assert event_edt.timestamp_utc == datetime(2026, 10, 23, 4, 30, 0, tzinfo=timezone.utc)

    # 4. Equivalent instants expressed in different offsets produce equal UTC values
    assert event_ist.timestamp_utc == event_edt.timestamp_utc


# ---------------------------------------------------------------------------
# 7. Invalid Confidence and Similarity Ranges
# ---------------------------------------------------------------------------

def test_confidence_and_similarity_range_constraints():
    # Confidence > 1.0
    with pytest.raises(ValidationError):
        ContextTIFindingItem(
            observable="198.51.100.1",
            observable_type="ipv4",
            confidence=1.1,
        )

    # Confidence < 0.0
    with pytest.raises(ValidationError):
        FactualClaimItem(
            claim_text="Test claim",
            category=ClaimCategory.INFERENCE,
            references_exist=True,
            grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED,
            confidence=-0.05,
        )

    # Similarity score > 1.0
    with pytest.raises(ValidationError):
        ContextKnowledgeChunkItem(
            chunk_id=uuid.uuid4(),
            source_document="doc.md",
            section_title="title",
            chunk_index=0,
            similarity_score=1.05,
            content="content",
        )

    # Similarity score < 0.0
    with pytest.raises(ValidationError):
        ContextKnowledgeChunkItem(
            chunk_id=uuid.uuid4(),
            source_document="doc.md",
            section_title="title",
            chunk_index=0,
            similarity_score=-0.1,
            content="content",
        )


# ---------------------------------------------------------------------------
# 8. Negative Counts and Inconsistent Budget Metrics
# ---------------------------------------------------------------------------

def test_negative_counts_and_budget_metrics_invariants():
    # Negative total_events_in_scope
    with pytest.raises(ValidationError):
        BudgetMetrics(
            total_events_in_scope=-5,
            events_included=0,
            events_omitted_count=0,
        )

    # events_included > total_events_in_scope
    with pytest.raises(ValidationError) as exc:
        BudgetMetrics(
            total_events_in_scope=5,
            events_included=10,
            events_omitted_count=0,
        )
    assert "cannot exceed total_events_in_scope" in str(exc.value)

    # Inconsistent events_omitted_count (5 total, 3 included => must be 2 omitted, not 0)
    with pytest.raises(ValidationError) as exc:
        BudgetMetrics(
            total_events_in_scope=5,
            events_included=3,
            events_omitted_count=0,
            context_truncated=True,
        )
    assert "events_omitted_count" in str(exc.value)

    # omitted_event_ids_summary count exceeds events_omitted_count
    with pytest.raises(ValidationError) as exc:
        BudgetMetrics(
            total_events_in_scope=5,
            events_included=4,
            events_omitted_count=1,
            omitted_event_ids_summary=[uuid.uuid4(), uuid.uuid4()],
            context_truncated=True,
        )
    assert "cannot exceed events_omitted_count" in str(exc.value)


# ---------------------------------------------------------------------------
# 9. Empty Investigation Scope
# ---------------------------------------------------------------------------

def test_empty_investigation_scope_permitted():
    start = datetime(2026, 10, 23, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 10, 23, 1, 0, 0, tzinfo=timezone.utc)

    budget = BudgetMetrics(
        total_events_in_scope=0,
        events_included=0,
        events_omitted_count=0,
        context_truncated=False,
    )
    repro = ReproducibilityRecord(
        time_window_start=start,
        time_window_end=end,
        context_sha256=VALID_SHA256_A,
    )

    ctx = InvestigationContext(
        scope_type=InvestigationScopeType.INCIDENT_TIMELINE,
        time_window_start=start,
        time_window_end=end,
        budget_metrics=budget,
        reproducibility=repro,
    )

    assert len(ctx.events) == 0
    assert len(ctx.entities) == 0
    assert ctx.budget_metrics.events_included == 0


# ---------------------------------------------------------------------------
# 10. Missing or Unavailable Threat-Intelligence Data
# ---------------------------------------------------------------------------

def test_missing_or_unavailable_threat_intel():
    # Default unpopulated finding state
    ti = ContextTIFindingItem(
        observable="192.0.2.1",
        observable_type="ipv4",
    )
    assert ti.verdict == ContextTIVerdict.UNKNOWN
    assert ti.threat_state == ContextTIThreatState.ENGINE_UNAVAILABLE
    assert ti.is_shielded is False
    assert ti.is_stale is False
    assert ti.tags == []
    assert ti.source_feeds == []

    # Invariant: is_shielded=True requires threat_state="shielded_internal"
    with pytest.raises(ValidationError) as exc:
        ContextTIFindingItem(
            observable="10.0.0.1",
            observable_type="ipv4",
            is_shielded=True,
            threat_state=ContextTIThreatState.ACTIVE,
        )
    assert "threat_state must be 'shielded_internal'" in str(exc.value)


# ---------------------------------------------------------------------------
# 11. Valid and Invalid Claim Categories
# ---------------------------------------------------------------------------

def test_claim_categories():
    for cat in [
        ClaimCategory.OBSERVED_FACT,
        ClaimCategory.EXTERNAL_INTELLIGENCE,
        ClaimCategory.INFERENCE,
        ClaimCategory.UNKNOWN,
    ]:
        claim = FactualClaimItem(
            claim_text="Sample text",
            category=cat,
            references_exist=True,
            grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED,
            confidence=0.5,
        )
        assert claim.category == cat

    with pytest.raises(ValidationError):
        FactualClaimItem(
            claim_text="Sample text",
            category="hallucinated_category",  # type: ignore[arg-type]
            references_exist=True,
            grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED,
            confidence=0.5,
        )


# ---------------------------------------------------------------------------
# 12. Valid and Invalid Grounding Statuses & Cross-Field Invariant
# ---------------------------------------------------------------------------

def test_grounding_statuses_and_invariants():
    ev_id = uuid.uuid4()
    for status in [
        GroundingStatus.VALIDATED_REFERENCE,
        GroundingStatus.ANALYST_REVIEW_REQUIRED,
        GroundingStatus.UNSUPPORTED,
        GroundingStatus.CONTRADICTED,
    ]:
        claim = FactualClaimItem(
            claim_text="Sample assertion",
            category=ClaimCategory.OBSERVED_FACT,
            supporting_evidence_ids=[ev_id],
            references_exist=True,
            grounding_status=status,
            confidence=0.9,
        )
        assert claim.grounding_status == status

    # Invariant: cannot be validated_reference if references_exist is False
    with pytest.raises(ValidationError) as exc:
        FactualClaimItem(
            claim_text="Asserting fact from non-existent evidence",
            category=ClaimCategory.OBSERVED_FACT,
            supporting_evidence_ids=[uuid.uuid4()],
            references_exist=False,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
            confidence=0.9,
        )
    assert "references_exist is False" in str(exc.value)

    # Invariant: cannot be validated_reference if supporting_evidence_ids is empty
    with pytest.raises(ValidationError) as exc:
        FactualClaimItem(
            claim_text="Asserting fact with no cited evidence",
            category=ClaimCategory.OBSERVED_FACT,
            supporting_evidence_ids=[],
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
            confidence=0.9,
        )
    assert "empty supporting_evidence_ids" in str(exc.value)


# ---------------------------------------------------------------------------
# 13. Incomplete-Context and Omission Metadata Consistency (F-02)
# ---------------------------------------------------------------------------

def test_incomplete_context_and_omission_metadata_consistency():
    start = datetime(2026, 10, 23, 8, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
    omitted_uuid = uuid.uuid4()

    # 1. Event-only omission with context_truncated=False must be rejected
    with pytest.raises(ValidationError) as exc:
        BudgetMetrics(
            total_events_in_scope=10,
            events_included=5,
            events_omitted_count=5,
            total_entities_in_scope=5,
            entities_included=5,
            context_truncated=False,
        )
    assert "context_truncated must be True when events or entities are omitted" in str(exc.value)

    # 2. Entity-only omission with context_truncated=False must be rejected (F-02 fix)
    with pytest.raises(ValidationError) as exc:
        BudgetMetrics(
            total_events_in_scope=5,
            events_included=5,
            events_omitted_count=0,
            total_entities_in_scope=50,
            entities_included=20,
            context_truncated=False,
        )
    assert "context_truncated must be True when events or entities are omitted" in str(exc.value)

    # 3. Both event and entity omission with context_truncated=True is valid
    bm_both = BudgetMetrics(
        total_events_in_scope=10,
        events_included=5,
        events_omitted_count=5,
        total_entities_in_scope=50,
        entities_included=20,
        context_truncated=True,
    )
    assert bm_both.context_truncated is True

    # 4. No omissions with context_truncated=True must be rejected as inconsistent
    with pytest.raises(ValidationError) as exc:
        BudgetMetrics(
            total_events_in_scope=5,
            events_included=5,
            events_omitted_count=0,
            total_entities_in_scope=10,
            entities_included=10,
            context_truncated=True,
        )
    assert "context_truncated is True but no events or entities were omitted" in str(exc.value)

    # 5. InvestigationContext: context_truncated requires uncertainty_flags disclosure
    budget = BudgetMetrics(
        total_events_in_scope=10,
        events_included=0,
        events_omitted_count=10,
        omitted_event_ids_summary=[omitted_uuid],
        context_truncated=True,
    )
    repro = ReproducibilityRecord(
        time_window_start=start,
        time_window_end=end,
        context_sha256=VALID_SHA256_A,
    )

    with pytest.raises(ValidationError) as exc:
        InvestigationContext(
            scope_type=InvestigationScopeType.INCIDENT_TIMELINE,
            time_window_start=start,
            time_window_end=end,
            budget_metrics=budget,
            reproducibility=repro,
            uncertainty_flags=[],  # Missing disclosure!
        )
    assert "uncertainty_flags contains no disclosure" in str(exc.value)

    # Providing the disclosure makes it valid
    valid_truncated_ctx = InvestigationContext(
        scope_type=InvestigationScopeType.INCIDENT_TIMELINE,
        time_window_start=start,
        time_window_end=end,
        budget_metrics=budget,
        reproducibility=repro,
        uncertainty_flags=["CONTEXT_TRUNCATED: 10 events omitted to fit 3500 token budget"],
    )
    assert valid_truncated_ctx.budget_metrics.context_truncated is True


# ---------------------------------------------------------------------------
# 14. Structured Output with Valid References & Grounding Score Consistency
# ---------------------------------------------------------------------------

def test_structured_output_validation():
    inv_id = uuid.uuid4()
    ev_id1 = uuid.uuid4()
    ev_id2 = uuid.uuid4()

    claim1 = FactualClaimItem(
        claim_text="Process powershell.exe executed encoded command.",
        category=ClaimCategory.OBSERVED_FACT,
        supporting_evidence_ids=[ev_id1],
        references_exist=True,
        grounding_status=GroundingStatus.VALIDATED_REFERENCE,
        confidence=0.95,
    )
    claim2 = FactualClaimItem(
        claim_text="Adversary may have established persistence.",
        category=ClaimCategory.INFERENCE,
        supporting_evidence_ids=[ev_id2],
        references_exist=True,
        grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED,
        confidence=0.6,
    )

    hypo = MitreAttackHypothesis(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactics=["Execution"],
        supporting_event_uuids=[ev_id1],
        confidence=0.9,
        reasoning="Process execution of powershell.exe with encoded arguments.",
    )

    # 1 out of 2 claims validated => ratio is 0.50
    output = StructuredInvestigationOutput(
        investigation_id=inv_id,
        model_identifier="ollama/qwen3:4b",
        investigation_summary="Suspicious PowerShell activity was detected executing encoded payloads.",
        claims=[claim1, claim2],
        mitre_attack_hypotheses=[hypo],
        recommended_analyst_actions=["Inspect child process tree", "Check network connection logs"],
        overall_grounding_score=0.50,
    )

    assert output.overall_grounding_score == 0.50
    assert len(output.claims) == 2
    assert len(output.mitre_attack_hypotheses) == 1

    # Inconsistent grounding score (> 0.01 deviation) rejected
    with pytest.raises(ValidationError) as exc:
        StructuredInvestigationOutput(
            investigation_id=inv_id,
            model_identifier="ollama/qwen3:4b",
            investigation_summary="Suspicious PowerShell activity was detected executing encoded payloads.",
            claims=[claim1, claim2],
            recommended_analyst_actions=["Inspect host"],
            overall_grounding_score=0.90,  # Expected 0.50!
        )
    assert "inconsistent with claims ratio" in str(exc.value)


# ---------------------------------------------------------------------------
# 15. Empty Uncertainty and Data-Gap Collections Where Permitted
# ---------------------------------------------------------------------------

def test_empty_collections_permitted():
    inv_id = uuid.uuid4()
    output = StructuredInvestigationOutput(
        investigation_id=inv_id,
        model_identifier="ollama/qwen3:4b",
        investigation_summary="Baseline clean activity observed across endpoints.",
        claims=[],
        mitre_attack_hypotheses=[],
        alternative_explanations=[],
        recommended_analyst_actions=["Continue passive monitoring"],
        uncertainty_and_data_gaps=[],
        overall_grounding_score=1.0,
    )

    assert output.claims == []
    assert output.mitre_attack_hypotheses == []
    assert output.alternative_explanations == []
    assert output.uncertainty_and_data_gaps == []


# ---------------------------------------------------------------------------
# 16. Independent Mutable Defaults Across Model Instances
# ---------------------------------------------------------------------------

def test_independent_mutable_defaults():
    # ContextEventItem attributes
    event_a = make_test_event()
    event_b = make_test_event()
    assert event_a.attributes is not event_b.attributes

    # ContextEntityItem roles and attributes
    entity_a = make_test_entity()
    entity_b = make_test_entity()
    assert entity_a.roles is not entity_b.roles
    assert entity_a.associated_event_uuids is not entity_b.associated_event_uuids
    assert entity_a.attributes is not entity_b.attributes

    # ContextTIFindingItem tags and feeds
    ti_a = ContextTIFindingItem(observable="1.1.1.1", observable_type="ipv4")
    ti_b = ContextTIFindingItem(observable="8.8.8.8", observable_type="ipv4")
    assert ti_a.tags is not ti_b.tags
    assert ti_a.source_feeds is not ti_b.source_feeds

    # BudgetMetrics omitted_event_ids_summary
    bm_a = BudgetMetrics(total_events_in_scope=0, events_included=0, events_omitted_count=0)
    bm_b = BudgetMetrics(total_events_in_scope=0, events_included=0, events_omitted_count=0)
    assert bm_a.omitted_event_ids_summary is not bm_b.omitted_event_ids_summary


# ---------------------------------------------------------------------------
# 17. Serialization and Deserialization Round Trips
# ---------------------------------------------------------------------------

def test_serialization_and_deserialization_round_trip():
    start = datetime(2026, 10, 23, 8, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)

    event = make_test_event(ts=start + timedelta(minutes=10))
    entity = make_test_entity(event_uuids=[event.event_uuid])
    chunk = make_test_chunk()

    budget = BudgetMetrics(
        total_events_in_scope=1,
        events_included=1,
        events_omitted_count=0,
        total_entities_in_scope=1,
        entities_included=1,
        knowledge_chunks_included=1,
        estimated_character_count=1200,
        estimated_tokens=342,
        context_truncated=False,
    )
    repro = ReproducibilityRecord(
        time_window_start=start,
        time_window_end=end,
        selected_event_uuids=[event.event_uuid],
        selected_chunk_ids=[chunk.chunk_id],
        context_sha256=VALID_SHA256_A,
    )

    ctx = InvestigationContext(
        scope_type=InvestigationScopeType.INCIDENT_TIMELINE,
        time_window_start=start,
        time_window_end=end,
        events=[event],
        entities=[entity],
        knowledge_chunks=[chunk],
        budget_metrics=budget,
        reproducibility=repro,
    )

    # JSON round trip
    json_str = ctx.model_dump_json()
    parsed_json = json.loads(json_str)
    assert parsed_json["schema_version"] == "1.0.0"
    assert parsed_json["events"][0]["event_id"] == "1"

    reconstructed = InvestigationContext.model_validate_json(json_str)
    assert reconstructed.investigation_id == ctx.investigation_id
    assert reconstructed.events[0].event_uuid == event.event_uuid
    assert reconstructed.entities[0].entity_value == entity.entity_value
    assert reconstructed.knowledge_chunks[0].chunk_id == chunk.chunk_id
    assert reconstructed == ctx


# ---------------------------------------------------------------------------
# 18. Unknown-Field Handling (Strict extra="forbid" Policy)
# ---------------------------------------------------------------------------

def test_unknown_field_handling_forbid_policy():
    # ContextEventItem
    with pytest.raises(ValidationError) as exc:
        ContextEventItem(
            event_uuid=uuid.uuid4(),
            raw_evidence_sha256=VALID_SHA256_A,
            event_id="1",
            event_type="test",
            timestamp_utc=datetime.now(timezone.utc),
            action="test",
            source_identifier="host",
            summary="test",
            unknown_injection="malicious_payload",  # Forbidden extra field!
        )
    assert "extra_forbidden" in str(exc.value)

    # BudgetMetrics
    with pytest.raises(ValidationError) as exc:
        BudgetMetrics(
            total_events_in_scope=0,
            events_included=0,
            events_omitted_count=0,
            unexpected_metric=42,  # Forbidden!
        )
    assert "extra_forbidden" in str(exc.value)

    # FactualClaimItem
    with pytest.raises(ValidationError) as exc:
        FactualClaimItem(
            claim_text="Test assertion",
            category=ClaimCategory.OBSERVED_FACT,
            references_exist=True,
            grounding_status=GroundingStatus.ANALYST_REVIEW_REQUIRED,
            confidence=0.8,
            hallucinated_property=True,  # Forbidden!
        )
    assert "extra_forbidden" in str(exc.value)


# ---------------------------------------------------------------------------
# 19. Strict Investigation Window Rules (F-03)
# ---------------------------------------------------------------------------

def test_strict_time_window_rules_across_contracts():
    t_base = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
    t_after = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Valid non-empty interval (start < end)
    req = InvestigationSynthesizeRequest(time_window_start=t_base, time_window_end=t_after)
    repro = ReproducibilityRecord(time_window_start=t_base, time_window_end=t_after, context_sha256=VALID_SHA256_A)
    assert req.time_window_start < req.time_window_end
    assert repro.time_window_start < repro.time_window_end

    # 2. Equal start and end (start == end) must be strictly rejected
    with pytest.raises(ValidationError) as exc_req:
        InvestigationSynthesizeRequest(time_window_start=t_base, time_window_end=t_base)
    assert "must be strictly before" in str(exc_req.value)

    with pytest.raises(ValidationError) as exc_repro:
        ReproducibilityRecord(time_window_start=t_base, time_window_end=t_base, context_sha256=VALID_SHA256_A)
    assert "must be strictly before" in str(exc_repro.value)

    budget = BudgetMetrics(total_events_in_scope=0, events_included=0, events_omitted_count=0)
    with pytest.raises(ValidationError) as exc_ctx:
        InvestigationContext(
            scope_type=InvestigationScopeType.INCIDENT_TIMELINE,
            time_window_start=t_base,
            time_window_end=t_base,
            budget_metrics=budget,
            reproducibility=repro,
        )
    assert "must be strictly before" in str(exc_ctx.value)

    # 3. Start after end (start > end) must be rejected
    with pytest.raises(ValidationError):
        InvestigationSynthesizeRequest(time_window_start=t_after, time_window_end=t_base)
    with pytest.raises(ValidationError):
        ReproducibilityRecord(time_window_start=t_after, time_window_end=t_base, context_sha256=VALID_SHA256_A)

    # 4. Equivalent instants expressed with different timezone offsets are recognized as equal and rejected
    ist = timezone(timedelta(hours=5, minutes=30))
    t_ist = datetime(2026, 10, 23, 15, 30, 0, tzinfo=ist)  # Equal to 10:00:00 UTC
    with pytest.raises(ValidationError) as exc_tz_equal:
        InvestigationSynthesizeRequest(time_window_start=t_base, time_window_end=t_ist)
    assert "must be strictly before" in str(exc_tz_equal.value)


# ---------------------------------------------------------------------------
# 20. Meaningful Non-Whitespace Summaries (F-04)
# ---------------------------------------------------------------------------

def test_meaningful_non_whitespace_summaries():
    inv_id = uuid.uuid4()

    # 1. ContextEventItem: empty summary rejected
    with pytest.raises(ValidationError) as exc_empty:
        make_test_event(summary="")
    assert "meaningful non-whitespace content" in str(exc_empty.value)

    # 2. ContextEventItem: whitespace-only summary rejected
    with pytest.raises(ValidationError) as exc_ws:
        make_test_event(summary="     \t \n  ")
    assert "meaningful non-whitespace content" in str(exc_ws.value)

    # 3. ContextEventItem: valid non-whitespace summary accepted
    ev = make_test_event(summary="Valid process creation event")
    assert ev.summary == "Valid process creation event"

    # 4. StructuredInvestigationOutput: whitespace-only summary rejected even if len >= 20
    with pytest.raises(ValidationError) as exc_out_ws:
        StructuredInvestigationOutput(
            investigation_id=inv_id,
            model_identifier="ollama/qwen3:4b",
            investigation_summary=" " * 25,  # 25 spaces
            recommended_analyst_actions=["Inspect host"],
            overall_grounding_score=1.0,
        )
    assert "at least 20 non-whitespace characters" in str(exc_out_ws.value)

    # 5. StructuredInvestigationOutput: trimmed length < 20 rejected
    with pytest.raises(ValidationError) as exc_out_short:
        StructuredInvestigationOutput(
            investigation_id=inv_id,
            model_identifier="ollama/qwen3:4b",
            investigation_summary="          Too short          ",  # 29 chars total, 9 non-whitespace
            recommended_analyst_actions=["Inspect host"],
            overall_grounding_score=1.0,
        )
    assert "at least 20 non-whitespace characters" in str(exc_out_short.value)

    # 6. StructuredInvestigationOutput: valid summary accepted
    valid_summary = "Suspicious encoded PowerShell execution was observed on endpoint WORKSTATION-01."
    out = StructuredInvestigationOutput(
        investigation_id=inv_id,
        model_identifier="ollama/qwen3:4b",
        investigation_summary=valid_summary,
        recommended_analyst_actions=["Inspect child processes"],
        overall_grounding_score=1.0,
    )
    assert out.investigation_summary == valid_summary
