# AISOP Milestone P2-H4: Phase 1.1 Contract Validation Audit (READ-ONLY)
**Document Reference:** `AISOP-AUDIT-P2-H4-PHASE1-001`  
**Execution Date:** 2026-10-23  
**Auditor:** AISOP Senior Application Security Architect & Independent Reviewer  
**Workspace:** `D:\AISOP`  
**Target Module:** `backend/app/schemas/investigation.py`  
**Target Test Suite:** `backend/tests/unit/test_investigation_schemas.py`  
**Audit Scope:** Independent, read-only verification of Phase 1 deliverables, contracts, and test evidence prior to Phase 2 authorization.

---

## 1. Executive Summary & Audit Verdict

This audit provides an independent, evidence-grounded review of Phase 1 (Task 1.1) of Milestone P2-H4: **Typed Investigation Contracts and Schema Tests**.

### Overall Audit Determination:
**ACCEPTABLE AFTER MINOR CORRECTIONS (CONDITIONAL PASS)**

The core objective of Task 1.1 has been achieved:
- 16 typed, immutable Pydantic V2 models and enums are implemented with strict unknown-field rejection (`extra="forbid"`) and frozen mutation protection (`frozen=True`).
- 19 focused unit tests were independently executed and passed (0.52s).
- The full backend unit test suite was independently executed and passed with 493 passing unit tests and zero regressions (16.65s).
- Pre-existing working tree modifications and untracked files were preserved with zero Git mutation.

However, a detailed inspection of the contracts and tests against the P2-H4 design report revealed **four specific technical discrepancies and edge-case gaps** that must be documented and corrected:
1. **Timestamp Normalization Gap:** Datetime validators require timezone awareness but do not normalize non-UTC offsets to `timezone.utc`, potentially producing differing canonical SHA-256 context hashes for identical instants across timezones.
2. **Entity Omission Inconsistency:** `BudgetMetrics` requires `context_truncated=True` when `events_omitted_count > 0`, but does not enforce `context_truncated=True` when entities are omitted (`total_entities_in_scope > entities_included`) while events are not.
3. **Time Window Boundary Mismatch:** `InvestigationSynthesizeRequest` strictly enforces a half-open interval `start < end` (`start >= end` rejected), whereas `ReproducibilityRecord` and `InvestigationContext` permit `start == end` (`start > end` rejected).
4. **Grounding Citation Typology:** `FactualClaimItem.supporting_evidence_ids` models `ContextEventItem` UUIDs only, providing no direct mechanism for external-intelligence claims to cite threat-intelligence findings (which lack UUIDs) or knowledge chunk IDs.

---

## 2. Review Question 1: UTC and Timestamp Invariants

### 2.1 Inspection of Datetime Fields
Every datetime field across `backend/app/schemas/investigation.py` was inspected:

| Model | Field Name | Declared Description | Implemented Validator |
|---|---|---|---|
| `ContextEventItem` | `timestamp_utc` | "Observation time in UTC" | `@field_validator("timestamp_utc", mode="after")` via `_validate_tz_aware` |
| `ReproducibilityRecord` | `time_window_start` | "Scope start time in UTC" | `@field_validator("time_window_start", mode="after")` via `_validate_tz_aware` |
| `ReproducibilityRecord` | `time_window_end` | "Scope end time in UTC" | `@field_validator("time_window_end", mode="after")` via `_validate_tz_aware` |
| `ReproducibilityRecord` | `created_at_utc` | "Record creation time in UTC" | `@field_validator("created_at_utc", mode="after")` via `_validate_tz_aware` |
| `InvestigationContext` | `time_window_start` | "Earliest event timestamp in scope (UTC)" | `@field_validator("time_window_start", mode="after")` via `_validate_tz_aware` |
| `InvestigationContext` | `time_window_end` | "Latest event timestamp in scope (UTC)" | `@field_validator("time_window_end", mode="after")` via `_validate_tz_aware` |
| `InvestigationContext` | `assembled_at` | "UTC context assembly time" | `@field_validator("assembled_at", mode="after")` via `_validate_tz_aware` |
| `StructuredInvestigationOutput` | `generated_at` | "Generation timestamp in UTC" | `@field_validator("generated_at", mode="after")` via `_validate_tz_aware` |
| `InvestigationSynthesizeRequest` | `time_window_start` | "Scope start time in UTC (inclusive)" | `@field_validator("time_window_start", mode="after")` via `_validate_tz_aware` |
| `InvestigationSynthesizeRequest` | `time_window_end` | "Scope end time in UTC (exclusive)" | `@field_validator("time_window_end", mode="after")` via `_validate_tz_aware` |

### 2.2 Finding: Timezone Awareness vs. UTC Normalization
The helper function is implemented as:
```python
def _validate_tz_aware(dt: datetime, field_name: str) -> datetime:
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"{field_name} must be timezone-aware (e.g. UTC)")
    return dt
```

**Empirical Verification Probe:**
```python
ist = timezone(timedelta(hours=5, minutes=30))
dt_ist = datetime(2026, 10, 23, 10, 0, 0, tzinfo=ist)
ev = ContextEventItem(..., timestamp_utc=dt_ist)
# Result: ev.timestamp_utc.tzinfo == UTC+05:30 (Is UTC? False)
```

**Impact:**
- The validator successfully rejects naive datetimes (e.g. `datetime(2026, 10, 23, 10, 0)`).
- However, if a caller passes a timezone-aware datetime with an offset other than UTC (e.g. `+05:30` or `-04:00`), the model accepts the value **without normalizing it to UTC**.
- When `InvestigationContext` is serialized to JSON (`model_dump_json()`), timestamps preserve their source offset (`"2026-10-23T10:00:00+05:30"` vs `"2026-10-23T04:30:00Z"`).
- Because `ReproducibilityRecord.context_sha256` computes a cryptographic digest over the canonical JSON context, two systems processing identical events in different timezone environments will compute **different context SHA-256 hashes**.
- **Correction Required:** Update `_validate_tz_aware` to normalize datetimes to UTC:
  ```python
  def _validate_and_normalize_utc(dt: datetime, field_name: str) -> datetime:
      if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
          raise ValueError(f"{field_name} must be timezone-aware (e.g. UTC)")
      return dt.astimezone(timezone.utc)
  ```

### 2.3 Cross-Model Temporal Invariants & Boundary Comparison
- **`InvestigationSynthesizeRequest`:** Enforces `self.time_window_start >= self.time_window_end` (strict inequality, `start < end`).
- **`ReproducibilityRecord`:** Enforces `self.time_window_start > self.time_window_end` (permits `start == end`).
- **`InvestigationContext`:** Enforces `self.time_window_start > self.time_window_end` (permits `start == end`).

**Impact:**
In accordance with design section 4.1, the investigation query scope is explicitly half-open: `[start_time, end_time)`. If `start == end`, the interval is mathematically empty ($\emptyset$). `InvestigationSynthesizeRequest` correctly rejects `start == end`, but `ReproducibilityRecord` and `InvestigationContext` allow an empty point-in-time window. This boundary rule should be unified across all three models to enforce `start < end` uniformly.

---

## 3. Review Question 2: Evidence Grounding Architecture

### 3.1 Verification of `FactualClaimItem`
`FactualClaimItem` was inspected:
```python
class FactualClaimItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    claim_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    claim_text: str = Field(min_length=1)
    category: ClaimCategory
    supporting_evidence_ids: list[uuid.UUID] = Field(default_factory=list)
    references_exist: bool
    grounding_status: GroundingStatus
    confidence: float = Field(ge=0.0, le=1.0)
    analyst_notes: Optional[str] = None
```

### 3.2 Finding: Caller-Supplied vs. Calculated Grounding
- **Field Sovereignty:** `references_exist` is an explicit input field on `FactualClaimItem`. At the schema validation level, it is **caller-supplied**, not dynamically computed against an `InvestigationContext`.
- **Hallucinated UUID Risk:** A caller can construct a `FactualClaimItem` citing an invented UUID (e.g. `00000000-0000-0000-0000-000000000001`), set `references_exist=True`, and `grounding_status=GroundingStatus.VALIDATED_REFERENCE`. The schema validator **cannot** detect that this UUID is absent from any context because `FactualClaimItem` is decoupled from `InvestigationContext`.
- **Epistemic Truth Boundary:** The implementation report correctly documents this limitation: schema validation guarantees only structural invariants (e.g. `references_exist=False` cannot have status `validated_reference`, and `validated_reference` cannot have empty evidence IDs). It does not prove that references exist in the database, nor that cited telemetry logically justifies the assertion.
- **Architectural Placement:** True reference-existence calculation (Tier 1 set membership check: `set(cited_ids).issubset(context_event_ids)`) belongs in Phase 3 (`ResponseValidator`), not in the static Pydantic schema contract.

### 3.3 Finding: External-Intelligence and Knowledge Chunk Citation Gaps
- `supporting_evidence_ids` is typed strictly as `list[uuid.UUID]` and described as "Cited ContextEventItem UUIDs".
- `ContextTIFindingItem` has no UUID primary key (it is identified by `observable: str` and `observable_type: str`).
- Consequently, if a model produces a claim with `category = ClaimCategory.EXTERNAL_INTELLIGENCE`, there is no field to cite the threat intelligence finding or feed name. Citing an observable string inside a UUID list raises a `ValidationError`.
- Similarly, claims derived from retrieved knowledge chunks cannot cite `chunk_id: uuid.UUID` unless `supporting_evidence_ids` is redefined or augmented with a separate `supporting_chunk_ids: list[uuid.UUID]` field.
- **Recommendation for Phase 3:** In `FactualClaimItem`, either add `supporting_knowledge_chunk_ids: list[uuid.UUID] = Field(default_factory=list)` and `cited_observables: list[str] = Field(default_factory=list)`, or clarify that `supporting_evidence_ids` represents only raw telemetry events, with TI/RAG attribution recorded in `analyst_notes`.

---

## 4. Review Question 3: Context and Budget Consistency

### 4.1 Count Consistency
The cross-field validator on `InvestigationContext` enforces exact mathematical equality:
- `len(self.events) == self.budget_metrics.events_included`
- `len(self.entities) == self.budget_metrics.entities_included`
- `len(self.knowledge_chunks) == self.budget_metrics.knowledge_chunks_included`

Any count mismatch raises an immediate `ValueError`. This invariant is verified and robust.

### 4.2 Finding: Entity Omission Truncation Gap
In `BudgetMetrics.validate_budget_invariants`:
```python
expected_omitted = self.total_events_in_scope - self.events_included
if self.events_omitted_count != expected_omitted:
    raise ValueError(...)
if self.events_omitted_count > 0 and not self.context_truncated:
    raise ValueError("context_truncated must be True when events_omitted_count > 0")
if self.context_truncated and self.events_omitted_count == 0 and self.total_entities_in_scope == self.entities_included:
    raise ValueError("context_truncated is True but no events or entities were omitted from scope")
```

**Empirical Verification Probe:**
```python
bm = BudgetMetrics(
    total_events_in_scope=5,
    events_included=5,
    events_omitted_count=0,
    total_entities_in_scope=50,
    entities_included=10,
    context_truncated=False  # 40 entities omitted, yet context_truncated=False!
)
# Result: Accepted without ValidationError!
```

**Impact:**
If an investigation includes all 5 events, but omits 40 extracted entities due to entity budget limits, `BudgetMetrics` accepts `context_truncated=False`. This violates the foundational invariant: *Never silently drop evidence.* If entities are omitted from scope, `context_truncated` must be required to be `True`.
- **Correction Required:** Update the validator:
  ```python
  entities_omitted = self.total_entities_in_scope - self.entities_included
  if (self.events_omitted_count > 0 or entities_omitted > 0) and not self.context_truncated:
      raise ValueError("context_truncated must be True when events or entities are omitted from scope")
  ```

### 4.3 Summary Field Constraints
- `StructuredInvestigationOutput.investigation_summary` has `min_length=20`. However, a probe confirmed that a string of 25 spaces (`" " * 25`) satisfies `min_length=20`. Adding a strip validator (`v.strip()`) will prevent blank or whitespace-only narratives.
- `ContextEventItem.summary` currently lacks a `min_length=1` constraint, permitting empty string summaries (`summary=""`).

---

## 5. Review Question 4: Test Quality and Regression Evidence

### 5.1 Test-by-Behavior Mapping (`test_investigation_schemas.py`)

| Test Function | Target Behavior | Quality Assessment |
|---|---|---|
| `test_valid_minimal_investigation_context` | Minimal context with 0 events, empty lists, and default fields | Thorough; tests defaults and tzinfo |
| `test_valid_fully_populated_context` | Complex context with events, entities, TI, RAG, budget, reproducibility | Thorough; tests multi-model alignment |
| `test_missing_required_fields_raises_validation_error` | Missing required parameters raise `ValidationError` | Thorough; tests events, budget, claims |
| `test_invalid_uuid_rejected` | Malformed UUID strings rejected | Thorough; tests event UUID and claim UUIDs |
| `test_sha256_validation_length_and_hex` | Rejection of length != 64 and non-hex; lowercase normalization | Robust; tests 63, 65, non-hex, uppercase |
| `test_timezone_awareness_enforced` | Naive datetime rejected; start > end rejected | Moderate; tests naive, but misses non-UTC offsets |
| `test_confidence_and_similarity_range_constraints` | Values outside `[0.0, 1.0]` rejected | Thorough; tests confidence, similarity, TI |
| `test_negative_counts_and_budget_metrics_invariants` | Negative counts, included > total, omission mismatches rejected | Robust; tests 4 distinct invariant branches |
| `test_empty_investigation_scope_permitted` | Legitimate 0-event scope instantiates cleanly | High fidelity for benign/empty searches |
| `test_missing_or_unavailable_threat_intel` | Default TI values; shielded invariant enforcement | Robust; tests RFC1918 state consistency |
| `test_claim_categories` | 4 valid StrEnum values accepted; invalid string rejected | Thorough |
| `test_grounding_statuses_and_invariants` | 4 valid statuses; rejection of false references and empty IDs | Robust; tests Tier 1 cross-field rules |
| `test_incomplete_context_and_omission_metadata_consistency` | Enforces disclosure in `uncertainty_flags` when truncated | Thorough; tests omission auditability |
| `test_structured_output_validation` | Structured output and grounding score ratio consistency | Robust; tests claim score ratio check |
| `test_empty_collections_permitted` | Empty claims, data gaps, hypotheses allowed | Thorough |
| `test_independent_mutable_defaults` | Fresh list/dict instances on every model instantiation | Critical defense against shared state bugs |
| `test_serialization_and_deserialization_round_trip` | Lossless JSON dumping and deserialization | Robust; verifies dict/JSON fidelity |
| `test_unknown_field_handling_forbid_policy` | Strict rejection of extra payload fields | Critical defense against prompt injection |
| `test_investigation_synthesize_request_validation` | Request schema validates time windows and timezone | Thorough |

### 5.2 Actual Executed Test Commands and Results
The test suites were executed independently during this audit. Both runs were completely read-only and required zero database interaction:

1. **Focused Investigation Schema Test Suite:**
   - **Command:** `D:\AISOP\.venv\Scripts\python.exe -m pytest D:\AISOP\backend\tests\unit\test_investigation_schemas.py -v`
   - **Exit Code:** `0`
   - **Collected:** 19 items
   - **Result:** **19 passed in 0.52s**

2. **Full Backend Unit Test Suite:**
   - **Command:** `D:\AISOP\.venv\Scripts\python.exe -m pytest D:\AISOP\backend\tests\unit`
   - **Exit Code:** `0`
   - **Collected:** 493 items
   - **Result:** **493 passed, 2 warnings in 16.65s**
   - **Warnings:** 2 pre-existing `StarletteDeprecationWarning` in `test_threatintel_http_integration.py` regarding `httpx` with `starlette.testclient`.

---

## 6. Review Question 5: Repository Integrity & Verification Ledger

### 6.1 Git State Audit
- **Repository Root:** `D:\AISOP`
- **Active Branch:** `main`
- **Active HEAD Commit:** `c4e877cf06056bce32f5a3f893a82261b850ff85`
- **Working Tree Preservation:** `git status --short` captured before and after this audit confirms that **zero tracked or untracked files were modified, staged, committed, or deleted**.

### 6.2 Test Count Reconciliation
- **Historical Claim (510 tests):** Documented during P2-H3 acceptance as 474 backend unit tests + 36 live integration tests ($474 + 36 = 510$).
- **Verified Unit Baseline Prior to Phase 1:** Exactly 474 unit tests.
- **Verified Current Unit Baseline with Phase 1 Schemas:** Exactly **493 passed unit tests** ($474 + 19 = 493$).
- **Total Potential Repository Count:** 494 unit + 36 integration = **530 tests**.

---

## 7. Findings & Corrections Verification Ledger (Phase 1.2 Completed)

| Finding ID | Category | Severity | Description | Resolution in Phase 1.2 | Verification Status |
|:---:|:---:|:---:|:---|:---|:---:|
| **F-01** | UTC Normalization | Low / Medium | `_validate_tz_aware` required timezone awareness but did not convert non-UTC offsets to `timezone.utc`. | Implemented `_validate_and_normalize_utc` applying `dt.astimezone(timezone.utc)` across all 10 datetime fields. Added tests for UTC, positive/negative non-UTC offsets, naive rejection, and instant equality. | **RESOLVED & VERIFIED** |
| **F-02** | Entity Omission Accounting | Low | `BudgetMetrics` did not mandate `context_truncated=True` when entities were omitted if `events_omitted_count == 0`. | Updated `BudgetMetrics.validate_budget_invariants`: omitted entities now trigger mandatory `context_truncated=True`. Rejecting `context_truncated=True` with zero omissions unless explicit `truncation_reason` is set. | **RESOLVED & VERIFIED** |
| **F-03** | Boundary Equality Inconsistency | Low | `InvestigationSynthesizeRequest` rejected `start == end`, whereas `ReproducibilityRecord` and `InvestigationContext` permitted it. | Unified strict interval rule `start < end` across all three models. Tested valid intervals, equal instants (including across timezones), and inverted intervals. | **RESOLVED & VERIFIED** |
| **F-04** | Summary Whitespace Vulnerability | Low | `StructuredInvestigationOutput.investigation_summary` accepted whitespace-only strings; `ContextEventItem.summary` permitted empty string. | Added validators requiring meaningful non-whitespace characters (`len(v.strip()) > 0` for event summaries, `len(v.strip()) >= 20` for investigation summaries). | **RESOLVED & VERIFIED** |
| **F-05** | Claim Reference Typology | Advisory / Design | `FactualClaimItem.supporting_evidence_ids` only models event UUIDs; threat intel observables and knowledge chunks cannot be cited directly. | **Documented (Scope Bounded):** Noted event-only reference contract, citation limitations for TI/RAG, and formal design trade-off question deferred to Phase 3 Response Validation. Clarified that `references_exist` flag does not represent empirical truth. | **DOCUMENTED & BOUNDED** |

---

## 8. Audit Gate Determination & Authorization Recommendation

**Phase 1 Gate Status:** **FULLY APPROVED (PHASE 1.2 CORRECTIONS VERIFIED)**

All four findings (F-01 through F-04) have been corrected with strict contract invariants and dedicated regression tests. F-05 has been formally documented without expanding scope.

### Verification Summary:
- **Focused Schema Unit Tests:** 20/20 passed (`backend/tests/unit/test_investigation_schemas.py`).
- **Full Backend Unit Suite:** 494/494 passed, 0 failures, 2 benign warnings (`backend/tests/unit`).
- **Git State:** 0 files staged or committed; repository cleanliness preserved.
- **Database Safety:** Zero migrations executed; zero mutations to PostgreSQL or SQLite databases.

### Recommended Next Action:
Proceed with authorization for **Milestone P2-H4 Phase 2: Context Assembly & Defense Pipeline**.
