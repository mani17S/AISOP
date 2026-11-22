/**
 * AISOP Phase 4 - Frontend Type Contracts and Schema Definitions.
 *
 * Grounded in backend schemas (app.schemas.case, app.schemas.query, app.core.rbac).
 */

export type GlobalRole =
  | 'security_admin'
  | 'analyst_tier_2'
  | 'analyst_tier_1'
  | 'auditor_viewer';

export type CaseRole = 'lead' | 'investigator' | 'viewer';

export type CaseStatus = 'open' | 'in_progress' | 'closed' | 'archived';

export type CaseSeverity = 'informational' | 'low' | 'medium' | 'high' | 'critical';

export interface HealthResponse {
  status: 'ok' | 'degraded';
  app: string;
  version: string;
  environment?: string;
  checks?: {
    database?: { status: string; detail?: string };
    llm_provider?: {
      status: 'healthy' | 'degraded' | 'unavailable' | 'error';
      provider: string;
      model: string;
      latency_ms?: number;
      detail?: string;
    };
  };
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
  has_next: boolean;
  has_previous: boolean;
}

export interface ExtractedEntityItem {
  id: string;
  event_id: string;
  raw_evidence_id: string;
  entity_type: string;
  entity_value: string;
  role: string;
}

export interface NormalizedEventSummary {
  id: string;
  event_id: string;
  event_timestamp?: string;
  observed_timestamp?: string;
  /** When AISOP ingested the record (UTC). Different from event_timestamp, the time the source generated it. */
  raw_ingested_at?: string | null;
  event_type: string;
  source_type?: string;
  source_identifier?: string;
  severity: string;
  provider?: string;
  action?: string;
  outcome?: string;
  primary_subject?: string | null;
  summary?: string;
  entities?: ExtractedEntityItem[];
}

export interface CaseResponse {
  id: string;
  case_number: string;
  title: string;
  description: string | null;
  severity: CaseSeverity;
  status: CaseStatus;
  lead_analyst_id: string;
  /** Set on case detail by the server; absent on list and write responses. */
  lead_analyst_username?: string | null;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface CaseCreateRequest {
  title: string;
  description?: string | null;
  severity: CaseSeverity;
  initial_evidence_ids?: string[];
}

export interface CaseScopedEvidenceItem {
  id: string;
  event_id: string;
  /** Backend field (CaseScopedEvidenceItem.event_timestamp). */
  event_timestamp: string;
  /** Not returned by the backend; retained only so older fixtures still type-check. */
  observed_timestamp?: string;
  event_type: string;
  source_type: string;
  source_identifier: string;
  severity: string;
  outcome: string;
  provider?: string;
  action?: string;
  primary_subject: string | null;
  summary: string;
  normalized_payload?: Record<string, any>;
  linked_at: string;
  linked_by?: string;
  linked_by_analyst_id?: string | null;
}

export interface CaseAuditEventItem {
  id: string;
  case_id: string;
  actor_analyst_id?: string | null;
  actor_username: string;
  action: string;
  context_sha256?: string | null;
  details?: Record<string, any>;
  created_at: string;
}

export interface FactualClaimItem {
  claim_id: string;
  claim_text: string;
  category: string;
  supporting_evidence_ids: string[];
  references_exist: boolean;
  grounding_status: string;
  confidence: number;
  analyst_notes?: string | null;
  /** Backend-supplied claim-verification-v1 result; absent/null for legacy claims without structured assertions. */
  verification?: ClaimVerification | null;
}

export interface MitreAttackHypothesis {
  technique_id: string;
  technique_name: string;
  tactics: string[];
  supporting_event_uuids: string[];
  confidence: number;
  reasoning: string;
}

export interface StructuredInvestigationOutput {
  investigation_id: string;
  generated_at: string;
  model_identifier: string;
  investigation_summary: string;
  claims: FactualClaimItem[];
  mitre_attack_hypotheses: MitreAttackHypothesis[];
  alternative_explanations: string[];
  recommended_analyst_actions: string[];
  uncertainty_and_data_gaps: string[];
  overall_grounding_score: number;
}

export interface InvestigationValidationResult {
  decision: 'pass' | 'remediate_to_pass' | 'reject_to_fallback' | string;
  is_valid: boolean;
  output: StructuredInvestigationOutput;
  violations: string[];
  context_sha256: string;
  validated_at_utc: string;
}

export interface UserContext {
  username: string;
  globalRole: GlobalRole;
  apiKey: string;
}

// ── Role-Tailored Report Bundle Types (Backend-Grounded) ─────────────────────

export type IncidentSeverityTier =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'
  | 'inconclusive';

export interface ExecutiveBrief {
  investigation_id: string;
  generated_at_utc: string;
  title: string;
  incident_severity: IncidentSeverityTier;
  severity_justification: string;
  is_inconclusive_or_fallback: boolean;
  executive_summary: string;
  evidenced_affected_assets: string[];
  key_confirmed_findings: string[];
  threat_intelligence_context: string;
  business_risk_statement: string;
  uncertainties_and_limitations: string[];
  governance_disclaimer: string;
}

export interface TimelineEventSummary {
  event_uuid: string;
  timestamp_utc: string;
  source_identifier: string;
  event_type: string;
  action: string;
  outcome: string;
  raw_evidence_sha256: string;
  summary: string;
}

export interface TechnicalReportClaim {
  claim_id: string;
  claim_text: string;
  category: string;
  grounding_status: string;
  confidence: number;
  supporting_event_uuids: string[];
  analyst_notes?: string | null;
  /** Persisted claim-verification-v1 result (new reports only); absent for historical reports. Never computed in the browser. */
  verification?: ClaimVerification | null;
}

export interface TechnicalIncidentReport {
  investigation_id: string;
  generated_at_utc: string;
  is_inconclusive_or_fallback: boolean;
  technical_narrative: string;
  investigation_timeline: TimelineEventSummary[];
  timeline_status_disclosure?: string | null;
  confirmed_findings: TechnicalReportClaim[];
  hypotheses_and_inferences: TechnicalReportClaim[];
  unsupported_or_contradicted_claims: TechnicalReportClaim[];
  mitre_attack_mappings: Record<string, any>[];
  threat_intelligence_enrichment: Record<string, any>[];
  investigation_gaps: string[];
  recommended_analyst_actions: string[];
  context_sha256: string;
  model_identifier: string;
  overall_grounding_score: number;
  governance_disclaimer: string;
}

export interface DetectionObservableItem {
  observable_type: string;
  observable_value: string;
  provenance_type: string;
  provenance_event_uuids: string[];
  provenance_claim_ids: string[];
  is_malicious_asserted: boolean;
  first_seen_utc?: string | null;
  last_seen_utc?: string | null;
}

export interface DetectionEngineeringReport {
  investigation_id: string;
  generated_at_utc: string;
  is_inconclusive_or_fallback: boolean;
  validated_observables: DetectionObservableItem[];
  mitre_coverage_targets: string[];
  candidate_detection_hypotheses: string[];
  recommended_log_sources: string[];
  candidate_hunting_pseudocode: string[];
  false_positive_considerations: string[];
  governance_disclaimer: string;
  /** Present only for unverified submitted reports; absent for verified/server-built reports. */
  analytics_withheld_reason?: string;
}

export interface ReportBundleProvenance {
  investigation_id: string;
  context_sha256: string;
  is_detached_format_mode: boolean;
  is_inconclusive_or_fallback: boolean;
  overall_grounding_score: number;
  model_identifier: string;
  is_verified_investigation: boolean;
  /** Present only for unverified submitted reports; absent for verified/server-built reports. */
  analytics_withheld_reason?: string;
}

export interface InvestigationReportBundle {
  investigation_id: string;
  generated_at_utc: string;
  context_sha256: string;
  is_fallback_active: boolean;
  provenance: ReportBundleProvenance;
  executive_brief: ExecutiveBrief;
  technical_report: TechnicalIncidentReport;
  detection_report: DetectionEngineeringReport;
  markdown_executive: string;
  markdown_technical: string;
  markdown_detection: string;
}

export interface CaseInvestigationSynthesizeRequest {
  time_window_start?: string | null;
  time_window_end?: string | null;
  root_event_id?: string | null;
  query_filter?: string | null;
  model_override?: string | null;
}

// ── Multi-Source Alert Ingestion & Triage Contracts (ADR-007) ───────────────

export type AlertSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'
  | 'unknown';

export type AlertCategory =
  | 'malware'
  | 'initial_access'
  | 'execution'
  | 'persistence'
  | 'privilege_escalation'
  | 'defense_evasion'
  | 'credential_access'
  | 'discovery'
  | 'lateral_movement'
  | 'collection'
  | 'exfiltration'
  | 'command_and_control'
  | 'impact'
  | 'suspicious_activity'
  | 'policy_violation'
  | 'system_anomaly'
  | 'other';

export type AlertStatus =
  | 'new'
  | 'triaged'
  | 'investigating'
  | 'closed'
  | 'suppressed';

export interface MitreAttackReference {
  tactic_id?: string | null;
  tactic_name?: string | null;
  technique_id?: string | null;
  technique_name?: string | null;
}

export interface AlertObservable {
  type: string;
  value: string;
  relevance?: string | null;
}

export interface AlertEntity {
  entity_type: string;
  entity_value: string;
  role: string;
  attributes?: Record<string, any>;
}

export interface AlertSummaryItem {
  id: string;
  source_alert_id: string;
  source_type: string;
  provider: string;
  source_identifier: string | null;
  title: string;
  description: string | null;
  category: AlertCategory;
  severity: AlertSeverity;
  vendor_severity: string | null;
  status: AlertStatus;
  timestamp: string;
  ingested_at: string;
  mitre_attack: MitreAttackReference[];
  top_observables: AlertObservable[];
  has_case: boolean;
  case_count: number;
}

export interface AlertDetailResponse {
  id: string;
  source_alert_id: string;
  source_type: string;
  provider: string;
  source_identifier: string | null;
  title: string;
  description: string | null;
  category: AlertCategory;
  severity: AlertSeverity;
  vendor_severity: string | null;
  status: AlertStatus;
  timestamp: string;
  ingested_at: string;
  raw_ref: string;
  mitre_attack: MitreAttackReference[];
  entities: Record<string, any>[];
  observables: AlertObservable[];
  host?: Record<string, any> | null;
  user?: Record<string, any> | null;
  process?: Record<string, any> | null;
  network?: Record<string, any> | null;
  file?: Record<string, any> | null;
  dns?: Record<string, any> | null;
  registry?: Record<string, any> | null;
  custom_fields: Record<string, any>;
  associated_case_ids: string[];
  has_case: boolean;
}

export interface AlertAdapterInfo {
  name: string;
  display_name: string;
  description: string;
  source_type: string;
  supported_categories?: string[];
  supported_severities?: string[];
}

export interface AlertAdaptersResponse {
  adapters: AlertAdapterInfo[];
  count: number;
  supported_severities: AlertSeverity[];
  supported_categories: AlertCategory[];
}

export interface AlertIngestRequest {
  source_type: string;
  source_identifier: string;
  alerts: Record<string, any>[];
}

export interface AlertIngestError {
  alert_index: number;
  error: string;
  raw_sample?: string | null;
}

export interface AlertIngestResponse {
  batch_id: string;
  source_type: string;
  total_received: number;
  total_normalized: number;
  total_entities_extracted: number;
  total_skipped_duplicates: number;
  existing_evidence_ids: string[];
  alert_ids: string[];
  errors: AlertIngestError[];
}

export interface ReportExportResponse {
  case_id: string;
  investigation_id: string;
  format: 'markdown' | 'json';
  view: 'bundle' | 'executive' | 'technical' | 'detection';
  filename: string;
  content: string;
  context_sha256: string;
  exported_at_utc: string;
  is_server_verified: boolean;
}





// ── Multi-source investigation (Stage 4, ADR-010) ───────────────────────────
export type MultiSourceVerdict = 'sufficient' | 'limited' | 'insufficient';
export type MultiSourceSectionName = 'status' | 'timeline' | 'correlation' | 'attack' | 'sufficiency' | 'report' | 'graph' | 'evidence';

// ── Source-agnostic evidence (Stage 6, ADR-011). All fields optional: results stored before Stage 6 do not carry them. ──
export interface DomainObservation {
  evidence_id: string;
  record_index: number;
  source_evidence_id: string | null;
  evidence_type: string;
  family: string;
  classification: 'normalized' | 'partial' | 'unclassified';
  source_system: string;
  source_category: string;
  collection_method: string;
  adapter: string;
  time_status: 'valid' | 'naive_assumed_utc' | 'missing' | 'invalid' | 'out_of_range';
  event_time: string | null;
  collected_at: string | null;
  raw_sha256: string;
  integrity: string;
  trust_class: string;
  counts_for_corroboration: boolean;
  outcome: string;
  title: string;
  on_timeline: boolean;
  entity_count: number;
  relationship_count: number;
}

export interface GraphNodeView { id: string; type: string; value: string; observation_count: number; sources: string[]; derived: boolean; analyst_note_count: number }
export interface GraphEdgeView {
  subject: string; predicate: string; object: string; kind: string; supporting_observations: string[];
  independent_support: number; sources: string[]; trust: string[]; rationale: string;
}
export interface GraphCorrelationView {
  observations: string[]; strength: 'strong' | 'specific' | 'weak'; shared_entities: string[]; seconds_apart: number;
  rationale: string; counts_as_corroboration: boolean;
}
export interface GraphView {
  observation_count: number;
  nodes: GraphNodeView[];
  edges: GraphEdgeView[];
  correlations: GraphCorrelationView[];
  contradictions: { observations: string[]; reason: string }[];
  uncertainties: { kind: string; detail: string; observations: string[] }[];
  truncated: boolean;
}
export interface EnrichmentView {
  entity: string; trust_class: string; observed_in: string[]; statement: string;
  matches: { source: string; kind: string; description: string; reference: string | null }[];
}
export interface AnalystStatementView {
  evidence_id: string; time: string | null; statement: string; analyst: string; entities: string[]; trust_class: string; counts_for_corroboration: boolean;
}
export interface DomainImportResult {
  schema: string; received: number; accepted: number; duplicates: number; quarantined: number; unclassified: number; undated: number;
  evidence: { record_index: number; evidence_id: string; sha256: string; evidence_type: string; classification: string; time_status: string; duplicate: boolean }[];
  quarantined_records: { record_index: number; reason: string; sha256_prefix: string | null }[];
}

export interface MultiSourceStartRequest {
  use_llm?: boolean;
  force?: boolean;
}

export interface MultiSourceReason {
  code: string;
  meaning: string;
}

/** ADR-013: a contradiction finding as returned by the API (fixed vocabulary, evidence ids, source names and times only). */
export interface ContradictionView {
  kind: 'ordering' | 'outcome' | 'identity' | 'temporal';
  proposition: string;
  materiality: 'material' | 'minor' | 'explained';
  relation: 'anchor' | 'corroborating' | 'relevant' | 'peripheral';
  affects_verdict: boolean;
  evidence_ids: string[];
  sources: string[];
  times: string[];
  time_quality: string[];
  claims: string[];
  link_strength: string;
  independence: 'independent' | 'same_source' | 'unknown';
  overlap_seconds: number;
  reliability: string[];
  explanation: string | null;
  resolution_hint: string;
  resolution_text: string;
}

/**
 * Sprint 1: same-pass, behaviour-preserving explanation of the CURRENT record-level suff-v4 decision. Identifiers (event UUIDs), fixed
 * codes and entity TYPE and STRENGTH only. Entity values are never part of it for any role (RESTRICTED visibility). Optional: results stored
 * before this feature have none.
 */
export interface MultiSourceRationale {
  schema: string;
  rule_version?: string;
  completeness: 'complete' | 'partial' | 'unavailable';
  trace_error?: string | null;
  independence_notion?: 'record_level';
  digest_check?: 'format_only';
  entity_values?: 'withheld';
  status?: {
    verdict: MultiSourceVerdict;
    meaning: string;
    model_call_permitted: boolean;
    llm_status: string;
    deterministic_report_available: boolean;
  };
  anchor?: { event_id: string | null; status: 'used' | 'dropped_temporal_anomaly' | 'absent_from_evidence' | 'none'; pairwise_without_anchor: boolean };
  units?: { unit: string; members: string[]; members_truncated?: boolean; attested_digest_format: boolean; relevant: boolean; role: string }[];
  collapsed?: { into: string; duplicate: string; basis: string[]; direct: boolean }[];
  corroboration?: {
    kind: 'corroborating' | 'repeated' | 'weak';
    unit_a: string;
    unit_b: string;
    shared_entities: { type: string; strength: string }[];
    tests: Record<string, boolean>;
  }[];
  exclusions?: { unit: string; reason: string }[];
  findings?: { code: string; qualifier: string | null; effect: string; evidence_ids: string[]; evidence_ids_truncated?: boolean }[];
  contradictions?: { kind: string; proposition: string; materiality: string; affects_verdict: boolean; evidence_ids: string[] }[];
  truncated?: Record<string, boolean>;
  limitations?: string[];
}

export interface MultiSourceSufficiency {
  rationale?: MultiSourceRationale;
  verdict: MultiSourceVerdict;
  rule_version: string;
  reason_codes: string[];
  reasons: MultiSourceReason[];
  assessment_sha256: string;
  abstain: boolean;
  counts: { events: number; evidence_units: number; relevant: number; attested: number; corroborating: number };
  evidence_ids: string[];
}

export interface MultiSourceTimelineEntry {
  position: number;
  timestamp: string;
  source_type: string;
  host: string | null;
  user: string | null;
  title: string;
  stage: string;
  severity: string;
  outcome: string;
  raw_sha256_prefix: string;
  membership: 'core' | 'weak_context';
  duplicates_collapsed: number;
  event_id: string;
  contradicts: string[];
}

export interface MultiSourceMitre {
  technique_id: string;
  technique_name: string;
  tactics: string[];
  rule_id: string;
  independent_evidence_count: number;
  vendor_asserted: boolean;
  limitation: string;
  evidence_event_ids: string[];
}

export interface MultiSourceLink {
  strength: 'strong' | 'specific' | 'weak';
  clusters: number[];
  entities: string[][];
}

export type ClaimVerificationOutcome = 'supported' | 'contradicted' | 'insufficient_evidence' | 'not_verifiable';

export interface AssertionResult {
  index: number;
  kind: string;
  outcome: ClaimVerificationOutcome;
  reason: string;
  field?: string | null;
  operator?: string | null;
  expected?: string | null;
  observed?: string | null;
  values_withheld?: boolean;
}

/** Deterministic check of the claim's structured assertions only (claim-verification-v1); never of the whole sentence. */
export interface ClaimVerification {
  schema_version: string;
  outcome: ClaimVerificationOutcome;
  reason: string;
  assertions_total: number;
  assertions_evaluated: number;
  assertions_truncated: boolean;
  results: AssertionResult[];
  applies_to: string;
  limits?: string[];
}

export interface MultiSourceClaim {
  claim_id: string;
  text: string;
  category: string;
  grounding: string;
  confidence: number;
  supporting_event_ids: string[];
  /** Absent/null for legacy claims that carry no structured assertions (shown as not machine-verifiable). */
  verification?: ClaimVerification | null;
}

export interface MultiSourceLlm {
  decision: string;
  is_valid: boolean;
  summary: string;
  grounding_score: number;
  claims: MultiSourceClaim[];
  uncertainty_and_data_gaps: string[];
  violations: string[];
}

export interface MultiSourceIncident {
  incident_id: string;
  severity: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  hosts: string[];
  users: string[];
  stages: string[];
  escalated: boolean;
  link_counts: Record<string, number>;
  weakly_related: string[];
  context_sha256: string;
  sufficiency: MultiSourceSufficiency;
  timeline: MultiSourceTimelineEntry[];
  links: MultiSourceLink[];
  weak_link_count: number;
  mitre: MultiSourceMitre[];
  asserted_only: string[];
  llm_status: string;
  llm: MultiSourceLlm | null;
  report_markdown: string;
  contradictions?: ContradictionView[];
  graph?: GraphView | null;
  enrichments?: EnrichmentView[];
  analyst_statements?: AnalystStatementView[];
}

/** The case lead's review of one stored investigation (human approval record). "stale" = the evidence changed after the run. */
export interface MultiSourceReview {
  state: 'not_reviewed' | 'approved' | 'rejected' | 'stale';
  decision: 'approved' | 'rejected' | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  note: string | null;
}

export interface MultiSourceReviewRequest {
  decision: 'approved' | 'rejected';
  evidence_fingerprint: string;
  note?: string;
}

export interface MultiSourceInvestigation {
  schema: string;
  status: string;
  created_at?: string;
  reused?: boolean;
  use_llm: boolean;
  workflow_version: string;
  evidence_fingerprint: string;
  counts: Record<string, number>;
  sources: { source_type: string; events: number; distinct_raw_records: number }[];
  rejected: { record_index: number; reason: string; raw_sha256_prefix: string }[];
  contradictions: { event_ids: string[]; reason: string }[];
  batch_sufficiency: MultiSourceSufficiency | null;
  batch_report_markdown: string | null;
  /** Present when the stored result lists fewer incidents/records than were found (size caps). */
  truncation?: {
    incidents_total: number; incidents_listed: number;
    rejected_total: number; rejected_listed: number;
    contradictions_total: number; contradictions_listed: number;
  };
  incidents: MultiSourceIncident[];
  observations?: DomainObservation[];
  observation_counts?: { total: number; listed: number; by_classification: Record<string, number>; undated: number; analyst_statements: number };
  batch_graph?: GraphView | null;
  ledger: { head: string; verified: boolean; steps: { seq: number; step: string; entry_hash: string }[] };
}
