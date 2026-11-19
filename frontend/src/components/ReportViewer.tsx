/**
 * AISOP Investigation Report Bundle Viewer Component.
 *
 * Implements role-tailored multi-audience presentation:
 * 1. Executive Brief (Leadership overview, business risk, affected assets)
 * 2. Technical IR Report (Grounded timeline, confirmed findings, inferences, MITRE ATT&CK)
 * 3. Detection Engineering Report (Observables with provenance, hunting pseudocode, false positives)
 * 4. Deterministic Markdown & JSON Export
 *
 * Security & Design Invariants:
 * - Zero dangerouslySetInnerHTML (all text rendered with automatic React JSX escaping).
 * - Cryptographic provenance and context binding verification surfaced prominently.
 * - Human-in-the-loop advisory notice (no autonomous containment actions).
 * - Full compliance with AISOP Website and Frontend Design Constitution.
 */

import { VerificationNote, LEGACY_GROUNDING_EXPLANATION } from './VerificationNote';
import React, { useState } from 'react';
import {
  DetectionObservableItem,
  IncidentSeverityTier,
  InvestigationReportBundle,
  TechnicalReportClaim,
  TimelineEventSummary,
} from '../types';
import { handleTabListKeyDown, tabButtonId, tabPanelId } from './tabs';
import { CheckIcon } from './Icons';

interface ReportViewerProps {
  bundle: InvestigationReportBundle;
  caseNumber?: string;
  caseTitle?: string;
  initialTab?: ReportTab;
  onRefresh?: () => void;
}

type ReportTab = 'executive' | 'technical' | 'detection' | 'markdown';

const REPORT_TAB_ORDER: readonly ReportTab[] = ['executive', 'technical', 'detection', 'markdown'];
const TAB_PREFIX = 'rv';

// Backend claim confidence is reported by the language model and can only be lowered by guardrail caps.
// It is not derived from evidence strength or corroboration.
const MODEL_CONFIDENCE_NOTE =
  'Reported by the language model and only capped by guardrails. It is not a measure of evidence strength or corroboration.';

export const ReportViewer: React.FC<ReportViewerProps> = ({
  bundle,
  caseNumber,
  caseTitle,
  initialTab,
  onRefresh,
}) => {
  const [activeTab, setActiveTab] = useState<ReportTab>(initialTab || 'executive');
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const {
    executive_brief,
    technical_report,
    detection_report,
    provenance,
    markdown_executive,
    markdown_technical,
    markdown_detection,
  } = bundle;

  const tabProps = (tab: ReportTab) => ({
    role: 'tab' as const,
    id: tabButtonId(TAB_PREFIX, tab),
    'aria-selected': activeTab === tab,
    'aria-controls': tabPanelId(TAB_PREFIX),
    tabIndex: activeTab === tab ? 0 : -1,
  });

  // Safe client-side file download helper
  const handleDownload = (filename: string, content: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleCopyMarkdown = async (text: string, sectionKey: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedSection(sectionKey);
      setTimeout(() => setCopiedSection(null), 2000);
    } catch {
      // Clipboard write failed or permission denied
    }
  };

  const getSeverityBadgeClass = (severity: IncidentSeverityTier): string => {
    switch (severity) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      case 'low':
        return 'badge-low';
      case 'informational':
        return 'badge-info';
      case 'inconclusive':
      default:
        return 'badge-inconclusive';
    }
  };

  const formatUtcTimestamp = (isoString?: string | null): string => {
    if (!isoString) return 'Unavailable';
    try {
      const dt = new Date(isoString);
      if (isNaN(dt.getTime())) return isoString;
      return dt.toISOString().replace('T', ' ').replace('Z', ' UTC');
    } catch {
      return isoString;
    }
  };

  return (
    <div className="report-viewer-card">
      {/* ── Header & Provenance Bar ─────────────────────────────────────── */}
      <div className="report-header">
        <div className="report-header-main">
          <div className="report-title-row">
            <h2 className="report-title">{executive_brief.title}</h2>
            <span className={`severity-badge ${getSeverityBadgeClass(executive_brief.incident_severity)}`}>
              {executive_brief.incident_severity.toUpperCase()}
            </span>
            {provenance.is_verified_investigation ? (
              <span className="provenance-badge verified" title="This output matches a server-side case audit record. It does not verify that any claim is true.">
                Server Audit Verified
              </span>
            ) : (
              <span className="provenance-badge unverified" title="Detached or unverified against database audit trail">
                Detached / Unverified
              </span>
            )}
            {bundle.is_fallback_active && (
              <span className="provenance-badge fallback" title="Synthesized via deterministic emergency fallback">
                Fallback Active
              </span>
            )}
          </div>

          <div className="report-meta-row">
            {caseNumber && (
              <span className="meta-item">
                <strong>Case:</strong> {caseNumber} {caseTitle ? `: ${caseTitle}` : ''}
              </span>
            )}
            <span className="meta-item">
              <strong>Generated:</strong> {formatUtcTimestamp(bundle.generated_at_utc)}
            </span>
            <span
              className="meta-item"
              title="Share of claims whose cited evidence passed validation. It is not a measure of evidence strength or corroboration."
            >
              <strong>Claims validated:</strong> {(provenance.overall_grounding_score * 100).toFixed(0)}%
            </span>
            <span className="meta-item">
              <strong>Model:</strong> {provenance.model_identifier}
            </span>
            <span className="meta-item mono" title={`SHA-256 Context: ${bundle.context_sha256}`}>
              <strong>Context Hash:</strong> {bundle.context_sha256.substring(0, 12)}...
            </span>
          </div>
        </div>

        <div className="report-header-actions">
          {onRefresh && (
            <button className="btn btn-secondary" onClick={onRefresh} title="Re-synthesize investigation bundle">
              Re-Synthesize
            </button>
          )}

          <div className="export-dropdown-group">
            <button
              className="btn btn-secondary"
              onClick={() =>
                handleDownload(
                  `aisop-report-bundle-${bundle.investigation_id}.json`,
                  JSON.stringify(bundle, null, 2),
                  'application/json'
                )
              }
              title="Export complete structured JSON bundle"
            >
              Export JSON
            </button>

            <button
              className="btn btn-primary"
              onClick={() => {
                const combined = `# ${executive_brief.title}\n\n## EXECUTIVE BRIEF\n\n${markdown_executive}\n\n---\n\n## TECHNICAL REPORT\n\n${markdown_technical}\n\n---\n\n## DETECTION ENGINEERING\n\n${markdown_detection}`;
                handleDownload(`aisop-full-report-${bundle.investigation_id}.md`, combined, 'text/markdown');
              }}
              title="Export consolidated Markdown report"
            >
              Export Markdown
            </button>
          </div>
        </div>
      </div>

      {/* ── View Selection Tabs ─────────────────────────────────────────── */}
      <div
        className="report-tab-bar"
        role="tablist"
        aria-label="Report views"
        onKeyDown={(e) => handleTabListKeyDown(e, REPORT_TAB_ORDER, activeTab, setActiveTab, TAB_PREFIX)}
      >
        <button
          {...tabProps('executive')}
          className={`report-tab-btn ${activeTab === 'executive' ? 'active' : ''}`}
          onClick={() => setActiveTab('executive')}
        >
          Executive Brief
        </button>
        <button
          {...tabProps('technical')}
          className={`report-tab-btn ${activeTab === 'technical' ? 'active' : ''}`}
          onClick={() => setActiveTab('technical')}
        >
          Technical IR Report
          <span className="tab-counter">{technical_report.investigation_timeline.length} events</span>
        </button>
        <button
          {...tabProps('detection')}
          className={`report-tab-btn ${activeTab === 'detection' ? 'active' : ''}`}
          onClick={() => setActiveTab('detection')}
        >
          Detection Engineering
          <span className="tab-counter">{detection_report.validated_observables.length} observables</span>
        </button>
        <button
          {...tabProps('markdown')}
          className={`report-tab-btn ${activeTab === 'markdown' ? 'active' : ''}`}
          onClick={() => setActiveTab('markdown')}
        >
          Raw Markdown Views
        </button>
      </div>

      <div role="tabpanel" id={tabPanelId(TAB_PREFIX)} aria-labelledby={tabButtonId(TAB_PREFIX, activeTab)}>
      {/* ── Tab 1: Executive Brief ─────────────────────────────────────── */}
      {activeTab === 'executive' && (
        <div className="report-content-pane">
          <section className="report-section">
            <h3 className="section-heading">Incident Executive Summary</h3>
            <p className="narrative-text">{executive_brief.executive_summary}</p>
          </section>

          <div className="brief-grid">
            <section className="report-section card-nested">
              <h4 className="sub-heading">Severity Justification</h4>
              <p className="narrative-text">{executive_brief.severity_justification}</p>
            </section>

            <section className="report-section card-nested">
              <h4 className="sub-heading">Business Risk Assessment</h4>
              <p className="narrative-text">{executive_brief.business_risk_statement}</p>
            </section>
          </div>

          <section className="report-section">
            <h3 className="section-heading">Key Findings (AI-generated, cited; not analyst-confirmed)</h3>
            {executive_brief.key_confirmed_findings.length > 0 ? (
              <ul className="finding-bullet-list">
                {executive_brief.key_confirmed_findings.map((finding, idx) => (
                  <li key={idx} className="finding-bullet-item">
                    <span className="finding-bullet-icon"><CheckIcon /></span>
                    <span>{finding}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="empty-state-notice">No validated findings confirmed in this investigation.</div>
            )}
          </section>

          <section className="report-section">
            <h3 className="section-heading">Evidenced Affected Assets</h3>
            {executive_brief.evidenced_affected_assets.length > 0 ? (
              <div className="tag-cloud">
                {executive_brief.evidenced_affected_assets.map((asset, idx) => (
                  <span key={idx} className="asset-tag">
                    {asset}
                  </span>
                ))}
              </div>
            ) : (
              <div className="empty-state-notice">No specific host or asset identifiers extracted from telemetry.</div>
            )}
          </section>

          <section className="report-section">
            <h3 className="section-heading">Threat Intelligence Context</h3>
            <p className="narrative-text">{executive_brief.threat_intelligence_context}</p>
          </section>

          {executive_brief.uncertainties_and_limitations.length > 0 && (
            <section className="report-section warning-box">
              <h4 className="sub-heading warning-title">Investigation Uncertainties & Limitations</h4>
              <ul className="standard-bullet-list">
                {executive_brief.uncertainties_and_limitations.map((limit, idx) => (
                  <li key={idx}>{limit}</li>
                ))}
              </ul>
            </section>
          )}

          <div className="governance-footer">{executive_brief.governance_disclaimer}</div>
        </div>
      )}

      {/* ── Tab 2: Technical Incident Response Report ───────────────────── */}
      {activeTab === 'technical' && (
        <div className="report-content-pane">
          <section className="report-section">
            <h3 className="section-heading">Technical Incident Narrative</h3>
            <p className="narrative-text">{technical_report.technical_narrative}</p>
          </section>

          {/* Investigation Timeline */}
          <section className="report-section">
            <div className="section-header-split">
              <h3 className="section-heading">Incident Timeline</h3>
              <span className="section-counter">
                {technical_report.investigation_timeline.length} Chronological Events
              </span>
            </div>

            {technical_report.timeline_status_disclosure && (
              <div className="alert-box alert-info">{technical_report.timeline_status_disclosure}</div>
            )}

            {technical_report.investigation_timeline.length > 0 ? (
              <div className="table-responsive">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th style={{ width: '180px' }}>Timestamp (UTC)</th>
                      <th style={{ width: '130px' }}>Sensor / Host</th>
                      <th style={{ width: '130px' }}>Event Type</th>
                      <th style={{ width: '100px' }}>Action</th>
                      <th style={{ width: '90px' }}>Outcome</th>
                      <th>Summary</th>
                    </tr>
                  </thead>
                  <tbody>
                    {technical_report.investigation_timeline.map((event: TimelineEventSummary) => (
                      <tr key={event.event_uuid}>
                        <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                          {formatUtcTimestamp(event.timestamp_utc)}
                        </td>
                        <td className="mono">{event.source_identifier}</td>
                        <td>
                          <span className="event-type-badge">{event.event_type}</span>
                        </td>
                        <td>{event.action}</td>
                        <td>
                          <span className={`outcome-pill ${event.outcome.toLowerCase()}`}>{event.outcome}</span>
                        </td>
                        <td className="summary-cell">{event.summary}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state-notice">No chronological telemetry events recorded for this case scope.</div>
            )}
          </section>

          {/* Claims & Epistemic Segregation */}
          <section className="report-section">
            <h3 className="section-heading">Factual Claims & Evidence Provenance</h3>

            <p className="claims-legend">{LEGACY_GROUNDING_EXPLANATION}</p>
            {/* Cited findings (legacy grounding) */}
            <div className="claims-category-group">
              <h4 className="claims-group-title confirmed">
                Cited Findings - legacy grounding, not analyst-confirmed ({technical_report.confirmed_findings.length})
              </h4>
              {technical_report.confirmed_findings.length > 0 ? (
                <div className="claims-list">
                  {technical_report.confirmed_findings.map((claim: TechnicalReportClaim) => (
                    <div key={claim.claim_id} className="claim-card confirmed">
                      <div className="claim-header">
                        <span className="claim-badge confirmed">{claim.grounding_status.toUpperCase()}</span>
                        <span className="claim-confidence" title={MODEL_CONFIDENCE_NOTE}>Model-reported confidence: {(claim.confidence * 100).toFixed(0)}%</span>
                        <span className="claim-category">Type: {claim.category}</span>
                      </div>
                      <p className="claim-text">{claim.claim_text}</p>
                      {claim.supporting_event_uuids.length > 0 && (
                        <div className="claim-provenance mono">
                          Supporting Events: {claim.supporting_event_uuids.join(', ')}
                        </div>
                      )}
                      {claim.analyst_notes && <div className="claim-notes">{claim.analyst_notes}</div>}
                      <VerificationNote verification={claim.verification} report />
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state-notice">No claims validated against telemetry evidence.</div>
              )}
            </div>

            {/* Inferences */}
            <div className="claims-category-group">
              <h4 className="claims-group-title inference">
                Hypotheses & Inferences ({technical_report.hypotheses_and_inferences.length})
              </h4>
              {technical_report.hypotheses_and_inferences.length > 0 ? (
                <div className="claims-list">
                  {technical_report.hypotheses_and_inferences.map((claim: TechnicalReportClaim) => (
                    <div key={claim.claim_id} className="claim-card inference">
                      <div className="claim-header">
                        <span className="claim-badge inference">ANALYST REVIEW REQUIRED</span>
                        <span className="claim-confidence" title={MODEL_CONFIDENCE_NOTE}>Model-reported confidence: {(claim.confidence * 100).toFixed(0)}%</span>
                        <span className="claim-category">Type: {claim.category}</span>
                      </div>
                      <p className="claim-text">{claim.claim_text}</p>
                      {claim.supporting_event_uuids.length > 0 && (
                        <div className="claim-provenance mono">
                          Associated Events: {claim.supporting_event_uuids.join(', ')}
                        </div>
                      )}
                      {claim.analyst_notes && <div className="claim-notes">{claim.analyst_notes}</div>}
                      <VerificationNote verification={claim.verification} report />
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state-notice">No ungrounded hypotheses or inferences recorded.</div>
              )}
            </div>

            {/* Unsupported / Refuted */}
            {technical_report.unsupported_or_contradicted_claims.length > 0 && (
              <div className="claims-category-group">
                <h4 className="claims-group-title refuted">
                  Refuted or Unsupported Claims ({technical_report.unsupported_or_contradicted_claims.length})
                </h4>
                <div className="claims-list">
                  {technical_report.unsupported_or_contradicted_claims.map((claim: TechnicalReportClaim) => (
                    <div key={claim.claim_id} className="claim-card refuted">
                      <div className="claim-header">
                        <span className="claim-badge refuted">{claim.grounding_status.toUpperCase()}</span>
                        <span className="claim-confidence" title={MODEL_CONFIDENCE_NOTE}>Model-reported confidence: {(claim.confidence * 100).toFixed(0)}%</span>
                      </div>
                      <p className="claim-text">{claim.claim_text}</p>
                      {claim.analyst_notes && <div className="claim-notes">{claim.analyst_notes}</div>}
                      <VerificationNote verification={claim.verification} report />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>

          {/* MITRE ATT&CK */}
          <section className="report-section">
            <h3 className="section-heading">MITRE ATT&CK Mappings</h3>
            {technical_report.mitre_attack_mappings.length > 0 ? (
              <div className="mitre-grid">
                {technical_report.mitre_attack_mappings.map((mapping: Record<string, any>, idx: number) => (
                  <div key={idx} className="mitre-card">
                    <div className="mitre-header">
                      <span className="mitre-id mono">{mapping.technique_id || 'Technique ID not provided'}</span>
                      <span className="mitre-tactic">{mapping.tactic || 'Tactic not provided'}</span>
                    </div>
                    <div className="mitre-name">{mapping.technique_name || 'Technique name not provided'}</div>
                    {mapping.supporting_evidence && (
                      <p className="mitre-evidence">{String(mapping.supporting_evidence)}</p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state-notice">No MITRE ATT&CK techniques explicitly mapped to this evidence.</div>
            )}
          </section>

          {/* Investigation Gaps */}
          {technical_report.investigation_gaps.length > 0 && (
            <section className="report-section">
              <h3 className="section-heading">Identified Investigation Gaps</h3>
              <ul className="standard-bullet-list">
                {technical_report.investigation_gaps.map((gap, idx) => (
                  <li key={idx}>{gap}</li>
                ))}
              </ul>
            </section>
          )}

          {/* Recommended Analyst Actions */}
          <section className="report-section">
            <h3 className="section-heading">Recommended Analyst Actions</h3>
            <div className="advisory-callout">
              <strong>Human-in-the-Loop Operational Policy:</strong>
              <p>
                The containment and investigative actions below are advisory recommendations only. AISOP does NOT
                perform automated host isolation, credential resets, or firewall modifications. All actions require
                authorized analyst review.
              </p>
            </div>
            {technical_report.recommended_analyst_actions.length > 0 ? (
              <ol className="action-numbered-list">
                {technical_report.recommended_analyst_actions.map((action, idx) => (
                  <li key={idx} className="action-item">
                    {action}
                  </li>
                ))}
              </ol>
            ) : (
              <div className="empty-state-notice">No specific analyst actions recommended.</div>
            )}
          </section>

          <div className="governance-footer">{technical_report.governance_disclaimer}</div>
        </div>
      )}

      {/* ── Tab 3: Detection Engineering ───────────────────────────────── */}
      {activeTab === 'detection' && (
        <div className="report-content-pane">
          {/* Validated Observables */}
          <section className="report-section">
            <div className="section-header-split">
              <h3 className="section-heading">Extracted Observables with Provenance</h3>
              <span className="section-counter">
                {detection_report.validated_observables.length} Indicators
              </span>
            </div>

            {detection_report.validated_observables.length > 0 ? (
              <div className="table-responsive">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th style={{ width: '130px' }}>Type</th>
                      <th>Observable Value</th>
                      <th style={{ width: '160px' }}>Provenance</th>
                      <th style={{ width: '110px' }}>Disposition</th>
                      <th style={{ width: '170px' }}>First Seen (UTC)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detection_report.validated_observables.map(
                      (obs: DetectionObservableItem, idx: number) => (
                        <tr key={idx}>
                          <td>
                            <span className="observable-type-badge">{obs.observable_type}</span>
                          </td>
                          <td className="mono break-all">{obs.observable_value}</td>
                          <td className="provenance-cell">
                            <span className={`provenance-tag ${obs.provenance_type}`}>
                              {obs.provenance_type}
                            </span>
                          </td>
                          <td>
                            {obs.is_malicious_asserted ? (
                              <span className="malicious-pill">Malicious</span>
                            ) : (
                              <span className="neutral-pill">Observed</span>
                            )}
                          </td>
                          <td className="mono">{formatUtcTimestamp(obs.first_seen_utc)}</td>
                        </tr>
                      )
                    )}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state-notice">No extracted observables available in this report.</div>
            )}
          </section>

          {/* Hunting Pseudocode */}
          <section className="report-section">
            <h3 className="section-heading">Candidate Threat Hunting Pseudocode</h3>
            {detection_report.candidate_hunting_pseudocode.length > 0 ? (
              <div className="pseudocode-stack">
                {detection_report.candidate_hunting_pseudocode.map((code, idx) => (
                  <pre key={idx} className="code-block mono">
                    <code>{code}</code>
                  </pre>
                ))}
              </div>
            ) : (
              <div className="empty-state-notice">No hunting pseudocode generated for this scope.</div>
            )}
          </section>

          {/* Candidate Detection Hypotheses */}
          <section className="report-section">
            <h3 className="section-heading">Detection Hypotheses & Engineering Guidance</h3>
            {detection_report.candidate_detection_hypotheses.length > 0 ? (
              <ul className="standard-bullet-list">
                {detection_report.candidate_detection_hypotheses.map((hypo, idx) => (
                  <li key={idx}>{hypo}</li>
                ))}
              </ul>
            ) : (
              <div className="empty-state-notice">No detection hypotheses specified.</div>
            )}
          </section>

          {/* False Positive Considerations */}
          <section className="report-section">
            <h3 className="section-heading">False-Positive Considerations</h3>
            {detection_report.false_positive_considerations.length > 0 ? (
              <ul className="standard-bullet-list">
                {detection_report.false_positive_considerations.map((fp, idx) => (
                  <li key={idx}>{fp}</li>
                ))}
              </ul>
            ) : (
              <div className="empty-state-notice">No specific false-positive conditions noted.</div>
            )}
          </section>

          {/* Recommended Log Sources */}
          {detection_report.recommended_log_sources.length > 0 && (
            <section className="report-section">
              <h3 className="section-heading">Recommended Telemetry Sources</h3>
              <div className="tag-cloud">
                {detection_report.recommended_log_sources.map((src, idx) => (
                  <span key={idx} className="source-tag">
                    {src}
                  </span>
                ))}
              </div>
            </section>
          )}

          <div className="governance-footer">{detection_report.governance_disclaimer}</div>
        </div>
      )}

      {/* ── Tab 4: Raw Markdown Views ─────────────────────────────────── */}
      {activeTab === 'markdown' && (
        <div className="report-content-pane">
          <div className="markdown-section">
            <div className="section-header-split">
              <h3 className="section-heading">Executive Brief (Deterministic Markdown)</h3>
              <div className="btn-group">
                <button
                  className="btn btn-secondary"
                  onClick={() => handleCopyMarkdown(markdown_executive, 'exec')}
                >
                  {copiedSection === 'exec' ? 'Copied!' : 'Copy Markdown'}
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() =>
                    handleDownload(
                      `executive-brief-${bundle.investigation_id}.md`,
                      markdown_executive,
                      'text/markdown'
                    )
                  }
                >
                  Download .md
                </button>
              </div>
            </div>
            <pre className="markdown-raw-block mono">
              <code>{markdown_executive}</code>
            </pre>
          </div>

          <div className="markdown-section">
            <div className="section-header-split">
              <h3 className="section-heading">Technical Report (Deterministic Markdown)</h3>
              <div className="btn-group">
                <button
                  className="btn btn-secondary"
                  onClick={() => handleCopyMarkdown(markdown_technical, 'tech')}
                >
                  {copiedSection === 'tech' ? 'Copied!' : 'Copy Markdown'}
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() =>
                    handleDownload(
                      `technical-report-${bundle.investigation_id}.md`,
                      markdown_technical,
                      'text/markdown'
                    )
                  }
                >
                  Download .md
                </button>
              </div>
            </div>
            <pre className="markdown-raw-block mono">
              <code>{markdown_technical}</code>
            </pre>
          </div>

          <div className="markdown-section">
            <div className="section-header-split">
              <h3 className="section-heading">Detection Engineering (Deterministic Markdown)</h3>
              <div className="btn-group">
                <button
                  className="btn btn-secondary"
                  onClick={() => handleCopyMarkdown(markdown_detection, 'detect')}
                >
                  {copiedSection === 'detect' ? 'Copied!' : 'Copy Markdown'}
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() =>
                    handleDownload(
                      `detection-report-${bundle.investigation_id}.md`,
                      markdown_detection,
                      'text/markdown'
                    )
                  }
                >
                  Download .md
                </button>
              </div>
            </div>
            <pre className="markdown-raw-block mono">
              <code>{markdown_detection}</code>
            </pre>
          </div>
        </div>
      )}
      </div>
    </div>
  );
};
