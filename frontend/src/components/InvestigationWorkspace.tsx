/**
 * AISOP Phase 4B - Investigation Workspace Component.
 *
 * Evidence-Centred Case Investigation and Analyst Workflow:
 * - Case Overview with authentic API-backed metadata (zero invented metrics).
 * - Evidence Panel with case-scoped filtering, pagination, and inspection (zero raw-payload leakage).
 * - Investigation Context distinguishing observed facts from enrichment and AI interpretations.
 * - Human-Invoked AI Investigation with deterministic fallback and offline provider awareness.
 * - Epistemically partitioned findings (Observed Facts vs Inferences, MITRE ATT&CK, Actions, Gaps).
 * - Immutable Activity & Audit history.
 * - Integration with full Report Viewer.
 *
 * Invariants:
 * - Zero emojis (uses accessible SVGs or textual labels).
 * - Zero purple gradients or pill-shaped buttons (radius <= 6px).
 * - Zero dangerouslySetInnerHTML (all text rendered through React JSX escaping).
 * - Zero automatic LLM invocation (strictly human-in-the-loop).
 */

import { VerificationNote, LEGACY_GROUNDING_EXPLANATION } from './VerificationNote';
import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import {
  CaseResponse,
  CaseScopedEvidenceItem,
  CaseAuditEventItem,
  InvestigationValidationResult,
} from '../types';
import { useAuth } from '../contexts/AuthContext';
import { AI_EXPLANATION_TIMEOUT_MS, AiRunStatus, MultiSourcePanel, useElapsedSeconds } from './MultiSourcePanel';
import { runWithDeadline } from '../utils/deadline';
import { Dialog } from './Dialog';
import { AuditDetailsCell, AuditDetailsRow } from './AuditDetails';
import { handleTabListKeyDown, tabButtonId, tabPanelId } from './tabs';
import { CloseIcon } from './Icons';
import { ExhibitTag } from './ExhibitTag';
import { useTimeZone } from '../contexts/TimeZoneContext';
import { formatInstant } from '../utils/time';

interface InvestigationWorkspaceProps {
  caseId: string;
  onBackToQueue: () => void;
  onNavigateToReport?: (caseId: string) => void;
  initialCaseDetail?: CaseResponse | null;
  initialValidationResult?: InvestigationValidationResult | null;
  initialTab?: WorkspaceTab;
  initialEvidence?: CaseScopedEvidenceItem[];
  initialActivity?: CaseAuditEventItem[];
  initialCaseError?: string | null;
}

type WorkspaceTab = 'evidence' | 'findings' | 'context' | 'activity' | 'multisource';

// Tab order is unchanged (Phase 2 adds semantics only).
const WORKSPACE_TAB_ORDER: readonly WorkspaceTab[] = ['evidence', 'findings', 'context', 'multisource', 'activity'];
const TAB_PREFIX = 'ws';

export const InvestigationWorkspace: React.FC<InvestigationWorkspaceProps> = ({
  caseId,
  onBackToQueue,
  onNavigateToReport,
  initialCaseDetail,
  initialValidationResult,
  initialTab,
  initialEvidence,
  initialActivity,
  initialCaseError,
}) => {
  const { canCloseCase, canSynthesizeReports } = useAuth();
  const { zone } = useTimeZone();

  // Case detail state
  const [caseDetail, setCaseDetail] = useState<CaseResponse | null>(initialCaseDetail || null);
  const [caseLoading, setCaseLoading] = useState<boolean>(!initialCaseDetail && !initialCaseError);
  const [caseError, setCaseError] = useState<string | null>(initialCaseError || null);

  // Active workspace tab
  const [activeTab, setActiveTab] = useState<WorkspaceTab>(initialTab || 'evidence');

  // Evidence panel state
  const [evidenceItems, setEvidenceItems] = useState<CaseScopedEvidenceItem[]>(initialEvidence || []);
  const [evidenceTotal, setEvidenceTotal] = useState<number>(initialEvidence ? initialEvidence.length : 0);
  const [evidencePage, setEvidencePage] = useState<number>(1);
  const [evidenceLimit] = useState<number>(15);
  const [evidenceLoading, setEvidenceLoading] = useState<boolean>(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');

  // Selected evidence for deep inspection
  const [inspectingEvidence, setInspectingEvidence] = useState<CaseScopedEvidenceItem | null>(null);

  // Link evidence modal state
  const [isLinkOpen, setIsLinkOpen] = useState<boolean>(false);
  const [evidenceIdToLink, setEvidenceIdToLink] = useState<string>('');
  const [linkSubmitting, setLinkSubmitting] = useState<boolean>(false);
  const [linkError, setLinkError] = useState<string | null>(null);

  // AI Investigation synthesis state
  const [validationResult, setValidationResult] = useState<InvestigationValidationResult | null>(
    initialValidationResult || null
  );
  const [synthesizing, setSynthesizing] = useState<boolean>(false);
  const [synthesisError, setSynthesisError] = useState<string | null>(null);
  const synthCancelRef = React.useRef<(() => void) | null>(null);
  const synthElapsed = useElapsedSeconds(synthesizing);
  const [queryFilter, setQueryFilter] = useState<string>('');

  // Case Activity state
  const [activities, setActivities] = useState<CaseAuditEventItem[]>(initialActivity || []);
  const [activityLoading, setActivityLoading] = useState<boolean>(false);
  const [activityError, setActivityError] = useState<string | null>(null);
  // Audit rows whose full details are disclosed (keyboard-operable disclosure, not hover-only).
  const [expandedAudit, setExpandedAudit] = useState<Set<string>>(new Set());
  const toggleAudit = (id: string) =>
    setExpandedAudit((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  // Close case modal state
  const [isCloseOpen, setIsCloseOpen] = useState<boolean>(false);
  const [closureReason, setClosureReason] = useState<string>('');
  const [closeSubmitting, setCloseSubmitting] = useState<boolean>(false);
  const [closeError, setCloseError] = useState<string | null>(null);

  // 1. Fetch Case Detail
  const fetchCaseDetail = useCallback(async () => {
    setCaseLoading(true);
    setCaseError(null);
    try {
      const data = await api.getCaseDetail(caseId);
      setCaseDetail(data);
    } catch (err: any) {
      setCaseError(err.message || 'Failed to retrieve case details. Access denied or case not found.');
    } finally {
      setCaseLoading(false);
    }
  }, [caseId]);

  // 2. Fetch Case Evidence
  const fetchEvidence = useCallback(async () => {
    setEvidenceLoading(true);
    setEvidenceError(null);
    try {
      const res = await api.getCaseEvidence(caseId, {
        page: evidencePage,
        limit: evidenceLimit,
      });
      // Filter client-side if query params are applied
      let items = res.items;
      if (eventTypeFilter) {
        items = items.filter((ev) => ev.event_type === eventTypeFilter);
      }
      if (severityFilter) {
        items = items.filter((ev) => ev.severity.toLowerCase() === severityFilter.toLowerCase());
      }
      setEvidenceItems(items);
      setEvidenceTotal(res.total);
    } catch (err: any) {
      setEvidenceError(err.message || 'Failed to retrieve case evidence.');
      setEvidenceItems([]);
      setEvidenceTotal(0);
    } finally {
      setEvidenceLoading(false);
    }
  }, [caseId, evidencePage, evidenceLimit, eventTypeFilter, severityFilter]);

  // 3. Fetch Case Activity
  const fetchActivity = useCallback(async () => {
    setActivityLoading(true);
    setActivityError(null);
    try {
      const list = await api.getCaseActivity(caseId);
      setActivities(list);
    } catch (err: any) {
      setActivityError(err.message || 'Failed to retrieve case activity history.');
      setActivities([]);
    } finally {
      setActivityLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    if (!initialCaseDetail && !initialCaseError) {
      fetchCaseDetail();
    }
  }, [fetchCaseDetail, initialCaseDetail, initialCaseError]);

  useEffect(() => {
    if (activeTab === 'evidence' || activeTab === 'context') {
      if (!initialEvidence) {
        fetchEvidence();
      }
    } else if (activeTab === 'activity') {
      if (!initialActivity) {
        fetchActivity();
      }
    }
  }, [activeTab, fetchEvidence, fetchActivity, initialEvidence, initialActivity]);

  // Handle Link Evidence
  const handleLinkEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanId = evidenceIdToLink.trim();
    if (!cleanId) return;

    setLinkSubmitting(true);
    setLinkError(null);
    try {
      await api.linkCaseEvidence(caseId, cleanId);
      setIsLinkOpen(false);
      setEvidenceIdToLink('');
      fetchEvidence();
      fetchActivity();
    } catch (err: any) {
      setLinkError(err.message || 'Failed to associate evidence with case.');
    } finally {
      setLinkSubmitting(false);
    }
  };

  // Handle Human-Invoked AI Investigation
  const handleStartInvestigation = async () => {
    if (synthCancelRef.current) return; // a run is already active: never send a duplicate request
    setSynthesizing(true);
    setSynthesisError(null);
    const handle = runWithDeadline(
      (signal) => api.synthesizeCaseInvestigation(caseId, { query_filter: queryFilter.trim() || undefined }, signal),
      AI_EXPLANATION_TIMEOUT_MS
    );
    synthCancelRef.current = handle.cancel;
    const outcome = await handle.result;
    synthCancelRef.current = null;
    if (outcome.kind === 'done') {
      setValidationResult(outcome.value);
      setActiveTab('findings');
      fetchActivity();
    } else if (outcome.kind === 'failed') {
      setSynthesisError(outcome.message || 'AI investigation synthesis failed.');
    } else if (outcome.kind === 'timeout') {
      setSynthesisError(`The local model did not answer within ${Math.round(AI_EXPLANATION_TIMEOUT_MS / 1000)} s, so the request was stopped. The server may still finish this run in the background. Use Retry to try again.`);
    } else {
      setSynthesisError('The AI investigation was cancelled. Nothing was changed. Use Retry to start it again.');
    }
    setSynthesizing(false);
  };

  // Handle Close case
  const handleCloseCase = async () => {
    if (!closureReason.trim()) return;
    setCloseSubmitting(true);
    setCloseError(null);
    try {
      const updated = await api.closeCase(caseId, closureReason.trim());
      setCaseDetail(updated);
      setIsCloseOpen(false);
      setClosureReason('');
      fetchActivity();
    } catch (err: any) {
      setCloseError(err.message || 'Failed to close case');
    } finally {
      setCloseSubmitting(false);
    }
  };

  const tabProps = (tab: WorkspaceTab) => ({
    role: 'tab' as const,
    id: tabButtonId(TAB_PREFIX, tab),
    'aria-selected': activeTab === tab,
    'aria-controls': tabPanelId(TAB_PREFIX),
    tabIndex: activeTab === tab ? 0 : -1,
  });

  // Written in the zone chosen in the header (UTC by default), always naming the zone. An unparseable value is shown as received.
  const formatUtc = (dateStr?: string | null): string => {
    if (!dateStr) return 'N/A';
    const out = formatInstant(dateStr, zone);
    return out === 'Unknown' ? dateStr : out;
  };

  const getSeverityBadgeClass = (sev: string): string => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      case 'low':
        return 'badge-low';
      default:
        return 'badge-info';
    }
  };

  if (caseLoading) {
    return (
      <div className="investigation-workspace">
        <div style={{ marginBottom: '16px' }}>
          <button className="btn btn-secondary" onClick={onBackToQueue}>
            Back to cases
          </button>
        </div>
        <div className="table-container" style={{ padding: '48px', textAlign: 'center' }}>
          <div style={{ color: 'var(--text-secondary)' }}>Loading investigation workspace for case {caseId}...</div>
        </div>
      </div>
    );
  }

  if (caseError || !caseDetail) {
    return (
      <div className="table-container" style={{ padding: '32px' }}>
        <div className="alert-box alert-error" style={{ marginBottom: '16px' }}>
          {caseError || 'Case not found or access denied.'}
        </div>
        <button className="btn btn-secondary" onClick={onBackToQueue}>
          Back to Case Queue
        </button>
      </div>
    );
  }

  return (
    <div className="investigation-workspace">
      {/* ── Section A: Case Overview Header ─────────────────────────────── */}
      <div
        style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border-color)',
          borderRadius: '6px',
          padding: '20px 24px',
          marginBottom: '24px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px 12px', marginBottom: '8px' }}>
              <button
                className="btn btn-secondary"
                style={{ padding: '4px 10px', fontSize: '12px', whiteSpace: 'nowrap' }}
                onClick={onBackToQueue}
              >
                Back to cases
              </button>
              <span className="font-mono" style={{ fontSize: '14px', color: 'var(--accent-teal)', fontWeight: 600 }}>
                {caseDetail.case_number}
              </span>
              <span className={`badge ${getSeverityBadgeClass(caseDetail.severity)}`}>
                {caseDetail.severity.toUpperCase()}
              </span>
              <span className={`badge badge-${caseDetail.status}`}>
                {caseDetail.status.toUpperCase()}
              </span>
            </div>
            <h1 style={{ fontSize: '22px', fontWeight: 600, color: 'var(--text-primary)' }}>
              {caseDetail.title}
            </h1>
            {caseDetail.description && (
              <p style={{ color: 'var(--text-secondary)', marginTop: '6px', maxWidth: '900px', fontSize: '13px' }}>
                {caseDetail.description}
              </p>
            )}
          </div>

          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {canSynthesizeReports() && caseDetail.status !== 'closed' && caseDetail.status !== 'archived' && (
              <button
                className="btn btn-primary"
                disabled={synthesizing}
                onClick={handleStartInvestigation}
                style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                {synthesizing ? 'Synthesizing AI investigation...' : 'Start AI investigation'}
              </button>
            )}

            {onNavigateToReport && (
              <button
                className="btn btn-secondary"
                onClick={() => onNavigateToReport(caseDetail.id)}
              >
                Report bundle
              </button>
            )}

            {canCloseCase() && caseDetail.status !== 'closed' && caseDetail.status !== 'archived' && (
              <button
                className="btn btn-danger"
                onClick={() => setIsCloseOpen(true)}
              >
                Close case
              </button>
            )}
          </div>
        </div>

        {/* Metadata Strip */}
        <div
          style={{
            display: 'flex',
            gap: '24px',
            marginTop: '16px',
            paddingTop: '16px',
            borderTop: '1px solid var(--border-subtle)',
            fontSize: '12px',
            color: 'var(--text-secondary)',
            flexWrap: 'wrap',
          }}
        >
          <div>
            Lead analyst:{' '}
            <span style={{ color: 'var(--text-primary)' }} title={caseDetail.lead_analyst_id}>
              {caseDetail.lead_analyst_username ?? caseDetail.lead_analyst_id}
            </span>
          </div>
          <div>
            Created: <span style={{ color: 'var(--text-primary)' }}>{formatUtc(caseDetail.created_at)}</span>
          </div>
          <div>
            Updated: <span style={{ color: 'var(--text-primary)' }}>{formatUtc(caseDetail.updated_at)}</span>
          </div>
          {caseDetail.closed_at && (
            <div>
              Closed: <span style={{ color: 'var(--severity-critical)' }}>{formatUtc(caseDetail.closed_at)}</span>
            </div>
          )}
          <div>
            Linked evidence: <span className="font-mono" style={{ color: 'var(--accent-text)', fontWeight: 600 }}>{evidenceTotal}</span>
          </div>
        </div>
      </div>

      {/* ── Navigation Tabs ─────────────────────────────────────────────── */}
      <div
        role="tablist"
        aria-label="Case workspace sections"
        onKeyDown={(e) => handleTabListKeyDown(e, WORKSPACE_TAB_ORDER, activeTab, setActiveTab, TAB_PREFIX)}
        style={{ display: 'flex', gap: '4px', borderBottom: '1px solid var(--border-color)', marginBottom: '20px' }}
      >
        <button
          {...tabProps('evidence')}
          className={`nav-item ${activeTab === 'evidence' ? 'active' : ''}`}
          style={{
            borderBottom: activeTab === 'evidence' ? '2px solid var(--accent-blue)' : '2px solid transparent',
            borderRadius: '6px 6px 0 0',
          }}
          onClick={() => setActiveTab('evidence')}
        >
          Evidence ({evidenceTotal})
        </button>
        <button
          {...tabProps('findings')}
          className={`nav-item ${activeTab === 'findings' ? 'active' : ''}`}
          style={{
            borderBottom: activeTab === 'findings' ? '2px solid var(--accent-blue)' : '2px solid transparent',
            borderRadius: '6px 6px 0 0',
          }}
          onClick={() => setActiveTab('findings')}
        >
          Findings {validationResult ? '(Available)' : ''}
        </button>
        <button
          {...tabProps('context')}
          className={`nav-item ${activeTab === 'context' ? 'active' : ''}`}
          style={{
            borderBottom: activeTab === 'context' ? '2px solid var(--accent-blue)' : '2px solid transparent',
            borderRadius: '6px 6px 0 0',
          }}
          onClick={() => setActiveTab('context')}
        >
          Context and indicators
        </button>
        <button
          {...tabProps('multisource')}
          className={`nav-item ${activeTab === 'multisource' ? 'active' : ''}`}
          style={{
            borderBottom: activeTab === 'multisource' ? '2px solid var(--accent-blue)' : '2px solid transparent',
            borderRadius: '6px 6px 0 0',
          }}
          onClick={() => setActiveTab('multisource')}
        >
          Multi-source
        </button>
        <button
          {...tabProps('activity')}
          className={`nav-item ${activeTab === 'activity' ? 'active' : ''}`}
          style={{
            borderBottom: activeTab === 'activity' ? '2px solid var(--accent-blue)' : '2px solid transparent',
            borderRadius: '6px 6px 0 0',
          }}
          onClick={() => setActiveTab('activity')}
        >
          Activity
        </button>
      </div>

      <div role="tabpanel" id={tabPanelId(TAB_PREFIX)} aria-labelledby={tabButtonId(TAB_PREFIX, activeTab)}>
      {/* ── Tab 1: Evidence Panel ────────────────────────────────────────── */}
      {activeTab === 'multisource' && (
        <MultiSourcePanel caseId={caseId} caseClosed={caseDetail?.status === 'closed' || caseDetail?.status === 'archived'} />
      )}

      {activeTab === 'evidence' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <select
                className="select-input"
                value={eventTypeFilter}
                onChange={(e) => {
                  setEventTypeFilter(e.target.value);
                  setEvidencePage(1);
                }}
              >
                <option value="">All event types</option>
                <option value="ProcessCreate">Process Create</option>
                <option value="NetworkConnect">Network Connect</option>
                <option value="FileCreate">File Create</option>
                <option value="DnsQuery">DNS Query</option>
                <option value="alert_triggered">Alert Triggered</option>
              </select>

              <select
                className="select-input"
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value);
                  setEvidencePage(1);
                }}
              >
                <option value="">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="informational">Informational</option>
              </select>
            </div>

            {canSynthesizeReports() && caseDetail.status !== 'closed' && (
              <button className="btn btn-secondary" onClick={() => setIsLinkOpen(true)}>
                + Link evidence
              </button>
            )}
          </div>

          <div style={{ background: 'var(--bg-card)', padding: '10px 14px', borderRadius: '4px', marginBottom: '16px', fontSize: '12px', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
            <strong>Evidence access:</strong> Raw evidence payloads reside strictly in offline forensic storage. The view below presents authorized, case-scoped normalized telemetry.
          </div>

          {evidenceError && <div className="alert-box alert-error">{evidenceError}</div>}

          <div className="table-container">
            {evidenceLoading ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                Loading case evidence records...
              </div>
            ) : evidenceItems.length === 0 ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                No evidence events currently linked to this case. Use "Link evidence" or promote an alert to attach evidence.
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Generated</th>
                    <th>Event type</th>
                    <th>Source</th>
                    <th>Action</th>
                    <th>Outcome</th>
                    <th>Severity</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {evidenceItems.map((item) => (
                    <tr key={item.id}>
                      <td style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                        {formatUtc(item.event_timestamp)}
                      </td>
                      <td>
                        <span className="font-mono" style={{ fontSize: '12px' }}>
                          <ExhibitTag id={item.id} /> {item.event_type}
                        </span>
                      </td>
                      <td className="font-mono" style={{ fontSize: '12px' }}>
                        {item.source_identifier || 'Unknown Host'}
                      </td>
                      <td
                        title={item.action || item.summary || undefined}
                        style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                      >
                        {item.action || item.summary || 'None recorded'}
                      </td>
                      <td>
                        <span style={{ fontSize: '12px', color: item.outcome === 'success' ? 'var(--status-ok)' : 'var(--text-secondary)' }}>
                          {item.outcome || 'N/A'}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${getSeverityBadgeClass(item.severity)}`}>
                          {item.severity}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '2px 8px', fontSize: '11px' }}
                          onClick={() => setInspectingEvidence(item)}
                        >
                          Inspect evidence
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ── Tab 2: Findings ────────────────────────────────── */}
      {activeTab === 'findings' && (
        <div>
          {synthesisError && (
            <div className="alert-box alert-error" role="alert" style={{ marginBottom: '16px', display: 'block' }}>
              {synthesisError}{' '}
              {canSynthesizeReports() && caseDetail.status !== 'closed' && caseDetail.status !== 'archived' && (
                <button className="btn btn-secondary" disabled={synthesizing} onClick={handleStartInvestigation}>
                  Retry
                </button>
              )}
            </div>
          )}

          {/* Trigger Box when not run */}
          {!validationResult && !synthesizing && (
            <div
              style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '32px',
                textAlign: 'center',
                marginBottom: '24px',
              }}
            >
              <h2 style={{ fontSize: '18px', fontWeight: 600, marginBottom: '8px' }}>
                Human-in-the-Loop Investigation Synthesis
              </h2>
              <p style={{ color: 'var(--text-secondary)', maxWidth: '640px', margin: '0 auto 20px', fontSize: '13px' }}>
                AISOP does not run autonomous background investigations. Click below to initiate an AI-assisted
                investigation across the {evidenceTotal} evidence event(s) linked to this case.
              </p>

              <div style={{ maxWidth: '400px', margin: '0 auto 20px' }}>
                <input
                  type="text"
                  className="input-field"
                  placeholder="Optional telemetry filter (e.g. process name)..."
                  value={queryFilter}
                  onChange={(e) => setQueryFilter(e.target.value)}
                  style={{ width: '100%', marginBottom: '8px' }}
                />
              </div>

              <button
                className="btn btn-primary"
                onClick={handleStartInvestigation}
                disabled={synthesizing || caseDetail.status === 'closed'}
              >
                Start AI investigation
              </button>

              <div style={{ marginTop: '16px', fontSize: '12px', color: 'var(--text-muted)' }}>
                Zero External Egress: Synthesis runs via local Ollama daemon or a deterministic offline provider.
              </div>
            </div>
          )}

          {/* Synthesizing Progress State */}
          {synthesizing && (
            <div className="table-container" style={{ padding: '48px', textAlign: 'center' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '8px' }}>
                Synthesizing AI investigation...
              </h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
                Applying 3-phase guardrail lifecycle: building canonical context snapshot, executing local inference,
                and validating epistemic grounding against case telemetry.
              </p>
              <AiRunStatus elapsed={synthElapsed} onCancel={() => synthCancelRef.current?.()} unchanged="The case evidence is unchanged." />
            </div>
          )}

          {/* Render Findings when available */}
          {validationResult && (
            <div>
              {/* Status Banner */}
              <div
                style={{
                  background: validationResult.is_valid ? '#0f291e' : '#2d1b11',
                  border: `1px solid ${validationResult.is_valid ? '#10b981' : '#f97316'}`,
                  borderRadius: '6px',
                  padding: '16px 20px',
                  marginBottom: '20px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '12px',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: '14px', color: validationResult.is_valid ? '#34d399' : '#fb923c' }}>
                    {validationResult.is_valid ? 'Server-Validated Output (guardrails passed)' : 'Deterministic Fallback Scope Active'}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                    Model: <span className="font-mono">{validationResult.output.model_identifier}</span> | Decision: <span className="font-mono">{validationResult.decision}</span> | Claims validated: <span className="font-mono" style={{ fontWeight: 600 }}>{(validationResult.output.overall_grounding_score * 100).toFixed(0)}%</span>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    className="btn btn-secondary"
                    style={{ fontSize: '12px' }}
                    onClick={handleStartInvestigation}
                    disabled={synthesizing}
                  >
                    Re-Run Investigation
                  </button>
                  {onNavigateToReport && (
                    <button
                      className="btn btn-primary"
                      style={{ fontSize: '12px' }}
                      onClick={() => onNavigateToReport(caseDetail.id)}
                    >
                      View report bundle
                    </button>
                  )}
                </div>
              </div>

              {/* Summary Narrative */}
              <div
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '6px',
                  padding: '20px',
                  marginBottom: '20px',
                }}
              >
                <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '8px' }}>
                  Investigation Summary
                </h3>
                <p style={{ color: 'var(--text-primary)', lineHeight: 1.6, fontSize: '13px' }}>
                  {validationResult.output.investigation_summary}
                </p>
              </div>

              {/* Partitioned Epistemic Claims */}
              <div
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '6px',
                  padding: '20px',
                  marginBottom: '20px',
                }}
              >
                <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '12px' }}>
                  Factual Claims & Hypotheses ({validationResult.output.claims.length})
                </h3>

                {validationResult.output.claims.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                    No atomic claims extracted for this synthesis.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {validationResult.output.claims.map((claim, idx) => {
                      const isFact = claim.category === 'observed_fact' && claim.grounding_status === 'validated_reference';
                      return (
                        <div
                          key={claim.claim_id || idx}
                          style={{
                            background: 'var(--bg-input)',
                            borderLeft: `3px solid ${isFact ? 'var(--status-ok)' : 'var(--severity-medium)'}`,
                            padding: '12px 14px',
                            borderRadius: '0 4px 4px 0',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '4px' }}>
                            <span style={{ fontWeight: 500, fontSize: '13px', color: 'var(--text-primary)' }}>
                              {claim.claim_text}
                            </span>
                            <span
                              className={`badge ${isFact ? 'badge-ok' : 'badge-medium'}`}
                              style={{ fontSize: '10px' }}
                            >
                              {isFact ? 'OBSERVED FACT (AI-STATED)' : 'INFERENCE'}
                            </span>
                          </div>

                          <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                            <span title="Reported by the language model and only capped by guardrails. It is not a measure of evidence strength.">
                              Model-reported confidence: {(claim.confidence * 100).toFixed(0)}%
                            </span>
                            <span title={LEGACY_GROUNDING_EXPLANATION}>Legacy grounding: {claim.grounding_status}</span>
                            {claim.supporting_evidence_ids && claim.supporting_evidence_ids.length > 0 && (
                              <span>
                                Cited Evidence: <span className="font-mono">{claim.supporting_evidence_ids.length} event(s)</span>
                              </span>
                            )}
                          </div>
                          <VerificationNote verification={claim.verification} />
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK Hypotheses */}
              {validationResult.output.mitre_attack_hypotheses && validationResult.output.mitre_attack_hypotheses.length > 0 && (
                <div
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    padding: '20px',
                    marginBottom: '20px',
                  }}
                >
                  <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '12px' }}>
                    MITRE ATT&CK Hypotheses ({validationResult.output.mitre_attack_hypotheses.length})
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
                    {validationResult.output.mitre_attack_hypotheses.map((hyp, i) => (
                      <div
                        key={i}
                        style={{
                          background: 'var(--bg-input)',
                          padding: '12px 14px',
                          borderRadius: '4px',
                          border: '1px solid var(--border-subtle)',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span className="font-mono" style={{ color: 'var(--accent-teal)', fontWeight: 600, fontSize: '13px' }}>
                            {hyp.technique_id}
                          </span>
                          <span
                            style={{ fontSize: '12px', color: 'var(--text-muted)' }}
                            title="Reported by the language model and only capped by guardrails. It is not a measure of evidence strength."
                          >
                            Model-reported confidence: {(hyp.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                        <div style={{ fontWeight: 500, fontSize: '12px', marginBottom: '4px' }}>
                          {hyp.technique_name}
                        </div>
                        <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                          {hyp.reasoning}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Actions & Uncertainty Gaps */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '24px' }}>
                <div
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    padding: '20px',
                  }}
                >
                  <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '10px' }}>
                    Recommended Non-Destructive Actions
                  </h3>
                  <ul style={{ paddingLeft: '18px', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                    {validationResult.output.recommended_analyst_actions.map((act, i) => (
                      <li key={i}>{act}</li>
                    ))}
                  </ul>
                </div>

                <div
                  style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    padding: '20px',
                  }}
                >
                  <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '10px' }}>
                    Uncertainties & Telemetry Gaps
                  </h3>
                  {validationResult.output.uncertainty_and_data_gaps.length === 0 ? (
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      No telemetry gaps or sensor blind spots flagged.
                    </div>
                  ) : (
                    <ul style={{ paddingLeft: '18px', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                      {validationResult.output.uncertainty_and_data_gaps.map((gap, i) => (
                        <li key={i}>{gap}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Tab 3: Context and indicators ───────────────────── */}
      {activeTab === 'context' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              padding: '20px',
            }}
          >
            <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '12px' }}>
              Extracted Observables from Case Telemetry
            </h3>
            {evidenceItems.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                No telemetry available to extract observables.
              </div>
            ) : (
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {Array.from(new Set(evidenceItems.map((e) => e.source_identifier).filter(Boolean))).map((host) => (
                  <span
                    key={host}
                    className="font-mono"
                    style={{
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-subtle)',
                      padding: '4px 10px',
                      borderRadius: '4px',
                      fontSize: '12px',
                    }}
                  >
                    HOST: {host}
                  </span>
                ))}
                {Array.from(new Set(evidenceItems.map((e) => e.event_type))).map((type) => (
                  <span
                    key={type}
                    style={{
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-subtle)',
                      padding: '4px 10px',
                      borderRadius: '4px',
                      fontSize: '12px',
                    }}
                  >
                    TYPE: {type}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Epistemic Provenance Boundary Explanation */}
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              padding: '20px',
            }}
          >
            <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '8px' }}>
              Context Classification Boundary
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px', marginTop: '12px' }}>
              <div style={{ background: 'var(--bg-input)', padding: '14px', borderRadius: '4px' }}>
                <span className="badge badge-ok" style={{ marginBottom: '8px' }}>Observed Evidence</span>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                  Cryptographically preserved telemetry (Sysmon, Windows Event Logs) directly associated with this case via junction records.
                </p>
              </div>

              <div style={{ background: 'var(--bg-input)', padding: '14px', borderRadius: '4px' }}>
                <span className="badge badge-info" style={{ marginBottom: '8px' }}>Enrichment Context</span>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                  Local Threat Intelligence cache, private shield IOC lookups, and MITRE ATT&CK enterprise tactics.
                </p>
              </div>

              <div style={{ background: 'var(--bg-input)', padding: '14px', borderRadius: '4px' }}>
                <span className="badge badge-medium" style={{ marginBottom: '8px' }}>AI Interpretations</span>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                  Synthesized hypotheses generated by the local LLM, subject to strict verification against the evidence context snapshot.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Tab 4: Activity & Audit Trail ────────────────────────────────── */}
      {activeTab === 'activity' && (
        <div>
          <div style={{ background: 'var(--bg-card)', padding: '12px 16px', borderRadius: '4px', marginBottom: '16px', fontSize: '12px', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
            <strong>Cryptographic Audit Invariant:</strong> The audit trail below is populated by PostgreSQL row and statement triggers. Updates, deletions, or truncations are rejected at the database engine level.
          </div>

          {activityError && <div className="alert-box alert-error">{activityError}</div>}

          <div className="table-container">
            {activityLoading ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                Loading case audit records...
              </div>
            ) : activities.length === 0 ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                No audit events recorded for this case.
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Recorded</th>
                    <th>Action</th>
                    <th>Actor</th>
                    <th>Context digest (SHA-256)</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {activities.map((act) => (
                    <React.Fragment key={act.id}>
                      <tr>
                        <td style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                          {formatUtc(act.created_at)}
                        </td>
                        <td>
                          <span className="font-mono" style={{ fontSize: '12px', fontWeight: 600, color: 'var(--accent-teal)' }}>
                            {act.action}
                          </span>
                        </td>
                        <td style={{ fontSize: '12px' }}>
                          {act.actor_username}
                        </td>
                        <td className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {act.context_sha256 ? `${act.context_sha256.substring(0, 16)}...` : 'N/A'}
                        </td>
                        <td style={{ fontSize: '11px', color: 'var(--text-secondary)', maxWidth: '360px' }}>
                          <AuditDetailsCell
                            audit={act}
                            expanded={expandedAudit.has(act.id)}
                            onToggle={toggleAudit}
                            when={formatUtc(act.created_at)}
                          />
                        </td>
                      </tr>
                      <AuditDetailsRow audit={act} expanded={expandedAudit.has(act.id)} columns={5} when={formatUtc(act.created_at)} />
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
      </div>

      {/* ── Modal: Inspect evidence ──────────────────────────────────────── */}
      {inspectingEvidence && (
        <Dialog onClose={() => setInspectingEvidence(null)} labelledBy="dlg-evidence-inspect-title" style={{ maxWidth: '720px' }}>
            <div className="modal-header">
              <h3 className="modal-title font-mono" id="dlg-evidence-inspect-title" style={{ fontSize: '14px' }}>
                Evidence Record: {inspectingEvidence.id}
              </h3>
              <button className="btn btn-secondary" aria-label="Close dialog" onClick={() => setInspectingEvidence(null)}><CloseIcon /></button>
            </div>
            <div className="modal-body">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px', fontSize: '12px' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Event type:</span>{' '}
                  <span className="font-mono" style={{ fontWeight: 600 }}>{inspectingEvidence.event_type}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Severity:</span>{' '}
                  <span className={`badge ${getSeverityBadgeClass(inspectingEvidence.severity)}`}>
                    {inspectingEvidence.severity}
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Host Identifier:</span>{' '}
                  <span className="font-mono">{inspectingEvidence.source_identifier || 'Unknown'}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Observation Time:</span>{' '}
                  <span>{formatUtc(inspectingEvidence.event_timestamp)}</span>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Normalized Payload</label>
                <pre
                  style={{
                    background: 'var(--bg-input)',
                    padding: '12px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    color: '#a7f3d0',
                    maxHeight: '300px',
                    overflowY: 'auto',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  {JSON.stringify(inspectingEvidence.normalized_payload || inspectingEvidence.summary, null, 2)}
                </pre>
              </div>

              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '8px' }}>
                Associated with Case on {formatUtc(inspectingEvidence.linked_at)}
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setInspectingEvidence(null)}>
                Close Window
              </button>
            </div>
        </Dialog>
      )}

      {/* ── Modal: Link Evidence ─────────────────────────────────────────── */}
      {isLinkOpen && (
        <Dialog onClose={() => setIsLinkOpen(false)} labelledBy="dlg-evidence-link-title">
            <form onSubmit={handleLinkEvidence}>
              <div className="modal-header">
                <h3 className="modal-title" id="dlg-evidence-link-title">Link Normalized Evidence</h3>
                <button type="button" className="btn btn-secondary" aria-label="Close dialog" onClick={() => setIsLinkOpen(false)}><CloseIcon /></button>
              </div>
              <div className="modal-body">
                {linkError && <div className="alert-box alert-error" role="alert">{linkError}</div>}
                <div className="form-group">
                  <label className="form-label">Evidence Event UUID *</label>
                  <input
                    type="text"
                    className="input-field font-mono"
                    required
                    placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000"
                    value={evidenceIdToLink}
                    onChange={(e) => setEvidenceIdToLink(e.target.value)}
                  />
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px', display: 'block' }}>
                    Must be a valid UUID of an existing normalized telemetry event.
                  </span>
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setIsLinkOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={linkSubmitting}>
                  {linkSubmitting ? 'Linking...' : 'Confirm Association'}
                </button>
              </div>
            </form>
        </Dialog>
      )}

      {/* ── Modal: Close case ────────────────────────────────────────────── */}
      {isCloseOpen && (
        <Dialog onClose={() => setIsCloseOpen(false)} labelledBy="dlg-workspace-close-title">
            <div className="modal-header">
              <h3 className="modal-title" id="dlg-workspace-close-title">Close case {caseDetail.case_number}</h3>
              <button className="btn btn-secondary" aria-label="Close dialog" onClick={() => setIsCloseOpen(false)}><CloseIcon /></button>
            </div>
            <div className="modal-body">
              {closeError && <div className="alert-box alert-error" role="alert">{closeError}</div>}
              <div className="form-group">
                <label className="form-label">Mandatory Audit Closure Reason *</label>
                <textarea
                  className="input-field"
                  rows={4}
                  required
                  placeholder="Provide resolution details, remediation validation, or false-positive rationale..."
                  value={closureReason}
                  onChange={(e) => setClosureReason(e.target.value)}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setIsCloseOpen(false)}>
                Cancel
              </button>
              <button
                className="btn btn-danger"
                disabled={closeSubmitting || !closureReason.trim()}
                onClick={handleCloseCase}
              >
                {closeSubmitting ? 'Closing...' : 'Confirm Case Closure'}
              </button>
            </div>
        </Dialog>
      )}
    </div>
  );
};
