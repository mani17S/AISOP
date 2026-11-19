/**
 * AISOP Investigation Reports Page.
 *
 * Owns case selection, authorized report orchestration, synthesis parameter configuration,
 * and lifecycle states (idle, synthesizing, rendered, error).
 *
 * Security Invariants:
 * - Backend is the sole authorization authority; case selection adheres to server-side filtering.
 * - Non-assigned case IDs return 404 (Anti-Enumeration Contract).
 * - Viewer role is visually indicated as read-only; synthesis triggers require Investigator/Lead.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import {
  CaseInvestigationSynthesizeRequest,
  CaseResponse,
  InvestigationReportBundle,
} from '../types';
import { useAuth } from '../contexts/AuthContext';
import { ReportViewer } from '../components/ReportViewer';

interface ReportsPageProps {
  initialCaseId?: string | null;
  onSelectCase?: (caseId: string) => void;
}

export const Reports: React.FC<ReportsPageProps> = ({ initialCaseId }) => {
  const { canSynthesizeReports } = useAuth();

  // Case list state
  const [cases, setCases] = useState<CaseResponse[]>([]);
  const [loadingCases, setLoadingCases] = useState<boolean>(true);
  const [casesError, setCasesError] = useState<string | null>(null);

  // Selected case state
  const [selectedCaseId, setSelectedCaseId] = useState<string>(initialCaseId || '');
  const [selectedCase, setSelectedCase] = useState<CaseResponse | null>(null);

  // Report state
  const [reportBundle, setReportBundle] = useState<InvestigationReportBundle | null>(null);
  const [synthesizing, setSynthesizing] = useState<boolean>(false);
  const [reportError, setReportError] = useState<string | null>(null);

  // Optional synthesis filters
  const [showAdvanced, setShowAdvanced] = useState<boolean>(false);
  const [queryFilter, setQueryFilter] = useState<string>('');
  const [rootEventId, setRootEventId] = useState<string>('');
  const [timeWindowStart, setTimeWindowStart] = useState<string>('');
  const [timeWindowEnd, setTimeWindowEnd] = useState<string>('');

  // Fetch authorized cases for selector
  const fetchAuthorizedCases = useCallback(async () => {
    setLoadingCases(true);
    setCasesError(null);
    try {
      const res = await api.getCases({ limit: 50 });
      setCases(res.items);
      const firstCase = res.items[0];
      if (initialCaseId) {
        const found = res.items.find((c) => c.id === initialCaseId);
        if (found) {
          setSelectedCase(found);
          setSelectedCaseId(found.id);
        }
      } else if (firstCase && !selectedCaseId) {
        setSelectedCase(firstCase);
        setSelectedCaseId(firstCase.id);
      }
    } catch (err: any) {
      setCasesError(err.message || 'Failed to retrieve authorized cases.');
      setCases([]);
    } finally {
      setLoadingCases(false);
    }
  }, [initialCaseId, selectedCaseId]);

  useEffect(() => {
    fetchAuthorizedCases();
  }, [fetchAuthorizedCases]);

  // When selected case ID changes, update case details and reset current report bundle
  const handleCaseChange = (caseId: string) => {
    setSelectedCaseId(caseId);
    setReportBundle(null);
    setReportError(null);
    const found = cases.find((c) => c.id === caseId);
    setSelectedCase(found || null);
  };

  // Synthesize report bundle via backend endpoint
  const handleSynthesizeReport = async () => {
    if (!selectedCaseId) return;

    setSynthesizing(true);
    setReportError(null);

    const payload: CaseInvestigationSynthesizeRequest = {};
    if (queryFilter.trim()) payload.query_filter = queryFilter.trim();
    if (rootEventId.trim()) payload.root_event_id = rootEventId.trim();
    if (timeWindowStart.trim()) payload.time_window_start = new Date(timeWindowStart).toISOString();
    if (timeWindowEnd.trim()) payload.time_window_end = new Date(timeWindowEnd).toISOString();

    try {
      const bundle = await api.synthesizeCaseReports(selectedCaseId, payload);
      setReportBundle(bundle);
    } catch (err: any) {
      setReportError(
        err.message || 'Failed to synthesize investigation report. Check backend logs and case assignment.'
      );
      setReportBundle(null);
    } finally {
      setSynthesizing(false);
    }
  };

  return (
    <div className="reports-page">
      {/* ── Top Bar: Case Selector & Controls ─────────────────────────── */}
      <div className="reports-control-panel">
        <div className="control-header">
          <div className="control-title-block">
            <h1 className="page-heading">Investigation Reports</h1>
            <p className="page-subheading">
              Grounded, role-tailored security synthesis from case-scoped evidence and threat intelligence.
            </p>
          </div>

          <div className="case-selector-group">
            <label className="selector-label">Target Incident Case:</label>
            <select
              className="select-input case-select"
              value={selectedCaseId}
              disabled={loadingCases || synthesizing}
              onChange={(e) => handleCaseChange(e.target.value)}
            >
              {cases.length === 0 && <option value="">No authorized cases found</option>}
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.case_number}: {c.title} ({c.severity.toUpperCase()})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Selected Case Summary Strip */}
        {selectedCase && (
          <div className="case-context-strip">
            <div className="context-item">
              <span className="context-label">Case Number:</span>
              <span className="context-value mono">{selectedCase.case_number}</span>
            </div>
            <div className="context-item">
              <span className="context-label">Severity:</span>
              <span className={`severity-tag ${selectedCase.severity}`}>
                {selectedCase.severity.toUpperCase()}
              </span>
            </div>
            <div className="context-item">
              <span className="context-label">Status:</span>
              <span className="status-tag">{selectedCase.status.toUpperCase()}</span>
            </div>
            <div className="context-item">
              <span className="context-label">Lead Analyst ID:</span>
              <span className="context-value mono">{selectedCase.lead_analyst_id || 'Assigned Lead'}</span>
            </div>
            <div className="context-item actions-right">
              <button
                className="btn btn-secondary"
                style={{ fontSize: '12px', padding: '4px 10px' }}
                onClick={() => setShowAdvanced(!showAdvanced)}
              >
                {showAdvanced ? 'Hide Scope Filters' : 'Scope Filters'}
              </button>

              {canSynthesizeReports() ? (
                <button
                  className="btn btn-primary"
                  disabled={synthesizing || !selectedCaseId}
                  onClick={handleSynthesizeReport}
                >
                  {synthesizing ? 'Synthesizing...' : reportBundle ? 'Re-Synthesize Bundle' : 'Synthesize Report'}
                </button>
              ) : (
                <span
                  className="badge-viewer-notice"
                  title="Auditors hold read-only permissions and cannot trigger AI synthesis"
                >
                  Read-Only Role
                </span>
              )}
            </div>
          </div>
        )}

        {/* Advanced Scope Filters Drawer */}
        {showAdvanced && (
          <div className="advanced-filters-drawer">
            <h4 className="drawer-title">Investigation Scope Parameters</h4>
            <div className="filters-grid">
              <div className="form-group">
                <label className="form-label">Query Filter (Event Substring / Lucene):</label>
                <input
                  type="text"
                  className="input-field"
                  placeholder="e.g. event_type:process_creation OR powershell"
                  value={queryFilter}
                  onChange={(e) => setQueryFilter(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Root Event Anchor UUID:</label>
                <input
                  type="text"
                  className="input-field mono"
                  placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000"
                  value={rootEventId}
                  onChange={(e) => setRootEventId(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Time Window Start (UTC):</label>
                <input
                  type="datetime-local"
                  className="input-field"
                  value={timeWindowStart}
                  onChange={(e) => setTimeWindowStart(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Time Window End (UTC):</label>
                <input
                  type="datetime-local"
                  className="input-field"
                  value={timeWindowEnd}
                  onChange={(e) => setTimeWindowEnd(e.target.value)}
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Content View Area ─────────────────────────────────────────── */}
      <div className="reports-view-area">
        {casesError && (
          <div className="alert-box alert-error">
            <strong>Case Loading Error:</strong> {casesError}
          </div>
        )}

        {reportError && (
          <div className="alert-box alert-error">
            <strong>Report Synthesis Error:</strong> {reportError}
          </div>
        )}

        {synthesizing && (
          <div className="synthesizing-state-card">
            <div className="spinner-animation" />
            <h3 className="loading-title">Synthesizing Role-Tailored Investigation Report</h3>
            <p className="loading-desc">
              Retrieving case-scoped evidence, querying local threat intelligence, assembling forensic context,
              and validating claims against cryptographic event hashes...
            </p>
          </div>
        )}

        {!synthesizing && reportBundle && (
          <ReportViewer
            bundle={reportBundle}
            caseNumber={selectedCase?.case_number}
            caseTitle={selectedCase?.title}
            onRefresh={canSynthesizeReports() ? handleSynthesizeReport : undefined}
          />
        )}

        {!synthesizing && !reportBundle && !reportError && selectedCase && (
          <div className="empty-report-card">
            <div className="empty-icon-shield">◈</div>
            <h3 className="empty-title">No Active Report Generated</h3>
            <p className="empty-text">
              Case <strong>{selectedCase.case_number}</strong> is selected with evidence telemetry linked. Click
              "Synthesize Report" above to generate a grounded executive brief, technical timeline, and detection
              engineering observables.
            </p>
            {canSynthesizeReports() ? (
              <button className="btn btn-primary" onClick={handleSynthesizeReport}>
                Generate Report Bundle
              </button>
            ) : (
              <p className="empty-subtext">
                Your active role (Auditor/Viewer) can view reports once generated by an assigned Investigator or Lead.
              </p>
            )}
          </div>
        )}

        {!loadingCases && cases.length === 0 && (
          <div className="empty-report-card">
            <h3 className="empty-title">No Assigned Cases Available</h3>
            <p className="empty-text">
              You currently have no active case assignments. Case-level authorization prevents unassigned operators
              from inspecting incident reports (Anti-Enumeration Contract).
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
