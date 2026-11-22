/**
 * AISOP Phase 4A - Multi-Source Vendor-Neutral Alert Triage & Ingestion Page.
 *
 * Grounded in:
 * - ADR-007 (Vendor-Neutral Alert Ingestion)
 * - Decision 1A (Sanitized Public Event Projections)
 * - AISOP Website and Frontend Design Constitution (AISOP-CONST-DESIGN-2026-001)
 *
 * Invariants:
 * - Zero emoji icons (uses clean SVG icons or accessible text glyphs).
 * - Zero purple gradients or pill-shaped buttons (border-radius <= 6px).
 * - Zero em dashes in user-facing copy.
 * - Zero fake SOC metrics or simulated threat statistics.
 * - Strict XSS mitigation (no dangerouslySetInnerHTML; native React JSX string escaping).
 * - Explicit labeling for synthetic/sample alert fixtures.
 * - Atomic case-evidence promotion using initial_evidence_ids.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import {
  AlertSummaryItem,
  AlertDetailResponse,
  AlertAdapterInfo,
  CaseSeverity,
} from '../types';
import { RoleGuard } from '../components/RoleGuard';
import { Dialog } from '../components/Dialog';
import { ExhibitTag } from '../components/ExhibitTag';
import { SetupNotice, isAuthMessage } from '../components/SetupNotice';
import { useAuth } from '../contexts/AuthContext';
import { useTimeZone } from '../contexts/TimeZoneContext';
import { TimePair } from '../components/TimePair';
import { describeIngestionLag, formatInstant } from '../utils/time';

interface AlertsProps {
  onNavigateToCase?: (caseId: string) => void;
}

export const Alerts: React.FC<AlertsProps> = ({ onNavigateToCase }) => {
  const { apiKey } = useAuth();
  const { zone } = useTimeZone();
  // Alert queue state
  const [alerts, setAlerts] = useState<AlertSummaryItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [limit, setLimit] = useState<number>(20);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filter state
  const [search, setSearch] = useState<string>('');
  const [debouncedSearch, setDebouncedSearch] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [sourceTypeFilter, setSourceTypeFilter] = useState<string>('');
  const [providerFilter, setProviderFilter] = useState<string>('');
  const [sourceIdFilter, setSourceIdFilter] = useState<string>('');
  const [startTimeFilter, setStartTimeFilter] = useState<string>('');
  const [endTimeFilter, setEndTimeFilter] = useState<string>('');

  // Inspection modal state
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [alertDetail, setAlertDetail] = useState<AlertDetailResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  // Promotion modal state
  const [promotingAlert, setPromotingAlert] = useState<AlertSummaryItem | AlertDetailResponse | null>(null);
  const [caseTitle, setCaseTitle] = useState<string>('');
  const [caseDescription, setCaseDescription] = useState<string>('');
  const [caseSeverity, setCaseSeverity] = useState<CaseSeverity>('medium');
  const [promoteSubmitting, setPromoteSubmitting] = useState<boolean>(false);
  const [promoteError, setPromoteError] = useState<string | null>(null);
  const [createdCaseId, setCreatedCaseId] = useState<string | null>(null);

  // Ingestion modal state
  const [isIngestOpen, setIsIngestOpen] = useState<boolean>(false);
  const [adapters, setAdapters] = useState<AlertAdapterInfo[]>([]);
  const [selectedAdapter, setSelectedAdapter] = useState<string>('generic_siem');
  const [sourceIdentifier, setSourceIdentifier] = useState<string>('siem-forwarder-01');
  const [rawAlertPayload, setRawAlertPayload] = useState<string>('');
  const [ingestSubmitting, setIngestSubmitting] = useState<boolean>(false);
  const [ingestError, setIngestError] = useState<string | null>(null);
  const [ingestResult, setIngestResult] = useState<{
    total_received: number;
    total_normalized: number;
    total_entities_extracted: number;
    total_skipped_duplicates: number;
    alert_ids: string[];
    errors: { alert_index: number; error: string }[];
  } | null>(null);

  // Debounce search input (300ms)
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedSearch(search.trim());
      setPage(1);
    }, 300);
    return () => clearTimeout(handler);
  }, [search]);

  // Fetch alert queue
  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getAlerts({
        page,
        limit,
        search: debouncedSearch || undefined,
        severity: severityFilter || undefined,
        category: categoryFilter || undefined,
        source_type: sourceTypeFilter || undefined,
        provider: providerFilter.trim() || undefined,
        source_identifier: sourceIdFilter.trim() || undefined,
        start_time: startTimeFilter ? new Date(startTimeFilter).toISOString() : undefined,
        end_time: endTimeFilter ? new Date(endTimeFilter).toISOString() : undefined,
      });
      setAlerts(res.items);
      setTotal(res.total);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve alert queue. Ensure API credentials are configured.');
      setAlerts([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [
    page,
    limit,
    debouncedSearch,
    severityFilter,
    categoryFilter,
    sourceTypeFilter,
    providerFilter,
    sourceIdFilter,
    startTimeFilter,
    endTimeFilter,
  ]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  // Load registered adapters for ingestion dialog
  const loadAdapters = async () => {
    try {
      const res = await api.getAlertAdapters();
      setAdapters(res.adapters);
    } catch {
      // Default fallback adapter list if endpoint is unavailable
      setAdapters([
        { name: 'generic_siem', display_name: 'Generic SIEM', description: 'Generic SIEM correlation alerts', source_type: 'generic_siem' },
        { name: 'sysmon', display_name: 'Sysmon Alert', description: 'Endpoint Sysmon detection alerts', source_type: 'sysmon' },
        { name: 'edr_malware', display_name: 'EDR Malware', description: 'Endpoint detection and response alerts', source_type: 'edr_malware' },
        { name: 'windows_security', display_name: 'Windows Security', description: 'Windows security event log alerts', source_type: 'windows_security' },
      ]);
    }
  };

  // Inspect alert detail
  const handleInspectAlert = async (alertId: string) => {
    setSelectedAlertId(alertId);
    setDetailLoading(true);
    setDetailError(null);
    try {
      const detail = await api.getAlertDetail(alertId);
      setAlertDetail(detail);
    } catch (err: any) {
      setDetailError(err.message || 'Failed to inspect alert detail.');
      setAlertDetail(null);
    } finally {
      setDetailLoading(false);
    }
  };

  // Open promotion modal
  const handleOpenPromote = (alert: AlertSummaryItem | AlertDetailResponse) => {
    setPromotingAlert(alert);
    setCreatedCaseId(null);
    setPromoteError(null);
    setCaseTitle(`[Alert] ${alert.title}`);

    // Map severity to valid case severity
    let initialSev: CaseSeverity = 'medium';
    if (alert.severity === 'critical' || alert.severity === 'high' || alert.severity === 'medium' || alert.severity === 'low' || alert.severity === 'informational') {
      initialSev = alert.severity;
    }
    setCaseSeverity(initialSev);

    // Initial description grounded in alert telemetry
    const descLines = [
      `Promoted from security alert: ${alert.title}`,
      `Originating Provider: ${alert.provider} (${alert.source_type})`,
      `Upstream Alert ID: ${alert.source_alert_id}`,
      `Detection Timestamp: ${alert.timestamp}`,
    ];
    if (alert.source_identifier) {
      descLines.push(`Source Sensor or host: ${alert.source_identifier}`);
    }
    if ('raw_ref' in alert && alert.raw_ref) {
      descLines.push(`Raw Evidence SHA-256: ${alert.raw_ref}`);
    }
    setCaseDescription(descLines.join('\n'));
  };

  // Submit case promotion
  const handlePromoteToCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!promotingAlert) return;
    if (!caseTitle.trim()) {
      setPromoteError('Case title is required.');
      return;
    }

    setPromoteSubmitting(true);
    setPromoteError(null);
    try {
      const createdCase = await api.createCase({
        title: caseTitle.trim(),
        description: caseDescription.trim() || null,
        severity: caseSeverity,
        initial_evidence_ids: [promotingAlert.id],
      });
      setCreatedCaseId(createdCase.id);
      // Re-fetch queue to update case status badges
      fetchAlerts();
      if (alertDetail && alertDetail.id === promotingAlert.id) {
        setAlertDetail({
          ...alertDetail,
          has_case: true,
          associated_case_ids: [...alertDetail.associated_case_ids, createdCase.id],
        });
      }
    } catch (err: any) {
      setPromoteError(err.message || 'Failed to promote alert to case.');
    } finally {
      setPromoteSubmitting(false);
    }
  };

  // Submit alert ingestion batch
  const handleIngestAlerts = async (e: React.FormEvent) => {
    e.preventDefault();
    setIngestError(null);
    setIngestResult(null);

    let parsedAlerts: any[];
    try {
      const parsed = JSON.parse(rawAlertPayload);
      if (Array.isArray(parsed)) {
        parsedAlerts = parsed;
      } else if (typeof parsed === 'object' && parsed !== null) {
        parsedAlerts = [parsed];
      } else {
        throw new Error('Payload must be a JSON object or an array of objects.');
      }
    } catch (err: any) {
      setIngestError(`JSON syntax error: ${err.message}`);
      return;
    }

    if (parsedAlerts.length === 0) {
      setIngestError('At least one alert record must be provided.');
      return;
    }

    setIngestSubmitting(true);
    try {
      const result = await api.ingestAlerts({
        source_type: selectedAdapter,
        source_identifier: sourceIdentifier.trim() || 'siem-forwarder',
        alerts: parsedAlerts,
      });
      setIngestResult({
        total_received: result.total_received,
        total_normalized: result.total_normalized,
        total_entities_extracted: result.total_entities_extracted,
        total_skipped_duplicates: result.total_skipped_duplicates,
        alert_ids: result.alert_ids,
        errors: result.errors,
      });
      fetchAlerts();
    } catch (err: any) {
      setIngestError(err.message || 'Alert batch ingestion failed.');
    } finally {
      setIngestSubmitting(false);
    }
  };

  const handleClearFilters = () => {
    setSearch('');
    setDebouncedSearch('');
    setSeverityFilter('');
    setCategoryFilter('');
    setSourceTypeFilter('');
    setProviderFilter('');
    setSourceIdFilter('');
    setStartTimeFilter('');
    setEndTimeFilter('');
    setPage(1);
  };

  // Helper: check if alert is synthetic/test fixture
  const isSyntheticAlert = (item: AlertSummaryItem | AlertDetailResponse): boolean => {
    const target = `${item.provider} ${item.source_identifier || ''} ${item.source_alert_id}`.toLowerCase();
    return (
      target.includes('sample') ||
      target.includes('synthetic') ||
      target.includes('test') ||
      target.includes('demo')
    );
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

  const totalPages = Math.ceil(total / limit) || 1;

  return (
    <div className="alerts-page">
      {/* ── Page Header ─────────────────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <h1>
            Alerts
          </h1>
          <p className="page-header-sub">
            Triage incoming alerts and promote them to cases
          </p>
        </div>

        <div className="btn-group">
          <RoleGuard allowedRoles={['security_admin', 'analyst_tier_2', 'analyst_tier_1']}>
            <button
              className="btn btn-primary"
              disabled={!apiKey}
              title={apiKey ? 'Ingest raw alerts from upstream SIEM or EDR adapters' : 'Set an API key first'}
              onClick={() => {
                loadAdapters();
                setIsIngestOpen(true);
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: '6px' }}>
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
              Ingest alerts
            </button>
          </RoleGuard>

          <button
            className="btn btn-secondary"
            onClick={fetchAlerts}
            title="Refresh alert queue"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: '6px' }}>
              <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
            </svg>
            Refresh
          </button>
        </div>
      </div>

      {/* ── Filter & Search Toolbar ─────────────────────────────────────────── */}
      <div className="filter-toolbar">
        <label className="field">
          <span className="field-label">Search</span>
          <input
            type="text"
            className="input-field"
            style={{ width: '240px' }}
            placeholder="Search title, description, ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </label>

        <label className="field">
          <span className="field-label">Severity</span>
          <select
            className="select-input"
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
          </select>
        </label>

        <label className="field">
          <span className="field-label">Category</span>
          <select
            className="select-input"
            value={categoryFilter}
            onChange={(e) => {
              setCategoryFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="">All categories</option>
            <option value="malware">Malware</option>
            <option value="initial_access">Initial Access</option>
            <option value="execution">Execution</option>
            <option value="persistence">Persistence</option>
            <option value="privilege_escalation">Privilege Escalation</option>
            <option value="defense_evasion">Defense Evasion</option>
            <option value="credential_access">Credential Access</option>
            <option value="discovery">Discovery</option>
            <option value="lateral_movement">Lateral Movement</option>
            <option value="command_and_control">Command & Control</option>
            <option value="exfiltration">Exfiltration</option>
            <option value="impact">Impact</option>
            <option value="suspicious_activity">Suspicious Activity</option>
            <option value="system_anomaly">System Anomaly</option>
            <option value="policy_violation">Policy Violation</option>
            <option value="other">Other</option>
          </select>
        </label>

        <label className="field">
          <span className="field-label">Adapter</span>
          <select
            className="select-input"
            value={sourceTypeFilter}
            onChange={(e) => {
              setSourceTypeFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="">All adapters</option>
            <option value="generic_siem">Generic SIEM</option>
            <option value="edr_malware">EDR Malware</option>
            <option value="sysmon">Sysmon</option>
            <option value="windows_security">Windows Security</option>
            <option value="linux_auth">Linux Auth</option>
            <option value="firewall_ids">Firewall / IDS</option>
            <option value="cloud_audit">Cloud Audit</option>
            <option value="email_phishing">Email Phishing</option>
          </select>
        </label>

        <label className="field">
          <span className="field-label">Provider</span>
          <input
            type="text"
            className="input-field"
            style={{ width: '160px' }}
            placeholder="Provider (e.g. crowdstrike)"
            value={providerFilter}
            onChange={(e) => {
              setProviderFilter(e.target.value);
              setPage(1);
            }}
          />
        </label>

        <label className="field">
          <span className="field-label">Host or sensor</span>
          <input
            type="text"
            className="input-field"
            style={{ width: '160px' }}
            placeholder="Host / Sensor ID"
            value={sourceIdFilter}
            onChange={(e) => {
              setSourceIdFilter(e.target.value);
              setPage(1);
            }}
          />
        </label>

        {(search || severityFilter || categoryFilter || sourceTypeFilter || providerFilter || sourceIdFilter || startTimeFilter || endTimeFilter) && (
          <button
            className="btn btn-secondary"
            style={{ padding: '6px 12px', fontSize: '12px' }}
            onClick={handleClearFilters}
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* ── Status Messages ─────────────────────────────────────────────────── */}
      {error && (isAuthMessage(error) ? <SetupNotice message={error} /> : <div className="alert-box alert-error" role="alert">{error}</div>)}

      {/* ── Alert Queue Table ───────────────────────────────────────────────── */}
      <div className="table-container">
        <div className="table-header-bar">
          <div className="table-header-title">
            Alert queue
            <span style={{ fontSize: '12px', fontWeight: 'normal', color: 'var(--text-secondary)', marginLeft: '8px' }}>
              ({loading ? 'Loading...' : error ? 'Unavailable' : `${total} alerts found`})
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-secondary)' }}>
            <span>Per page:</span>
            <select
              className="select-input"
              style={{ padding: '2px 8px', fontSize: '12px' }}
              value={limit}
              onChange={(e) => {
                setLimit(Number(e.target.value));
                setPage(1);
              }}
            >
              <option value="10">10</option>
              <option value="20">20</option>
              <option value="50">50</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            Retrieving normalized alert events...
          </div>
        ) : error ? null : alerts.length === 0 ? (
          <div className="empty-state-notice" style={{ margin: '20px' }}>
            No security alerts match the selected filter criteria.
          </div>
        ) : (
          <table className="data-table alerts-table">
            <thead>
              <tr>
                <th style={{ width: '88px' }}>Severity</th>
                <th>Alert and source ID</th>
                <th style={{ width: '152px' }}>Category and adapter</th>
                <th style={{ width: '104px' }}>MITRE ATT&CK</th>
                <th style={{ width: '184px' }}>Indicators</th>
                <th style={{ width: '272px' }}>Generated and ingested</th>
                <th style={{ width: '96px' }}>Case</th>
                <th style={{ width: '176px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>
                    <span className={`badge ${getSeverityBadgeClass(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                        {alert.title}
                      </span>
                      {isSyntheticAlert(alert) && (
                        <span className="badge badge-synthetic" title="Synthetic sample data fixture">
                          SYNTHETIC
                        </span>
                      )}
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', marginTop: '4px', fontSize: '12px', color: 'var(--text-muted)' }}>
                      <span className="font-mono"><ExhibitTag id={alert.id} /> {alert.source_alert_id}</span>
                      <span>
                        <span className="badge badge-provider">{alert.provider}</span>
                        {alert.source_identifier ? ` from ${alert.source_identifier}` : ''}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span className="badge badge-category">{alert.category}</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {alert.source_type}
                      </span>
                    </div>
                  </td>
                  <td>
                    {alert.mitre_attack && alert.mitre_attack.length > 0 ? (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                        {alert.mitre_attack.slice(0, 2).map((ref, i) => (
                          <span key={i} className="badge-mitre" title={`${ref.technique_name || ''} (${ref.tactic_name || ''})`}>
                            {ref.technique_id || ref.tactic_id || 'ATT&CK'}
                          </span>
                        ))}
                        {alert.mitre_attack.length > 2 && (
                          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            +{alert.mitre_attack.length - 2}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)' }} aria-label="None">-</span>
                    )}
                  </td>
                  <td>
                    {alert.top_observables && alert.top_observables.length > 0 ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        {alert.top_observables.slice(0, 2).map((obs, i) => (
                          <div key={i} className="observable-chip" title={`${obs.type}: ${obs.value}`}>
                            <span className="observable-type-tag">{obs.type}:</span>
                            <span>{obs.value}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)' }} aria-label="None">-</span>
                    )}
                  </td>
                  <td>
                    <TimePair eventTime={alert.timestamp} ingestedAt={alert.ingested_at} />
                  </td>
                  <td>
                    {alert.has_case ? (
                      <span className="badge badge-open" title={`Linked to ${alert.case_count} case(s)`}>
                        Linked ({alert.case_count})
                      </span>
                    ) : (
                      <span className="badge badge-closed">Unassigned</span>
                    )}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '6px' }}>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '4px 8px', fontSize: '12px' }}
                        onClick={() => handleInspectAlert(alert.id)}
                        title="Inspect full alert details"
                      >
                        Inspect
                      </button>
                      <RoleGuard allowedRoles={['security_admin', 'analyst_tier_2', 'analyst_tier_1']}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '4px 8px', fontSize: '12px' }}
                          onClick={() => handleOpenPromote(alert)}
                          title="Promote alert to formal investigation case"
                        >
                          Promote
                        </button>
                      </RoleGuard>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* ── Pagination Controls ───────────────────────────────────────────── */}
        {!error && <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderTop: '1px solid var(--border-color)', fontSize: '13px', color: 'var(--text-secondary)' }}>
          <div>
            Showing Page {page} of {totalPages} ({total} total alerts)
          </div>
          <div className="btn-group">
            <button
              className="btn btn-secondary"
              style={{ padding: '4px 10px', fontSize: '12px' }}
              disabled={page <= 1}
              onClick={() => setPage((prev) => Math.max(1, prev - 1))}
            >
              Previous
            </button>
            <button
              className="btn btn-secondary"
              style={{ padding: '4px 10px', fontSize: '12px' }}
              disabled={page >= totalPages}
              onClick={() => setPage((prev) => Math.min(totalPages, prev + 1))}
            >
              Next
            </button>
          </div>
        </div>}
      </div>

      {/* ── Alert Detail Modal ──────────────────────────────────────────────── */}
      {selectedAlertId && (
        <Dialog
          onClose={() => setSelectedAlertId(null)}
          labelledBy="dlg-alert-detail-title"
          className="modal-dialog modal-dialog-large"
        >
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <h3 className="modal-title" id="dlg-alert-detail-title">Alert detail</h3>
                {alertDetail && (
                  <span className={`badge ${getSeverityBadgeClass(alertDetail.severity)}`}>
                    {alertDetail.severity}
                  </span>
                )}
              </div>
              <button
                className="btn btn-secondary"
                style={{ padding: '2px 8px' }}
                aria-label="Close dialog"
                onClick={() => setSelectedAlertId(null)}
              >
                Close
              </button>
            </div>

            <div className="modal-body">
              {detailLoading ? (
                <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                  Loading canonical alert telemetry...
                </div>
              ) : detailError ? (
                <div className="alert-box alert-error" role="alert">{detailError}</div>
              ) : alertDetail ? (
                <>
                  {/* Overview Section */}
                  <div className="detail-section">
                    <div className="detail-section-title">Alert Identity & Provenance</div>
                    <div className="detail-grid">
                      <div className="detail-field">
                        <span className="detail-field-label">Headline / Title</span>
                        <span className="detail-field-value" style={{ fontWeight: '600' }}>
                          {alertDetail.title}
                        </span>
                      </div>
                      <div className="detail-field">
                        <span className="detail-field-label">Evidence UUID (Normalized Event ID)</span>
                        <span className="detail-field-value font-mono" style={{ fontSize: '12px' }}>
                          {alertDetail.id}
                        </span>
                      </div>
                      <div className="detail-field">
                        <span className="detail-field-label">Vendor Provider & Adapter</span>
                        <span className="detail-field-value">
                          {alertDetail.provider} ({alertDetail.source_type})
                        </span>
                      </div>
                      <div className="detail-field">
                        <span className="detail-field-label">Upstream Alert Identifier</span>
                        <span className="detail-field-value font-mono">
                          {alertDetail.source_alert_id}
                        </span>
                      </div>
                      <div className="detail-field">
                        <span className="detail-field-label">Generated at the source (event time)</span>
                        <span className="detail-field-value">
                          {formatInstant(alertDetail.timestamp, zone)}
                          {zone !== 'UTC' && <span className="time-also"> ({formatInstant(alertDetail.timestamp, 'UTC')})</span>}
                        </span>
                      </div>
                      <div className="detail-field">
                        <span className="detail-field-label">Ingested by AISOP</span>
                        <span className="detail-field-value">
                          {formatInstant(alertDetail.ingested_at, zone)}
                          {zone !== 'UTC' && <span className="time-also"> ({formatInstant(alertDetail.ingested_at, 'UTC')})</span>}
                        </span>
                      </div>
                      <div className="detail-field">
                        <span className="detail-field-label">Gap between the two</span>
                        <span className="detail-field-value">{describeIngestionLag(alertDetail.timestamp, alertDetail.ingested_at).text}</span>
                      </div>
                      <div className="detail-field">
                        <span className="detail-field-label">Raw Evidence Digest (SHA-256)</span>
                        <span className="detail-field-value font-mono break-all" style={{ fontSize: '11px', color: 'var(--accent-teal)' }}>
                          {alertDetail.raw_ref}
                        </span>
                      </div>
                      <div className="detail-field">
                        <span className="detail-field-label">Triage Lifecycle Status</span>
                        <span className="detail-field-value">
                          <span className="badge badge-info">{alertDetail.status}</span>
                        </span>
                      </div>
                    </div>

                    {alertDetail.description && (
                      <div style={{ marginTop: '12px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                        <span className="detail-field-label">Description / Rationale</span>
                        <p style={{ fontSize: '13px', marginTop: '4px', color: 'var(--text-secondary)' }}>
                          {alertDetail.description}
                        </p>
                      </div>
                    )}
                  </div>

                  {/* MITRE ATT&CK Mapping */}
                  <div className="detail-section">
                    <div className="detail-section-title">MITRE ATT&CK Mappings</div>
                    {alertDetail.mitre_attack && alertDetail.mitre_attack.length > 0 ? (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                        {alertDetail.mitre_attack.map((m, i) => (
                          <div
                            key={i}
                            style={{
                              padding: '6px 10px',
                              backgroundColor: 'var(--bg-input)',
                              border: '1px solid var(--border-subtle)',
                              borderRadius: '4px',
                              fontSize: '12px',
                            }}
                          >
                            <span className="badge-mitre" style={{ marginRight: '6px' }}>
                              {m.technique_id || m.tactic_id}
                            </span>
                            <span style={{ fontWeight: '500' }}>
                              {m.technique_name || m.tactic_name}
                            </span>
                            {m.tactic_name && m.technique_name && (
                              <span style={{ color: 'var(--text-muted)', marginLeft: '4px' }}>
                                [{m.tactic_name}]
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        No MITRE ATT&CK techniques mapped to this alert.
                      </div>
                    )}
                  </div>

                  {/* Observables & IOCs */}
                  <div className="detail-section">
                    <div className="detail-section-title">Extracted Observables (IOCs)</div>
                    {alertDetail.observables && alertDetail.observables.length > 0 ? (
                      <table className="data-table" style={{ fontSize: '12px' }}>
                        <thead>
                          <tr>
                            <th style={{ width: '120px' }}>Type</th>
                            <th>Value</th>
                            <th style={{ width: '120px' }}>Relevance</th>
                          </tr>
                        </thead>
                        <tbody>
                          {alertDetail.observables.map((obs, i) => (
                            <tr key={i}>
                              <td>
                                <span className="observable-type-tag">{obs.type}</span>
                              </td>
                              <td className="font-mono break-all">{obs.value}</td>
                              <td>
                                <span className="badge badge-info">{obs.relevance || 'observed'}</span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        No IOC observables extracted.
                      </div>
                    )}
                  </div>

                  {/* Normalized Context Entities */}
                  {(alertDetail.host || alertDetail.user || alertDetail.process || alertDetail.network) && (
                    <div className="detail-section">
                      <div className="detail-section-title">Normalized Context Entities</div>
                      <div className="detail-grid">
                        {alertDetail.host && (
                          <div className="detail-field">
                            <span className="detail-field-label">Host Entity</span>
                            <span className="detail-field-value font-mono">
                              {JSON.stringify(alertDetail.host)}
                            </span>
                          </div>
                        )}
                        {alertDetail.user && (
                          <div className="detail-field">
                            <span className="detail-field-label">User Entity</span>
                            <span className="detail-field-value font-mono">
                              {JSON.stringify(alertDetail.user)}
                            </span>
                          </div>
                        )}
                        {alertDetail.process && (
                          <div className="detail-field">
                            <span className="detail-field-label">Process Entity</span>
                            <span className="detail-field-value font-mono break-all">
                              {JSON.stringify(alertDetail.process)}
                            </span>
                          </div>
                        )}
                        {alertDetail.network && (
                          <div className="detail-field">
                            <span className="detail-field-label">Network Entity</span>
                            <span className="detail-field-value font-mono">
                              {JSON.stringify(alertDetail.network)}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Vendor Custom Fields */}
                  {alertDetail.custom_fields && Object.keys(alertDetail.custom_fields).length > 0 && (
                    <div className="detail-section">
                      <div className="detail-section-title">Unmapped Vendor Attributes</div>
                      <div
                        style={{
                          backgroundColor: 'var(--bg-input)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: '4px',
                          padding: '12px',
                          maxHeight: '200px',
                          overflowY: 'auto',
                          fontSize: '12px',
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--text-secondary)',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all',
                        }}
                      >
                        {JSON.stringify(alertDetail.custom_fields, null, 2)}
                      </div>
                    </div>
                  )}

                  {/* Case Linkage Notice */}
                  {alertDetail.has_case && (
                    <div className="alert-box alert-info" style={{ marginTop: '12px' }}>
                      Associated with existing case(s): {alertDetail.associated_case_ids.join(', ')}
                    </div>
                  )}
                </>
              ) : null}
            </div>

            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={() => setSelectedAlertId(null)}
              >
                Close
              </button>
              {alertDetail && (
                <RoleGuard allowedRoles={['security_admin', 'analyst_tier_2', 'analyst_tier_1']}>
                  <button
                    className="btn btn-primary"
                    onClick={() => {
                      setSelectedAlertId(null);
                      handleOpenPromote(alertDetail);
                    }}
                  >
                    Promote to Incident Case
                  </button>
                </RoleGuard>
              )}
            </div>
        </Dialog>
      )}

      {/* ── Case Promotion Modal ────────────────────────────────────────────── */}
      {promotingAlert && (
        <Dialog onClose={() => setPromotingAlert(null)} labelledBy="dlg-alert-promote-title">
            <div className="modal-header">
              <h3 className="modal-title" id="dlg-alert-promote-title">Promote Alert to Incident Case</h3>
              <button
                className="btn btn-secondary"
                style={{ padding: '2px 8px' }}
                aria-label="Close dialog"
                onClick={() => setPromotingAlert(null)}
              >
                Close
              </button>
            </div>

            {createdCaseId ? (
              <div className="modal-body">
                <div className="alert-box alert-info" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', borderColor: 'var(--status-ok)', color: '#34d399' }}>
                  <strong>Case Created Successfully:</strong> Case ID {createdCaseId} is now actively linked to evidence {promotingAlert.id}.
                </div>
                <p style={{ marginTop: '12px', color: 'var(--text-secondary)' }}>
                  The alert evidence record was atomically linked as initial evidence. The audit trail records full provenance.
                </p>
                <div style={{ marginTop: '20px', display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
                  <button
                    className="btn btn-secondary"
                    onClick={() => setPromotingAlert(null)}
                  >
                    Done
                  </button>
                  {onNavigateToCase && (
                    <button
                      className="btn btn-primary"
                      onClick={() => {
                        setPromotingAlert(null);
                        onNavigateToCase(createdCaseId);
                      }}
                    >
                      View in Cases
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <form onSubmit={handlePromoteToCase}>
                <div className="modal-body">
                  <div className="alert-box alert-info">
                    Atomic promotion creates a new formal investigation case and binds Evidence UUID{' '}
                    <code className="font-mono">{promotingAlert.id}</code> as initial evidence within a single database transaction.
                  </div>

                  {promoteError && <div className="alert-box alert-error">{promoteError}</div>}

                  <div className="form-group" style={{ marginBottom: '14px' }}>
                    <label className="form-label">Case Title</label>
                    <input
                      type="text"
                      className="input-field"
                      style={{ width: '100%' }}
                      value={caseTitle}
                      onChange={(e) => setCaseTitle(e.target.value)}
                      required
                    />
                  </div>

                  <div className="form-group" style={{ marginBottom: '14px' }}>
                    <label className="form-label">Case Severity</label>
                    <select
                      className="select-input"
                      style={{ width: '100%' }}
                      value={caseSeverity}
                      onChange={(e) => setCaseSeverity(e.target.value as CaseSeverity)}
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="informational">Informational</option>
                    </select>
                  </div>

                  <div className="form-group" style={{ marginBottom: '14px' }}>
                    <label className="form-label">Investigation Description & Rationale</label>
                    <textarea
                      className="input-field"
                      style={{ width: '100%', height: '110px', fontFamily: 'var(--font-sans)', fontSize: '13px' }}
                      value={caseDescription}
                      onChange={(e) => setCaseDescription(e.target.value)}
                    />
                  </div>

                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    <span>Initial Linked Evidence: </span>
                    <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                      {promotingAlert.id} ({promotingAlert.source_alert_id})
                    </span>
                  </div>
                </div>

                <div className="modal-footer">
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => setPromotingAlert(null)}
                    disabled={promoteSubmitting}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={promoteSubmitting}
                  >
                    {promoteSubmitting ? 'Creating Case...' : 'Confirm & Create Case'}
                  </button>
                </div>
              </form>
            )}
        </Dialog>
      )}

      {/* ── Alert Ingestion Modal ───────────────────────────────────────────── */}
      {isIngestOpen && (
        <Dialog
          onClose={() => setIsIngestOpen(false)}
          labelledBy="dlg-alert-ingest-title"
          className="modal-dialog modal-dialog-large"
        >
            <div className="modal-header">
              <h3 className="modal-title" id="dlg-alert-ingest-title">Multi-Source Vendor Alert Ingestion</h3>
              <button
                className="btn btn-secondary"
                style={{ padding: '2px 8px' }}
                aria-label="Close dialog"
                onClick={() => setIsIngestOpen(false)}
              >
                Close
              </button>
            </div>

            <form onSubmit={handleIngestAlerts}>
              <div className="modal-body">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                    Ingest raw alert batches via registered vendor adapters.
                  </span>
                </div>

                {ingestError && <div className="alert-box alert-error" role="alert">{ingestError}</div>}

                {ingestResult && (
                  <div className="alert-box alert-info" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', borderColor: 'var(--status-ok)', color: '#34d399', marginBottom: '16px' }}>
                    <div style={{ fontWeight: '600', marginBottom: '4px' }}>Ingestion Batch Summary:</div>
                    <ul style={{ paddingLeft: '16px', fontSize: '12px' }}>
                      <li>Total Received: {ingestResult.total_received}</li>
                      <li>Total Normalized: {ingestResult.total_normalized}</li>
                      <li>Graph Entities Extracted: {ingestResult.total_entities_extracted}</li>
                      <li>Duplicate Alerts Skipped: {ingestResult.total_skipped_duplicates}</li>
                      {ingestResult.errors.length > 0 && (
                        <li style={{ color: 'var(--severity-critical)' }}>
                          Errors: {ingestResult.errors.length} (inspect below)
                        </li>
                      )}
                    </ul>
                  </div>
                )}

                <div style={{ display: 'flex', gap: '12px', marginBottom: '14px', flexWrap: 'wrap' }}>
                  <div style={{ flex: 1, minWidth: '200px' }}>
                    <label className="form-label">Vendor Adapter</label>
                    <select
                      className="select-input"
                      style={{ width: '100%' }}
                      value={selectedAdapter}
                      onChange={(e) => setSelectedAdapter(e.target.value)}
                    >
                      {adapters.map((a) => (
                        <option key={a.source_type} value={a.source_type}>
                          {a.display_name} ({a.source_type})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div style={{ flex: 1, minWidth: '200px' }}>
                    <label className="form-label">Source Identifier / Collector</label>
                    <input
                      type="text"
                      className="input-field"
                      style={{ width: '100%' }}
                      value={sourceIdentifier}
                      onChange={(e) => setSourceIdentifier(e.target.value)}
                      required
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Raw Alerts Payload (JSON Array or Object)</label>
                  <textarea
                    className="input-field"
                    style={{
                      width: '100%',
                      height: '220px',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '12px',
                      lineHeight: '1.4',
                    }}
                    placeholder={`[\n  {\n    "alert_id": "ALERT-001",\n    "title": "Malware Detection",\n    "severity": "high",\n    "timestamp": "${new Date().toISOString()}"\n  }\n]`}
                    value={rawAlertPayload}
                    onChange={(e) => setRawAlertPayload(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setIsIngestOpen(false)}
                  disabled={ingestSubmitting}
                >
                  Close
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={ingestSubmitting}
                >
                  {ingestSubmitting ? 'Ingesting Batch...' : 'Submit Alert Batch'}
                </button>
              </div>
            </form>
        </Dialog>
      )}
    </div>
  );
};
