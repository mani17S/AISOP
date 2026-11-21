/**
 * AISOP SOC Overview Dashboard Page.
 *
 * Visualizes operational platform metrics, subsystem health (DB, local LLM),
 * and case volume indicators.
 */

import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { HealthResponse, CaseResponse } from '../types';
import { RoleGuard } from '../components/RoleGuard';
import { useAuth } from '../contexts/AuthContext';
import { SetupNotice } from '../components/SetupNotice';

export interface DashboardProps {
  onNavigate: (tab: string) => void;
  onCreateIncident?: () => void;
  onNavigateToCase?: (caseId: string) => void;
  initialHealth?: HealthResponse | null;
  initialCases?: CaseResponse[];
  initialErrorType?: 'auth' | 'forbidden' | 'api' | null;
  initialErrorMessage?: string | null;
  initialLoading?: boolean;
}

export const Dashboard: React.FC<DashboardProps> = ({
  onNavigate,
  onCreateIncident,
  onNavigateToCase,
  initialHealth,
  initialCases,
  initialErrorType,
  initialErrorMessage,
  initialLoading,
}) => {
  const { apiKey } = useAuth();
  const [health, setHealth] = useState<HealthResponse | null>(initialHealth ?? null);
  const [cases, setCases] = useState<CaseResponse[]>(initialCases ?? []);
  const [loading, setLoading] = useState<boolean>(initialLoading ?? true);
  const [errorType, setErrorType] = useState<'auth' | 'forbidden' | 'api' | null>(initialErrorType ?? null);
  const [errorMessage, setErrorMessage] = useState<string | null>(initialErrorMessage ?? null);

  useEffect(() => {
    let isMounted = true;

    const loadData = async () => {
      setLoading(true);
      setErrorType(null);
      setErrorMessage(null);
      try {
        const [healthRes, casesRes] = await Promise.allSettled([
          api.getHealth(),
          api.getCases({ limit: 5 }),
        ]);

        if (isMounted) {
          if (healthRes.status === 'fulfilled') {
            setHealth(healthRes.value);
          }

          if (casesRes.status === 'fulfilled') {
            setCases(casesRes.value.items);
            setErrorType(null);
            setErrorMessage(null);
          } else {
            setCases([]);
            const reason = casesRes.reason;
            const msg = reason instanceof Error ? reason.message : String(reason || '');
            const lowerMsg = msg.toLowerCase();

            if (lowerMsg.includes('authentication') || lowerMsg.includes('401') || lowerMsg.includes('credential')) {
              setErrorType('auth');
              setErrorMessage('Authentication required. Configure your API key to load case data.');
            } else if (lowerMsg.includes('forbidden') || lowerMsg.includes('403') || lowerMsg.includes('privilege')) {
              setErrorType('forbidden');
              setErrorMessage('Access forbidden. Your role has insufficient privileges to view case telemetry.');
            } else {
              setErrorType('api');
              setErrorMessage('Service unavailable. Failed to retrieve case telemetry from backend.');
            }
          }
        }
      } catch (err: any) {
        if (isMounted) {
          setErrorType('api');
          setErrorMessage(err.message || 'Failed to load dashboard data');
          setCases([]);
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    loadData();
    return () => {
      isMounted = false;
    };
  }, [apiKey]);

  const openCases = cases.filter((c) => c.status === 'open' || c.status === 'in_progress');
  const criticalCases = cases.filter((c) => c.severity === 'critical' || c.severity === 'high');

  const renderCaseMetric = (count: number) => {
    if (loading) return '...';
    if (errorType === 'auth') return 'Key needed';
    if (errorType === 'forbidden') return 'Forbidden';
    if (errorType === 'api') return 'Unavailable';
    return count;
  };

  return (
    <div className="dashboard-page">
      <header className="page-header">
        <div>
          <h1>Overview</h1>
          <p className="page-header-sub">
            Alerts, cases and evidence in one analyst-controlled workflow
            {health?.version ? ` · Platform v${health.version}` : ''}
            {health?.environment ? `` : ''}
          </p>
        </div>
        <RoleGuard allowedRoles={['security_admin', 'analyst_tier_2', 'analyst_tier_1']}>
          <button
            className="btn btn-primary"
            disabled={!apiKey}
            title={apiKey ? undefined : 'Set an API key first'}
            onClick={() => {
              if (onCreateIncident) {
                onCreateIncident();
              } else {
                onNavigate('cases');
              }
            }}
          >
            New case
          </button>
        </RoleGuard>
      </header>

      {errorMessage && (errorType === 'auth'
        ? <SetupNotice message={errorMessage} />
        : <div className="alert-box alert-error" role="alert">{errorMessage}</div>)}

      <div className="dash-grid">
        <div className="dash-main">
      <div className="table-container">
        <div className="table-header-bar">
          <div className="table-header-title">Recent cases</div>
          <button className="btn btn-secondary" onClick={() => onNavigate('cases')}>
            All cases
          </button>
        </div>

        {loading ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            Loading security telemetry...
          </div>
        ) : errorType === 'auth' ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            No case data loaded.
          </div>
        ) : errorType === 'forbidden' ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            Access forbidden. Your assigned role has insufficient privileges to query case telemetry.
          </div>
        ) : errorType === 'api' ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            Service unavailable. Failed to retrieve case telemetry from backend.
          </div>
        ) : cases.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            No active cases found in current assignment scope.
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Case number</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((item) => (
                <tr
                  key={item.id}
                  onClick={() => onNavigateToCase?.(item.id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onNavigateToCase?.(item.id);
                    }
                  }}
                  tabIndex={0}
                  role="button"
                  aria-label={`Open investigation for case ${item.case_number}: ${item.title}`}
                  style={{ cursor: onNavigateToCase ? 'pointer' : 'default' }}
                >
                  <td className="font-mono">{item.case_number}</td>
                  <td>{item.title}</td>
                  <td>
                    <span className={`badge badge-${item.severity}`}>{item.severity}</span>
                  </td>
                  <td>
                    <span className={`badge badge-${item.status}`}>{item.status}</span>
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>
                    {new Date(item.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
        </div>

        <aside className="dash-side" aria-label="Status and workflow">
          <section>
            <h2 className="section-title">Status</h2>
            <dl className="status-list">
              <div>
                <dt>Backend</dt>
                <dd>
                  <span className={`status-dot ${health ? (health.status === 'ok' ? 'ok' : 'degraded') : loading ? 'down' : 'degraded'}`} />
                  {health ? (health.status === 'ok' ? 'Online' : 'Degraded') : loading ? 'Connecting...' : 'Degraded'}
                </dd>
              </div>
              <div>
                <dt>Version</dt>
                <dd className="font-mono">{health?.version ?? 'Unavailable'}</dd>
              </div>
              <div>
                <dt>Active investigations</dt>
                <dd><div className="font-mono">{renderCaseMetric(openCases.length)}</div></dd>
              </div>
              <div>
                <dt>High and critical priority</dt>
                <dd><div className="font-mono">{renderCaseMetric(criticalCases.length)}</div></dd>
              </div>
            </dl>
            <p className="status-note">
              {errorType ? 'Case telemetry query paused' : 'Based on the five most recent cases'}
            </p>
          </section>

        </aside>
      </div>
    </div>
  );
};

