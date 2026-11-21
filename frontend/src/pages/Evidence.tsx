/**
 * AISOP Evidence Exploration Page.
 *
 * Provides analyst query capabilities across normalized security events,
 * correlation timelines, and extracted atomic entity indicators (IOCs).
 * Enforces resilient rendering, null safety, and graceful degradation.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { NormalizedEventSummary } from '../types';
import { ExhibitTag } from '../components/ExhibitTag';
import { SetupNotice, isAuthMessage } from '../components/SetupNotice';

export interface EvidenceProps {
  initialEvents?: NormalizedEventSummary[];
  initialTotal?: number;
  initialLoading?: boolean;
  initialError?: string | null;
}

const formatTimestamp = (rawTs?: string | null): string => {
  if (!rawTs) return 'N/A';
  try {
    const d = new Date(rawTs);
    if (isNaN(d.getTime())) return String(rawTs);
    return d.toISOString().replace('T', ' ').slice(0, 19);
  } catch {
    return String(rawTs);
  }
};

export const Evidence: React.FC<EvidenceProps> = ({
  initialEvents,
  initialTotal,
  initialLoading,
  initialError,
}) => {
  const [events, setEvents] = useState<NormalizedEventSummary[]>(initialEvents ?? []);
  const [total, setTotal] = useState<number>(initialTotal ?? (initialEvents ? initialEvents.length : 0));
  const [page, setPage] = useState<number>(1);
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [sourceFilter, setSourceFilter] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(initialLoading ?? (initialEvents !== undefined ? false : true));
  const [error, setError] = useState<string | null>(initialError ?? null);

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getEvents({
        page,
        limit: 15,
        eventType: eventTypeFilter || undefined,
        severity: severityFilter || undefined,
        sourceIdentifier: sourceFilter.trim() || undefined,
      });
      setEvents(Array.isArray(res?.items) ? res.items : []);
      setTotal(typeof res?.total === 'number' ? res.total : 0);
    } catch (err: any) {
      setError(err?.message || 'Failed to retrieve telemetry events');
      setEvents([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [page, eventTypeFilter, severityFilter, sourceFilter]);

  useEffect(() => {
    if (initialEvents !== undefined && page === 1 && !eventTypeFilter && !severityFilter && !sourceFilter) {
      return;
    }
    fetchEvents();
  }, [fetchEvents, initialEvents]);

  return (
    <div className="evidence-page">
      <div className="page-header">
        <div>
        <h1>Evidence</h1>
        <p className="page-header-sub">
          Normalized events and the indicators extracted from them
        </p>
        </div>
      </div>

      <div className="toolbar">
        <input
          type="text"
          className="input-field"
          style={{ width: '220px' }}
          placeholder="Filter by host/sensor..."
          value={sourceFilter}
          onChange={(e) => {
            setSourceFilter(e.target.value);
            setPage(1);
          }}
        />

        <select
          className="select-input"
          value={eventTypeFilter}
          onChange={(e) => {
            setEventTypeFilter(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All event types</option>
          <option value="alert.malware">EDR / Malware Alert</option>
          <option value="process_creation">Process Creation</option>
          <option value="network_connection">Network Connection</option>
          <option value="file_creation">File Creation</option>
          <option value="registry_modification">Registry Modification</option>
          <option value="dns_query">DNS Query</option>
        </select>

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
      </div>

      {error && (isAuthMessage(error) ? <SetupNotice message={error} /> : <div className="alert-box alert-error" role="alert" style={{ marginBottom: '16px' }}>{error}</div>)}

      <div className="table-container">
        <div className="table-header-bar">
          <div className="table-header-title">Events {error ? '(unavailable)' : `(${total})`}</div>
        </div>

        {loading ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            Querying telemetry database...
          </div>
        ) : error ? (
          isAuthMessage(error) ? null : <div style={{ padding: '32px', textAlign: 'center' }}>
            <div
              className="alert-box alert-error"
              style={{ display: 'inline-block', maxWidth: '600px', textAlign: 'left' }}
            >
              <div style={{ fontWeight: 600, marginBottom: '6px' }}>Unable to display telemetry</div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
                {error}
              </div>
              <button className="btn btn-secondary" onClick={() => fetchEvents()}>
                Retry query
              </button>
            </div>
          </div>
        ) : events.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            No telemetry events matching the selected filters.
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Observed (UTC)</th>
                <th>Type and provider</th>
                <th>Source host</th>
                <th>Severity</th>
                <th>Summary</th>
                <th>Entities</th>
              </tr>
            </thead>
            <tbody>
              {events.map((evt) => {
                const rawTimestamp = evt.event_timestamp || evt.observed_timestamp;
                const displayTime = formatTimestamp(rawTimestamp);
                const eventEntities = Array.isArray(evt.entities) ? evt.entities : [];
                const summaryText =
                  evt.summary ||
                  (evt.action
                    ? `${evt.action}${evt.outcome ? ` (${evt.outcome})` : ''}`
                    : evt.provider || evt.event_id || 'Security Event');
                const subjectText = evt.primary_subject || (evt.event_id ? `ID: ${evt.event_id}` : null);

                return (
                  <tr key={evt.id}>
                    <td className="font-mono" style={{ whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                      {displayTime}
                    </td>
                    <td>
                      <span className="event-type"><ExhibitTag id={evt.id} /> {evt.event_type || 'event'}</span>
                      {evt.provider && (
                        <div
                          className="font-mono"
                          style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}
                        >
                          {evt.provider}
                        </div>
                      )}
                    </td>
                    <td className="font-mono">{evt.source_identifier || evt.source_type || 'N/A'}</td>
                    <td>
                      <span className={`badge badge-${evt.severity || 'informational'}`}>
                        {evt.severity || 'info'}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 500 }}>{summaryText}</div>
                      {subjectText && (
                        <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          Subject: {subjectText}
                        </div>
                      )}
                    </td>
                    <td>
                      {eventEntities.length > 0 ? (
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {eventEntities.slice(0, 3).map((entity, idx) => (
                            <span
                              key={entity.id || `${entity.entity_type}-${idx}`}
                              className="badge"
                              style={{
                                background: 'var(--bg-input)',
                                border: '1px solid var(--border-color)',
                                color: 'var(--text-secondary)',
                              }}
                              title={`${entity.entity_type}: ${entity.entity_value}`}
                            >
                              {entity.entity_type}:{' '}
                              {entity.entity_value && entity.entity_value.length > 20
                                ? `${entity.entity_value.slice(0, 20)}...`
                                : entity.entity_value || 'N/A'}
                            </span>
                          ))}
                          {eventEntities.length > 3 && (
                            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                              +{eventEntities.length - 3} more
                            </span>
                          )}
                        </div>
                      ) : (
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {evt.provider ? `${evt.provider} (${evt.action || 'logged'})` : 'No entity metadata'}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
