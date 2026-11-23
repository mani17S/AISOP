/**
 * Security: what this server observed being done to it (rejected keys, lockouts, probes of paths that do not exist, oversized
 * or malformed requests, role refusals), counted per source address. Security admin only: the server refuses everyone else.
 *
 * This page shows what ONE server process saw. It is not a firewall log and a quiet page does not prove nothing happened; the
 * page says so in plain words rather than implying coverage it does not have.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../services/api';
import { SecurityOverview } from '../types';
import { SetupNotice, isAuthMessage } from '../components/SetupNotice';
import { useTimeZone } from '../contexts/TimeZoneContext';
import { formatInstant } from '../utils/time';

export const KIND_LABELS: Record<string, string> = {
  auth_failed: 'Rejected API key',
  auth_locked_out: 'Locked out after repeated bad keys',
  rate_limited: 'Rate limited',
  forbidden: 'Refused: role not allowed',
  unknown_path: 'Probe of a path that does not exist',
  method_not_allowed: 'Wrong HTTP method',
  payload_too_large: 'Request too large',
  unsupported_media_type: 'Unsupported content type',
  malformed_request: 'Malformed request',
};

export const kindLabel = (kind: string): string => KIND_LABELS[kind] ?? kind;

const WINDOWS: { hours: number; label: string }[] = [
  { hours: 1, label: 'Last hour' },
  { hours: 24, label: 'Last 24 hours' },
  { hours: 168, label: 'Last 7 days' },
];

interface SecurityProps {
  /** Tests render the page with data already loaded, as the other pages do. */
  initialOverview?: SecurityOverview | null;
  initialError?: string | null;
}

/** One bar per hour. Accessible name states the total and the peak; the same numbers are available as a table below. */
const HourlyBars: React.FC<{ data: SecurityOverview['timeline'] }> = ({ data }) => {
  const { zone } = useTimeZone();
  const max = Math.max(1, ...data.map((d) => d.count));
  const first = data[0];
  const last = data[data.length - 1];
  const peak = data.reduce((best, d) => (d.count > best.count ? d : best), first ?? { hour: '', count: 0 });
  const total = data.reduce((sum, d) => sum + d.count, 0);
  const W = 720;
  const H = 120;
  const gap = data.length > 60 ? 1 : 3;
  const bar = Math.max(1, (W - gap * (data.length - 1)) / Math.max(1, data.length));
  const summary =
    total === 0
      ? 'No suspicious requests in this window.'
      : `${total} suspicious requests over ${data.length} hours. The busiest hour started ${formatInstant(peak.hour, zone)} with ${peak.count}.`;
  return (
    <figure className="sec-chart">
      <svg viewBox={`0 0 ${W} ${H + 4}`} role="img" aria-label={summary} preserveAspectRatio="none">
        <line x1="0" y1={H} x2={W} y2={H} className="sec-chart-axis" />
        <line x1="0" y1={H / 2} x2={W} y2={H / 2} className="sec-chart-grid" />
        {data.map((d, i) => {
          const h = d.count === 0 ? 0 : Math.max(2, (d.count / max) * (H - 4));
          return <rect key={d.hour} x={i * (bar + gap)} y={H - h} width={bar} height={h} className="sec-chart-bar" />;
        })}
      </svg>
      <figcaption className="sec-chart-caption">
        <span>{first ? formatInstant(first.hour, zone) : ''}</span>
        <span>Peak {peak.count} per hour</span>
        <span>{last ? formatInstant(last.hour, zone) : ''}</span>
      </figcaption>
    </figure>
  );
};

export const Security: React.FC<SecurityProps> = ({ initialOverview, initialError }) => {
  const { zone } = useTimeZone();
  const [hours, setHours] = useState<number>(24);
  const [data, setData] = useState<SecurityOverview | null>(initialOverview ?? null);
  const [error, setError] = useState<string | null>(initialError ?? null);
  const [loading, setLoading] = useState<boolean>(initialOverview === undefined && initialError === undefined);
  const skipFirstLoad = useRef<boolean>(initialOverview !== undefined || initialError !== undefined);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api.getSecurityOverview(hours));
    } catch (e) {
      setData(null);
      setError(e instanceof Error ? e.message : 'The security overview could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [hours]);

  useEffect(() => {
    if (skipFirstLoad.current) {
      skipFirstLoad.current = false;
      return;
    }
    void load();
  }, [load]);

  const maxKind = Math.max(1, ...(data?.totals_by_kind ?? []).map((k) => k.count));

  return (
    <div className="security-page">
      <div className="page-header">
        <div>
          <h1>Security</h1>
          <p className="page-header-sub">What this server observed being done to it</p>
        </div>
        <div className="toolbar" style={{ margin: 0 }}>
          <label className="visually-hidden" htmlFor="security-window">
            Time window
          </label>
          <select id="security-window" className="select-input" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {WINDOWS.map((w) => (
              <option key={w.hours} value={w.hours}>
                {w.label}
              </option>
            ))}
          </select>
          <button className="btn btn-secondary" onClick={() => void load()} disabled={loading}>
            Refresh
          </button>
        </div>
      </div>

      {error && (isAuthMessage(error) ? <SetupNotice message={error} /> : <div className="alert-box alert-error" role="alert">{error}</div>)}

      {loading && !data && <div className="sec-empty">Reading the security log...</div>}

      {data && (
        <>
          <section className="sec-summary" aria-label="Summary">
            <div>
              <div className="sec-total">{data.total_events}</div>
              <div className="sec-total-label">suspicious requests in the window</div>
            </div>
            <div className="sec-window">
              {formatInstant(data.window_start, zone)} to {formatInstant(data.window_end, zone)}
              <br />
              from {data.top_sources.length} source{data.top_sources.length === 1 ? '' : 's'} shown below
            </div>
          </section>

          {(data.truncated || data.not_recorded_since_start > 0) && (
            <div className="alert-box alert-info" role="status">
              {data.truncated && <div>This window held more records than the page reads, so the totals are a lower bound.</div>}
              {data.not_recorded_since_start > 0 && (
                <div>
                  {data.not_recorded_since_start} events were not recorded since the server started because the log was full. A flood
                  is under way or recent.
                </div>
              )}
            </div>
          )}

          {data.total_events === 0 ? (
            <div className="sec-empty">
              No suspicious requests were recorded in this window. That is what this server saw; it does not prove nothing else
              happened.
            </div>
          ) : (
            <>
              <section aria-labelledby="sec-timeline-title" className="sec-block">
                <h2 id="sec-timeline-title" className="sec-h2">Requests over time</h2>
                <HourlyBars data={data.timeline} />
                <details className="sec-details">
                  <summary>Show the hourly counts as a table</summary>
                  <table className="data-table sec-small-table">
                    <thead>
                      <tr>
                        <th>Hour starting</th>
                        <th style={{ textAlign: 'right' }}>Requests</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.timeline.map((t) => (
                        <tr key={t.hour}>
                          <td>{formatInstant(t.hour, zone)}</td>
                          <td style={{ textAlign: 'right' }}>{t.count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </details>
              </section>

              <section aria-labelledby="sec-kind-title" className="sec-block">
                <h2 id="sec-kind-title" className="sec-h2">What was attempted</h2>
                <ul className="sec-ranked">
                  {data.totals_by_kind.map((k) => (
                    <li key={k.kind}>
                      <span className="sec-ranked-label">{kindLabel(k.kind)}</span>
                      <span className="sec-ranked-track" aria-hidden="true">
                        <span className="sec-ranked-fill" style={{ width: `${Math.max(2, (k.count / maxKind) * 100)}%` }} />
                      </span>
                      <span className="sec-ranked-count">{k.count}</span>
                    </li>
                  ))}
                </ul>
              </section>

              <div className="sec-two">
                <section aria-labelledby="sec-sources-title" className="sec-block">
                  <h2 id="sec-sources-title" className="sec-h2">Busiest sources</h2>
                  <table className="data-table sec-small-table">
                    <thead>
                      <tr>
                        <th>Source address</th>
                        <th>Mostly</th>
                        <th style={{ textAlign: 'right' }}>Requests</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.top_sources.map((s) => (
                        <tr key={s.source_ip}>
                          <td className="font-mono">{s.source_ip}</td>
                          <td>{s.kinds.map((k) => kindLabel(k.kind)).join(', ')}</td>
                          <td style={{ textAlign: 'right' }}>{s.count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>

                <section aria-labelledby="sec-paths-title" className="sec-block">
                  <h2 id="sec-paths-title" className="sec-h2">Most requested paths</h2>
                  <table className="data-table sec-small-table">
                    <thead>
                      <tr>
                        <th>Path</th>
                        <th>Kind</th>
                        <th style={{ textAlign: 'right' }}>Requests</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.top_paths.map((p) => (
                        <tr key={`${p.kind}:${p.path}`}>
                          <td className="font-mono sec-path">{p.path}</td>
                          <td>{kindLabel(p.kind)}</td>
                          <td style={{ textAlign: 'right' }}>{p.count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>
              </div>

              <section aria-labelledby="sec-recent-title" className="sec-block">
                <h2 id="sec-recent-title" className="sec-h2">Most recent</h2>
                <div className="table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Minute</th>
                        <th>Kind</th>
                        <th>Request</th>
                        <th>Source</th>
                        <th style={{ textAlign: 'right' }}>Count</th>
                        <th>Client</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.recent.map((r, i) => (
                        <tr key={`${r.time}:${r.kind}:${r.source_ip}:${r.path}:${i}`}>
                          <td style={{ whiteSpace: 'nowrap' }}>{formatInstant(r.time, zone)}</td>
                          <td>{kindLabel(r.kind)}</td>
                          <td className="font-mono sec-path">
                            {r.method} {r.path} ({r.status_code})
                          </td>
                          <td className="font-mono">{r.source_ip}</td>
                          <td style={{ textAlign: 'right' }}>{r.count}</td>
                          <td className="sec-agent">{r.user_agent ?? ''}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}

          <section className="sec-notes" aria-label="How to read this page">
            <h2 className="sec-h2">How to read this page</h2>
            <ul>
              {data.notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </section>
        </>
      )}
    </div>
  );
};
