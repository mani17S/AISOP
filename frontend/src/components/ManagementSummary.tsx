/**
 * Management summary of one multi-source investigation, for a security leader: how much reading it saved, the verdict mix, which kinds of telemetry
 * are present in THIS evidence and which are absent, what to collect next, and how trustworthy the data is. Every figure comes from the server
 * (backend/app/modules/correlation/management_view.py); nothing is computed or guessed here, and nothing recommends a response action.
 */

import React from 'react';
import { ManagementView } from '../types';

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

export const ManagementSummary: React.FC<{ view?: ManagementView | null }> = ({ view }) => {
  if (!view) return null; // results stored before this summary existed
  const { workload: w, verdicts: v, telemetry: t, next_steps: steps, data_quality: q } = view;
  return (
    <section className="management-summary" aria-labelledby="management-summary-title">
      <h4 id="management-summary-title">Management summary</h4>
      <p>
        From {plural(w.records, 'record', 'records')} to {plural(w.evidence_units, 'evidence unit', 'evidence units')} to{' '}
        {plural(w.incidents, 'incident', 'incidents')}
        {w.fewer_items_pct !== null ? ` (${w.fewer_items_pct}% fewer items to read).` : '.'}
      </p>
      <p>
        Evidence adequacy: {v.sufficient} sufficient, {v.limited} limited, {v.insufficient} insufficient.
      </p>
      <p>
        Telemetry in this evidence: {t.present.length > 0 ? t.present.join(', ') : 'none recognised'}.
        {t.absent.length > 0 && (
          <>
            {' '}Not in this evidence:{' '}
            {t.absent.map((d, i) => (
              <span key={d}>
                {i > 0 ? '; ' : ''}
                {d} ({t.collect[d]})
              </span>
            ))}
            .
          </>
        )}
      </p>
      {steps.length > 0 && (
        <>
          <p className="management-summary-lead">What to collect next:</p>
          <ul>
            {steps.map((s) => (
              <li key={s.reason_code}>
                {plural(s.incidents, 'incident', 'incidents')}: {s.action} <span className="font-mono">({s.reason_code})</span>
              </li>
            ))}
          </ul>
        </>
      )}
      <p>
        Data quality: {plural(q.records_rejected, 'record', 'records')} rejected; {plural(q.records_with_assumed_time, 'record', 'records')} with an assumed
        time. Audit hash chain {view.integrity.ledger_verified ? 'verified' : 'NOT verified'}.
      </p>
      <p className="management-summary-caveat">{view.caveat}</p>
    </section>
  );
};
