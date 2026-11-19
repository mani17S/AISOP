/**
 * AISOP Stage 6 - Source-agnostic evidence views (ADR-011).
 *
 * Presentational components for evidence that does not come from a SIEM alert: per-record classification and
 * provenance, the entity graph with typed relationships and correlation rationale, external intelligence and
 * analyst statements. Labelling rules (never hidden, never upgraded):
 * - Observed evidence, external intelligence, analyst statements and AI output are visibly different categories.
 * - A correlation is labelled "Corroboration" only for strong/specific links; weak links are "Context only".
 * - Undated evidence is shown as undated; no time is invented. Unclassified evidence is shown as preserved, not interpreted.
 * Invariants: no dangerouslySetInnerHTML (React escapes all text), no raw payloads (the API does not return them),
 * no emojis, no em dashes, buttons radius <= 6px.
 */

import React, { useState } from 'react';
import { api } from '../services/api';
import {
  AnalystStatementView,
  ContradictionView,
  DomainImportResult,
  DomainObservation,
  EnrichmentView,
  GraphView,
} from '../types';

const CLASSIFICATION: Record<string, string> = {
  normalized: 'Normalized',
  partial: 'Partially normalized (nothing linkable extracted)',
  unclassified: 'Unclassified (preserved, not interpreted)',
};

const TIME: Record<string, string> = {
  valid: 'Valid',
  naive_assumed_utc: 'No time zone given; UTC assumed',
  missing: 'Undated: no event time supplied (none was invented)',
  invalid: 'Undated: event time unreadable (none was invented)',
  out_of_range: 'Undated: event time out of range (none was invented)',
};

const TRUST: Record<string, string> = {
  raw_observed: 'Observed (collector record)',
  tool_asserted: 'Tool-asserted (forensic tool interpretation)',
  analyst_observation: 'Analyst statement (context only)',
  ti_context: 'External intelligence (context only)',
  derived: 'Derived',
  model_inference: 'AI inference',
  analyst_confirmed: 'Analyst confirmed',
};

const fmt = (s?: string | null): string => (s ? new Date(s).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : 'Undated');

export const EvidenceTable: React.FC<{ observations: DomainObservation[] }> = ({ observations }) => (
  <div className="table-container" aria-label="Case evidence and provenance">
    <table>
      <thead>
        <tr>
          <th>#</th><th>Type</th><th>Source system</th><th>Collection</th><th>Classification</th><th>Time</th>
          <th>Trust</th><th>Corroboration</th><th>On timeline</th><th>Raw SHA-256 (prefix)</th>
        </tr>
      </thead>
      <tbody>
        {observations.map((o) => (
          <tr key={o.evidence_id}>
            <td>{o.record_index}</td>
            <td className="font-mono">{o.evidence_type}</td>
            <td>{o.source_system}</td>
            <td>{o.collection_method}</td>
            <td>{CLASSIFICATION[o.classification] ?? o.classification}</td>
            <td>{o.event_time ? fmt(o.event_time) : TIME[o.time_status] ?? o.time_status}</td>
            <td>{TRUST[o.trust_class] ?? o.trust_class}</td>
            <td>{o.counts_for_corroboration ? 'Can corroborate' : 'Never corroborates'}</td>
            <td>{o.on_timeline ? 'yes' : 'no'}</td>
            <td className="font-mono">{o.raw_sha256.slice(0, 12)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

export const GraphSection: React.FC<{ graph: GraphView }> = ({ graph }) => (
  <div aria-label="Entity graph">
    <p>
      {graph.nodes.length} entities and {graph.edges.length} typed relationships from {graph.observation_count} observed record(s). Every
      relationship below is stated by at least one record; none is inferred. Independent support counts distinct evidence units, so
      duplicate records count once.
    </p>
    {graph.truncated && <p role="alert">The graph view is truncated to its size limit.</p>}
    {graph.edges.length > 0 && (
      <div className="table-container">
        <table>
          <thead><tr><th>Subject</th><th>Relationship</th><th>Object</th><th>Independent support</th><th>Sources</th><th>Trust</th></tr></thead>
          <tbody>
            {graph.edges.map((e, i) => (
              <tr key={`${e.subject}-${e.predicate}-${e.object}-${i}`}>
                <td className="font-mono">{e.subject}</td>
                <td>{e.predicate}</td>
                <td className="font-mono">{e.object}</td>
                <td>{e.independent_support}</td>
                <td>{e.sources.join(', ')}</td>
                <td>{e.trust.map((t) => TRUST[t] ?? t).join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}

    <h5>Why evidence was correlated</h5>
    {graph.correlations.length === 0 ? (
      <p>No two independent evidence units share an entity.</p>
    ) : (
      <div className="table-container">
        <table>
          <thead><tr><th>Basis</th><th>Shared entities</th><th>Seconds apart</th><th>Rationale</th></tr></thead>
          <tbody>
            {graph.correlations.map((c, i) => (
              <tr key={`${c.observations.join('-')}-${i}`}>
                <td>{c.counts_as_corroboration ? `Corroboration (${c.strength})` : 'Context only (weak)'}</td>
                <td className="font-mono">{c.shared_entities.join(', ')}</td>
                <td>{Math.round(c.seconds_apart)}</td>
                <td>{c.rationale}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}

    {graph.contradictions.length > 0 && (
      <div className="alert-box alert-error" role="alert">
        <strong>Contradictory evidence</strong>
        <ul>{graph.contradictions.map((c, i) => <li key={`${c.reason}-${i}`}><span className="font-mono">{c.reason}</span> ({c.observations.length} records)</li>)}</ul>
      </div>
    )}

    <h5>Uncertainty and missing information</h5>
    {graph.uncertainties.length === 0 ? (
      <p>None recorded.</p>
    ) : (
      <ul>{graph.uncertainties.map((u) => <li key={u.kind}><strong className="font-mono">{u.kind}</strong>: {u.detail}</li>)}</ul>
    )}
  </div>
);

const KIND_LABEL: Record<string, string> = {
  ordering: 'Event ordering (an artefact is timestamped before the event said to cause it)',
  outcome: 'Outcome (independent sources report opposite results)',
  identity: 'Identity (one session attributed to two different canonical principals)',
  temporal: 'Time (one event reported with incompatible event times)',
};

const MATERIALITY_LABEL: Record<string, string> = {
  material: 'Material: unresolved, affects the verdict',
  minor: 'Minor: disclosed only',
  explained: 'Explained: disclosed only',
};

const whyText = (c: ContradictionView): string => {
  if (c.affects_verdict) {
    return `Independent sources disagree about the same proposition and the disagreement touches the investigated hypothesis (${c.relation}). The pair no longer counts as corroboration and the verdict is capped at LIMITED.`;
  }
  if (c.explanation === 'timezone_assumed') {
    return 'A source gave no time zone, so UTC was assumed; no material time-based claim can be made. Disclosed only.';
  }
  if (c.explanation === 'clock_skew_within_tolerance') {
    return 'The difference is within the approved 5-second clock-skew tolerance, so it is explained as possible clock skew. Disclosed only.';
  }
  if (c.independence === 'same_source') {
    return 'Both records come from the same source or the same upstream collection, so this is an internal inconsistency, not independent disagreement. Disclosed only.';
  }
  if (c.independence === 'unknown') {
    return 'Whether the two sources are independent could not be established, so it is not treated as independent. Disclosed only.';
  }
  return 'The link between the records is weak, or they are peripheral to the hypothesis. Disclosed only.';
};

/** ADR-013: contradictions between observed records. Never presented as resolved; the verdict effect is stated per finding. */
export const ContradictionSection: React.FC<{ items: ContradictionView[] }> = ({ items }) => {
  if (items.length === 0) return null;
  const material = items.some((c) => c.affects_verdict);
  return (
    <div aria-label="Contradictions between records" role={material ? 'alert' : 'status'} style={{ border: `1px solid ${material ? 'var(--severity-critical)' : 'var(--border-color)'}`, borderRadius: '6px', padding: '12px 16px', marginBottom: '12px' }}>
      <strong>{material ? 'Conflicting evidence limits this verdict' : 'Conflicts were found and disclosed'}</strong>
      <p>These records conflict about the same proposition. The conflict is reported, not resolved.</p>
      <div className="table-container">
        <table>
          <thead>
            <tr><th>Kind</th><th>Effect</th><th>Record 1</th><th>Record 2</th><th>Why</th><th>What would resolve it</th></tr>
          </thead>
          <tbody>
            {items.map((c, i) => (
              <tr key={`${c.evidence_ids.join('-')}-${i}`}>
                <td>{KIND_LABEL[c.kind] ?? c.kind}</td>
                <td>{MATERIALITY_LABEL[c.materiality] ?? c.materiality}</td>
                {[0, 1].map((n) => (
                  <td key={n}>
                    <span className="font-mono">{c.sources[n]}</span>, {fmt(c.times[n])}: {c.claims[n]}
                    {c.time_quality[n] === 'naive_assumed_utc' ? ' (time zone assumed)' : ''}
                  </td>
                ))}
                <td>{whyText(c)}</td>
                <td>{c.resolution_text}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const IntelligenceSection: React.FC<{ items: EnrichmentView[] }> = ({ items }) => (
  <div aria-label="External intelligence">
    <h5>External intelligence (context only, not observed in this case)</h5>
    {items.length === 0 ? (
      <p>No external intelligence was attached to this incident.</p>
    ) : (
      <>
        <div className="table-container">
          <table>
            <thead><tr><th>Indicator</th><th>Source</th><th>Intelligence</th><th>Observed in</th></tr></thead>
            <tbody>
              {items.flatMap((en) => en.matches.map((m, i) => (
                <tr key={`${en.entity}-${m.source}-${i}`}>
                  <td className="font-mono">{en.entity}</td><td>{m.source}</td><td>{m.description}</td><td>{en.observed_in.length} record(s)</td>
                </tr>
              )))}
            </tbody>
          </table>
        </div>
        <p>This describes the indicator in general. It did not influence correlation, the sufficiency verdict or technique mapping.</p>
      </>
    )}
  </div>
);

export const AnalystStatements: React.FC<{ items: AnalystStatementView[] }> = ({ items }) => (
  <div aria-label="Analyst statements">
    <h5>Analyst statements (context only, never corroboration)</h5>
    {items.length === 0 ? (
      <p>No analyst statement refers to this incident.</p>
    ) : (
      <>
        <ul>
          {items.map((s) => (
            <li key={s.evidence_id}>
              {s.statement} <span className="font-mono">[{s.analyst}, {fmt(s.time)}, {s.entities.join(' ')}]</span>
            </li>
          ))}
        </ul>
        <p>Unverified statements from a person. They did not count toward the sufficiency verdict or any technique mapping.</p>
      </>
    )}
  </div>
);

export const DomainEvidenceCounts: React.FC<{ counts: NonNullable<import('../types').MultiSourceInvestigation['observation_counts']> }> = ({ counts }) => (
  <p>
    {counts.total} evidence record(s):{' '}
    {Object.entries(counts.by_classification).map(([k, v]) => `${v} ${CLASSIFICATION[k] ?? k}`).join('; ')}.{' '}
    {counts.undated > 0 ? `${counts.undated} undated (not placed on the timeline). ` : ''}
    {counts.analyst_statements > 0 ? `${counts.analyst_statements} analyst statement(s) (context only).` : ''}
  </p>
);

const parseEvidenceText = (text: string): unknown[] => {
  try {
    const doc = JSON.parse(text);
    const items = Array.isArray(doc) ? doc : doc && typeof doc === 'object' ? (doc as { evidence?: unknown }).evidence : undefined;
    if (!Array.isArray(items)) throw new Error('The file must be a JSON array, or an object with an "evidence" array.');
    return items;
  } catch (e) {
    if (e instanceof SyntaxError) {
      return text.split(/\r?\n/).filter((l) => l.trim()).map((l) => JSON.parse(l));
    }
    throw e;
  }
};

export const DomainEvidenceImport: React.FC<{ caseId: string; caseClosed?: boolean; onImported?: () => void }> = ({ caseId, caseClosed, onImported }) => {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DomainImportResult | null>(null);

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const records = parseEvidenceText(await file.text());
      setResult(await api.importDomainEvidence(caseId, records));
      onImported?.();
    } catch (e) {
      setError(e instanceof Error && e.message ? e.message : 'The evidence file could not be imported.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div aria-label="Import source-agnostic evidence" style={{ marginBottom: '16px' }}>
      <label>
        Import evidence file (JSON or JSON Lines, aisop.evidence/1 records):{' '}
        <input type="file" accept=".json,.jsonl,application/json" disabled={busy || caseClosed} onChange={(e) => void onFile(e.target.files?.[0])} />
      </label>
      <p style={{ color: 'var(--text-secondary)' }}>
        Each record is validated on the server. Malformed records are quarantined and not stored; valid and unrecognised records are
        preserved unchanged with a SHA-256 digest. Importing does not start an investigation.
      </p>
      {error && <div className="alert-box alert-error" role="alert">{error}</div>}
      {result && (
        <div role="status">
          Received {result.received}; accepted {result.accepted} ({result.duplicates} already stored, {result.unclassified} unclassified,{' '}
          {result.undated} undated); quarantined {result.quarantined}.
          {result.quarantined_records.length > 0 && (
            <ul>
              {result.quarantined_records.map((q) => (
                <li key={q.record_index}>Record {q.record_index} quarantined: <span className="font-mono">{q.reason}</span></li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
};
