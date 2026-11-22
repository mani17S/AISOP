/**
 * AISOP Stage 4 - Multi-source Panel (ADR-010).
 *
 * Case-scoped analyst view of the deterministic multi-source investigation:
 * - Explicit, human-initiated start (never automatic). The optional AI-assisted analysis is a separate,
 *   clearly labelled choice and is only offered to roles that may run case synthesis.
 * - Evidence sufficiency verdict with plain-language reasons, shown prominently: LIMITED and INSUFFICIENT can
 *   never be mistaken for a confirmed finding.
 * - Contributing sources, evidence timeline with raw-evidence digest prefixes, entity relationships (strong,
 *   specific and weak link counts), ATT&CK techniques with the rule that produced them and its limitation.
 * - Report text and, when an AI analysis ran, each claim with its legacy grounding status (cited events exist and a text screen
 *   passed: "Cited and text-screened"; never "verified") plus a separate deterministic assertion-verification line.
 * - Failures, rejected input, contradictions, stale evidence and limitations are listed, never hidden.
 *
 * Invariants (same design constitution as the investigation workspace): no automatic LLM invocation, no
 * response or containment actions, zero dangerouslySetInnerHTML (all text is escaped by React), no raw
 * payloads (the API does not return them), no emojis, buttons radius <= 6px.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../services/api';
import { ApiError } from '../services/errors';
import { VerificationNote, LEGACY_GROUNDING_EXPLANATION } from './VerificationNote';
import { ClassGlyph } from './EvidenceClassMark';
import { MultiSourceClaim, MultiSourceIncident, MultiSourceInvestigation, MultiSourceRationale, MultiSourceReview, MultiSourceSufficiency } from '../types';
import { useAuth } from '../contexts/AuthContext';
import { explainRecordCode, whatWouldRaiseVerdict } from '../utils/explain';
import { runWithDeadline } from '../utils/deadline';
import {
  AnalystStatements,
  ContradictionSection,
  DomainEvidenceCounts,
  DomainEvidenceImport,
  EvidenceTable,
  GraphSection,
  IntelligenceSection,
} from './DomainEvidencePanel';
import { EnrichmentView, AnalystStatementView, ContradictionView, GraphView, DomainObservation } from '../types';

const INSUFFICIENT_STYLE = {
  color: 'var(--severity-critical)',
  label: 'INSUFFICIENT',
  message: 'The evidence is insufficient. No AI analysis was run and no conclusion is offered. The deterministic report is still produced.',
};

const VERDICT_STYLE: Record<string, { color: string; label: string; message: string }> = {
  sufficient: {
    color: 'var(--accent-teal)',
    label: 'SUFFICIENT',
    message: 'The evidence meets the criteria for an investigation. Listed limitations still apply.',
  },
  limited: {
    color: '#f59e0b',
    label: 'LIMITED',
    message: 'Bounded findings only. These are NOT confirmed conclusions: review the reasons below before relying on them.',
  },
  insufficient: {
    color: 'var(--severity-critical)',
    label: 'INSUFFICIENT',
    message: 'The evidence is insufficient. No AI analysis was run and no conclusion is offered. The deterministic report is still produced.',
  },
};

const formatUtc = (s?: string | null): string => {
  if (!s) return '-';
  const d = new Date(s);
  // An unparseable timestamp must render as unknown, never throw and take the whole panel down.
  return Number.isNaN(d.getTime()) ? 'Unknown time' : d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
};

const shortId = (id: string): string => id.slice(0, 8);

const ANCHOR_TEXT: Record<string, string> = {
  used: 'An anchor event was selected and used.',
  none: 'No anchor event was supplied. Evaluated without an anchor: any two attested, specifically linked evidence units were considered against each other.',
  absent_from_evidence: 'The anchor event named for the question is not part of the evidence. No anchor was used.',
  dropped_temporal_anomaly: 'The anchor event was dated outside the investigation window and was dropped. Evaluated without an anchor.',
};

const BASIS_TEXT: Record<string, string> = {
  same_key: 'same event record',
  same_digest: 'same stored digest',
  same_upstream_id: 'same upstream id declared inside the records (declared by the submitter, not verified)',
  same_content: 'same identity and content',
  near_duplicate_within_window: 'same identity and entities within 2 seconds',
  transitive_chain: 'merged through other records (no direct match with the surviving unit)',
};

const KIND_TEXT: Record<string, string> = {
  corroborating: 'Corroborating under the current rule',
  repeated: 'Repetition of the same observation (does not corroborate)',
  weak: 'Context link only (host, user or internal address; does not corroborate)',
};

const ROLE_TEXT: Record<string, string> = {
  anchor: 'anchor',
  corroborating: 'corroborating',
  repeated_observation: 'repeated observation',
  weak_link: 'context link only',
  context: 'considered, no pair',
  excluded: 'excluded',
};

const REASON_TEXT: Record<string, string> = {
  temporal_anomaly: 'dated outside the window or in the future',
  irrelevant_to_question: 'not relevant to the question',
  unattested_digest_format: 'no well-formed stored digest (format check only)',
  contradiction_removed_pair: 'its pair was removed from corroboration by a material contradiction',
  repeated_observation: 'repetition of the same observation',
  weak_link_only: 'related only by host, user, internal address or process name',
  no_qualifying_shared_entity: 'no qualifying shared entity with the anchor or another unit',
};

/**
 * Sprint 1: "Why this result?" - a same-pass explanation of the CURRENT record-level rule. It shows evidence identifiers (shortened),
 * entity TYPE and STRENGTH only (never values, for any role), and states the limits of the rule: distinct records are not proof of
 * independent sensors, digest "attested" means a well-formed stored digest (not authenticity), and payload-declared identity is unverified.
 */
export const RationalePanel: React.FC<{ r?: MultiSourceRationale }> = ({ r }) => {
  if (!r) {
    return (
      <p className="font-mono" style={{ margin: '8px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
        Rationale not recorded for this run (it was stored before the rationale feature). Start a new run to generate one.
      </p>
    );
  }
  const units = r.units ?? [];
  const collapsed = r.collapsed ?? [];
  const pairs = r.corroboration ?? [];
  const exclusions = r.exclusions ?? [];
  const findings = r.findings ?? [];
  const contradictions = r.contradictions ?? [];
  const cut = Object.entries(r.truncated ?? {}).filter(([, v]) => v).map(([k]) => k);
  return (
    <details style={{ marginTop: '10px' }}>
      <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Why this result? Evidence sufficiency rationale</summary>
      <div style={{ marginTop: '8px' }} aria-label="Evidence sufficiency rationale">
        {r.completeness !== 'complete' && (
          <p role="status" style={{ margin: '0 0 8px' }}>
            This rationale is {r.completeness === 'partial' ? 'partial' : 'unavailable'}: the explanation could not be fully recorded
            {r.trace_error ? ` (${r.trace_error})` : ''}. The verdict above is unaffected.
          </p>
        )}
        {r.status && (
          <>
            <h4 style={{ margin: '8px 0 4px' }}>What the status means</h4>
            <p style={{ margin: 0 }}>{r.status.meaning}</p>
            <ul style={{ margin: '4px 0 0 18px' }}>
              <li>Model call: {r.status.model_call_permitted ? 'permitted by the check' : 'blocked by the check'} (run status: {r.status.llm_status}).</li>
              <li>Deterministic report: {r.status.deterministic_report_available ? 'available' : 'not available'}.</li>
            </ul>
          </>
        )}
        {r.anchor && (
          <>
            <h4 style={{ margin: '8px 0 4px' }}>Anchor</h4>
            <p style={{ margin: 0 }}>
              {ANCHOR_TEXT[r.anchor.status] ?? r.anchor.status}
              {r.anchor.event_id ? <> Anchor event <span className="font-mono">{shortId(r.anchor.event_id)}</span>.</> : null}
            </p>
          </>
        )}
        <h4 style={{ margin: '8px 0 4px' }}>Evidence units considered ({units.length})</h4>
        {units.length === 0 ? (
          <p style={{ margin: 0 }}>No evidence units were evaluated.</p>
        ) : (
          <table className="data-table">
            <caption style={{ textAlign: 'left', fontSize: '12px', color: 'var(--text-secondary)', padding: '4px 0' }}>
              Evidence units considered and their role under the current rule
            </caption>
            <thead>
              <tr>
                <th scope="col">Unit</th>
                <th scope="col">Records in unit</th>
                <th scope="col">Digest format</th>
                <th scope="col">Role</th>
              </tr>
            </thead>
            <tbody>
              {units.map((u) => (
                <tr key={u.unit}>
                  <td className="font-mono">{shortId(u.unit)}</td>
                  <td>{u.members.length}{u.members_truncated ? '+' : ''}</td>
                  <td>{u.attested_digest_format ? 'well formed' : 'missing or malformed'}</td>
                  <td>{ROLE_TEXT[u.role] ?? u.role}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <h4 style={{ margin: '8px 0 4px' }}>Records collapsed as duplicates ({collapsed.length})</h4>
        {collapsed.length === 0 ? (
          <p style={{ margin: 0 }}>No records were collapsed.</p>
        ) : (
          <ul style={{ margin: '0 0 0 18px' }}>
            {collapsed.map((c) => (
              <li key={c.duplicate}>
                <span className="font-mono">{shortId(c.duplicate)}</span> counted once with <span className="font-mono">{shortId(c.into)}</span>:{' '}
                {c.basis.map((b) => BASIS_TEXT[b] ?? b).join('; ')}.
              </li>
            ))}
          </ul>
        )}
        <h4 style={{ margin: '8px 0 4px' }}>Pairs examined ({pairs.length})</h4>
        {pairs.length === 0 ? (
          <p style={{ margin: 0 }}>No pair of evidence units shared a qualifying entity.</p>
        ) : (
          <ul style={{ margin: '0 0 0 18px' }}>
            {pairs.map((p) => (
              <li key={`${p.kind}-${p.unit_a}-${p.unit_b}`}>
                {KIND_TEXT[p.kind] ?? p.kind}: <span className="font-mono">{shortId(p.unit_a)}</span> and <span className="font-mono">{shortId(p.unit_b)}</span>, sharing{' '}
                {p.shared_entities.length === 0 ? 'no entity' : p.shared_entities.map((e) => `${e.type} (${e.strength})`).join(', ')}.
              </li>
            ))}
          </ul>
        )}
        <h4 style={{ margin: '8px 0 4px' }}>Units not counted toward corroboration ({exclusions.length})</h4>
        {exclusions.length === 0 ? (
          <p style={{ margin: 0 }}>None.</p>
        ) : (
          <ul style={{ margin: '0 0 0 18px' }}>
            {exclusions.map((e) => (
              <li key={`${e.unit}-${e.reason}`}>
                <span className="font-mono">{shortId(e.unit)}</span>: {REASON_TEXT[e.reason] ?? e.reason}.
              </li>
            ))}
          </ul>
        )}
        <h4 style={{ margin: '8px 0 4px' }}>Limiting findings and contradictions ({findings.length + contradictions.length})</h4>
        {findings.length + contradictions.length === 0 ? (
          <p style={{ margin: 0 }}>None.</p>
        ) : (
          <ul style={{ margin: '0 0 0 18px' }}>
            {findings.map((f) => (
              <li key={`${f.code}-${f.qualifier ?? ''}-${f.evidence_ids.join(',')}`}>
                <span className="font-mono">{f.code}{f.qualifier ? `:${f.qualifier}` : ''}</span> ({f.effect}){f.evidence_ids.length > 0 ? `, ${f.evidence_ids.length}${f.evidence_ids_truncated ? '+' : ''} record(s)` : ''}.
              </li>
            ))}
            {contradictions.map((c, i) => (
              <li key={`contradiction-${i}`}>
                Contradiction ({c.kind}, {c.materiality}{c.affects_verdict ? ', affects the verdict' : ''}) between{' '}
                {c.evidence_ids.map((id) => shortId(id)).join(' and ')}.
              </li>
            ))}
          </ul>
        )}
        {cut.length > 0 && (
          <p role="status" style={{ margin: '8px 0 0' }}>Some lists were shortened to keep this view bounded: {cut.join(', ')}.</p>
        )}
        <h4 style={{ margin: '8px 0 4px' }}>Limits of this explanation</h4>
        <ul style={{ margin: '0 0 0 18px' }}>
          {(r.limitations ?? []).map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
        <p className="font-mono" style={{ margin: '8px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
          Shared entity values are not shown to any role; only entity type and strength. Rule {r.rule_version ?? 'unknown'}, rationale {r.schema}.
        </p>
      </div>
    </details>
  );
};

export const VerdictBanner: React.FC<{ s: MultiSourceSufficiency; title?: string }> = ({ s, title }) => {
  const style = VERDICT_STYLE[s.verdict] ?? INSUFFICIENT_STYLE;
  const raise = s.verdict === 'sufficient' ? [] : whatWouldRaiseVerdict(s.reason_codes);
  return (
    <div
      role="status"
      aria-label={`Evidence sufficiency verdict ${style.label}`}
      style={{ border: `2px solid ${style.color}`, borderRadius: '6px', padding: '12px 16px', marginBottom: '12px' }}
    >
      <div style={{ fontWeight: 600, color: style.color }}>
        {title ? `${title}: ` : ''}Evidence sufficiency: {style.label} <span className="font-mono">({s.rule_version})</span>
      </div>
      <div style={{ margin: '6px 0' }}>{style.message}</div>
      {s.reason_codes.some((c) => c.startsWith('CONTRADICTORY_EVIDENCE')) && (
        <div style={{ margin: '6px 0' }}>
          <strong>Conflicting evidence.</strong> Records disagree and the conflict has not been resolved; see the contradictions below.
        </div>
      )}
      {s.reasons.length > 0 && (
        <ul style={{ margin: '6px 0 0 18px' }}>
          {s.reasons.map((r) => (
            <li key={r.code}>
              <span className="font-mono">{r.code}</span>: {r.meaning}
            </li>
          ))}
        </ul>
      )}
      {raise.length > 0 && (
        <div style={{ margin: '8px 0 0' }}>
          <strong>What would raise this verdict</strong>
          <ul style={{ margin: '4px 0 0 18px' }}>
            {raise.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        </div>
      )}
      <div className="font-mono" style={{ marginTop: '8px', fontSize: '12px', color: 'var(--text-secondary)' }}>
        events {s.counts.events}, evidence units {s.counts.evidence_units}, relevant {s.counts.relevant}, digest format checked{' '}
        {s.counts.attested}, corroborating units (record-level rule) {s.counts.corroborating}
      </div>
      <RationalePanel r={s.rationale} />
    </div>
  );
};

const groundingLabel = (grounding: string, category: string): string => {
  if (grounding === 'validated_reference' && category === 'observed_fact') return 'Cited and text-screened (legacy grounding)';
  if (grounding === 'contradicted') return 'Contradicted by evidence';
  if (grounding === 'unsupported') return 'Unsupported (indeterminate)';
  if (category === 'inference') return 'Inference (analyst review required)';
  return 'Needs analyst review';
};

/** Per-claim verification note (shared presentation lives in VerificationNote). */
export const ClaimVerificationNote: React.FC<{ claim: MultiSourceClaim }> = ({ claim }) => <VerificationNote verification={claim.verification} />;

export const IncidentView: React.FC<{ inc: MultiSourceIncident; index: number }> = ({ inc, index }) => (
  <section style={{ marginBottom: '28px' }} aria-label={`Incident ${index + 1}`}>
    <h3 style={{ marginBottom: '8px' }}>
      Incident {index + 1}{' '}
      <span className={`badge badge-${inc.severity}`}>{inc.severity}</span>{' '}
      <span className="font-mono" style={{ fontSize: '12px' }}>{inc.incident_id.slice(0, 8)}</span>
    </h3>
    <div style={{ color: 'var(--text-secondary)', marginBottom: '8px' }}>
      {inc.event_count} event(s); hosts: {inc.hosts.join(', ') || '-'}; users: {inc.users.join(', ') || '-'};{' '}
      {formatUtc(inc.first_seen)} to {formatUtc(inc.last_seen)}
      {inc.escalated ? '; severity raised: three or more kill-chain stages' : ''}
    </div>

    <VerdictBanner s={inc.sufficiency} />
    {inc.contradictions && inc.contradictions.length > 0 && <ContradictionSection items={inc.contradictions} />}

    <h4>Evidence timeline</h4>
    <div className="table-container">
      <table>
<caption className="visually-hidden">Evidence timeline, one row per event in time order, with source, outcome and raw SHA-256 prefix</caption>
        <thead>
          <tr>
            <th scope="col">#</th><th scope="col">Time (UTC)</th><th scope="col">Source</th><th scope="col">Host</th><th scope="col">User</th><th scope="col">Event</th><th scope="col">Stage</th>
            <th scope="col">Outcome</th><th scope="col">Provenance (raw SHA-256)</th><th scope="col">Notes</th>
          </tr>
        </thead>
        <tbody>
          {inc.timeline.map((t) => (
            <tr key={t.event_id}>
              <td>{t.position}</td>
              <td className="font-mono">{formatUtc(t.timestamp)}</td>
              <td>{t.source_type}</td>
              <td>{t.host ?? '-'}</td>
              <td>{t.user ?? '-'}</td>
              <td>{t.title}</td>
              <td>{t.stage}</td>
              <td>{t.outcome}</td>
              <td className="font-mono">{t.raw_sha256_prefix}</td>
              <td>
                {t.membership === 'weak_context' ? 'Related by host/user/internal IP only (context, not corroboration). ' : ''}
                {t.duplicates_collapsed > 0 ? `${t.duplicates_collapsed} duplicate record(s) collapsed. ` : ''}
                {t.contradicts.length > 0 ? 'Contradicted by another record.' : ''}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>

    <h4>Relationships between events</h4>
    <p>
      Strong: {inc.link_counts.strong ?? 0}, specific: {inc.link_counts.specific ?? 0}, weak: {inc.weak_link_count}. Only strong
      (same logon session or process instance) and specific (same file hash, domain or public IP) links join evidence; weak links
      (same host, user, internal IP) are context and never count as corroboration.
    </p>
    {inc.links.length > 0 && (
      <div className="table-container">
        <table>
<caption className="visually-hidden">Links between evidence units, with strength and shared entities</caption>
          <thead><tr><th scope="col">Strength</th><th scope="col">Evidence units</th><th scope="col">Shared entities</th></tr></thead>
          <tbody>
            {inc.links.map((l, i) => (
              <tr key={`${l.clusters.join('-')}-${i}`}>
                <td>{l.strength}</td>
                <td className="font-mono">{l.clusters.join(' - ')}</td>
                <td className="font-mono">{l.entities.map((e) => `${e[0]}=${e[1]}`).join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}

    <h4>ATT&amp;CK techniques (deterministic rules)</h4>
    {inc.mitre.length === 0 ? (
      <p>No technique could be derived by the rule table from this evidence.</p>
    ) : (
      <div className="table-container">
        <table>
<caption className="visually-hidden">ATT&CK techniques derived by rule, with the independent evidence behind each</caption>
          <thead>
            <tr><th scope="col">Technique</th><th scope="col">Tactic(s)</th><th scope="col">Rule</th><th scope="col">Independent evidence</th><th scope="col">Source also asserted</th><th scope="col">Limitation</th></tr>
          </thead>
          <tbody>
            {inc.mitre.map((m) => (
              <tr key={m.rule_id}>
                <td>{m.technique_id} {m.technique_name}</td>
                <td>{m.tactics.join(', ')}</td>
                <td className="font-mono">{m.rule_id}</td>
                <td>{m.independent_evidence_count}</td>
                <td>{m.vendor_asserted ? 'yes' : 'no'}</td>
                <td>{m.limitation}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
    {inc.asserted_only.length > 0 && (
      <p>Asserted by a source but NOT derived by any rule (unverified): <span className="font-mono">{inc.asserted_only.join(', ')}</span></p>
    )}

    {inc.graph && (
      <>
        <h4>Entity graph and correlation rationale</h4>
        <GraphSection graph={inc.graph} />
      </>
    )}
    {(inc.enrichments !== undefined || inc.graph) && <IntelligenceSection items={inc.enrichments ?? []} />}
    {(inc.analyst_statements !== undefined || inc.graph) && <AnalystStatements items={inc.analyst_statements ?? []} />}

    <h4>AI-assisted analysis</h4>
    {inc.llm === null ? (
      <p>
        {inc.llm_status === 'abstained'
          ? 'Not run: the evidence is insufficient (or the sufficiency check failed), so the platform abstained.'
          : inc.llm_status.startsWith('skipped:')
          ? 'Not run for this incident: the per-run limit on AI analyses was reached. The deterministic analysis above is complete.'
          : 'Not requested. Everything above is deterministic and was produced without a language model.'}
      </p>
    ) : (
      <div>
        {inc.llm_status === 'disabled' && (
          <p>
            <strong>AI assistance is disabled by configuration.</strong> No model was called and no AI result was generated; what follows is the deterministic
            fallback, not AI output. The deterministic investigation above is complete and independent of AI.
          </p>
        )}
        {inc.llm_status.startsWith('fallback:') && (
          <p>
            <strong>AI assistance was unavailable for this run</strong> (provider failure or invalid output). No AI result was generated; what follows is the
            deterministic fallback. The deterministic investigation above is unaffected.
          </p>
        )}
        <p>
          Status: <span className="font-mono">{inc.llm_status}</span>; guardrail decision: <span className="font-mono">{inc.llm.decision}</span>.
          {LEGACY_GROUNDING_EXPLANATION} Each AI claim is shown with its separate assertion-verification line below.
        </p>
        <p>{inc.llm.summary}</p>
        <ul>
          {inc.llm.claims.map((c) => (
            <li key={c.claim_id}>
              <strong>{groundingLabel(c.grounding, c.category)}</strong>: {c.text}{' '}
              <span className="font-mono">[{c.category}, {c.grounding}, model-reported confidence {c.confidence}]</span>
              <ClaimVerificationNote claim={c} />
            </li>
          ))}
        </ul>
        {inc.llm.uncertainty_and_data_gaps.length > 0 && (
          <div>
            <strong>Limitations and data gaps</strong>
            <ul>{inc.llm.uncertainty_and_data_gaps.map((g) => <li key={g}>{g}</li>)}</ul>
          </div>
        )}
      </div>
    )}

    <h4>Investigation report</h4>
    <pre style={{ whiteSpace: 'pre-wrap', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '12px' }}>
      {inc.report_markdown}
    </pre>
  </section>
);

export const MultiSourceResultView: React.FC<{ data: MultiSourceInvestigation; stale?: boolean }> = ({ data, stale }) => (
  <div>
    {stale && (
      <div className="alert-box alert-error" role="alert">
        The case evidence changed after this investigation ran. The results below are out of date: run the investigation again.
      </div>
    )}
    <p style={{ color: 'var(--text-secondary)' }}>
      Investigation stored {formatUtc(data.created_at)}; engine {data.workflow_version}; AI analysis{' '}
      {data.use_llm ? 'requested' : 'not requested'}. Audit hash chain {data.ledger.verified ? 'verified' : 'NOT verified'}:{' '}
      <span className="font-mono">{data.ledger.head.slice(0, 16)}</span>
    </p>

    <h4>Contributing sources</h4>
    <div className="table-container">
      <table>
<caption className="visually-hidden">Contributing sources with event and distinct raw record counts</caption>
        <thead><tr><th scope="col">Source</th><th scope="col">Events</th><th scope="col">Distinct raw records</th></tr></thead>
        <tbody>
          {data.sources.map((s) => (
            <tr key={s.source_type}><td>{s.source_type}</td><td>{s.events}</td><td>{s.distinct_raw_records}</td></tr>
          ))}
        </tbody>
      </table>
    </div>

    {data.truncation && (data.truncation.incidents_total > data.truncation.incidents_listed || data.truncation.rejected_total > data.truncation.rejected_listed || data.truncation.contradictions_total > data.truncation.contradictions_listed) && (
      <div className="alert-box alert-error" role="alert">
        <strong>Stored result is truncated.</strong> Showing {data.truncation.incidents_listed} of {data.truncation.incidents_total} incidents,{' '}
        {data.truncation.rejected_listed} of {data.truncation.rejected_total} rejected records and {data.truncation.contradictions_listed} of{' '}
        {data.truncation.contradictions_total} contradictions. Narrow the evidence linked to the case to see everything.
      </div>
    )}

    {((data.rejected ?? []).length > 0 || (data.contradictions ?? []).length > 0) && (
      <div className="alert-box alert-error" role="alert">
        <strong>Data-quality problems</strong>
        <ul>
          {(data.rejected ?? []).map((r) => (
            <li key={r.record_index}>Record {r.record_index} could not be normalized. {explainRecordCode(r.reason)} (<span className="font-mono">{r.reason}</span>, SHA-256 {r.raw_sha256_prefix}).</li>
          ))}
          {(data.contradictions ?? []).map((c, i) => (
            <li key={`${c.reason}-${i}`}>Contradictory evidence: <span className="font-mono">{c.reason}</span> ({c.event_ids.length} events).</li>
          ))}
        </ul>
      </div>
    )}

    {data.observation_counts && data.observation_counts.total > 0 && (
      <>
        <h4>Case evidence (source-agnostic)</h4>
        <DomainEvidenceCounts counts={data.observation_counts} />
        {data.observations && data.observations.length > 0 && <EvidenceTable observations={data.observations} />}
      </>
    )}

    {data.batch_sufficiency && <VerdictBanner s={data.batch_sufficiency} title="No incident formed" />}
    {data.batch_graph && !data.incidents.length && <GraphSection graph={data.batch_graph} />}
    {data.incidents.map((inc, i) => <IncidentView key={inc.incident_id} inc={inc} index={i} />)}

    <h4>Limitations</h4>
    <ul>
      <li>Mappings and links are rule-based and explainable, not probabilistic; absence of a link is not evidence of absence.</li>
      <li>Provenance is the SHA-256 of each preserved raw record: integrity since ingestion, not proof the source was truthful.</li>
      <li>No response or containment action is taken by this view; all conclusions require analyst judgement.</li>
    </ul>
  </div>
);

interface MultiSourcePanelProps {
  caseId: string;
  caseClosed?: boolean;
  initialResult?: MultiSourceInvestigation | null;
  initialStale?: boolean;
}

export const MultiSourcePanel: React.FC<MultiSourcePanelProps> = ({ caseId, caseClosed, initialResult, initialStale }) => {
  const { canSynthesizeReports, canCloseCase } = useAuth();
  const [result, setResult] = useState<MultiSourceInvestigation | null>(initialResult ?? null);
  const [stale, setStale] = useState<boolean>(initialStale ?? false);
  const [busy, setBusy] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState<boolean>(!!initialResult);

  const loadExisting = useCallback(async () => {
    try {
      const status = await api.getMultiSourceSection<{ stale_evidence: boolean }>(caseId, 'status');
      const [domainGraph, domainEvidence] = await Promise.all([
        api.getMultiSourceSection<{ batch_graph?: GraphView | null; incidents: { incident_id: string; graph?: GraphView | null; enrichments?: EnrichmentView[]; analyst_statements?: AnalystStatementView[] }[] }>(caseId, 'graph'),
        api.getMultiSourceSection<{ observations?: DomainObservation[]; observation_counts?: MultiSourceInvestigation['observation_counts'] }>(caseId, 'evidence'),
      ]);
      const [timeline, correlation, attack, sufficiency, report] = await Promise.all([
        api.getMultiSourceSection<{ incidents: { incident_id: string; timeline: MultiSourceIncident['timeline'] }[] }>(caseId, 'timeline'),
        api.getMultiSourceSection<{ incidents: { incident_id: string; links: MultiSourceIncident['links']; weak_link_count: number; hosts: string[]; users: string[]; stages: string[]; escalated: boolean; severity: string; link_counts: Record<string, number>; weakly_related: string[] }[] }>(caseId, 'correlation'),
        api.getMultiSourceSection<{ incidents: { incident_id: string; mitre: MultiSourceIncident['mitre']; asserted_only: string[] }[] }>(caseId, 'attack'),
        api.getMultiSourceSection<{ incidents: { incident_id: string; sufficiency: MultiSourceSufficiency; llm_status: string; contradictions?: ContradictionView[] }[] }>(caseId, 'sufficiency'),
        api.getMultiSourceSection<{ batch_report_markdown: string | null; incidents: { incident_id: string; llm: MultiSourceIncident['llm']; report_markdown: string }[] }>(caseId, 'report'),
      ]);
      const st = status as unknown as MultiSourceInvestigation & { stale_evidence: boolean; incidents: { incident_id: string; event_count: number }[] };
      const incidents: MultiSourceIncident[] = correlation.incidents.map((c) => {
        const t = timeline.incidents.find((x) => x.incident_id === c.incident_id);
        const a = attack.incidents.find((x) => x.incident_id === c.incident_id);
        const s = sufficiency.incidents.find((x) => x.incident_id === c.incident_id);
        const r = report.incidents.find((x) => x.incident_id === c.incident_id);
        const base = st.incidents.find((x) => x.incident_id === c.incident_id);
        return {
          incident_id: c.incident_id, severity: c.severity, event_count: base?.event_count ?? (t?.timeline.length ?? 0),
          first_seen: t?.timeline[0]?.timestamp ?? null, last_seen: t?.timeline[t.timeline.length - 1]?.timestamp ?? null,
          hosts: c.hosts, users: c.users, stages: c.stages, escalated: c.escalated, link_counts: c.link_counts,
          weakly_related: c.weakly_related, context_sha256: '', sufficiency: s!.sufficiency, timeline: t?.timeline ?? [],
          links: c.links, weak_link_count: c.weak_link_count, mitre: a?.mitre ?? [], asserted_only: a?.asserted_only ?? [],
          llm_status: s!.llm_status, llm: r?.llm ?? null, report_markdown: r?.report_markdown ?? '',
          contradictions: s?.contradictions,
          graph: domainGraph.incidents.find((x) => x.incident_id === c.incident_id)?.graph ?? null,
          enrichments: domainGraph.incidents.find((x) => x.incident_id === c.incident_id)?.enrichments,
          analyst_statements: domainGraph.incidents.find((x) => x.incident_id === c.incident_id)?.analyst_statements,
        };
      });
      setResult({
        ...st, incidents, batch_report_markdown: report.batch_report_markdown ?? null,
        observations: domainEvidence.observations, observation_counts: domainEvidence.observation_counts, batch_graph: domainGraph.batch_graph ?? null,
      } as MultiSourceInvestigation);
      setStale(status.stale_evidence);
    } catch (e) {
      setResult(null);
      const msg = e instanceof Error ? e.message : '';
      // A missing investigation (404) is the normal empty state; any other failure (401/403/5xx/network) is shown, not hidden.
      // Classified by the stable error kind (from the HTTP status and backend error code), never by message text.
      const notFound = e instanceof ApiError && e.kind === 'not_found';
      if (msg && !notFound) setError(msg);
    } finally {
      setLoaded(true);
    }
  }, [caseId]);

  useEffect(() => {
    if (!initialResult) void loadExisting();
  }, [initialResult, loadExisting]);

  const start = async (force: boolean) => {
    setBusy(true);
    setError(null);
    try {
      // The deterministic investigation never waits for the AI step: it is always requested with the model off.
      const data = await api.startMultiSourceInvestigation(caseId, { use_llm: false, force });
      setResult(data);
      setStale(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The investigation could not be completed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div aria-label="Multi-source investigation">
      <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '16px' }}>
        <button className="btn btn-primary" disabled={busy || caseClosed} onClick={() => void start(false)}>
          {busy ? 'Investigating...' : result ? 'Re-run multi-source investigation' : 'Start multi-source investigation'}
        </button>
        {result && (
          <button className="btn btn-secondary" disabled={busy || caseClosed} onClick={() => void start(true)}>
            Force a new run
          </button>
        )}
      </div>
      {!caseClosed && <DomainEvidenceImport caseId={caseId} caseClosed={caseClosed} />}
      <p style={{ color: 'var(--text-secondary)' }}>
        The deterministic investigation uses only evidence linked to this case and needs no language model. Nothing here executes a response or containment action.
      </p>
      {error && <div className="alert-box alert-error" role="alert">{error}</div>}
      {busy && <p role="status">Processing: normalizing evidence, correlating sources and evaluating sufficiency...</p>}
      {!result && loaded && !busy && !error && (
        <p role="status">No multi-source investigation has been run for this case yet. Select &quot;Start&quot; to analyse the linked evidence.</p>
      )}
      {result && canSynthesizeReports() && !caseClosed && (
        <AiExplanationStep
          caseId={caseId}
          disabled={busy}
          alreadyRun={result.use_llm}
          onResult={(data) => {
            setResult(data);
            setStale(false);
          }}
        />
      )}
      {result && <ReviewStep caseId={caseId} fingerprint={result.evidence_fingerprint} caseClosed={caseClosed} canReview={canCloseCase()} />}
      {result && <MultiSourceResultView data={result} stale={stale} />}
    </div>
  );
};

/** The case lead's review of the stored result: a record of a human decision. It changes neither the investigation nor the evidence. */
export const reviewText = (r: MultiSourceReview | null): string => {
  if (!r) return 'Loading the review state.';
  if (r.state === 'stale') return 'The evidence changed after this result was produced, so any earlier review no longer applies. Run the investigation again and review the new result.';
  if (r.state === 'approved') return `Approved by ${r.reviewed_by ?? 'the case lead'}${r.reviewed_at ? ` at ${r.reviewed_at}` : ''}.`;
  if (r.state === 'rejected') return `Rejected by ${r.reviewed_by ?? 'the case lead'}${r.reviewed_at ? ` at ${r.reviewed_at}` : ''}.`;
  return 'Not reviewed. The case lead has not recorded a decision on this result.';
};

export const ReviewStep: React.FC<{
  caseId: string;
  fingerprint: string;
  caseClosed?: boolean;
  canReview: boolean;
  initialReview?: MultiSourceReview | null;
}> = ({ caseId, fingerprint, caseClosed, canReview, initialReview }) => {
  const [review, setReview] = useState<MultiSourceReview | null>(initialReview ?? null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialReview !== undefined) return undefined;
    let live = true;
    api.getMultiSourceSection<{ review?: MultiSourceReview }>(caseId, 'status')
      .then((s) => { if (live) setReview(s.review ?? null); })
      .catch(() => { if (live) setReview(null); });
    return () => { live = false; };
  }, [caseId, fingerprint, initialReview]);

  const download = async () => {
    setBusy(true);
    setError(null);
    try {
      const out = await api.exportMultiSourceReport(caseId);
      const url = URL.createObjectURL(new Blob([out.markdown], { type: 'text/markdown' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = out.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The report could not be released.');
    } finally {
      setBusy(false);
    }
  };

  const submit = async (decision: 'approved' | 'rejected') => {
    setBusy(true);
    setError(null);
    try {
      setReview(await api.reviewMultiSourceInvestigation(caseId, { decision, evidence_fingerprint: fingerprint, note: note.trim() || undefined }));
      setNote('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The review could not be recorded.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-label="Lead review" className="alert-box alert-info" style={{ display: 'block', margin: '0 0 16px' }}>
      <strong>Lead review</strong>
      <p role="status" style={{ margin: '4px 0' }}>{reviewText(review)}</p>
      {review?.note && <p style={{ margin: '4px 0' }}>Note: {review.note}</p>}
      <p style={{ margin: '4px 0 8px', color: 'var(--text-secondary)' }}>
        A review records the lead&apos;s decision about this result. It does not change the investigation or the evidence, and nothing is sent anywhere.
      </p>
      {canReview && !caseClosed && (
        <div>
          <label className="field-label" htmlFor="review-note">Note (optional)</label>
          <textarea id="review-note" className="input-field" maxLength={500} rows={2} value={note} onChange={(e) => setNote(e.target.value)} style={{ width: '100%', marginBottom: '8px' }} />
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="btn btn-primary" disabled={busy} onClick={() => void submit('approved')}>Approve this result</button>
            <button className="btn btn-secondary" disabled={busy} onClick={() => void submit('rejected')}>Reject this result</button>
          </div>
        </div>
      )}
      {!canReview && <p style={{ margin: '4px 0 0', color: 'var(--text-secondary)' }}>Only the case lead can record a review.</p>}
      {review?.state === 'approved' ? (
        <button className="btn btn-secondary" style={{ marginTop: '8px' }} disabled={busy} onClick={() => void download()}>Download approved report (.md)</button>
      ) : (
        <p style={{ margin: '8px 0 0', color: 'var(--text-secondary)' }}>The report can be downloaded only after the case lead approves the current result.</p>
      )}
      {error && <p role="alert" style={{ margin: '8px 0 0' }}>{error}</p>}
    </section>
  );
};

/** The AI explanation is optional, on demand and never blocks the deterministic result shown above it. */
export const AI_EXPLANATION_TIMEOUT_MS = 90_000;

type AiStepState = { kind: 'idle' } | { kind: 'running' } | { kind: 'done'; seconds: number } | { kind: 'timeout' } | { kind: 'cancelled' } | { kind: 'failed'; message: string };

export const AiExplanationStep: React.FC<{
  caseId: string;
  disabled?: boolean;
  alreadyRun?: boolean;
  onResult: (data: MultiSourceInvestigation) => void;
  timeoutMs?: number;
}> = ({ caseId, disabled, alreadyRun, onResult, timeoutMs = AI_EXPLANATION_TIMEOUT_MS }) => {
  const [state, setState] = useState<AiStepState>({ kind: 'idle' });
  const [elapsed, setElapsed] = useState(0);
  const cancelRef = React.useRef<(() => void) | null>(null);

  useEffect(() => {
    if (state.kind !== 'running') return undefined;
    const t0 = Date.now();
    setElapsed(0);
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 1000);
    return () => clearInterval(id);
  }, [state.kind]);

  const run = async () => {
    setState({ kind: 'running' });
    const t0 = Date.now();
    const handle = runWithDeadline((signal) => api.startMultiSourceInvestigation(caseId, { use_llm: true }, signal), timeoutMs);
    cancelRef.current = handle.cancel;
    const outcome = await handle.result;
    cancelRef.current = null;
    if (outcome.kind === 'done') {
      onResult(outcome.value);
      setState({ kind: 'done', seconds: Math.round((Date.now() - t0) / 1000) });
    } else if (outcome.kind === 'failed') {
      setState({ kind: 'failed', message: outcome.message });
    } else {
      setState({ kind: outcome.kind });
    }
  };

  return (
    <section aria-label="AI explanation" className="setup-notice alert-box alert-info" style={{ display: 'block', margin: '0 0 16px' }}>
      <strong><ClassGlyph cls="model_inference" /> AI explanation (optional)</strong>
      <p style={{ margin: '4px 0 8px' }}>
        The investigation above is complete without it. A local language model runs on this machine and can be slow. It runs only if the evidence check allows it, and every claim it makes is checked against the evidence.
      </p>
      {state.kind === 'running' ? (
        <div role="status">
          AI explanation running, {elapsed} s. The result above is unchanged.{' '}
          <button className="btn btn-secondary" onClick={() => cancelRef.current?.()}>
            Cancel
          </button>
        </div>
      ) : (
        <button className="btn btn-primary" disabled={disabled} onClick={() => void run()}>
          {alreadyRun || state.kind === 'done' ? 'Run AI explanation again' : 'Run AI explanation'}
        </button>
      )}
      {state.kind === 'done' && <p role="status" style={{ margin: '8px 0 0' }}>AI explanation finished in {state.seconds} s. Its status for each incident is shown below.</p>}
      {state.kind === 'timeout' && <p role="status" style={{ margin: '8px 0 0' }}>AI timed out after {Math.round(timeoutMs / 1000)} s. The deterministic result is unchanged. The server may still finish this run in the background.</p>}
      {state.kind === 'cancelled' && <p role="status" style={{ margin: '8px 0 0' }}>AI explanation cancelled. The deterministic result is unchanged. The server may still finish this run in the background.</p>}
      {state.kind === 'failed' && <p role="alert" style={{ margin: '8px 0 0' }}>The AI explanation could not be completed ({state.message}). The deterministic result is unchanged.</p>}
    </section>
  );
};
