/**
 * AISOP Stage 6 - source-agnostic evidence views test suite (ADR-011).
 * Server-side rendering only (no network, no DOM). Verifies: provenance and classification are visible, undated and
 * unclassified evidence are never presented as normal, weak correlations are never labelled corroboration, external
 * intelligence and analyst statements are labelled as context, graph edges show rationale inputs, escaping, and
 * that results stored before Stage 6 (no new fields) still render.
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { AnalystStatements, ContradictionSection, DomainEvidenceCounts, DomainEvidenceImport, EvidenceTable, GraphSection, IntelligenceSection } from '../src/components/DomainEvidencePanel';
import { MultiSourceResultView, VerdictBanner } from '../src/components/MultiSourcePanel';
import { AuthProvider } from '../src/contexts/AuthContext';
import { ContradictionView, DomainObservation, GraphView, MultiSourceInvestigation } from '../src/types';

const obs = (o: Partial<DomainObservation>): DomainObservation => ({
  evidence_id: 'e1', record_index: 0, source_evidence_id: null, evidence_type: 'identity.signin', family: 'identity',
  classification: 'normalized', source_system: 'idp-synthetic', source_category: 'identity', collection_method: 'api_export',
  adapter: 'identity@domain-adapters-1', time_status: 'valid', event_time: '2026-11-03T09:07:00+00:00', collected_at: null,
  raw_sha256: 'ab'.repeat(32), integrity: 'digest_attested', trust_class: 'raw_observed', counts_for_corroboration: true,
  outcome: 'success', title: 'Sign-in', on_timeline: true, entity_count: 3, relationship_count: 2, ...o,
});

const graph: GraphView = {
  observation_count: 3,
  nodes: [{ id: 'user:a', type: 'user', value: 'a', observation_count: 2, sources: ['idp'], derived: false, analyst_note_count: 0 }],
  edges: [{ subject: 'user:alice', predicate: 'AUTHENTICATED_FROM', object: 'ip:91.240.118.172', kind: 'stated', supporting_observations: ['e1'],
    independent_support: 1, sources: ['idp-synthetic'], trust: ['raw_observed'], rationale: 'Stated directly' }],
  correlations: [
    { observations: ['e1', 'e2'], strength: 'specific', shared_entities: ['ip:91.240.118.172'], seconds_apart: 300, rationale: 'Same artefact not shared by accident', counts_as_corroboration: true },
    { observations: ['e2', 'e3'], strength: 'weak', shared_entities: ['host:ws1'], seconds_apart: 60, rationale: 'Only a bare context value', counts_as_corroboration: false },
  ],
  contradictions: [{ observations: ['e1', 'e2'], reason: 'OUTCOME_CONFLICT_WITHIN_2S' }],
  uncertainties: [{ kind: 'TOOL_ASSERTED_ONLY', detail: 'Interpretation produced by a forensic tool', observations: ['e3'] }],
  truncated: false,
};

const render = (el: React.ReactElement) => renderToStaticMarkup(<AuthProvider>{el}</AuthProvider>);

describe('Domain evidence views', () => {
  it('shows classification, time status, trust and provenance for every record', () => {
    const html = render(<EvidenceTable observations={[
      obs({}),
      obs({ evidence_id: 'e2', classification: 'unclassified', evidence_type: 'vendorx.widget_event', counts_for_corroboration: false }),
      obs({ evidence_id: 'e3', time_status: 'missing', event_time: null, on_timeline: false }),
      obs({ evidence_id: 'e4', trust_class: 'analyst_observation', counts_for_corroboration: false }),
      obs({ evidence_id: 'e5', trust_class: 'tool_asserted', classification: 'partial' }),
    ]} />);
    assert.ok(html.includes('Unclassified (preserved, not interpreted)'));
    assert.ok(html.includes('Undated: no event time supplied (none was invented)'));
    assert.ok(html.includes('Analyst statement (context only)') && html.includes('Never corroborates'));
    assert.ok(html.includes('Tool-asserted') && html.includes('Partially normalized'));
    assert.ok(html.includes('abababababab') && html.includes('idp-synthetic') && html.includes('api_export'));
  });

  it('labels weak correlations as context only and only strong or specific as corroboration', () => {
    const html = render(<GraphSection graph={graph} />);
    assert.ok(html.includes('Corroboration (specific)') && html.includes('Context only (weak)'));
    assert.ok(!html.includes('Corroboration (weak)'));
    assert.ok(html.includes('none is inferred') && html.includes('AUTHENTICATED_FROM'));
  });

  it('shows contradictions and uncertainty instead of hiding them', () => {
    const html = render(<GraphSection graph={graph} />);
    assert.ok(html.includes('OUTCOME_CONFLICT_WITHIN_2S') && html.includes('role="alert"'));
    assert.ok(html.includes('TOOL_ASSERTED_ONLY') && html.includes('forensic tool'));
  });

  it('separates external intelligence and analyst statements from observed evidence', () => {
    const ti = render(<IntelligenceSection items={[{ entity: 'ip:1.2.3.4', trust_class: 'ti_context', observed_in: ['e1'], statement: 's',
      matches: [{ source: 'synthetic-feed', kind: 'indicator', description: 'Listed source', reference: null }] }]} />);
    assert.ok(ti.includes('context only, not observed in this case') && ti.includes('did not influence correlation'));
    assert.ok(render(<IntelligenceSection items={[]} />).includes('No external intelligence'));
    const an = render(<AnalystStatements items={[{ evidence_id: 'n1', time: null, statement: 'Looks hostile', analyst: 't2', entities: ['ip:1.2.3.4'], trust_class: 'analyst_observation', counts_for_corroboration: false }]} />);
    assert.ok(an.includes('never corroboration') && an.includes('did not count toward the sufficiency verdict') && an.includes('Undated'));
  });

  it('escapes evidence text', () => {
    const html = render(<EvidenceTable observations={[obs({ evidence_type: '<img src=x onerror=1>' })]} />);
    assert.ok(!html.includes('<img src=x') && html.includes('&lt;img src=x'));
  });

  it('summarises counts including undated and analyst statements', () => {
    const html = render(<DomainEvidenceCounts counts={{ total: 6, listed: 6, by_classification: { normalized: 4, unclassified: 1, partial: 1 }, undated: 2, analyst_statements: 1 }} />);
    assert.ok(html.includes('2 undated (not placed on the timeline)') && html.includes('1 analyst statement(s) (context only)'));
  });

  it('import control states that records are validated, quarantined and that it does not start an investigation', () => {
    const html = render(<DomainEvidenceImport caseId="11111111-1111-1111-1111-111111111111" />);
    assert.ok(html.includes('quarantined and not stored') && html.includes('does not start an investigation'));
  });

  it('renders results stored before Stage 6 (no graph, evidence or enrichment fields) unchanged', () => {
    const legacy = { schema: 'multisource-v1', status: 'completed', use_llm: false, workflow_version: 'multi-source-v1', evidence_fingerprint: 'f'.repeat(64),
      counts: {}, sources: [], rejected: [], contradictions: [], batch_sufficiency: null, batch_report_markdown: null, incidents: [],
      ledger: { head: 'b'.repeat(64), verified: true, steps: [] } } as MultiSourceInvestigation;
    const html = render(<MultiSourceResultView data={legacy} />);
    assert.ok(!html.includes('Case evidence (source-agnostic)') && !html.includes('Entity graph'));
  });

  it('shows the case evidence section when observations are present', () => {
    const d = { schema: 'multisource-v1', status: 'completed', use_llm: false, workflow_version: 'multi-source-v2', evidence_fingerprint: 'f'.repeat(64),
      counts: {}, sources: [], rejected: [], contradictions: [], batch_sufficiency: null, batch_report_markdown: null, incidents: [],
      observations: [obs({})], observation_counts: { total: 1, listed: 1, by_classification: { normalized: 1 }, undated: 0, analyst_statements: 0 },
      ledger: { head: 'b'.repeat(64), verified: true, steps: [] } } as MultiSourceInvestigation;
    assert.ok(render(<MultiSourceResultView data={d} />).includes('Case evidence (source-agnostic)'));
  });

  it('complies with the design constitution (no innerHTML, no emoji, no em dash, no pill buttons)', () => {
    const src = readFileSync(new URL('../src/components/DomainEvidencePanel.tsx', import.meta.url), 'utf8');
    assert.ok(!/dangerouslySetInnerHTML\s*=/.test(src));
    assert.ok(!/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(src));
    assert.ok(!src.replace(/^\s*\*.*$/gm, '').includes('—'));
    assert.ok(!/borderRadius:\s*'(9|[1-9][0-9])+px'/.test(src));
  });
});

const contradiction = (o: Partial<ContradictionView>): ContradictionView => ({
  kind: 'ordering', proposition: 'attachment_delivery_order', materiality: 'material', relation: 'anchor', affects_verdict: true,
  evidence_ids: ['e1', 'e2'], sources: ['mailgw-synthetic', 'dfir-collector-synthetic'],
  times: ['2026-11-05T08:00:00+00:00', '2026-11-05T07:00:00+00:00'], time_quality: ['valid', 'valid'], claims: ['delivery', 'artefact_earlier'],
  link_strength: 'specific', independence: 'independent', overlap_seconds: 3600, reliability: ['raw_observed', 'raw_observed'], explanation: null,
  resolution_hint: 'ARTEFACT_TIME_PROVENANCE', resolution_text: 'Obtain the creation and modification times of the artefact with their provenance.', ...o,
});

describe('Contradiction display (ADR-013)', () => {
  it('states that a material contradiction limits the verdict, shows both records and what would resolve it, and does not call it resolved', () => {
    const html = render(<ContradictionSection items={[contradiction({})]} />);
    assert.ok(html.includes('Conflicting evidence limits this verdict') && html.includes('role="alert"'));
    assert.ok(html.includes('mailgw-synthetic') && html.includes('dfir-collector-synthetic') && html.includes('delivery') && html.includes('artefact_earlier'));
    assert.ok(html.includes('Material: unresolved, affects the verdict') && html.includes('capped at LIMITED'));
    assert.ok(html.includes('reported, not resolved') && html.includes('Obtain the creation and modification times'));
    assert.ok(!/resolved by/.test(html));
  });

  it('shows a minor or time-zone-assumed contradiction as disclosed only, without the alert role', () => {
    const html = render(<ContradictionSection items={[contradiction({ materiality: 'minor', affects_verdict: false, explanation: 'timezone_assumed', time_quality: ['naive_assumed_utc', 'valid'] })]} />);
    assert.ok(html.includes('Conflicts were found and disclosed') && html.includes('Minor: disclosed only') && html.includes('time zone assumed'));
    assert.ok(html.includes('role="status"') && !html.includes('role="alert"') && !html.includes('capped at LIMITED'));
  });

  it('renders nothing when there is no contradiction, and escapes source names', () => {
    assert.strictEqual(render(<ContradictionSection items={[]} />), '');
    const html = render(<ContradictionSection items={[contradiction({ sources: ['<img src=x>', 'ok'] })]} />);
    assert.ok(!html.includes('<img src=x>') && html.includes('&lt;img src=x&gt;'));
  });

  it('adds a conflicting-evidence line to the verdict banner only when a contradiction reason code is present', () => {
    const base = { verdict: 'limited', rule_version: 'suff-v4', reasons: [], assessment_sha256: 'a'.repeat(64), abstain: false,
      counts: { events: 5, evidence_units: 5, relevant: 4, attested: 4, corroborating: 1 }, evidence_ids: [] } as const;
    const withC = renderToStaticMarkup(<VerdictBanner s={{ ...base, reason_codes: ['CONTRADICTORY_EVIDENCE:ordering'] } as never} />);
    const without = renderToStaticMarkup(<VerdictBanner s={{ ...base, reason_codes: ['UNCORROBORATED_QUESTION'] } as never} />);
    assert.ok(withC.includes('Conflicting evidence.') && withC.includes('has not been resolved'));
    assert.ok(!without.includes('Conflicting evidence.'));
  });

  it('keeps the incident view working for results stored before suff-v4 (no contradictions field)', () => {
    const src = readFileSync(new URL('../src/components/MultiSourcePanel.tsx', import.meta.url), 'utf8');
    assert.ok(/inc\.contradictions && inc\.contradictions\.length > 0/.test(src));
  });
});

describe('Contradiction display: identity, temporal, independence and tolerance (ADR-013 D1 to D5)', () => {
  it('labels identity and temporal contradictions in plain language', () => {
    const id = render(<ContradictionSection items={[contradiction({ kind: 'identity', proposition: 'session_principal', claims: ['principal_a', 'principal_b'], resolution_text: 'Obtain the identity directory record.' })]} />);
    const tm = render(<ContradictionSection items={[contradiction({ kind: 'temporal', proposition: 'event_time', claims: ['earlier_time', 'later_time'] })]} />);
    assert.ok(id.includes('one session attributed to two different canonical principals') && id.includes('Obtain the identity directory record.'));
    assert.ok(tm.includes('one event reported with incompatible event times'));
  });

  it('explains clock skew, same-source and unknown independence as disclosed only, never as a verdict cap', () => {
    const skew = render(<ContradictionSection items={[contradiction({ materiality: 'explained', affects_verdict: false, explanation: 'clock_skew_within_tolerance' })]} />);
    const same = render(<ContradictionSection items={[contradiction({ materiality: 'minor', affects_verdict: false, independence: 'same_source' })]} />);
    const unknown = render(<ContradictionSection items={[contradiction({ materiality: 'minor', affects_verdict: false, independence: 'unknown' })]} />);
    assert.ok(skew.includes('5-second clock-skew tolerance') && skew.includes('Explained: disclosed only'));
    assert.ok(same.includes('same source or the same upstream collection') && same.includes('not independent disagreement'));
    assert.ok(unknown.includes('could not be established, so it is not treated as independent'));
    for (const html of [skew, same, unknown]) assert.ok(!html.includes('capped at LIMITED') && !html.includes('role="alert"'));
  });
});
