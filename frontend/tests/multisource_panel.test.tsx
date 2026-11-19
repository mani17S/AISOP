/**
 * AISOP Stage 4 - Multi-Source Investigation Panel test suite (ADR-010).
 *
 * Verifies: verdicts cannot be mistaken for confirmed findings, reasons are shown, provenance and sources are shown,
 * claims are labelled by grounding, data-quality problems and stale evidence are visible, strict output escaping,
 * human-initiated start, and design-constitution compliance. Server-side rendering only (no network, no DOM).
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { VerificationNote } from '../src/components/VerificationNote';
import { ClaimVerificationNote, MultiSourcePanel, MultiSourceResultView, VerdictBanner } from '../src/components/MultiSourcePanel';
import { AuthProvider } from '../src/contexts/AuthContext';
import { ClaimVerification, ClaimVerificationOutcome, MultiSourceClaim, MultiSourceInvestigation, MultiSourceRationale, MultiSourceSufficiency } from '../src/types';

const suff = (verdict: 'sufficient' | 'limited' | 'insufficient', codes: string[] = []): MultiSourceSufficiency => ({
  verdict,
  rule_version: 'suff-v2',
  reason_codes: codes,
  reasons: codes.map((c) => ({ code: c, meaning: `meaning of ${c}` })),
  assessment_sha256: 'a'.repeat(64),
  abstain: verdict === 'insufficient',
  counts: { events: 3, evidence_units: 2, relevant: 2, attested: 2, corroborating: 0 },
  evidence_ids: [],
});

const data = (verdict: 'sufficient' | 'limited' | 'insufficient'): MultiSourceInvestigation => ({
  schema: 'multisource-v1',
  status: 'completed',
  created_at: '2026-11-12T10:00:00+00:00',
  use_llm: true,
  workflow_version: 'multi-source-v1',
  evidence_fingerprint: 'f'.repeat(64),
  counts: { incidents: 1 },
  sources: [{ source_type: 'windows_security', events: 3, distinct_raw_records: 3 }],
  rejected: [{ record_index: 4, reason: 'NO_ADAPTER', raw_sha256_prefix: 'abcdef123456' }],
  contradictions: [{ event_ids: ['e1', 'e2'], reason: 'OUTCOME_CONFLICT_WITHIN_2S' }],
  batch_sufficiency: null,
  batch_report_markdown: null,
  ledger: { head: 'b'.repeat(64), verified: true, steps: [] },
  incidents: [
    {
      incident_id: '11111111-2222-3333-4444-555555555555',
      severity: 'high',
      event_count: 3,
      first_seen: '2026-11-10T09:00:05+00:00',
      last_seen: '2026-11-10T09:02:40+00:00',
      hosts: ['ws-fin-07'],
      users: ['jdoe'],
      stages: ['credential-access'],
      escalated: false,
      link_counts: { strong: 1, specific: 2, weak: 5 },
      weakly_related: [],
      context_sha256: 'c'.repeat(64),
      sufficiency: suff(verdict, verdict === 'sufficient' ? [] : ['UNCORROBORATED_QUESTION']),
      timeline: [
        {
          position: 1, timestamp: '2026-11-10T09:00:05+00:00', source_type: 'windows_security', host: 'ws-fin-07', user: 'jdoe',
          title: '<script>alert(1)</script> Failed Logon', stage: 'credential-access', severity: 'high', outcome: 'failure',
          raw_sha256_prefix: '36c9fd2b3d5a', membership: 'weak_context', duplicates_collapsed: 2, event_id: 'e1', contradicts: ['e2'],
        },
      ],
      links: [{ strength: 'specific', clusters: [0, 1], entities: [['ip', '185.220.101.4']] }],
      weak_link_count: 5,
      mitre: [{
        technique_id: 'T1110', technique_name: 'Brute Force', tactics: ['credential-access'], rule_id: 'MAP-T1110-REPEATED-FAILED-LOGON',
        independent_evidence_count: 3, vendor_asserted: true, limitation: 'Cannot distinguish brute force from a misconfigured service.',
        evidence_event_ids: [],
      }],
      asserted_only: ['T1071'],
      llm_status: 'validated',
      llm: {
        decision: 'pass', is_valid: true, summary: 'Scripted summary.', grounding_score: 0.5,
        claims: [
          { claim_id: 'c1', text: 'Three failed logons occurred.', category: 'observed_fact', grounding: 'validated_reference', confidence: 0.9, supporting_event_ids: ['e1'] },
          { claim_id: 'c2', text: 'This may be a coordinated attack.', category: 'inference', grounding: 'analyst_review_required', confidence: 0.3, supporting_event_ids: ['e1'] },
          { claim_id: 'c3', text: 'A second host was compromised.', category: 'inference', grounding: 'unsupported', confidence: 0, supporting_event_ids: [] },
        ],
        uncertainty_and_data_gaps: ['EVIDENCE_SUFFICIENCY[suff-v2]=LIMITED: UNCORROBORATED_QUESTION'],
        violations: [],
      },
      report_markdown: '# Incident report\n<b>not html</b>',
    },
  ],
});

const render = (el: React.ReactElement) => renderToStaticMarkup(<AuthProvider>{el}</AuthProvider>);

describe('Multi-source panel', () => {
  it('shows LIMITED prominently with reasons and a not-confirmed warning', () => {
    const html = render(<MultiSourceResultView data={data('limited')} />);
    assert.ok(html.includes('Evidence sufficiency: LIMITED'));
    assert.ok(html.includes('NOT confirmed conclusions'));
    assert.ok(html.includes('UNCORROBORATED_QUESTION') && html.includes('meaning of UNCORROBORATED_QUESTION'));
    assert.ok(html.includes('role="status"'));
  });

  it('shows INSUFFICIENT as no conclusion and SUFFICIENT without the warning', () => {
    assert.ok(renderToStaticMarkup(<VerdictBanner s={suff('insufficient', ['NO_EVIDENCE'])} />).includes('No AI analysis was run and no conclusion is offered'));
    const ok = renderToStaticMarkup(<VerdictBanner s={suff('sufficient')} />);
    assert.ok(ok.includes('SUFFICIENT') && !ok.includes('NOT confirmed'));
  });

  it('shows sources, provenance prefixes, link strengths, ATT&CK rules with limitations and asserted-only techniques', () => {
    const html = render(<MultiSourceResultView data={data('limited')} />);
    assert.ok(html.includes('windows_security') && html.includes('36c9fd2b3d5a'));
    assert.ok(html.includes('Strong: 1, specific: 2, weak: 5') && html.includes('ip=185.220.101.4'));
    assert.ok(html.includes('MAP-T1110-REPEATED-FAILED-LOGON') && html.includes('misconfigured service'));
    assert.ok(html.includes('T1071') && html.includes('NOT derived by any rule'));
    assert.ok(html.includes('context, not corroboration') && html.includes('2 duplicate record(s) collapsed') && html.includes('Contradicted by another record'));
  });

  it('labels claims by grounding: only validated observed facts are evidence-supported', () => {
    const html = render(<MultiSourceResultView data={data('limited')} />);
    assert.ok(html.includes('Cited and text-screened (legacy grounding)</strong>: Three failed logons occurred.'));
    assert.ok(html.includes('Inference (analyst review required)</strong>: This may be a coordinated attack.'));
    assert.ok(html.includes('Unsupported (indeterminate)</strong>: A second host was compromised.'));
    assert.ok(html.includes('EVIDENCE_SUFFICIENCY[suff-v2]=LIMITED'));
  });

  it('lists data-quality problems and stale evidence', () => {
    const html = render(<MultiSourceResultView data={data('limited')} stale />);
    assert.ok(html.includes('NO_ADAPTER') && html.includes('OUTCOME_CONFLICT_WITHIN_2S'));
    assert.ok(html.includes('results below are out of date'));
  });

  it('escapes evidence and report text (no markup injection)', () => {
    const html = render(<MultiSourceResultView data={data('limited')} />);
    assert.ok(!html.includes('<script>alert(1)</script>') && html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    assert.ok(!html.includes('<b>not html</b>') && html.includes('&lt;b&gt;not html&lt;/b&gt;'));
  });

  it('is human-initiated: the empty state asks the analyst to start and no AI option is offered without the role', () => {
    const html = render(<MultiSourcePanel caseId="11111111-1111-1111-1111-111111111111" initialResult={null} />);
    assert.ok(html.includes('Start multi-source investigation'));
    assert.ok(html.includes('Nothing here executes a response or containment action'));
  });

  it('renders a re-run action when a result exists', () => {
    const html = render(<MultiSourcePanel caseId="11111111-1111-1111-1111-111111111111" initialResult={data('sufficient')} />);
    assert.ok(html.includes('Re-run multi-source investigation') && html.includes('Force a new run'));
  });

  it('discloses a truncated stored result instead of presenting it as complete', () => {
    const d = { ...data('limited'), truncation: { incidents_total: 40, incidents_listed: 25, rejected_total: 900, rejected_listed: 200, contradictions_total: 0, contradictions_listed: 0 } };
    const html = render(<MultiSourceResultView data={d} />);
    assert.ok(html.includes('Stored result is truncated') && html.includes('25 of 40 incidents') && html.includes('200 of 900 rejected records'));
    assert.ok(!render(<MultiSourceResultView data={data('limited')} />).includes('Stored result is truncated'));
  });

  it('shows new rejection reasons verbatim as codes, never as free text', () => {
    const d = data('limited');
    d.rejected = [{ record_index: 1, reason: 'TIMESTAMP_MISSING_OR_INVALID', raw_sha256_prefix: 'abc' }, { record_index: 2, reason: 'RECORD_TOO_DEEP', raw_sha256_prefix: '000' }];
    const html = render(<MultiSourceResultView data={d} />);
    assert.ok(html.includes('TIMESTAMP_MISSING_OR_INVALID') && html.includes('RECORD_TOO_DEEP'));
  });

  it('does not hide API failures as an empty state (source check of the load path)', () => {
    const src = readFileSync(new URL('../src/components/MultiSourcePanel.tsx', import.meta.url), 'utf8');
    // Phase 2.3: classified by the stable error kind, no longer by message text (behaviour is tested in dom_accessibility.test.tsx).
    assert.ok(/kind === 'not_found'/.test(src) && /setError\(msg\)/.test(src) && !/not found\/i\.test/.test(src));
  });

  it('does not describe an AI analysis skipped by the per-run limit as "not requested"', () => {
    const d = data('limited');
    d.incidents[0] = { ...d.incidents[0], llm: null, llm_status: 'skipped:llm_incident_limit' };
    const html = render(<MultiSourceResultView data={d} />);
    assert.ok(html.includes('per-run limit on AI analyses') && !html.includes('Not requested. Everything above'));
  });

  it('complies with the design constitution (no innerHTML, no emoji, no pill buttons)', () => {
    const src = readFileSync(new URL('../src/components/MultiSourcePanel.tsx', import.meta.url), 'utf8');
    assert.ok(!/dangerouslySetInnerHTML\s*=/.test(src));
    assert.ok(!/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(src));
    assert.ok(!/borderRadius:\s*'(9|[1-9][0-9])+px'/.test(src.replace(/borderRadius: '6px'/g, '')));
  });

  // ── Sprint 1: analyst-visible suff-v4 rationale (current record-level semantics only) ──────────────────────────────
  const U1 = '11111111-aaaa-bbbb-cccc-000000000001';
  const U2 = '22222222-aaaa-bbbb-cccc-000000000002';
  const U3 = '33333333-aaaa-bbbb-cccc-000000000003';
  const rationale = (over: Partial<MultiSourceRationale> = {}): MultiSourceRationale => ({
    schema: 'suff-rationale-v1',
    rule_version: 'suff-v4',
    completeness: 'complete',
    independence_notion: 'record_level',
    digest_check: 'format_only',
    entity_values: 'withheld',
    status: { verdict: 'sufficient', meaning: 'Under the current record-level rule at least one different evidence unit corroborates the anchor.', model_call_permitted: true, llm_status: 'not_requested', deterministic_report_available: true },
    anchor: { event_id: U1, status: 'used', pairwise_without_anchor: false },
    units: [
      { unit: U1, members: [U1, U3], attested_digest_format: true, relevant: true, role: 'anchor' },
      { unit: U2, members: [U2], attested_digest_format: true, relevant: true, role: 'corroborating' },
    ],
    collapsed: [{ into: U1, duplicate: U3, basis: ['same_content', 'near_duplicate_within_window'], direct: true }],
    corroboration: [{ kind: 'corroborating', unit_a: U2, unit_b: U1, shared_entities: [{ type: 'domain', strength: 'specific' }], tests: { different_observation_class: true } }],
    exclusions: [{ unit: U3, reason: 'weak_link_only' }],
    findings: [{ code: 'DUPLICATE_EVIDENCE_COLLAPSED', qualifier: null, effect: 'disclosure', evidence_ids: [U3] }],
    contradictions: [],
    truncated: { units: false },
    limitations: [
      'Distinct evidence units are distinct records under the current rule. They are not proof of independent sensors or sources.',
      "'Digest attested' means a stored digest is present and well formed. The record content is not re-hashed, so this is not authenticity.",
    ],
    ...over,
  });
  const withRationale = (r?: MultiSourceRationale, verdict: 'sufficient' | 'limited' | 'insufficient' = 'sufficient') => ({ ...suff(verdict), rationale: r });

  it('shows status, anchor, units, duplicate basis, pairs by type and strength, and findings', () => {
    const html = renderToStaticMarkup(<VerdictBanner s={withRationale(rationale())} />);
    assert.ok(html.includes('Why this result? Evidence sufficiency rationale') && html.includes('aria-label="Evidence sufficiency rationale"'));
    assert.ok(html.includes('An anchor event was selected and used.') && html.includes('11111111'));
    assert.ok(html.includes('Evidence units considered (2)') && html.includes('well formed') && html.includes('corroborating'));
    assert.ok(html.includes('same identity and content; same identity and entities within 2 seconds'));
    assert.ok(html.includes('Corroborating under the current rule') && html.includes('domain (specific)'));
    assert.ok(html.includes('Units not counted toward corroboration (1)') && html.includes('related only by host, user, internal address or process name'));
    assert.ok(html.includes('DUPLICATE_EVIDENCE_COLLAPSED'));
  });

  it('separates model-call eligibility from deterministic report availability', () => {
    const blocked = rationale({ status: { verdict: 'insufficient', meaning: 'The model call is blocked.', model_call_permitted: false, llm_status: 'abstained', deterministic_report_available: true } });
    const html = renderToStaticMarkup(<VerdictBanner s={withRationale(blocked, 'insufficient')} />);
    assert.ok(html.includes('Model call: blocked by the check') && html.includes('Deterministic report: available'));
    assert.ok(html.includes('The deterministic report is still produced.') && html.includes('No AI analysis was run and no conclusion is offered'));
    assert.ok(!html.includes('Deterministic report: not available'));
  });

  it('explains absent, dropped and missing anchors without implying an anchor was used', () => {
    const none = renderToStaticMarkup(<VerdictBanner s={withRationale(rationale({ anchor: { event_id: null, status: 'none', pairwise_without_anchor: true } }))} />);
    assert.ok(none.includes('No anchor event was supplied') && none.includes('any two attested, specifically linked evidence units') && !none.includes('was selected and used'));
    const dropped = renderToStaticMarkup(<VerdictBanner s={withRationale(rationale({ anchor: { event_id: U1, status: 'dropped_temporal_anomaly', pairwise_without_anchor: true } }))} />);
    assert.ok(dropped.includes('dropped') && !dropped.includes('was selected and used'));
    const absent = renderToStaticMarkup(<VerdictBanner s={withRationale(rationale({ anchor: { event_id: U1, status: 'absent_from_evidence', pairwise_without_anchor: true } }))} />);
    assert.ok(absent.includes('is not part of the evidence'));
  });

  it('has meaningful empty, partial and absent states', () => {
    assert.ok(renderToStaticMarkup(<VerdictBanner s={withRationale(undefined)} />).includes('Rationale not recorded for this run'));
    const partial = renderToStaticMarkup(<VerdictBanner s={withRationale(rationale({ completeness: 'partial', trace_error: 'RuntimeError' }))} />);
    assert.ok(partial.includes('partial') && partial.includes('The verdict above is unaffected') && partial.includes('RuntimeError'));
    const empty = renderToStaticMarkup(<VerdictBanner s={withRationale(rationale({ units: [], collapsed: [], corroboration: [], exclusions: [], findings: [] }))} />);
    assert.ok(empty.includes('No evidence units were evaluated.') && empty.includes('No records were collapsed.') && empty.includes('No pair of evidence units shared a qualifying entity.'));
    const cut = renderToStaticMarkup(<VerdictBanner s={withRationale(rationale({ truncated: { units: true, collapsed: true } }))} />);
    assert.ok(cut.includes('Some lists were shortened') && cut.includes('units, collapsed'));
  });

  it('never renders entity values, even if a response carried an extra value field', () => {
    const leaky = rationale({ corroboration: [{ kind: 'corroborating', unit_a: U2, unit_b: U1, tests: {}, shared_entities: [{ type: 'domain', strength: 'specific', value: 'c2.badcdn.example' } as never] }] });
    const html = renderToStaticMarkup(<VerdictBanner s={withRationale(leaky)} />);
    assert.ok(html.includes('domain (specific)') && !html.includes('c2.badcdn.example'));
    assert.ok(html.includes('Shared entity values are not shown to any role'));
  });

  it('no longer claims verified provenance, independent sensors or authenticity', () => {
    const html = render(<MultiSourceResultView data={data('sufficient')} />) + renderToStaticMarkup(<VerdictBanner s={withRationale(rationale())} />);
    const lower = html.toLowerCase();
    for (const bad of ['verified provenance', 'independently corroborating', 'cryptographic', 'authentic sensor', 'trusted sensor', 'verifiable']) {
      assert.ok(!lower.includes(bad), `forbidden wording present: ${bad}`);
    }
    assert.ok(html.includes('digest format checked') && html.includes('corroborating units (record-level rule)'));
    assert.ok(html.includes('not proof of independent sensors') && html.includes('this is not authenticity'));
    const src = readFileSync(new URL('../src/components/MultiSourcePanel.tsx', import.meta.url), 'utf8');
    assert.ok(!/verified provenance/i.test(src));
  });

  it('keeps the rationale keyboard operable and labelled (native disclosure, table caption and column scope)', () => {
    const html = renderToStaticMarkup(<VerdictBanner s={withRationale(rationale())} />);
    assert.ok(/<details[^>]*><summary[^>]*>Why this result\?/.test(html));
    assert.ok(html.includes('<caption') && html.includes('scope="col"'));
    assert.ok(!html.includes('tabindex="-1"') && !html.includes('onclick'));
  });
  it('shows claim verification as text, scoped to listed assertions, with legacy claims marked not machine-verifiable', () => {
    const base: MultiSourceClaim = { claim_id: 'c1', text: 'x', category: 'observed_fact', grounding: 'validated_reference', confidence: 0.5, supporting_event_ids: [] };
    const legacy = renderToStaticMarkup(<ClaimVerificationNote claim={base} />);
    assert.ok(legacy.includes('Not machine-checkable') && legacy.includes('not analyst-confirmed'));
    const verified = renderToStaticMarkup(
      <ClaimVerificationNote
        claim={{
          ...base,
          verification: {
            schema_version: 'claim-verification-v1', outcome: 'contradicted', reason: 'ASSERTION_CONTRADICTED', assertions_total: 2, assertions_evaluated: 2,
            assertions_truncated: false, applies_to: 'listed_assertions_only',
            results: [{ index: 0, kind: 'event_field', outcome: 'contradicted', reason: 'VALUE_DIFFERS', values_withheld: true }],
          },
        }}
      />,
    );
    assert.ok(verified.includes('Listed assertions contradicted by cited evidence') && verified.includes('listed assertion'));
    assert.ok(verified.includes('not the whole sentence') && verified.includes('Values withheld for privacy') && /<details/.test(verified));
    assert.ok(verified.includes('Why this result?') && !verified.includes('Expected '));
  });

  it('replaces the old Evidence-supported label with an accurate legacy-grounding label and renders verification for each AI claim', () => {
    const html = render(<MultiSourceResultView data={data('limited')} />);
    assert.ok(html.includes('Cited and text-screened (legacy grounding)</strong>: Three failed logons occurred.'));
    assert.ok(html.includes('Verification: Not machine-checkable'));
    assert.ok(!html.includes('Evidence-supported'), 'the ambiguous label must be gone');
    assert.ok(html.includes('not a check of the claim&#x27;s assertions and not analyst confirmation') || html.includes("not a check of the claim's assertions"));
  });

  it('presents each of the four outcomes in text with bounded wording, and escapes untrusted strings', () => {
    const mk = (outcome: ClaimVerificationOutcome, reason = 'R'): ClaimVerification => ({
      schema_version: 'claim-verification-v1', outcome, reason, assertions_total: 1, assertions_evaluated: 1, assertions_truncated: false,
      applies_to: 'listed_assertions_only', results: [{ index: 0, kind: 'event_field', outcome, reason, values_withheld: false, expected: 'a', observed: 'b' }],
    });
    const want: Record<string, string> = {
      supported: 'Listed assertions supported by cited evidence', contradicted: 'Listed assertions contradicted by cited evidence',
      insufficient_evidence: 'Insufficient evidence to check listed assertions', not_verifiable: 'Not machine-checkable',
    };
    for (const o of Object.keys(want) as ClaimVerificationOutcome[]) {
      const html = renderToStaticMarkup(<VerificationNote verification={mk(o)} />);
      assert.ok(html.includes(`Verification: ${want[o]}`) && html.includes('not the whole sentence') && html.includes('not analyst-confirmed'));
      assert.ok(!/confirmed (incident|attack)|verified attack|compromise/i.test(html));
    }
    const hostile = renderToStaticMarkup(<VerificationNote verification={mk('supported', '<img src=x onerror=alert(1)>')} />);
    assert.ok(!hostile.includes('<img') && hostile.includes('&lt;img'));
    assert.ok(renderToStaticMarkup(<VerificationNote unavailable />).includes('not included in this view'));
  });
  it('says plainly when AI assistance is disabled or unavailable and that the deterministic result is complete', () => {
    const base = data('limited');
    const withStatus = (llm_status: string): MultiSourceInvestigation => ({ ...base, incidents: base.incidents.map((i) => ({ ...i, llm_status })) });
    const off = render(<MultiSourceResultView data={withStatus('disabled')} />);
    assert.ok(off.includes('AI assistance is disabled by configuration') && off.includes('not AI output') && off.includes('complete and independent of AI'));
    const down = render(<MultiSourceResultView data={withStatus('fallback:LLMConnectionError')} />);
    assert.ok(down.includes('AI assistance was unavailable for this run') && !down.includes('disabled by configuration'));
    assert.ok(!render(<MultiSourceResultView data={withStatus('validated')} />).includes('AI assistance was unavailable'));
  });
});
