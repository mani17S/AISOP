/**
 * Case evidence-sufficiency badge.
 *
 * It presents only what the server stored. No verdict, an unknown value, or a missing field must read "Not assessed" and never
 * look like a verdict; each real verdict shows its own word and shape class.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';
import { VerdictBadge, mergeCaseVerdict } from '../src/components/VerdictBadge';
import type { CaseResponse } from '../src/types';

const render = (item: Record<string, unknown>) => renderToStaticMarkup(<VerdictBadge item={item as never} />);

describe('VerdictBadge', () => {
  it('shows Not assessed when nothing was stored', () => {
    for (const item of [{}, { sufficiency_verdict: null }, { sufficiency_verdict: undefined }]) {
      const html = render(item);
      assert.ok(html.includes('Not assessed'));
      assert.ok(html.includes('verdict-badge--none'));
    }
  });

  it('never turns an unknown value into a verdict', () => {
    const html = render({ sufficiency_verdict: 'definitive' });
    assert.ok(html.includes('Not assessed'));
    assert.ok(!html.includes('Sufficient'));
  });

  it('shows each stored verdict with its own word and shape class', () => {
    assert.ok(render({ sufficiency_verdict: 'sufficient' }).includes('verdict-badge--sufficient'));
    assert.ok(render({ sufficiency_verdict: 'limited' }).includes('verdict-badge--limited'));
    const insufficient = render({ sufficiency_verdict: 'insufficient' });
    assert.ok(insufficient.includes('verdict-badge--insufficient'));
    assert.ok(insufficient.includes('>Insufficient<'));
  });

  it('states rule version, assessment time, truncation and staleness in the tooltip', () => {
    const html = render({
      sufficiency_verdict: 'limited',
      sufficiency_rule_version: 'sufficiency-v1',
      sufficiency_assessed_at: '2026-11-21T19:37:26Z',
      sufficiency_incidents_truncated: true,
    });
    assert.ok(html.includes('Rule sufficiency-v1.'));
    assert.ok(html.includes('Assessed 2026-11-21 19:37 UTC.'));
    assert.ok(html.includes('Only the listed incidents are covered.'));
    assert.ok(html.includes('Evidence added since is not reflected.'));
  });

  it('shows visible partial text and an accessible explanation only when the incident list is truncated', () => {
    const partial = render({ sufficiency_verdict: 'limited', sufficiency_incidents_truncated: true });
    assert.ok(partial.includes('Limited (partial)'));
    assert.ok(partial.includes('verdict-glyph'));
    assert.ok(partial.includes('verdict-badge--limited'));
    assert.ok(/aria-label="[^"]*Covers only the incidents stored with the run/.test(partial));
    assert.ok(/title="[^"]*Covers only the incidents stored with the run/.test(partial));
    for (const flag of [false, null, undefined]) {
      const html = render({ sufficiency_verdict: 'limited', sufficiency_incidents_truncated: flag });
      assert.ok(!html.includes('(partial)'));
      assert.ok(!html.includes('Covers only the incidents'));
    }
    assert.ok(render({ sufficiency_incidents_truncated: true }).includes('Not assessed'));
    assert.ok(!render({ sufficiency_incidents_truncated: true }).includes('(partial)'));
  });

  it('survives a malformed time and hostile text', () => {
    const html = render({ sufficiency_verdict: 'sufficient', sufficiency_assessed_at: 'not a date', sufficiency_rule_version: '<img src=x onerror=alert(1)>' });
    assert.ok(!html.includes('<img'));
    assert.ok(!html.includes('Assessed'));
  });
});

describe('mergeCaseVerdict', () => {
  const prev = {
    id: 'c1', status: 'open', sufficiency_verdict: 'limited', sufficiency_rule_version: 'sufficiency-v1',
    sufficiency_assessed_at: '2026-11-21T19:37:26Z', sufficiency_incidents_truncated: true,
  } as unknown as CaseResponse;

  it('takes the new object when it carries a verdict', () => {
    const next = { id: 'c1', status: 'closed', sufficiency_verdict: 'sufficient', sufficiency_rule_version: 'v2', sufficiency_assessed_at: null, sufficiency_incidents_truncated: false } as unknown as CaseResponse;
    const out = mergeCaseVerdict(prev, next);
    assert.strictEqual(out.status, 'closed');
    assert.strictEqual(out.sufficiency_verdict, 'sufficient');
    assert.strictEqual(out.sufficiency_rule_version, 'v2');
    assert.strictEqual(out.sufficiency_incidents_truncated, false);
  });

  it('accepts a null verdict from the server as a real not assessed', () => {
    const next = { id: 'c1', status: 'closed', sufficiency_verdict: null, sufficiency_rule_version: null, sufficiency_assessed_at: null, sufficiency_incidents_truncated: null } as unknown as CaseResponse;
    const out = mergeCaseVerdict(prev, next);
    assert.strictEqual(out.sufficiency_verdict, null);
    assert.strictEqual(out.sufficiency_rule_version, null);
  });

  it('keeps the previous verdict fields when the new object lacks them, and takes the rest from the new object', () => {
    const next = { id: 'c1', status: 'closed' } as unknown as CaseResponse;
    const out = mergeCaseVerdict(prev, next);
    assert.strictEqual(out.status, 'closed');
    assert.strictEqual(out.sufficiency_verdict, 'limited');
    assert.strictEqual(out.sufficiency_rule_version, 'sufficiency-v1');
    assert.strictEqual(out.sufficiency_assessed_at, '2026-11-21T19:37:26Z');
    assert.strictEqual(out.sufficiency_incidents_truncated, true);
    assert.ok(!('sufficiency_verdict' in next), 'the input object is not mutated');
  });

  it('returns the new object when there is no previous one', () => {
    const next = { id: 'c1' } as unknown as CaseResponse;
    assert.strictEqual(mergeCaseVerdict(null, next), next);
  });
});

describe('verdict refresh wiring', () => {
  // MultiSourcePanel needs a live API and DOM events to start a run; the repository's tests render it statically, so the wiring is
  // checked from source: the panel calls the callback after each stored result, and the workspace refreshes in place.
  const panel = readFileSync(new URL('../src/components/MultiSourcePanel.tsx', import.meta.url), 'utf8');
  const workspace = readFileSync(new URL('../src/components/InvestigationWorkspace.tsx', import.meta.url), 'utf8');

  it('MultiSourcePanel calls the optional callback after a started run and after an AI run, never when absent', () => {
    assert.ok(panel.includes('onInvestigationChanged?: () => void'));
    assert.ok(/setResult\(data\);\s*setStale\(false\);\s*onInvestigationChanged\?\.\(\);/.test(panel));
    assert.ok(/setAiResult\(data\);\s*setStale\(false\);\s*onInvestigationChanged\?\.\(\);/.test(panel));
    assert.strictEqual(panel.match(/onInvestigationChanged\?\.\(\)/g)?.length, 2);
  });

  it('the workspace re-fetches the case in place on that callback and merges verdicts on replace', () => {
    assert.ok(workspace.includes('onInvestigationChanged={() => void fetchCaseDetail(true)}'));
    assert.ok(workspace.includes('setCaseDetail((prev) => mergeCaseVerdict(prev, updated))'));
    assert.ok(workspace.includes('setCaseDetail((prev) => mergeCaseVerdict(prev, data))'));
  });
});
