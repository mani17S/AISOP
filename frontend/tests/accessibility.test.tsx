/**
 * AISOP Phase 2: accessibility and interaction integrity.
 *
 * No DOM library is installed, so this suite covers (a) the pure focus-trap and tab-key logic, (b) ARIA structure in
 * server-rendered markup, (c) source guards (no native alert(), no hand-written modal wrappers, named close buttons)
 * and (d) computed WCAG contrast for the design tokens. Runtime behaviour (focus movement, Escape, inert background)
 * needs a real browser or a DOM test library and is NOT covered here.
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Dialog, trapTarget } from '../src/components/Dialog';
import { nextTabIndex, tabButtonId, tabPanelId } from '../src/components/tabs';
import { ReportViewer } from '../src/components/ReportViewer';
import { InvestigationReportBundle } from '../src/types';

const SRC = join(process.cwd(), 'src');

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? sourceFiles(join(dir, entry.name)) : /\.tsx?$/.test(entry.name) ? [join(dir, entry.name)] : [],
  );
}

// ── Contrast helpers (WCAG 2.1 relative luminance) ──────────────────────────
const luminance = (hex: string): number => {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((v) => (v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4))) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const contrast = (a: string, b: string): number => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
};
const css = readFileSync(join(SRC, 'styles', 'index.css'), 'utf8');
const token = (name: string): string => {
  const match = css.match(new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`));
  assert.ok(match, `token --${name} must be a 6-digit hex value`);
  return match![1]!;
};

describe('Phase 2: focus trap logic', () => {
  it('wraps Tab from the last control to the first and Shift+Tab from the first to the last', () => {
    assert.strictEqual(trapTarget(4, 3, false), 0);
    assert.strictEqual(trapTarget(4, 0, true), 3);
  });
  it('lets the browser handle Tab between interior controls', () => {
    assert.strictEqual(trapTarget(4, 1, false), null);
    assert.strictEqual(trapTarget(4, 2, true), null);
  });
  it('pulls focus into the dialog when it is outside or on the container', () => {
    assert.strictEqual(trapTarget(3, -1, false), 0);
    assert.strictEqual(trapTarget(3, -1, true), 2);
  });
  it('keeps focus on the container when there is nothing focusable', () => {
    assert.strictEqual(trapTarget(0, -1, false), -1);
  });
});

describe('Phase 2: tab keyboard logic', () => {
  it('moves with ArrowRight and ArrowLeft and wraps at both ends', () => {
    assert.strictEqual(nextTabIndex('ArrowRight', 0, 4), 1);
    assert.strictEqual(nextTabIndex('ArrowRight', 3, 4), 0);
    assert.strictEqual(nextTabIndex('ArrowLeft', 0, 4), 3);
    assert.strictEqual(nextTabIndex('ArrowLeft', 2, 4), 1);
  });
  it('supports Home and End and ignores other keys', () => {
    assert.strictEqual(nextTabIndex('Home', 2, 5), 0);
    assert.strictEqual(nextTabIndex('End', 1, 5), 4);
    assert.strictEqual(nextTabIndex('Enter', 1, 5), null);
    assert.strictEqual(nextTabIndex('ArrowRight', 0, 0), null);
  });
});

describe('Phase 2: Dialog markup', () => {
  it('renders a modal dialog with an accessible name and focus target', () => {
    const html = renderToStaticMarkup(
      <Dialog onClose={() => {}} labelledBy="t1" describedBy="d1">
        <h3 id="t1">Title</h3>
        <p id="d1">Body</p>
      </Dialog>,
    );
    assert.ok(html.includes('role="dialog"'));
    assert.ok(html.includes('aria-modal="true"'));
    assert.ok(html.includes('aria-labelledby="t1"'));
    assert.ok(html.includes('aria-describedby="d1"'));
    assert.ok(html.includes('tabindex="-1"'), 'container must be programmatically focusable');
    assert.ok(html.includes('class="modal-backdrop"'));
  });
  it('supports alertdialog and class/style passthrough', () => {
    const html = renderToStaticMarkup(
      <Dialog onClose={() => {}} labelledBy="t2" role="alertdialog" className="modal-dialog modal-dialog-large" style={{ maxWidth: '720px' }}>
        <h3 id="t2">Confirm</h3>
      </Dialog>,
    );
    assert.ok(html.includes('role="alertdialog"'));
    assert.ok(html.includes('modal-dialog-large'));
    assert.ok(html.includes('max-width:720px'));
  });
});

const baseBundle = (): InvestigationReportBundle =>
  ({
    bundle_id: 'b',
    case_id: 'c',
    generated_at_utc: '2026-01-01T00:00:00Z',
    context_sha256: 'a'.repeat(64),
    is_fallback_active: false,
    provenance: { is_verified_investigation: true, overall_grounding_score: 1, model_identifier: 'm' },
    executive_brief: { title: 'T', incident_severity: 'low', executive_summary: 's', severity_justification: 's', business_risk_statement: 's', affected_assets: [], recommended_immediate_actions: [], leadership_decisions_required: [] },
    technical_report: { investigation_timeline: [], confirmed_findings: [], hypotheses_and_inferences: [], unsupported_or_contradicted_claims: [], mitre_attack_mappings: [], investigation_gaps: [], recommended_analyst_actions: [], alternative_explanations: [], uncertainties_and_limitations: [] },
    detection_report: { validated_observables: [], hunting_queries: [], false_positive_considerations: [], mitre_coverage_targets: [] },
    markdown_executive: '', markdown_technical: '', markdown_detection: '',
  }) as unknown as InvestigationReportBundle;

describe('Phase 2: ReportViewer tab semantics', () => {
  it('renders tablist, tabs with selection state and a labelled tabpanel', () => {
    const html = renderToStaticMarkup(<ReportViewer bundle={baseBundle()} initialTab="technical" />);
    assert.ok(html.includes('role="tablist"'));
    assert.strictEqual((html.match(/role="tab"/g) ?? []).length, 4);
    assert.strictEqual((html.match(/aria-selected="true"/g) ?? []).length, 1);
    assert.strictEqual((html.match(/aria-selected="false"/g) ?? []).length, 3);
    assert.ok(html.includes(`id="${tabButtonId('rv', 'technical')}"`));
    assert.ok(html.includes(`aria-controls="${tabPanelId('rv')}"`));
    assert.ok(html.includes(`role="tabpanel" id="${tabPanelId('rv')}" aria-labelledby="${tabButtonId('rv', 'technical')}"`));
  });
  it('uses roving tabindex: only the selected tab is in the tab order', () => {
    const html = renderToStaticMarkup(<ReportViewer bundle={baseBundle()} initialTab="technical" />);
    const tabs = html.match(/<button[^>]*role="tab"[^>]*>/g) ?? [];
    assert.strictEqual(tabs.length, 4);
    assert.strictEqual(tabs.filter((t) => t.includes('tabindex="0"')).length, 1);
    assert.strictEqual(tabs.filter((t) => t.includes('tabindex="-1"')).length, 3);
    assert.ok(tabs.find((t) => t.includes('tabindex="0"'))!.includes(tabButtonId('rv', 'technical')));
  });
});

describe('Phase 2: source guards', () => {
  const files = sourceFiles(SRC);
  it('has no native alert() or window.alert() calls', () => {
    const offenders = files.filter((f) => /(^|[^.\w])(window\.)?alert\(/m.test(readFileSync(f, 'utf8')));
    assert.deepStrictEqual(offenders, []);
  });
  it('builds modals only through the shared Dialog (no hand-written backdrop)', () => {
    const offenders = files
      .filter((f) => !f.endsWith('Dialog.tsx'))
      .filter((f) => readFileSync(f, 'utf8').includes('className="modal-backdrop"'));
    assert.deepStrictEqual(offenders, []);
  });
  it('gives every close glyph button an accessible name', () => {
    for (const f of files) {
      const text = readFileSync(f, 'utf8');
      for (const match of text.matchAll(/<button[^>]*>\s*✕\s*<\/button>/g)) {
        assert.ok(match[0].includes('aria-label='), `${f}: close button without aria-label`);
      }
    }
  });
  it('gives every Dialog use an accessible name reference that exists in the same file', () => {
    for (const f of files.filter((p) => !p.endsWith('Dialog.tsx'))) {
      const text = readFileSync(f, 'utf8');
      for (const match of text.matchAll(/labelledBy="([^"]+)"/g)) {
        assert.ok(text.includes(`id="${match[1]}"`), `${f}: no element with id ${match[1]}`);
      }
    }
  });
});

describe('Phase 2: computed contrast of design tokens (WCAG AA)', () => {
  const surfaces = ['bg-primary', 'bg-secondary', 'bg-card', 'bg-hover', 'bg-input'].map((n) => [n, token(n)] as const);
  it('muted text is at least 4.5:1 on every surface (was 2.69:1 on card)', () => {
    for (const [name, hex] of surfaces) {
      assert.ok(contrast(token('text-muted'), hex) >= 4.5, `text-muted on ${name}: ${contrast(token('text-muted'), hex).toFixed(2)}`);
    }
  });
  it('secondary and accent text are at least 4.5:1 on every surface', () => {
    for (const [name, hex] of surfaces) {
      assert.ok(contrast(token('text-secondary'), hex) >= 4.5, `text-secondary on ${name}`);
      assert.ok(contrast(token('accent-text'), hex) >= 4.5, `accent-text on ${name}`);
    }
  });
  it('primary action fill carries white text at 4.5:1 or more, default and hover (was 3.68:1)', () => {
    assert.ok(contrast('#ffffff', token('accent-action')) >= 4.5);
    assert.ok(contrast('#ffffff', token('accent-action-hover')) >= 4.5);
  });
  it('danger button text and hover fill meet 4.5:1', () => {
    for (const [name, hex] of surfaces) assert.ok(contrast(token('severity-critical-text'), hex) >= 4.5, `severity-critical-text on ${name}`);
    assert.ok(contrast('#ffffff', '#dc2626') >= 4.5);
  });
  it('focus ring meets 3:1 against every surface', () => {
    for (const [name, hex] of surfaces) {
      assert.ok(contrast(token('focus-ring'), hex) >= 3, `focus-ring on ${name}`);
    }
  });
  it('records the two accessible text tones in the design constitution with matching values', () => {
    const constitution = readFileSync(join(process.cwd(), '..', 'docs', '08_Frontend', 'AISOP_Website_Design_Constitution.md'), 'utf8');
    assert.ok(constitution.includes('`--accent-text` | `' + token('accent-text')));
    assert.ok(constitution.includes('`--severity-critical-text` | `' + token('severity-critical-text')));
  });
  it('declares a visible focus style and a reduced-motion rule', () => {
    assert.ok(/:focus-visible\s*\{[^}]*outline:\s*2px solid var\(--focus-ring\)/.test(css));
    assert.ok(css.includes('@media (prefers-reduced-motion: reduce)'));
    assert.ok(!/\.(input-field|select-input):focus\s*\{[^}]*outline:\s*none/.test(css), 'focus outline must not be removed');
  });
});

describe('Phase 2.2: muted-text and action tokens (constitution A2) and 12px policy (A3)', () => {
  const constitution = readFileSync(join(process.cwd(), '..', 'docs', '08_Frontend', 'AISOP_Website_Design_Constitution.md'), 'utf8');
  const approvedSurfaces = ['bg-primary', 'bg-secondary', 'bg-card', 'bg-input'].map((n) => [n, token(n)] as const);

  it('records --text-muted and --accent-action in the constitution with the stylesheet values', () => {
    assert.ok(constitution.includes('`--text-muted` | `' + token('text-muted') + '`'));
    assert.ok(constitution.includes('`--accent-action` (hover `--accent-action-hover`) | `' + token('accent-action') + '` (hover `' + token('accent-action-hover') + '`)'));
    assert.ok(constitution.includes('Amendment A2') && constitution.includes('Amendment A3'));
  });
  it('muted text meets 4.5:1 on every approved surface and on the hover surface', () => {
    for (const [name, hex] of [...approvedSurfaces, ['bg-hover', token('bg-hover')] as const]) {
      assert.ok(contrast(token('text-muted'), hex) >= 4.5, `text-muted on ${name}`);
    }
  });
  it('action fill: white label 4.5:1 (default and hover); fill boundary 3:1 on the approved surfaces only', () => {
    assert.ok(contrast('#ffffff', token('accent-action')) >= 4.5);
    assert.ok(contrast('#ffffff', token('accent-action-hover')) >= 4.5);
    for (const [name, hex] of approvedSurfaces) {
      assert.ok(contrast(token('accent-action'), hex) >= 3, `accent-action boundary on ${name}`);
    }
    // The documented limits are real: the approval must not be widened silently.
    assert.ok(contrast(token('accent-action'), token('bg-hover')) < 3, 'documented as not meeting 3:1 on bg-hover');
    assert.ok(contrast(token('accent-action'), token('bg-card')) < 4.5, 'documented as unusable as text');
  });
  it('no muted-text rule or inline style is below 12px except documented technical identifiers', () => {
    const offenders: string[] = [];
    for (const m of css.matchAll(/(^|\n)([^{}\n]+)\{([^{}]*)\}/g)) {
      const body = m[3]!;
      const size = body.match(/font-size:\s*(\d+)px/);
      if (size && Number(size[1]) < 12 && /color:\s*var\(--text-muted\)/.test(body) && m[2]!.trim() !== '.claim-provenance') {
        offenders.push(`css ${m[2]!.trim()}`);
      }
    }
    for (const file of sourceFiles(SRC).filter((f) => f.endsWith('.tsx'))) {
      readFileSync(file, 'utf8').split(/\r?\n/).forEach((line, i) => {
        if (/fontSize:\s*'1[01]px'/.test(line) && line.includes("var(--text-muted)") && !line.includes('className="font-mono"')) {
          offenders.push(`${file}:${i + 1}`);
        }
      });
    }
    assert.deepStrictEqual(offenders, []);
  });
});