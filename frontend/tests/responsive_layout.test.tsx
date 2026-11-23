/**
 * Responsive and touch rules found by scripts/ui_audit.mjs (2026-11-23), pinned so they cannot silently regress:
 * the three data tables stack into labelled cards on small screens, tap targets are 44px, and no text is under 12px.
 * These read the source and the stylesheet; the browser audit itself is the script.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = join(process.cwd(), 'src');
const read = (rel: string) => readFileSync(join(SRC, rel), 'utf8');
const css = read('styles/index.css');

/** The `<td ...>` openings inside the first table of a page, from the table-stack class to the closing tag. */
const cellsOfStackedTable = (file: string): string[] => {
  const src = read(file);
  const start = src.indexOf('table-stack');
  assert.ok(start > 0, `${file} must use the table-stack class`);
  const end = src.indexOf('</table>', start);
  return [...src.slice(start, end).matchAll(/<td\b[^>]*>/g)].map((m) => m[0]);
};

describe('stacked tables: every cell names itself', () => {
  for (const [file, minCells] of [['pages/Alerts.tsx', 8], ['pages/Evidence.tsx', 6], ['pages/Cases.tsx', 6]] as const) {
    it(`${file}: each of the ${minCells} cells has a data-label`, () => {
      const cells = cellsOfStackedTable(file);
      assert.ok(cells.length >= minCells, `expected at least ${minCells} cells, found ${cells.length}`);
      for (const cell of cells) assert.match(cell, /data-label="[^"]+"/, `${file}: ${cell}`);
    });
  }
});

describe('stylesheet rules from the browser audit', () => {
  it('stacks tables below 1024px, clears the fixed row height, keeps the header for screen readers', () => {
    assert.match(css, /@media \(max-width: 1023px\) \{\s*\.data-table\.table-stack \{[^}]*min-width: 0/);
    assert.match(css, /\.table-stack td \{[^}]*height: auto/);
    assert.match(css, /\.table-stack thead \{[^}]*clip: rect\(0 0 0 0\)/);
    assert.match(css, /\.table-stack td::before \{[^}]*content: attr\(data-label\)/);
  });
  it('navigation, controls and the landing button are 44px on touch and on tablets', () => {
    assert.match(css, /@media \(pointer: coarse\), \(max-width: 1023px\) \{\s*:root \{\s*--control-height: 44px;/);
    assert.match(css, /\.nav-item,\s*\.lp \.btn \{\s*min-height: 44px;/);
  });
  it('short links and the role-strip disclosure are full-size targets', () => {
    assert.match(css, /\.role-strip-details summary \{[^}]*min-height: 44px/);
    assert.match(css, /\.app-footer a,\s*\.legal-back \{\s*min-width: 44px/);
  });
  it('the observable chip and its type tag are not below 12px', () => {
    for (const selector of ['.observable-chip', '.observable-type-tag']) {
      for (const m of css.matchAll(new RegExp(`${selector.replace('.', '\\.')}\\s*\\{([^}]*)\\}`, 'g'))) {
        const size = m[1]!.match(/font-size:\s*(\d+)px/);
        if (size) assert.ok(Number(size[1]) >= 12, `${selector} is ${size[1]}px`);
      }
    }
  });
});

describe('the role strip does not repeat the account the header shows', () => {
  it('says "Your role" and keeps the account name out of the strip', () => {
    const strip = read('components/RoleStrip.tsx');
    assert.ok(strip.includes('Your role: <strong>'));
    assert.ok(!strip.includes('Signed in as'), 'the header owns the account name');
  });
});
