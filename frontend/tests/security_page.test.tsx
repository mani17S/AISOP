/**
 * Security page: what the server observed being done to it.
 *
 * Verifies the numbers and wording shown, that an empty page does not claim safety, that attacker-controlled text is escaped,
 * that the chart has a text equivalent, and that a refused role sees the server's reason instead of a blank screen.
 */
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Security, kindLabel } from '../src/pages/Security';
import { AuthProvider } from '../src/contexts/AuthContext';
import { SecurityOverview } from '../src/types';

const render = (el: React.ReactElement): string => renderToStaticMarkup(<AuthProvider>{el}</AuthProvider>);

const overview = (patch: Partial<SecurityOverview> = {}): SecurityOverview => ({
  window_hours: 24,
  window_start: '2026-11-22T10:00:00Z',
  window_end: '2026-11-22T13:30:00Z',
  total_events: 19,
  totals_by_kind: [
    { kind: 'unknown_path', count: 9 },
    { kind: 'auth_failed', count: 7 },
    { kind: 'auth_locked_out', count: 2 },
    { kind: 'method_not_allowed', count: 1 },
  ],
  timeline: [
    { hour: '2026-11-22T10:00:00Z', count: 0 },
    { hour: '2026-11-22T11:00:00Z', count: 4 },
    { hour: '2026-11-22T12:00:00Z', count: 15 },
    { hour: '2026-11-22T13:00:00Z', count: 0 },
  ],
  top_sources: [{ source_ip: '203.0.113.7', count: 17, kinds: [{ kind: 'unknown_path', count: 9 }, { kind: 'auth_failed', count: 8 }] }],
  top_paths: [{ kind: 'unknown_path', path: '/.env', count: 9 }],
  recent: [
    { time: '2026-11-22T12:05:00Z', kind: 'unknown_path', status_code: 404, method: 'GET', path: '/.env', source_ip: '203.0.113.7', user_agent: 'zgrab/0.x', count: 9 },
  ],
  rows_read: 5,
  truncated: false,
  not_recorded_since_start: 0,
  notes: ['This page shows what this server process observed. It does not prove that nothing else happened.'],
  ...patch,
});

describe('Security page', () => {
  it('shows the total, the plain-language kinds, the busiest source and the most requested path', () => {
    const html = render(<Security initialOverview={overview()} />);
    assert.match(html, />19</);
    assert.match(html, /suspicious requests in the window/);
    assert.match(html, /Probe of a path that does not exist/);
    assert.match(html, /Rejected API key/);
    assert.match(html, /Locked out after repeated bad keys/);
    assert.match(html, /203\.0\.113\.7/);
    assert.match(html, /\/\.env/);
    assert.match(html, /UTC/);
  });

  it('gives the chart a text equivalent naming the total, the peak hour and the zone', () => {
    const html = render(<Security initialOverview={overview()} />);
    assert.match(html, /role="img" aria-label="19 suspicious requests over 4 hours\. The busiest hour started 2026-11-22 12:00:00 UTC with 15\./);
    assert.match(html, /Show the hourly counts as a table/);
  });

  it('says what it cannot know, and never claims safety when nothing was recorded', () => {
    const html = render(<Security initialOverview={overview({ total_events: 0, totals_by_kind: [], top_sources: [], top_paths: [], recent: [] })} />);
    assert.match(html, /No suspicious requests were recorded in this window/);
    assert.match(html, /does not prove nothing else\s+happened/);
    assert.doesNotMatch(html, /\bsafe\b|\bsecure\b|all clear/i);
  });

  it('warns when the totals are a lower bound or events were not recorded', () => {
    const html = render(<Security initialOverview={overview({ truncated: true, not_recorded_since_start: 40 })} />);
    assert.match(html, /lower bound/);
    assert.match(html, /40 events were not recorded/);
  });

  it('escapes attacker-controlled text in paths, sources and client strings', () => {
    const hostile = '<script>alert(1)</script>';
    const html = render(
      <Security
        initialOverview={overview({
          top_paths: [{ kind: 'unknown_path', path: hostile, count: 1 }],
          recent: [{ time: '2026-11-22T12:05:00Z', kind: 'unknown_path', status_code: 404, method: 'GET', path: hostile, source_ip: hostile, user_agent: hostile, count: 1 }],
        })}
      />
    );
    assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
    assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  });

  it('shows the server\'s reason when the role is refused, instead of a blank page', () => {
    const html = render(<Security initialOverview={null} initialError="Security monitoring is limited to the security admin role." />);
    assert.match(html, /role="alert"/);
    assert.match(html, /limited to the security admin role/);
    assert.doesNotMatch(html, /suspicious requests in the window/);
  });

  it('labels every kind the server can send, and shows an unknown kind as received', () => {
    for (const k of ['auth_failed', 'auth_locked_out', 'rate_limited', 'forbidden', 'unknown_path', 'method_not_allowed', 'payload_too_large', 'unsupported_media_type', 'malformed_request']) {
      assert.notStrictEqual(kindLabel(k), k, k);
    }
    assert.strictEqual(kindLabel('something_new'), 'something_new');
  });

  it('follows the design constitution: no emoji, no em dash, sentence case headings', () => {
    const html = render(<Security initialOverview={overview()} />);
    assert.doesNotMatch(html, /—/);
    assert.doesNotMatch(html, /[\u{1F300}-\u{1FAFF}☀-➿]/u);
    assert.match(html, /<h1>Security<\/h1>/);
    assert.match(html, /How to read this page/);
  });
});
