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
  alerts: [],
  alerts_note: 'These alerts are about AISOP itself. They are separate from the Alerts page, which holds telemetry from your own sources.',
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

  it('shows platform security alerts with the severity written out, what happened, why it matters and what to do', () => {
    const html = render(
      <Security
        initialOverview={overview({
          alerts: [
            { id: 'a1', rule: 'key_used_after_guessing', severity: 'critical', title: 'A valid API key was used from 203.0.113.50, which had been guessing keys',
              what_happened: '6 rejected keys came from 203.0.113.50, and the key of dana was then accepted.', why_it_matters: 'This is the pattern of a stolen key.',
              recommended_action: 'Confirm with dana right away. If it was not them, revoke this key now.', subject: '203.0.113.50',
              first_seen: '2026-11-22T12:00:00Z', last_seen: '2026-11-22T12:30:00Z', count: 6 },
            { id: 'a2', rule: 'secret_probing', severity: 'medium', title: 'Probing for secrets and admin panels from 203.0.113.9',
              what_happened: '5 requests asked for environment files.', why_it_matters: 'Automated scanning.', recommended_action: 'Watch this address.',
              subject: '203.0.113.9', first_seen: '2026-11-22T11:00:00Z', last_seen: '2026-11-22T11:10:00Z', count: 1 },
          ],
        })}
      />
    );
    assert.match(html, /Platform security alerts/);
    assert.match(html, /Critical/);
    assert.match(html, /Medium/);
    assert.match(html, /What happened/);
    assert.match(html, /Why it matters/);
    assert.match(html, /What to do/);
    assert.match(html, /1 request\./, 'singular request count');
    assert.match(html, /6 requests\./);
    assert.ok(html.indexOf('guessing keys') < html.indexOf('Probing for secrets'), 'the serious alert is listed first');
  });

  it('says these alerts are separate from the telemetry alerts', () => {
    const html = render(<Security initialOverview={overview()} />);
    assert.match(html, /separate from the Alerts page/);
    assert.match(html, /telemetry from your own sources/);
  });

  it('shows an honest empty state for alerts', () => {
    const html = render(<Security initialOverview={overview()} />);
    assert.match(html, /No platform security alerts in this window/);
    assert.match(html, /does not prove nothing else happened/);
  });

  it('escapes hostile text inside an alert', () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const html = render(
      <Security
        initialOverview={overview({
          alerts: [{ id: 'a3', rule: 'key_guessing', severity: 'high', title: hostile, what_happened: hostile, why_it_matters: hostile, recommended_action: hostile,
            subject: hostile, first_seen: '2026-11-22T11:00:00Z', last_seen: '2026-11-22T11:10:00Z', count: 2 }],
        })}
      />
    );
    assert.doesNotMatch(html, /<img src=x/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  });
});
