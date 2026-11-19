/**
 * AISOP Phase 6.6 — Evidence & Telemetry Component Verification Test Suite.
 *
 * Verifies:
 * 1. Initial loading state rendering without unhandled exceptions.
 * 2. Graceful rendering of sanitized events (event_timestamp, undefined entities) without blank screens.
 * 3. Graceful rendering of events with populated entities array.
 * 4. Resilient handling of malformed or missing timestamps (no RangeError).
 * 5. Explicit error state and retry prompt on API failure.
 * 6. Empty state rendering when zero events match.
 * 7. Design Constitution compliance (zero emojis, zero em dashes, zero purple gradients).
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Evidence } from '../src/pages/Evidence';
import { AuthProvider } from '../src/contexts/AuthContext';
import { NormalizedEventSummary } from '../src/types';

const renderWithAuth = (component: React.ReactElement): string => {
  return renderToStaticMarkup(<AuthProvider>{component}</AuthProvider>);
};

const mockSanitizedEvent: NormalizedEventSummary = {
  id: '7924078a-7027-425a-bd5a-622633e541b4',
  event_id: 'ldt:a98bf234e101:549102',
  event_type: 'alert.malware',
  event_timestamp: '2026-10-31T09:35:10.512300Z',
  provider: 'CrowdStrike Falcon',
  action: 'alert_triggered',
  outcome: 'success',
  severity: 'critical',
  source_type: 'edr_malware',
  source_identifier: 'cs-falcon-agent',
};

const mockEventWithEntities: NormalizedEventSummary = {
  id: 'uuid-evt-002',
  event_id: 'sysmon:proc:102',
  event_type: 'process_creation',
  observed_timestamp: '2026-10-31T09:40:00Z',
  provider: 'Sysmon',
  action: 'process_create',
  outcome: 'success',
  severity: 'high',
  source_type: 'sysmon',
  source_identifier: 'WIN-SRV-01',
  summary: 'powershell.exe spawned suspicious process',
  primary_subject: 'powershell.exe',
  entities: [
    { id: 'ent-1', entity_type: 'file_name', entity_value: 'beacon.exe', role: 'target' },
    { id: 'ent-2', entity_type: 'ip_address', entity_value: '198.51.100.24', role: 'destination' },
    { id: 'ent-3', entity_type: 'command_line', entity_value: 'powershell.exe -enc AAAA', role: 'command' },
    { id: 'ent-4', entity_type: 'hash_sha256', entity_value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', role: 'hash' },
  ],
};

const mockMalformedTimestampEvent: NormalizedEventSummary = {
  id: 'uuid-evt-003',
  event_id: 'sysmon:net:103',
  event_type: 'network_connection',
  event_timestamp: 'INVALID_TIMESTAMP_STRING',
  severity: 'medium',
};

describe('AISOP Phase 6.6: Evidence & Telemetry Page Verification', () => {
  it('renders initial loading state without crashing', () => {
    const html = renderWithAuth(<Evidence initialLoading={true} initialEvents={[]} />);
    assert.ok(html.includes('Evidence Explorer'), 'Page title must render');
    assert.ok(html.includes('Querying telemetry database...'), 'Loading indicator must render');
  });

  it('renders sanitized backend events (undefined entities, event_timestamp) without throwing or blanking', () => {
    const html = renderWithAuth(
      <Evidence initialEvents={[mockSanitizedEvent]} initialTotal={1} initialLoading={false} />
    );
    assert.ok(html.includes('Normalized Events (1)'), 'Total count must render');
    assert.ok(html.includes('2026-10-31 09:35:10'), 'Timestamp must format correctly');
    assert.ok(html.includes('alert.malware'), 'Event type badge must render');
    assert.ok(html.includes('CrowdStrike Falcon'), 'Provider must render');
    assert.ok(html.includes('cs-falcon-agent'), 'Source identifier must render');
    assert.ok(html.includes('badge-critical'), 'Severity badge must render');
    assert.ok(html.includes('alert_triggered'), 'Action must render');
  });

  it('renders events with populated entities array correctly with overflow badge', () => {
    const html = renderWithAuth(
      <Evidence initialEvents={[mockEventWithEntities]} initialTotal={1} initialLoading={false} />
    );
    assert.ok(html.includes('beacon.exe'), 'Entity value must render');
    assert.ok(html.includes('198.51.100.24'), 'Entity value must render');
    assert.ok(html.includes('+1 more'), 'Overflow indicator must render for >3 entities');
  });

  it('handles malformed or missing timestamps gracefully without throwing RangeError', () => {
    const html = renderWithAuth(
      <Evidence initialEvents={[mockMalformedTimestampEvent]} initialTotal={1} initialLoading={false} />
    );
    assert.ok(html.includes('INVALID_TIMESTAMP_STRING') || html.includes('N/A'), 'Fallback time displayed');
    assert.ok(html.includes('network_connection'), 'Event type renders safely');
  });

  it('renders explicit error notification and retry button when API fails', () => {
    const html = renderWithAuth(
      <Evidence
        initialEvents={[]}
        initialTotal={0}
        initialLoading={false}
        initialError="Authentication required. Please provide a valid API key."
      />
    );
    assert.ok(html.includes('alert-error'), 'Error alert box must render');
    assert.ok(html.includes('Unable to Display Telemetry'), 'Error card heading must render');
    assert.ok(html.includes('Authentication required'), 'Specific error message must render');
    assert.ok(html.includes('Retry Query'), 'Retry button must render');
  });

  it('renders clean empty state when zero events match filters', () => {
    const html = renderWithAuth(
      <Evidence initialEvents={[]} initialTotal={0} initialLoading={false} />
    );
    assert.ok(html.includes('No telemetry events matching the selected filters.'), 'Empty state text must render');
  });

  it('conforms strictly to AISOP Design Constitution (zero emojis, zero em dashes, zero purple gradients)', () => {
    const html = renderWithAuth(
      <Evidence initialEvents={[mockSanitizedEvent, mockEventWithEntities]} initialTotal={2} initialLoading={false} />
    );
    // Design check: No em dashes (\u2014)
    assert.ok(!html.includes('—'), 'Prohibited em-dash must not be present');
    // Design check: No forbidden purple gradient (#8b5cf6, #7c3aed, #a855f7)
    assert.ok(!html.includes('#8b5cf6'), 'Prohibited purple gradient token must not be present');
    assert.ok(!html.includes('#7c3aed'), 'Prohibited purple gradient token must not be present');
    // Design check: No emojis
    const emojiRegex = /[\u{1F300}-\u{1FAFF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/u;
    assert.ok(!emojiRegex.test(html), 'Forbidden emojis must not be present in rendered UI');
  });
});
