/**
 * AISOP Phase 6.5 — SOC Dashboard & Navigation Interaction Test Suite.
 *
 * Verifies:
 * 1. Initial dashboard structure, headers, and loading telemetry state.
 * 2. 401 Authentication Required handling (explicit error banner, paused metrics, table prompt).
 * 3. 403 Forbidden handling (explicit permission message, paused metrics, table prompt).
 * 4. API Service Unavailable handling (failure message, unavailable metrics).
 * 5. Interactive case rows with keyboard navigation attributes (role="button", tabIndex=0, aria-label).
 * 6. Metric calculations when telemetry is populated.
 * 7. Navbar UI preview role disclaimer ("UI Preview Role - Does not change backend permissions").
 * 8. Cases component with initialOpenCreate modal trigger.
 * 9. Design Constitution compliance (zero emojis, zero em dashes, zero purple gradients).
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Dashboard } from '../src/pages/Dashboard';
import { Navbar } from '../src/components/Navbar';
import { Cases } from '../src/pages/Cases';
import { AuthProvider } from '../src/contexts/AuthContext';
import { CaseResponse, HealthResponse } from '../src/types';

// Helper to wrap components with AuthProvider
const renderWithAuth = (component: React.ReactElement): string => {
  return renderToStaticMarkup(<AuthProvider>{component}</AuthProvider>);
};

const mockHealth: HealthResponse = {
  status: 'ok',
  app: 'AISOP',
  version: '1.0.0',
  environment: 'development',
};

const mockCases: CaseResponse[] = [
  {
    id: 'case-uuid-001',
    case_number: 'CASE-2026-0042',
    title: 'Suspicious PowerShell Download Cradle on DC-01',
    description: 'High-severity detection involving encoded script execution.',
    severity: 'critical',
    status: 'open',
    lead_analyst_id: 'analyst-sec-01',
    created_at: '2026-10-31T10:00:00Z',
    updated_at: '2026-10-31T10:05:00Z',
    closed_at: null,
    closure_reason: null,
  },
  {
    id: 'case-uuid-002',
    case_number: 'CASE-2026-0043',
    title: 'Outbound Beaconing to Untrusted IP',
    description: 'Medium-severity Zeek network connection alert.',
    severity: 'medium',
    status: 'in_progress',
    lead_analyst_id: 'analyst-sec-02',
    created_at: '2026-10-31T11:00:00Z',
    updated_at: '2026-10-31T11:10:00Z',
    closed_at: null,
    closure_reason: null,
  },
  {
    id: 'case-uuid-003',
    case_number: 'CASE-2026-0044',
    title: 'Archived Incident for Verification',
    description: 'Closed case for testing.',
    severity: 'low',
    status: 'closed',
    lead_analyst_id: 'analyst-sec-01',
    created_at: '2026-10-30T09:00:00Z',
    updated_at: '2026-10-30T12:00:00Z',
    closed_at: '2026-10-30T12:00:00Z',
    closure_reason: 'Resolved false positive',
  },
];

describe('AISOP P6.5: Dashboard & Navbar Component Verification', () => {
  it('renders initial dashboard loading structure and subsystem health cards', () => {
    const html = renderWithAuth(
      <Dashboard
        onNavigate={() => {}}
        initialLoading={true}
      />
    );

    assert.ok(html.includes('Overview'), 'Overview header must be present');
    assert.ok(html.includes('New case'), 'Create incident button must be present');
    assert.ok(html.includes('Loading security telemetry...'), 'Loading placeholder must be present');
    assert.ok(!html.includes('Ollama Local Runtime'), 'Static LLM runtime claim must not be present');
    assert.ok(!html.includes('Evidence validation and AI guardrails'), 'Static guardrails claim must not be present');
    assert.ok(html.includes('All cases'), 'All cases button must be present');
  });

  it('renders explicit 401 authentication required banner and metric states', () => {
    const html = renderWithAuth(
      <Dashboard
        onNavigate={() => {}}
        initialLoading={false}
        initialCases={[]}
        initialErrorType="auth"
        initialErrorMessage="Authentication required. Configure your API key to load case data."
      />
    );

    assert.ok(
      html.includes('Authentication required. Configure your API key to load case data.'),
      '401 error message must be displayed in banner'
    );
    assert.ok(
      html.includes('Key needed'),
      'Card values must display Auth Required instead of zero'
    );
    assert.ok(
      html.includes('Case telemetry query paused'),
      'Card subtitle must indicate telemetry is paused'
    );
    assert.ok(
      html.includes('alert-info'),
      'Auth prompt must use alert-info styling per design rules'
    );
  });

  it('renders explicit 403 access forbidden banner and metric states', () => {
    const html = renderWithAuth(
      <Dashboard
        onNavigate={() => {}}
        initialLoading={false}
        initialCases={[]}
        initialErrorType="forbidden"
        initialErrorMessage="Access forbidden. Your role has insufficient privileges to view case telemetry."
      />
    );

    assert.ok(
      html.includes('Access forbidden. Your role has insufficient privileges to view case telemetry.'),
      '403 error message must be displayed in banner'
    );
    assert.ok(
      html.includes('Forbidden'),
      'Card values must display Forbidden'
    );
    assert.ok(
      html.includes('alert-error'),
      'Forbidden error must use alert-error styling'
    );
  });

  it('renders service unavailable banner when backend API fails', () => {
    const html = renderWithAuth(
      <Dashboard
        onNavigate={() => {}}
        initialLoading={false}
        initialCases={[]}
        initialErrorType="api"
        initialErrorMessage="Service unavailable. Failed to retrieve case telemetry from backend."
      />
    );

    assert.ok(
      html.includes('Service unavailable. Failed to retrieve case telemetry from backend.'),
      'Service unavailable message must be displayed'
    );
    assert.ok(
      html.includes('Unavailable'),
      'Card values must display Unavailable'
    );
  });

  it('renders loaded cases with interactive keyboard-accessible row attributes', () => {
    const html = renderWithAuth(
      <Dashboard
        onNavigate={() => {}}
        onNavigateToCase={() => {}}
        initialLoading={false}
        initialHealth={mockHealth}
        initialCases={mockCases}
        initialErrorType={null}
        initialErrorMessage={null}
      />
    );

    // Case table elements
    assert.ok(html.includes('CASE-2026-0042'), 'Case 0042 number must be rendered');
    assert.ok(html.includes('Suspicious PowerShell Download Cradle on DC-01'), 'Case 0042 title must be rendered');
    assert.ok(html.includes('CASE-2026-0043'), 'Case 0043 number must be rendered');

    // Accessibility and interaction attributes
    assert.ok(html.includes('role="button"'), 'Case rows must have role="button"');
    assert.ok(html.includes('tabindex="0"'), 'Case rows must have tabindex="0"');
    assert.ok(
      html.includes('aria-label="Open investigation for case CASE-2026-0042: Suspicious PowerShell Download Cradle on DC-01"'),
      'Case rows must have descriptive aria-label'
    );

    // Metric counts: 2 open cases (case-001 is open, case-002 is in_progress), 1 critical/high case (case-001 is critical)
    assert.ok(html.includes('>2</div>'), 'Active investigations count must be 2');
    assert.ok(html.includes('>1</div>'), 'High & Critical priority count must be 1');
  });

  it('renders Navbar with explicit UI Preview Role disclosure and role options', () => {
    const html = renderWithAuth(
      <Navbar currentTab="dashboard" onSelectTab={() => {}} />
    );

    assert.ok(
      html.includes('UI Preview Role - Does not change backend permissions'),
      'Navbar must disclose that UI preview role does not change backend permissions'
    );
    assert.ok(html.includes('value="security_admin"'), 'Security Admin option must exist');
    assert.ok(html.includes('value="analyst_tier_2"'), 'Tier-2 Analyst option must exist');
    assert.ok(html.includes('value="analyst_tier_1"'), 'Tier-1 Analyst option must exist');
    assert.ok(html.includes('value="auditor_viewer"'), 'Auditor option must exist');
  });

  it('renders Cases create incident modal when initialOpenCreate is true', () => {
    const html = renderWithAuth(
      <Cases initialOpenCreate={true} onClearInitialOpenCreate={() => {}} />
    );

    assert.ok(
      html.includes('New case'),
      'Create modal header must be rendered when initialOpenCreate is true'
    );
    assert.ok(
      html.includes('Title *'),
      'Title input label must be present'
    );
    assert.ok(
      html.includes('Severity Tier *'),
      'Severity selector label must be present'
    );
  });

  it('conforms strictly to AISOP Design Constitution (no em dashes, no purple gradients, no emojis)', () => {
    const dashboardHtml = renderWithAuth(
      <Dashboard
        onNavigate={() => {}}
        initialLoading={false}
        initialHealth={mockHealth}
        initialCases={mockCases}
      />
    );
    const navbarHtml = renderWithAuth(
      <Navbar currentTab="dashboard" onSelectTab={() => {}} />
    );

    const combinedHtml = dashboardHtml + navbarHtml;

    // Check for em dashes (\u2014 or &mdash; or actual —)
    assert.strictEqual(
      combinedHtml.includes('—'),
      false,
      'Rendered output must not contain em dashes'
    );
    assert.strictEqual(
      combinedHtml.includes('&mdash;'),
      false,
      'Rendered output must not contain &mdash; entities'
    );

    // Check for purple gradient patterns
    assert.strictEqual(
      combinedHtml.toLowerCase().includes('gradient'),
      false,
      'Rendered output must not contain gradients'
    );

    // Check for emojis
    const emojiRegex = /[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/u;
    assert.strictEqual(
      emojiRegex.test(combinedHtml),
      false,
      'Rendered output must not contain emojis'
    );
  });
});

