/**
 * AISOP Phase 4B — Investigation Workspace Component Test Suite.
 *
 * Verifies:
 * 1. Initial loading state rendering with case ID and back button.
 * 2. Header metadata rendering (Case number, Title, Severity, Status, Lead Analyst).
 * 3. Evidence Panel (Area B): case-scoped listing, payload inspection, zero raw leakage.
 * 4. Investigation Context & Observables (Area C): facts vs enrichment vs inferences.
 * 5. Human-Invoked AI Investigation (Area D): explicit trigger, offline fallback notice.
 * 6. Findings & Report (Area E): epistemic partitioning, MITRE ATT&CK, actions, gaps.
 * 7. Activity & Audit Trail: immutable history, actor attribution, event ordering.
 * 8. Strict XSS escaping across all dynamic fields.
 * 9. Design Constitution compliance (no emojis, no purple gradients, standard button radius).
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { InvestigationWorkspace } from '../src/components/InvestigationWorkspace';
import { AuthProvider } from '../src/contexts/AuthContext';
import {
  CaseResponse,
  CaseScopedEvidenceItem,
  CaseAuditEventItem,
  InvestigationValidationResult,
} from '../src/types';

// Helper to wrap components with AuthProvider for role context
const renderWithAuth = (component: React.ReactElement): string => {
  return renderToStaticMarkup(<AuthProvider>{component}</AuthProvider>);
};

const mockCase: CaseResponse = {
  id: '11111111-1111-1111-1111-111111111111',
  case_number: 'CASE-2026-0042',
  title: 'Suspicious PowerShell Download Cradle on DC-01',
  description: 'High-severity detection involving encoded script execution and C2 beaconing.',
  severity: 'high',
  status: 'open',
  lead_analyst_id: 'analyst-sec-01',
  created_at: '2026-10-31T10:00:00Z',
  updated_at: '2026-10-31T10:05:00Z',
  closed_at: null,
  closure_reason: null,
};

const mockEvidenceList: CaseScopedEvidenceItem[] = [
  {
    id: 'ev-11111111-1111-1111-1111-111111111111',
    event_id: 'ev-11111111-1111-1111-1111-111111111111',
    event_type: 'ProcessCreate',
    source_type: 'edr_malware',
    source_identifier: 'DC-01',
    severity: 'high',
    outcome: 'success',
    provider: 'CrowdStrike',
    action: 'powershell.exe -enc SQBFAFgA',
    primary_subject: 'SYSTEM',
    summary: 'Encoded PowerShell Execution',
    event_timestamp: '2026-10-31T09:55:00Z',
    linked_at: '2026-10-31T10:00:00Z',
    linked_by_analyst_id: 'analyst-sec-01',
    normalized_payload: {
      process: { name: 'powershell.exe', command_line: 'powershell.exe -enc SQBFAFgA' },
      host: { hostname: 'DC-01', ip: '10.0.1.10' },
      user: { username: 'SYSTEM' },
    },
  },
  {
    id: 'ev-22222222-2222-2222-2222-222222222222',
    event_id: 'ev-22222222-2222-2222-2222-222222222222',
    event_type: 'NetworkConnect',
    source_type: 'network_traffic',
    source_identifier: 'DC-01',
    severity: 'medium',
    outcome: 'success',
    provider: 'Zeek',
    action: 'TCP outbound 198.51.100.45:443',
    primary_subject: 'powershell.exe',
    summary: 'Outbound Connection to Suspicious IP',
    event_timestamp: '2026-10-31T09:56:00Z',
    linked_at: '2026-10-31T10:01:00Z',
    linked_by_analyst_id: 'analyst-sec-01',
    normalized_payload: {
      network: { destination_ip: '198.51.100.45', destination_port: 443, protocol: 'tcp' },
    },
  },
];

const mockValidationResult: InvestigationValidationResult = {
  decision: 'pass',
  is_valid: true,
  context_sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
  validated_at_utc: '2026-10-31T10:05:00Z',
  violations: [],
  output: {
    investigation_id: 'inv-99999999-9999-9999-9999-999999999999',
    generated_at: '2026-10-31T10:05:00Z',
    model_identifier: 'ollama/llama3.1:8b',
    investigation_summary: 'The host DC-01 was observed running an encoded PowerShell command communicating with C2 address 198.51.100.45.',
    overall_grounding_score: 0.94,
    claims: [
      {
        claim_id: 'claim-1',
        claim_text: 'powershell.exe executed with encoded command line on host DC-01.',
        category: 'observed_fact',
        grounding_status: 'validated_reference',
        confidence: 0.98,
        supporting_evidence_ids: ['ev-11111111-1111-1111-1111-111111111111'],
        references_exist: true,
        analyst_notes: null,
      },
      {
        claim_id: 'claim-2',
        claim_text: 'Outbound TCP connection established to 198.51.100.45:443.',
        category: 'observed_fact',
        grounding_status: 'validated_reference',
        confidence: 0.95,
        supporting_evidence_ids: ['ev-22222222-2222-2222-2222-222222222222'],
        references_exist: true,
        analyst_notes: null,
      },
      {
        claim_id: 'claim-3',
        claim_text: 'Threat actor may have performed credential dumping prior to cradle invocation.',
        category: 'hypothesis',
        grounding_status: 'unverified_inference',
        confidence: 0.50,
        supporting_evidence_ids: [],
        references_exist: false,
        analyst_notes: 'Analytical hypothesis; no LSASS access events in window.',
      },
    ],
    mitre_attack_hypotheses: [
      {
        technique_id: 'T1059.001',
        technique_name: 'PowerShell',
        tactics: ['Execution'],
        confidence: 0.95,
        reasoning: 'Direct match with PowerShell invocation.',
        supporting_event_uuids: ['ev-11111111-1111-1111-1111-111111111111'],
      },
      {
        technique_id: 'T1071.001',
        technique_name: 'Web Protocols',
        tactics: ['Command and Control'],
        confidence: 0.88,
        reasoning: 'Observed HTTPS egress to untrusted IP.',
        supporting_event_uuids: ['ev-22222222-2222-2222-2222-222222222222'],
      },
    ],
    alternative_explanations: ['Administrative maintenance script run by unauthorized engineer.'],
    recommended_analyst_actions: [
      'Isolate Host DC-01 from network segment.',
      'Block egress traffic to destination IP 198.51.100.45.',
    ],
    uncertainty_and_data_gaps: [
      'Missing Windows Event Log 4624/4625 for surrounding authentication context.',
      'Memory capture not yet collected.',
    ],
  },
};

const mockActivities: CaseAuditEventItem[] = [
  {
    id: 'act-001',
    case_id: '11111111-1111-1111-1111-111111111111',
    action: 'created',
    actor_username: 'analyst-sec-01',
    actor_analyst_id: 'analyst-sec-01',
    context_sha256: null,
    details: { title: 'Suspicious PowerShell Download Cradle on DC-01' },
    created_at: '2026-10-31T10:00:00Z',
  },
  {
    id: 'act-002',
    case_id: '11111111-1111-1111-1111-111111111111',
    action: 'evidence_linked',
    actor_username: 'analyst-sec-01',
    actor_analyst_id: 'analyst-sec-01',
    context_sha256: null,
    details: { evidence_id: 'ev-11111111-1111-1111-1111-111111111111', event_type: 'edr_malware' },
    created_at: '2026-10-31T10:00:05Z',
  },
  {
    id: 'act-003',
    case_id: '11111111-1111-1111-1111-111111111111',
    action: 'investigation_synthesized',
    actor_username: 'analyst-sec-01',
    actor_analyst_id: 'analyst-sec-01',
    context_sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
    details: { decision: 'pass', grounding_score: 0.94 },
    created_at: '2026-10-31T10:05:00Z',
  },
];

describe('AISOP Phase 4B: Investigation Workspace Component Verification', () => {
  it('renders initial loading state with case ID and back button', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId="test-case-uuid-42"
        onBackToQueue={() => {}}
      />
    );

    assert.ok(html.includes('Back to Cases'), 'Back button must be rendered');
    assert.ok(html.includes('Loading investigation workspace for case test-case-uuid-42...'), 'Loading text must contain case ID');
  });

  it('renders Case Overview metadata correctly (Area A)', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={mockCase.id}
        initialCaseDetail={mockCase}
        onBackToQueue={() => {}}
        onNavigateToReport={() => {}}
      />
    );

    assert.ok(html.includes('CASE-2026-0042'), 'Case number must be rendered');
    assert.ok(html.includes('Suspicious PowerShell Download Cradle on DC-01'), 'Title must be rendered');
    assert.ok(html.includes('badge-high'), 'Severity badge class must be rendered');
    assert.ok(html.includes('badge-open'), 'Status badge class must be rendered');
    assert.ok(html.includes('analyst-sec-01'), 'Lead analyst ID must be rendered');
    assert.ok(html.includes('View Full Report Bundle'), 'Report navigation button must be rendered');
    assert.ok(html.includes('Close Case'), 'Close case button must be rendered');
  });

  it('renders Evidence Panel with case-scoped evidence and zero raw-payload leakage (Area B)', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={mockCase.id}
        initialCaseDetail={mockCase}
        initialEvidence={mockEvidenceList}
        initialTab="evidence"
        onBackToQueue={() => {}}
      />
    );

    assert.ok(html.includes('Link Evidence by UUID'), 'Link evidence action must be present');
    assert.ok(html.includes('powershell.exe -enc SQBFAFgA'), 'First evidence action/summary must be rendered');
    assert.ok(html.includes('TCP outbound 198.51.100.45:443'), 'Second evidence action/summary must be rendered');
    assert.ok(html.includes('ProcessCreate'), 'Event type must be rendered');
    assert.ok(html.includes('NetworkConnect'), 'Event type must be rendered');
    // Backend contract: CaseScopedEvidenceItem.event_timestamp. A rename here once rendered every row as N/A.
    assert.ok(html.includes('2026-10-31 09:55:00 UTC'), 'Evidence timestamp must be rendered from event_timestamp');

    // Verify zero raw-payload leakage
    assert.strictEqual(html.includes('raw_payload'), false, 'Raw payload keys must never be exposed');
    assert.strictEqual(html.includes('RawPayload'), false, 'Raw payload references must never be exposed');
  });

  it('renders Investigation Context distinguishing observed facts from enrichment (Area C)', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={mockCase.id}
        initialCaseDetail={mockCase}
        initialEvidence={mockEvidenceList}
        initialTab="context"
        onBackToQueue={() => {}}
      />
    );

    assert.ok(html.includes('Extracted Observables from Case Telemetry'), 'Section title must be present');
    assert.ok(html.includes('Observed Evidence'), 'Observed facts badge must be present');
    assert.ok(html.includes('Enrichment Context'), 'Enrichment context badge must be present');
    assert.ok(html.includes('AI Interpretations'), 'AI interpretations badge must be present');
    assert.ok(html.includes('HOST: DC-01'), 'Observed host observable must be present');
    assert.ok(html.includes('TYPE: ProcessCreate'), 'Observed event type observable must be present');
  });

  it('renders Human-Invoked AI Investigation trigger and offline disclaimer (Area D)', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={mockCase.id}
        initialCaseDetail={mockCase}
        initialTab="findings"
        onBackToQueue={() => {}}
      />
    );

    assert.ok(html.includes('Human-in-the-Loop Investigation Synthesis'), 'Synthesis section must be present');
    assert.ok(html.includes('Start AI Investigation'), 'Explicit human action button must be present');
    assert.ok(html.includes('AISOP does not run autonomous background investigations'), 'Anti-autonomous notice must be present');
    assert.ok(html.includes('Zero External Egress: Synthesis runs via local Ollama daemon or a deterministic offline provider'), 'Offline disclaimer must be present');
  });

  it('shows backend-supplied claim verification, marks legacy claims, and never labels a claim analyst-confirmed', () => {
    const withV: InvestigationValidationResult = {
      ...mockValidationResult,
      output: {
        ...mockValidationResult.output,
        claims: mockValidationResult.output.claims.map((c, i) =>
          i === 0
            ? {
                ...c,
                verification: {
                  schema_version: 'claim-verification-v1', outcome: 'contradicted', reason: 'ASSERTION_CONTRADICTED_BY_CITED_EVIDENCE',
                  assertions_total: 1, assertions_evaluated: 1, assertions_truncated: false, applies_to: 'listed_assertions_only',
                  results: [{ index: 0, kind: 'event_field', outcome: 'contradicted', reason: 'FIELD_DIFFERS_FROM_ASSERTED_VALUE', values_withheld: true }],
                },
              }
            : c,
        ),
      },
    };
    const html = renderWithAuth(
      <InvestigationWorkspace caseId={mockCase.id} initialCaseDetail={mockCase} initialValidationResult={withV} initialTab="findings" onBackToQueue={() => {}} onNavigateToReport={() => {}} />,
    );
    assert.ok(html.includes('Listed assertions contradicted by cited evidence') && html.includes('Why this result?'));
    assert.ok(html.includes('Verification: Not machine-checkable'), 'claims without verification are shown as legacy, not failed or supported');
    assert.ok(html.includes('Legacy grounding: validated_reference') && html.includes('OBSERVED FACT (AI-STATED)'));
    assert.ok(!/analyst-confirmed finding|Evidence-supported/.test(html));
  });

  it('renders Epistemically Partitioned Findings with MITRE ATT&CK and actions (Area E)', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={mockCase.id}
        initialCaseDetail={mockCase}
        initialValidationResult={mockValidationResult}
        initialTab="findings"
        onBackToQueue={() => {}}
        onNavigateToReport={() => {}}
      />
    );

    // Grounding header & badges
    assert.ok(html.includes('Claims validated:'), 'Claims validated label must be displayed');
    assert.ok(html.includes('Model-reported confidence:'), 'Claim confidence must be labelled model-reported');
    assert.ok(html.includes('94%'), 'Grounding score percentage must be displayed');
    assert.ok(html.includes('Server-Validated Output (guardrails passed)') && !html.includes('Server-Verified'), 'Validation status badge must be displayed without claiming verification');

    // Epistemic partitioning
    assert.ok(html.includes('Factual Claims &amp; Hypotheses (3)'), 'Claims partition header must be rendered');
    assert.ok(html.includes('OBSERVED FACT'), 'Observed fact badge must be rendered');
    assert.ok(html.includes('INFERENCE'), 'Inference badge must be rendered');

    // Claims content
    assert.ok(html.includes('powershell.exe executed with encoded command line'), 'Validated claim must be rendered');
    assert.ok(html.includes('Outbound TCP connection established to 198.51.100.45:443'), 'Validated claim must be rendered');
    assert.ok(html.includes('Threat actor may have performed credential dumping'), 'Hypothesis claim must be rendered');

    // MITRE ATT&CK section
    assert.ok(html.includes('MITRE ATT&amp;CK Hypotheses (2)'), 'MITRE ATT&CK section header must be rendered');
    assert.ok(html.includes('T1059.001'), 'Technique ID must be rendered');
    assert.ok(html.includes('PowerShell'), 'Technique name must be rendered');
    assert.ok(html.includes('T1071.001'), 'C2 technique ID must be rendered');
    assert.ok(html.includes('Web Protocols'), 'C2 technique name must be rendered');

    // Recommended Actions
    assert.ok(html.includes('Recommended Non-Destructive Actions'), 'Actions section header must be rendered');
    assert.ok(html.includes('Isolate Host DC-01 from network segment.'), 'Action 1 must be rendered');
    assert.ok(html.includes('Block egress traffic to destination IP 198.51.100.45.'), 'Action 2 must be rendered');

    // Data gaps
    assert.ok(html.includes('Uncertainties &amp; Telemetry Gaps'), 'Data gaps section header must be rendered');
    assert.ok(html.includes('Missing Windows Event Log 4624/4625'), 'Data gap item must be rendered');
  });

  it('renders Activity & Audit trail with immutable event ordering (Area F)', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={mockCase.id}
        initialCaseDetail={mockCase}
        initialActivity={mockActivities}
        initialTab="activity"
        onBackToQueue={() => {}}
      />
    );

    assert.ok(html.includes('Cryptographic Audit Invariant:'), 'Audit invariant note must be rendered');
    assert.ok(html.includes('created'), 'Action created must be rendered');
    assert.ok(html.includes('evidence_linked'), 'Action evidence_linked must be rendered');
    assert.ok(html.includes('investigation_synthesized'), 'Action investigation_synthesized must be rendered');
    assert.ok(html.includes('analyst-sec-01'), 'Actor analyst attribution must be rendered');
  });

  it('strictly escapes XSS injection payloads in case title, description, and claims', () => {
    const xssPayload = '<script>alert("XSS")</script><img src="x" onerror="steal()"/>';
    const xssCase: CaseResponse = {
      ...mockCase,
      title: xssPayload,
      description: xssPayload,
    };

    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={xssCase.id}
        initialCaseDetail={xssCase}
        onBackToQueue={() => {}}
      />
    );

    assert.strictEqual(html.includes('<script>'), false, 'Script tags must be entity-encoded');
    assert.ok(html.includes('&lt;script&gt;'), 'Script tags must be converted to &lt;script&gt;');
    assert.strictEqual(html.includes('<img'), false, 'Img tags must be entity-encoded');
    assert.ok(html.includes('&lt;img'), 'Img tags must be converted to &lt;img');
  });

  it('renders unauthorized or not found error state with back button', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId="unauthorized-case-id"
        initialCaseError="Case not found or access denied."
        onBackToQueue={() => {}}
      />
    );

    assert.ok(html.includes('Case not found or access denied.'), 'Error message must be displayed');
    assert.ok(html.includes('Back to Case Queue'), 'Back to case queue button must be displayed');
  });

  it('renders empty state when zero evidence items are linked to case', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={mockCase.id}
        initialCaseDetail={mockCase}
        initialEvidence={[]}
        initialTab="evidence"
        onBackToQueue={() => {}}
      />
    );

    assert.ok(html.includes('No evidence events currently linked to this case'), 'Evidence empty state text must be present');
    assert.ok(html.includes('+ Link Evidence by UUID'), 'Link evidence button must be available in empty state');
  });

  it('renders empty state when zero activity events are recorded for case', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={mockCase.id}
        initialCaseDetail={mockCase}
        initialActivity={[]}
        initialTab="activity"
        onBackToQueue={() => {}}
      />
    );

    assert.ok(html.includes('No audit events recorded for this case'), 'Activity empty state text must be present');
  });

  it('renders deterministic fallback badge when synthesis rejects to fallback', () => {
    const fallbackValidationResult: InvestigationValidationResult = {
      decision: 'reject_to_fallback',
      is_valid: false,
      context_sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
      validated_at_utc: '2026-10-31T10:05:00Z',
      violations: ['LLM provider unavailable: connection timeout'],
      output: {
        ...mockValidationResult.output,
        model_identifier: 'offline-deterministic-fallback',
        overall_grounding_score: 0.0,
      },
    };

    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={mockCase.id}
        initialCaseDetail={mockCase}
        initialValidationResult={fallbackValidationResult}
        initialTab="findings"
        onBackToQueue={() => {}}
      />
    );

    assert.ok(html.includes('Deterministic Fallback Scope Active'), 'Fallback badge must be displayed');
    assert.ok(html.includes('reject_to_fallback'), 'Decision badge must show reject_to_fallback');
  });

  it('disables or hides investigation and close triggers on closed cases', () => {
    const closedCase: CaseResponse = {
      ...mockCase,
      status: 'closed',
      closed_at: '2026-10-31T12:00:00Z',
      closure_reason: 'Resolved and remediated.',
    };

    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={closedCase.id}
        initialCaseDetail={closedCase}
        initialTab="findings"
        onBackToQueue={() => {}}
      />
    );

    assert.ok(html.includes('badge-closed'), 'Closed badge must be present');
    assert.strictEqual(html.includes('Close Case</button>'), false, 'Close case button must not be rendered for closed case');
  });

  it('strictly adheres to Design Constitution (no emojis, no purple gradients, standard button radius)', () => {
    const html = renderWithAuth(
      <InvestigationWorkspace
        caseId={mockCase.id}
        initialCaseDetail={mockCase}
        initialEvidence={mockEvidenceList}
        initialValidationResult={mockValidationResult}
        initialActivity={mockActivities}
        initialTab="findings"
        onBackToQueue={() => {}}
      />
    );

    // Zero emojis
    assert.strictEqual(/[\u{1F300}-\u{1F9FF}]/u.test(html), false, 'Prohibited emoji icons must not appear in output');

    // Zero purple gradients
    assert.strictEqual(html.includes('linear-gradient') && html.includes('purple'), false, 'Purple gradients are banned');

    // Standard button classes and no pill buttons
    assert.ok(html.includes('btn btn-primary'), 'Standard button classes must be present');
    assert.strictEqual(html.includes('btn-pill'), false, 'Pill buttons are prohibited');
  });
});
