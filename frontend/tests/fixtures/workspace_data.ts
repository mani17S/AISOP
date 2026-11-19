/** Synthetic populated fixtures for the browser harness (copied from investigation_workspace.test.tsx; no real evidence). */
import { CaseAuditEventItem, InvestigationValidationResult } from '../../src/types';

export const populatedValidationResult: InvestigationValidationResult = {
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

export const populatedActivities: CaseAuditEventItem[] = [
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

export const populatedAlertDetailExtras = {
  mitre_attack: [
    { tactic_id: 'TA0002', tactic_name: 'Execution', technique_id: 'T1059.001', technique_name: 'PowerShell' },
    { tactic_id: 'TA0011', tactic_name: 'Command and Control', technique_id: 'T1071.001', technique_name: 'Web Protocols' },
  ],
  observables: [
    { type: 'ip', value: '198.51.100.45', relevance: 'suspicious' },
    { type: 'cmdline', value: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgASQBFAFgASQBFAFgA-synthetic-long-value-for-wrapping-0123456789', relevance: 'suspicious' },
    { type: 'sha256', value: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0', relevance: null },
  ],
  host: { hostname: 'HOST-01', ip: '10.0.0.5' },
  user: { username: 'SYNTHETIC\\analyst' },
  process: { name: 'synthetic.exe', command_line: 'synthetic.exe --flag value' },
  custom_fields: { vendor_rule: 'synthetic-rule-42', note: 'synthetic custom attribute' },
};
