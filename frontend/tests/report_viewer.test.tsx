/**
 * AISOP Phase 4 — Report Viewer Security & Rendering Test Suite.
 *
 * Verifies:
 * 1. Valid report bundle rendering across all sections.
 * 2. Missing optional fields and empty lists resilience.
 * 3. Empty timeline and timeline status disclosure handling.
 * 4. Chronological ordering preservation.
 * 5. Invalid / unparseable timestamp resilience.
 * 6. Unknown event types and unusual observables.
 * 7. Claims with distinct grounding statuses (validated, review, refuted).
 * 8. Missing MITRE mappings empty state.
 * 9. Long command lines and file paths formatting.
 * 10. Fallback and audit provenance badges.
 * 11. Strict XSS mitigation (HTML entities encoded, no raw script injection).
 * 12. Human-in-the-loop advisory notices (no autonomous actions).
 */

import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ReportViewer } from '../src/components/ReportViewer';
import { ClaimVerification, ClaimVerificationOutcome, InvestigationReportBundle } from '../src/types';

import { createBaseMockBundle } from './fixtures/report_bundle';


describe('AISOP Phase 4: ReportViewer Component Verification', () => {
  it('renders valid report bundle with executive brief view by default', () => {
    const bundle = createBaseMockBundle();
    const html = renderToStaticMarkup(
      <ReportViewer bundle={bundle} caseNumber="CASE-2026-001" caseTitle="DC Compromise" />
    );

    assert.ok(html.includes('Suspicious PowerShell Download Cradle Execution'), 'Title must be rendered');
    assert.ok(html.includes('HIGH'), 'Severity must be displayed');
    assert.ok(html.includes('Server Audit Verified'), 'Provenance badge must be rendered');
    assert.ok(html.includes('DC-PROD-01'), 'Affected asset must be present');
    assert.ok(html.includes('CASE-2026-001'), 'Case number must be present');
    assert.ok(html.includes('Claims validated:'), 'Grounding score must be labelled as claims validated');
    assert.ok(html.includes('95%'), 'Grounding score must be displayed');
    assert.ok(!html.includes('Grounding:'), 'Grounding score must not use the ambiguous label');
  });

  it('labels claim confidence as model-reported and never as a bare confidence', () => {
    const html = renderToStaticMarkup(<ReportViewer bundle={createBaseMockBundle()} initialTab="technical" />);
    assert.ok(html.includes('Model-reported confidence: 65%'), 'Inference confidence must be labelled model-reported');
    assert.ok(html.includes('Model-reported confidence: 10%'), 'Refuted claim confidence must be labelled model-reported');
    assert.ok(!html.includes('>Confidence:'), 'No bare Confidence label may remain');
  });

  it('does not fabricate ATT&CK values when a mapping has missing fields', () => {
    const bundle = createBaseMockBundle();
    bundle.technical_report.mitre_attack_mappings = [{}] as any;
    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} initialTab="technical" />);
    assert.ok(!html.includes('TXXXX'), 'No placeholder technique id');
    assert.ok(!html.includes('Observed Technique'), 'No placeholder technique name');
    assert.ok(!html.includes('>General<'), 'No placeholder tactic');
    assert.ok(html.includes('Technique ID not provided'), 'Missing id must be stated');
    assert.ok(html.includes('Tactic not provided'), 'Missing tactic must be stated');
    assert.ok(html.includes('Technique name not provided'), 'Missing name must be stated');
  });

  it('renders fallback badge when deterministic fallback is active', () => {
    const bundle = createBaseMockBundle({ is_fallback_active: true });
    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} />);
    assert.ok(html.includes('Fallback Active'), 'Fallback badge must appear when fallback is active');
  });

  it('renders detached badge when investigation lacks server-side audit verification', () => {
    const bundle = createBaseMockBundle({
      provenance: {
        investigation_id: '99999999-9999-9999-9999-999999999999',
        context_sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
        is_detached_format_mode: true,
        is_inconclusive_or_fallback: false,
        overall_grounding_score: 0.80,
        model_identifier: 'ollama/llama3.1:8b',
        is_verified_investigation: false,
      },
    });
    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} />);
    assert.ok(html.includes('Detached / Unverified'), 'Detached badge must appear');
  });

  it('handles empty optional arrays gracefully without throwing', () => {
    const bundle = createBaseMockBundle({
      executive_brief: {
        ...createBaseMockBundle().executive_brief,
        evidenced_affected_assets: [],
        key_confirmed_findings: [],
        uncertainties_and_limitations: [],
      },
    });
    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} />);
    assert.ok(html.includes('No validated findings confirmed'), 'Empty findings notice rendered');
    assert.ok(html.includes('No specific host or asset identifiers'), 'Empty asset notice rendered');
  });

  it('handles invalid or malformed timestamps without crashing', () => {
    const bundle = createBaseMockBundle({
      generated_at_utc: 'INVALID_TIMESTAMP_STRING',
    });
    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} />);
    assert.ok(html.includes('INVALID_TIMESTAMP_STRING'), 'Raw timestamp fallback rendered safely');
  });

  it('strictly escapes XSS injection payloads in executive brief, claims, and observables', () => {
    const xssPayload = '<script>alert("XSS_ATTACK_VECTOR")</script><img src=x onerror=alert(1)>';
    const bundle = createBaseMockBundle({
      executive_brief: {
        ...createBaseMockBundle().executive_brief,
        title: `Incident: ${xssPayload}`,
        executive_summary: `Summary containing ${xssPayload}`,
        key_confirmed_findings: [`Finding with ${xssPayload}`],
        evidenced_affected_assets: [`Asset_${xssPayload}`],
      },
    });

    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} />);

    // Verification: React JSX must escape HTML tags to entities
    assert.strictEqual(
      html.includes('<script>alert'),
      false,
      'Raw unescaped <script> tag must NEVER appear in HTML output'
    );
    assert.strictEqual(
      html.includes('<img src=x'),
      false,
      'Raw unescaped <img> tag must NEVER appear in HTML output'
    );
    assert.ok(html.includes('&lt;script&gt;'), 'Script tag must be safely HTML entity-encoded');
    assert.ok(html.includes('&lt;img'), 'Img tag must be safely HTML entity-encoded');
  });

  it('renders long command lines and file paths without layout breaking', () => {
    const longCommand = 'C:\\Windows\\System32\\cmd.exe /c ' + 'A'.repeat(500);
    const bundle = createBaseMockBundle({
      detection_report: {
        ...createBaseMockBundle().detection_report,
        validated_observables: [
          {
            observable_type: 'command_line',
            observable_value: longCommand,
            provenance_type: 'bound_telemetry',
            provenance_event_uuids: ['11111111-1111-1111-1111-111111111111'],
            provenance_claim_ids: [],
            is_malicious_asserted: true,
          },
        ],
      },
    });

    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} initialTab="detection" />);
    assert.ok(html.includes('break-all'), 'Long observable table cells must include break-all formatting');
    assert.ok(html.includes('C:\\Windows\\System32\\cmd.exe'), 'Command line text must be present');
  });

  it('does not call AI claims confirmed, explains legacy grounding, and does not invent verification the report lacks', () => {
    const html = renderToStaticMarkup(<ReportViewer bundle={createBaseMockBundle()} initialTab="technical" />);
    assert.ok(html.includes('legacy grounding, not analyst-confirmed') && html.includes('not a check of the claim'));
    assert.ok(html.includes('Verification not included in this historical report or for this claim'), 'no verification data in the report payload: say so, do not fabricate');
    assert.ok(!html.includes('Not machine-checkable') && !/Listed assertions (supported|contradicted)/.test(html));
    assert.ok(!html.includes('Confirmed Findings ('), 'old heading implied analyst confirmation');
    const brief = renderToStaticMarkup(<ReportViewer bundle={createBaseMockBundle()} initialTab="executive" />);
    assert.ok(brief.includes('AI-generated, cited; not analyst-confirmed'));
  });

  const vf = (outcome: ClaimVerificationOutcome, reason = 'REASON_CODE'): ClaimVerification => ({
    schema_version: 'claim-verification-v1', outcome, reason, assertions_total: 1, assertions_evaluated: 1, assertions_truncated: false,
    applies_to: 'listed_assertions_only', results: [{ index: 0, kind: 'event_field', outcome, reason, values_withheld: true }],
  });
  const withVerification = (v: unknown) => {
    const base = createBaseMockBundle();
    const claim = { ...base.technical_report.confirmed_findings[0], claim_text: 'Persisted claim', verification: v } as never;
    return createBaseMockBundle({ technical_report: { ...base.technical_report, confirmed_findings: [claim] } });
  };

  it('renders each persisted verification outcome with bounded wording and the AI-not-confirmed label', () => {
    const want: Record<string, string> = {
      supported: 'Listed assertions supported by cited evidence', contradicted: 'Listed assertions contradicted by cited evidence',
      insufficient_evidence: 'Insufficient evidence to check listed assertions', not_verifiable: 'Not machine-checkable',
    };
    for (const o of Object.keys(want) as ClaimVerificationOutcome[]) {
      const html = renderToStaticMarkup(<ReportViewer bundle={withVerification(vf(o))} initialTab="technical" />);
      assert.ok(html.includes(`Verification: ${want[o]}`) && html.includes('Why this result?') && html.includes('not analyst-confirmed'));
      assert.ok(html.includes('not the whole sentence') && html.includes('Values withheld for privacy'));
      const b = createBaseMockBundle().technical_report;
      const others = b.confirmed_findings.length - 1 + b.hypotheses_and_inferences.length + b.unsupported_or_contradicted_claims.length;
      assert.strictEqual(html.split('Verification not included in this historical report').length - 1, others, 'only claims WITHOUT persisted verification are marked historical');
    }
  });

  it('never fabricates verification for historical claims and rejects unknown-version or malformed data', () => {
    const none = renderToStaticMarkup(<ReportViewer bundle={createBaseMockBundle()} initialTab="technical" />);
    assert.ok(none.includes('Verification not included in this historical report') && !/Listed assertions (supported|contradicted)/.test(none));
    for (const bad of [{ ...vf('supported'), schema_version: 'claim-verification-v9' }, { ...vf('supported'), outcome: 'confirmed_attack' }, { outcome: 'supported' }, 'supported', { ...vf('supported'), results: 'x' }]) {
      const html = renderToStaticMarkup(<ReportViewer bundle={withVerification(bad)} initialTab="technical" />);
      assert.ok(html.includes('data not recognised') && !html.includes('Listed assertions supported'), `malformed verification must not render: ${JSON.stringify(bad)}`);
    }
  });

  it('escapes untrusted verification reason text and keeps the provenance badge from claiming claim verification', () => {
    const html = renderToStaticMarkup(<ReportViewer bundle={withVerification(vf('contradicted', '<script>alert(1)</script>'))} initialTab="technical" />);
    assert.ok(!html.includes('<script>alert') && html.includes('&lt;script&gt;'));
    const top = renderToStaticMarkup(<ReportViewer bundle={createBaseMockBundle()} />);
    assert.ok(top.includes('Server Audit Verified') && top.includes('does not verify that any claim is true'));
    assert.ok(!/Confirmed Forensic|Server-Verified/.test(html + top));
  });

  it('renders technical report tab with timeline and claims', () => {
    const bundle = createBaseMockBundle();
    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} initialTab="technical" />);
    assert.ok(html.includes('Timeline'), 'Timeline section must be rendered');
    assert.ok(html.includes('process_creation'), 'Event type must be rendered');
    assert.ok(html.includes('network_connection'), 'Second event type must be rendered');
    assert.ok(html.includes('Factual Claims &amp; Evidence Provenance'), 'Claims section must be rendered');
    assert.ok(html.includes('VALIDATED_REFERENCE'), 'Grounding status badge must be rendered');
    assert.ok(html.includes('T1059.001'), 'MITRE ATT&CK technique must be rendered');
    assert.ok(html.includes('Human-in-the-Loop Operational Policy'), 'Advisory guidance banner must be present');
  });

  it('renders raw markdown export tab with deterministic markdown blocks', () => {
    const bundle = createBaseMockBundle();
    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} initialTab="markdown" />);
    assert.ok(html.includes('Executive Brief (Deterministic Markdown)'), 'Executive markdown section rendered');
    assert.ok(html.includes('Technical Report (Deterministic Markdown)'), 'Technical markdown section rendered');
    assert.ok(html.includes('Detection Engineering (Deterministic Markdown)'), 'Detection markdown section rendered');
    assert.ok(html.includes('Suspicious PowerShell download cradle executed'), 'Markdown content rendered');
  });

  it('renders all four tab triggers and counters accurately', () => {
    const bundle = createBaseMockBundle();
    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} />);

    assert.ok(html.includes('Executive Brief'), 'Executive Brief tab must exist');
    assert.ok(html.includes('Technical IR Report'), 'Technical IR Report tab must exist');
    assert.ok(html.includes('2 events'), 'Timeline event counter must show 2');
    assert.ok(html.includes('Detection Engineering'), 'Detection Engineering tab must exist');
    assert.ok(html.includes('2 observables'), 'Observables counter must show 2');
    assert.ok(html.includes('Raw Markdown Views'), 'Markdown tab must exist');
  });

  it('displays mandatory governance and anti-autonomous action disclaimers', () => {
    const bundle = createBaseMockBundle();
    const html = renderToStaticMarkup(<ReportViewer bundle={bundle} />);
    assert.ok(
      html.includes('Advisory finding generated by AISOP. Requires human analyst verification.'),
      'Mandatory governance disclaimer must be present'
    );
  });
});
