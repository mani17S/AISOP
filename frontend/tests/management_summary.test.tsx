/**
 * Management summary: renders only what the server sent, says what is absent from THIS evidence, asks for evidence and never for a response, and
 * disappears for results stored before it existed.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ManagementSummary } from '../src/components/ManagementSummary';
import { ManagementView } from '../src/types';

const view: ManagementView = {
  workload: { records: 2000, evidence_units: 852, incidents: 23, fewer_items_pct: 98.9 },
  verdicts: { sufficient: 0, limited: 23, insufficient: 0 },
  telemetry: {
    present: ['identity'],
    absent: ['endpoint', 'network'],
    collect: { endpoint: 'process, file and registry telemetry from an EDR or Sysmon', network: 'DNS, proxy and firewall flow logs' },
  },
  next_steps: [{ reason_code: 'SAME_VANTAGE_ONLY', incidents: 18, action: 'All the corroboration came from one source at one host. Add evidence from a second source type or a second host.' }],
  data_quality: { records_rejected: 0, rejected_reasons: {}, records_with_assumed_time: 2000 },
  integrity: { ledger_verified: true },
  caveat: 'This describes the evidence that was supplied to this investigation, not the company\'s whole logging.',
};

// React inserts comment markers between adjacent text nodes in server markup; read the visible text.
const visible = (markup: string) => markup.replace(/<!-- -->/g, '').replace(/<[^>]+>/g, '');
const html = visible(renderToStaticMarkup(<ManagementSummary view={view} />));

describe('ManagementSummary', () => {
  it('shows the workload, the verdict mix and the audit chain from the server figures', () => {
    assert.match(html, /From 2000 records to 852 evidence units to 23 incidents \(98\.9% fewer items to read\)\./);
    assert.match(html, /0 sufficient, 23 limited, 0 insufficient/);
    assert.match(html, /Audit hash chain verified/);
  });
  it('says which telemetry is present and which is absent from this evidence, with what to collect', () => {
    assert.match(html, /Telemetry in this evidence: identity\./);
    assert.match(html, /Not in this evidence:.*endpoint \(process, file and registry telemetry from an EDR or Sysmon\); network \(DNS, proxy and firewall flow logs\)/);
  });
  it('lists what to collect next with the reason code, and counts assumed times as a data-quality fact', () => {
    assert.match(html, /18 incidents: All the corroboration came from one source/);
    assert.match(html, /SAME_VANTAGE_ONLY/);
    assert.match(html, /0 records rejected; 2000 records with an assumed time/);
  });
  it('carries the caveat that it describes the supplied evidence, not detection coverage', () => {
    assert.match(html, /not the company&#x27;s whole logging|not the company's whole logging/);
  });
  it('is absent for a result stored before the summary existed, and never invents a figure', () => {
    assert.equal(renderToStaticMarkup(<ManagementSummary view={undefined} />), '');
    assert.equal(renderToStaticMarkup(<ManagementSummary view={null} />), '');
    const noPct = renderToStaticMarkup(<ManagementSummary view={{ ...view, workload: { records: 0, evidence_units: 0, incidents: 0, fewer_items_pct: null } }} />);
    assert.ok(!noPct.includes('fewer items'));
  });
  it('never tells the reader to take a response action', () => {
    assert.ok(!/\b(isolate|quarantine|block the|disable|delete|remediate)\b/i.test(html));
  });
});
