/**
 * The "View as" selector changes what the interface shows. These tests pin the visible difference per role.
 * The selector is a preview only and sends nothing to the server.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AuthProvider } from '../src/contexts/AuthContext';
import { RoleStrip } from '../src/components/RoleStrip';
import { Cases } from '../src/pages/Cases';

const strip = (role: 'security_admin' | 'analyst_tier_2' | 'analyst_tier_1' | 'auditor_viewer') =>
  renderToStaticMarkup(<AuthProvider initialRole={role}><RoleStrip /></AuthProvider>);

describe('Role preview strip', () => {
  it('lead can close cases and manage assignments', () => {
    const html = strip('analyst_tier_2');
    assert.ok(html.includes('Tier-2 analyst (lead)'));
    assert.ok(/class="can"[^>]*><span[^>]*>Can<\/span> close cases/.test(html));
    assert.ok(/class="can"[^>]*><span[^>]*>Can<\/span> manage assignments/.test(html));
  });

  it('Tier-1 cannot close cases or manage assignments but can investigate', () => {
    const html = strip('analyst_tier_1');
    assert.ok(/class="cannot"[^>]*><span[^>]*>Cannot<\/span> close cases/.test(html));
    assert.ok(/class="cannot"[^>]*><span[^>]*>Cannot<\/span> manage assignments/.test(html));
    assert.ok(/class="can"[^>]*><span[^>]*>Can<\/span> run ai investigation and reports/.test(html));
  });

  it('auditor is read-only for every action', () => {
    const html = strip('auditor_viewer');
    assert.equal((html.match(/class="cannot"/g) ?? []).length, 5);
    assert.ok(html.includes('Read-only'));
  });

  it('security admin is shown without implicit case access', () => {
    assert.ok(strip('security_admin').includes('no implicit access to cases'.replace('no', 'no')) || strip('security_admin').includes('Holds no implicit access'));
  });

  it('always states that it is a preview and the server decides', () => {
    for (const r of ['security_admin', 'analyst_tier_2', 'analyst_tier_1', 'auditor_viewer'] as const) {
      assert.ok(strip(r).includes('Preview only. The server decides'));
    }
  });

  it('the Cases page hides New case for the auditor and shows it for a lead', () => {
    const page = (role: 'analyst_tier_2' | 'auditor_viewer') =>
      renderToStaticMarkup(<AuthProvider initialRole={role}><Cases onNavigateToReport={() => {}} /></AuthProvider>);
    assert.ok(page('analyst_tier_2').includes('New case'));
    assert.ok(!page('auditor_viewer').includes('New case'));
  });
});
