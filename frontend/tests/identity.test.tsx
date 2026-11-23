/**
 * The interface learns who the caller is from the server (GET /api/v1/auth/me) instead of asking for a role.
 * Presentation only: the server decides every request from the key.
 */
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { identityFromMe, presentationRole } from '../src/utils/identity';
import { AuthProvider } from '../src/contexts/AuthContext';
import { RoleStrip } from '../src/components/RoleStrip';
import { Navbar } from '../src/components/Navbar';

describe('presentationRole', () => {
  it('maps the roles an analyst or admin can hold to the same interface role', () => {
    assert.strictEqual(presentationRole('security_admin'), 'security_admin');
    assert.strictEqual(presentationRole('analyst_tier_2'), 'analyst_tier_2');
    assert.strictEqual(presentationRole('analyst_tier_1'), 'analyst_tier_1');
  });
  it('shows a sensor (ingest) read-only, because it has no analyst screens', () => {
    assert.strictEqual(presentationRole('ingest'), 'auditor_viewer');
  });
  it('does not guess a role it does not know', () => {
    assert.strictEqual(presentationRole('superuser'), null);
    assert.strictEqual(presentationRole(null), null);
    assert.strictEqual(presentationRole(undefined), null);
  });
});

describe('identityFromMe', () => {
  it('builds an identity from a full answer', () => {
    assert.deepStrictEqual(identityFromMe({ username: 'dana', global_role: 'analyst_tier_2' }), {
      username: 'dana',
      serverRole: 'analyst_tier_2',
      role: 'analyst_tier_2',
    });
  });
  it('returns null for a machine key with no account, a missing role or an unknown role', () => {
    assert.strictEqual(identityFromMe({ username: null, global_role: null }), null);
    assert.strictEqual(identityFromMe({ username: 'dana', global_role: null }), null);
    assert.strictEqual(identityFromMe({ username: 'dana', global_role: 'root' }), null);
    assert.strictEqual(identityFromMe(null), null);
  });
});

const dana = { username: 'dana', serverRole: 'analyst_tier_2', role: 'analyst_tier_2' as const };

describe('what the screen says', () => {
  it('role strip states the role, does not repeat the account the header shows, and says the server set the role', () => {
    const html = renderToStaticMarkup(
      <AuthProvider initialIdentity={dana}>
        <RoleStrip />
      </AuthProvider>
    );
    assert.match(html, /Your role: <strong>Tier-2 analyst \(lead\)<\/strong>\./);
    assert.doesNotMatch(html, /dana/, 'the account name appears once, in the header');
    assert.match(html, /Set by the server from your API key\./);
    assert.doesNotMatch(html, /Preview only\. <span/);
    assert.match(html, /whatever this screen shows/);
  });

  it('role strip still says preview when the server has not said who the key belongs to', () => {
    const html = renderToStaticMarkup(
      <AuthProvider initialRole="analyst_tier_1">
        <RoleStrip />
      </AuthProvider>
    );
    assert.match(html, /Viewing as <strong>Tier-1 analyst \(investigator\)<\/strong>\. Preview only\./);
  });

  it('navbar shows the signed-in account and no role selector when the server knows the role', () => {
    const html = renderToStaticMarkup(
      <AuthProvider initialIdentity={dana}>
        <Navbar currentTab="dashboard" onSelectTab={() => undefined} />
      </AuthProvider>
    );
    assert.match(html, /Signed in as/);
    assert.match(html, /<strong>dana<\/strong>/);
    assert.doesNotMatch(html, />View as</);
    assert.doesNotMatch(html, /Auditor \(Viewer\)/, 'no way to switch to another role');
  });

  it('navbar keeps the selector as a preview when no identity is known', () => {
    const html = renderToStaticMarkup(
      <AuthProvider initialRole="analyst_tier_2">
        <Navbar currentTab="dashboard" onSelectTab={() => undefined} />
      </AuthProvider>
    );
    assert.match(html, />View as</);
    assert.match(html, /Auditor \(Viewer\)/);
  });

  it('only a real security admin identity shows the Security tab', () => {
    const admin = { username: 'root_admin', serverRole: 'security_admin', role: 'security_admin' as const };
    const withAdmin = renderToStaticMarkup(
      <AuthProvider initialIdentity={admin}>
        <Navbar currentTab="dashboard" onSelectTab={() => undefined} />
      </AuthProvider>
    );
    const withLead = renderToStaticMarkup(
      <AuthProvider initialIdentity={dana}>
        <Navbar currentTab="dashboard" onSelectTab={() => undefined} />
      </AuthProvider>
    );
    assert.match(withAdmin, />Security</);
    assert.doesNotMatch(withLead, />Security</);
  });
});
