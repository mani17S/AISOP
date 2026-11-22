/**
 * Shows what the selected "View as" role can and cannot do in this interface.
 *
 * The list is derived from the same permission functions that hide and show the buttons, so choosing another role
 * visibly changes both this strip and the screens below it. This is a preview of the interface only: the server decides
 * what each API key may do, and the selector sends nothing to the server.
 */

import React from 'react';
import { useAuth } from '../contexts/AuthContext';
import { GlobalRole } from '../types';

const ROLE_NAMES: Record<string, string> = {
  security_admin: 'Security admin',
  analyst_tier_2: 'Tier-2 analyst (lead)',
  analyst_tier_1: 'Tier-1 analyst (investigator)',
  auditor_viewer: 'Auditor (viewer)',
};

const ROLE_NOTES: Record<string, string> = {
  security_admin: 'Holds no implicit access to cases. Each case still needs an assignment, enforced by the server.',
  analyst_tier_2: 'Leads cases: can assign analysts and close cases.',
  analyst_tier_1: 'Investigates cases assigned to them. A lead closes cases and manages assignments.',
  auditor_viewer: 'Read-only. Cannot create, change or run anything.',
};

export const RoleStrip: React.FC = () => {
  const { globalRole, canCreateCase, canTriageEvents, canSynthesizeReports, canCloseCase, canManageAssignments } = useAuth();
  const abilities: { label: string; allowed: boolean }[] = [
    { label: 'Create cases', allowed: canCreateCase() },
    { label: 'Triage and promote alerts', allowed: canTriageEvents() },
    { label: 'Run AI investigation and reports', allowed: canSynthesizeReports() },
    { label: 'Close cases', allowed: canCloseCase() },
    { label: 'Manage assignments', allowed: canManageAssignments() },
  ];
  const role = globalRole as GlobalRole;
  return (
    <section className="role-strip" aria-label="Interface preview for the selected role" data-role={role}>
      <details className="role-strip-details">
        <summary className="role-strip-title">
          Viewing as <strong>{ROLE_NAMES[role] ?? role}</strong>. Preview only. <span className="role-strip-more">What this role can do</span>
        </summary>
        <p className="role-strip-note-line">{ROLE_NOTES[role] ?? ''}</p>
        <ul className="role-strip-list">
          {abilities.map((a) => (
            <li key={a.label} className={a.allowed ? 'can' : 'cannot'}>
              <span className="role-strip-mark">{a.allowed ? 'Can' : 'Cannot'}</span> {a.label.toLowerCase()}
            </li>
          ))}
        </ul>
        <p className="role-strip-note">Preview only. The server decides what each API key may do.</p>
      </details>
    </section>
  );
};
