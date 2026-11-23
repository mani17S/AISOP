/**
 * The server knows who the caller is (GET /api/v1/auth/me). The interface uses that to show the real account and to scope what it
 * shows, instead of asking the person to pick a role. This only changes presentation: the server decides every request from the
 * key, whatever the interface shows.
 */

import { GlobalRole } from '../types';

export interface ServerIdentity {
  username: string;
  /** The role string the server reported. */
  serverRole: string;
  /** How the interface presents that role. */
  role: GlobalRole;
}

/**
 * Map a server role to the interface role. A sensor (ingest) has no analyst screens, so it is shown read-only. A role the
 * interface does not know is not guessed: null keeps the manual preview.
 */
export function presentationRole(serverRole: string | null | undefined): GlobalRole | null {
  switch (serverRole) {
    case 'security_admin':
    case 'analyst_tier_2':
    case 'analyst_tier_1':
      return serverRole;
    case 'ingest':
      return 'auditor_viewer';
    default:
      return null;
  }
}

export function identityFromMe(me: { username?: string | null; global_role?: string | null } | null | undefined): ServerIdentity | null {
  if (!me || !me.username || !me.global_role) return null;
  const role = presentationRole(me.global_role);
  return role ? { username: me.username, serverRole: me.global_role, role } : null;
}
