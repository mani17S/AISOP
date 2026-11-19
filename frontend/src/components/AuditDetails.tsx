/**
 * Keyboard- and screen-reader-accessible disclosure for audit-event details (Phase 2.3).
 *
 * Replaces reliance on the `title` attribute (mouse-only) for the truncated "Details" cell. The compact table cell keeps
 * its one-line preview; a real <button> with aria-expanded / aria-controls reveals the full text in a row directly below.
 * The text is rendered as React text (never HTML), is wrapped (no horizontal overflow), and the scrollable region is
 * focusable so keyboard users can scroll long content. Nothing here changes the audit record or who may read it.
 */

import React from 'react';
import { CaseAuditEventItem } from '../types';

export interface FormattedAuditDetails {
  /** One-line preview text (same as the previous cell content). */
  compact: string;
  /** Pretty-printed full text, multi-line. */
  full: string;
  /** True when there is nothing to disclose (null, undefined or an empty object). */
  isEmpty: boolean;
}

export function formatAuditDetails(details: CaseAuditEventItem['details'] | null | undefined): FormattedAuditDetails {
  if (details === null || details === undefined) return { compact: '{}', full: '', isEmpty: true };
  let compact: string;
  let full: string;
  try {
    compact = JSON.stringify(details) ?? '{}';
    full = JSON.stringify(details, null, 2) ?? '';
  } catch {
    // Circular or otherwise unserialisable: never throw while rendering an audit table.
    return { compact: '[details could not be displayed]', full: '', isEmpty: true };
  }
  const isEmpty = typeof details === 'object' && Object.keys(details as object).length === 0;
  return { compact, full, isEmpty };
}

export const auditRegionId = (auditId: string): string => `audit-details-${auditId.replace(/[^A-Za-z0-9_-]/g, '_')}`;

interface CellProps {
  audit: CaseAuditEventItem;
  expanded: boolean;
  onToggle: (id: string) => void;
  /** Human-readable time used in the accessible names. */
  when: string;
}

/** The compact "Details" cell: one-line preview plus the disclosure button. */
export const AuditDetailsCell: React.FC<CellProps> = ({ audit, expanded, onToggle, when }) => {
  const { compact, isEmpty } = formatAuditDetails(audit.details);
  if (isEmpty) {
    return <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No details recorded</span>;
  }
  const label = `${expanded ? 'Hide' : 'Show'} details for ${audit.action} at ${when}`;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
      <span
        title={compact}
        style={{ flex: '1 1 auto', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
      >
        {compact}
      </span>
      <button
        type="button"
        className="btn btn-secondary"
        style={{ flex: '0 0 auto', padding: '2px 8px', fontSize: '12px' }}
        aria-expanded={expanded}
        aria-controls={auditRegionId(audit.id)}
        aria-label={label}
        onClick={() => onToggle(audit.id)}
      >
        {expanded ? 'Hide details' : 'Show details'}
      </button>
    </div>
  );
};

interface RowProps {
  audit: CaseAuditEventItem;
  expanded: boolean;
  columns: number;
  when: string;
}

/** The disclosed row. Always present in the DOM (so aria-controls resolves) and `hidden` while collapsed. */
export const AuditDetailsRow: React.FC<RowProps> = ({ audit, expanded, columns, when }) => {
  const { full, isEmpty } = formatAuditDetails(audit.details);
  if (isEmpty) return null;
  return (
    <tr id={auditRegionId(audit.id)} hidden={!expanded}>
      <td colSpan={columns} style={{ background: 'var(--bg-input)', padding: '8px 12px' }}>
        <div
          role="region"
          aria-label={`Details for ${audit.action} at ${when}`}
          tabIndex={0}
          style={{ maxHeight: '240px', overflow: 'auto' }}
        >
          <pre
            className="font-mono"
            style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}
          >
            {full}
          </pre>
        </div>
      </td>
    </tr>
  );
};
