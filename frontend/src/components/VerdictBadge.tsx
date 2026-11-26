/**
 * Evidence-sufficiency verdict for a case, as stored by the last multi-source investigation.
 *
 * It only presents what the server returned. It never works out a verdict, never defaults to one, and shows "Not assessed" when
 * the server sent nothing (no investigation run yet). Shape plus word, no colour of its own (design constitution A4, A7):
 * sufficient = filled square, limited = half-filled, insufficient = hollow, not assessed = dashed.
 */

import React from 'react';
import { CaseResponse } from '../types';

type Verdict = NonNullable<CaseResponse['sufficiency_verdict']>;

const LABEL: Record<Verdict, string> = {
  sufficient: 'Sufficient',
  limited: 'Limited',
  insufficient: 'Insufficient',
};

const isVerdict = (v: unknown): v is Verdict => typeof v === 'string' && Object.prototype.hasOwnProperty.call(LABEL, v);

const utc = (iso: string): string => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
};

const VERDICT_FIELDS = ['sufficiency_verdict', 'sufficiency_rule_version', 'sufficiency_assessed_at', 'sufficiency_incidents_truncated'] as const;

/**
 * Replace a case with a newer server object without erasing a verdict already shown. A response that lacks the verdict fields
 * (verdict undefined, e.g. an older server) keeps the previous verdict fields; a null verdict is the server's real "not assessed"
 * and is accepted as is.
 */
export const mergeCaseVerdict = (prev: CaseResponse | null, next: CaseResponse): CaseResponse => {
  if (!prev || next.sufficiency_verdict !== undefined) return next;
  const merged: CaseResponse = { ...next };
  for (const key of VERDICT_FIELDS) {
    (merged as unknown as Record<string, unknown>)[key] = prev[key];
  }
  return merged;
};

const PARTIAL_NOTE = 'Covers only the incidents stored with the run';

export const VerdictBadge: React.FC<{ item: Pick<CaseResponse, 'sufficiency_verdict' | 'sufficiency_rule_version' | 'sufficiency_assessed_at' | 'sufficiency_incidents_truncated'> }> = ({ item }) => {
  const verdict = item.sufficiency_verdict;
  if (!isVerdict(verdict)) {
    return (
      <span className="verdict-badge verdict-badge--none" title="No multi-source investigation has been run for this case yet.">
        <span className="verdict-glyph" aria-hidden="true" />
        Not assessed
      </span>
    );
  }
  const partial = item.sufficiency_incidents_truncated === true;
  const when = item.sufficiency_assessed_at ? utc(item.sufficiency_assessed_at) : '';
  const parts = [
    'Result of the last multi-source investigation.',
    item.sufficiency_rule_version ? `Rule ${item.sufficiency_rule_version}.` : '',
    when ? `Assessed ${when}.` : '',
    partial ? `${PARTIAL_NOTE}. Only the listed incidents are covered.` : '',
    'Evidence added since is not reflected.',
  ].filter(Boolean);
  const text = partial ? `${LABEL[verdict]} (partial)` : LABEL[verdict];
  return (
    <span
      className={`verdict-badge verdict-badge--${verdict}`}
      title={parts.join(' ')}
      aria-label={`Evidence sufficiency: ${text}${partial ? `. ${PARTIAL_NOTE}` : ''}`}
    >
      <span className="verdict-glyph" aria-hidden="true" />
      {text}
    </span>
  );
};
