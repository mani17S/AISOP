/**
 * Shared presentation of a claim's deterministic verification (claim-verification-v1), used by every screen that renders AI claims.
 *
 * Four different things are never merged into one status (AISOP evidence-integrity rule):
 *   1. a citation points at an event;  2. the legacy grounding label (cited events exist + a text screen passed);
 *   3. a deterministic check of the claim's listed structured assertions (this component);  4. analyst confirmation (a human decision, never shown here).
 * Only backend-supplied verification data is rendered; nothing is inferred or invented in the browser. Outcomes are conveyed in text, not colour alone.
 */

import React from 'react';
import { ClaimVerification } from '../types';

export const VERIFICATION_LABEL: Record<string, string> = {
  supported: 'Listed assertions supported by cited evidence',
  contradicted: 'Listed assertions contradicted by cited evidence',
  insufficient_evidence: 'Insufficient evidence to check listed assertions',
  not_verifiable: 'Not machine-checkable',
};

export const LEGACY_GROUNDING_EXPLANATION =
  'Legacy grounding = the cited events exist and a text-match screen passed. It is not a check of the claim\'s assertions and not analyst confirmation.';

const OUTCOMES = new Set(Object.keys(VERIFICATION_LABEL));

/** Structural guard for backend data of unknown provenance/version: anything else is reported as unrecognised, never rendered as an outcome. */
export const isRenderableVerification = (v: unknown): v is ClaimVerification => {
  if (!v || typeof v !== 'object') return false;
  const o = v as Record<string, unknown>;
  return (
    o.schema_version === 'claim-verification-v1' &&
    typeof o.outcome === 'string' && OUTCOMES.has(o.outcome) &&
    typeof o.reason === 'string' &&
    typeof o.assertions_total === 'number' && typeof o.assertions_evaluated === 'number' &&
    Array.isArray(o.results) &&
    o.results.every((r) => !!r && typeof r === 'object' && typeof (r as Record<string, unknown>).index === 'number' && OUTCOMES.has(String((r as Record<string, unknown>).outcome)))
  );
};

/** `verification` undefined/null: the claim carries no structured assertions. `unavailable`: this screen's data source does not include verification. */
export const VerificationNote: React.FC<{ verification?: ClaimVerification | null; unavailable?: boolean; report?: boolean }> = ({ verification, unavailable, report }) => {
  if (unavailable) {
    return (
      <div className="claim-verification">
        <strong>Verification: not included in this view's data</strong> (assertion verification is shown in the investigation views). This is an AI claim; it is not analyst-confirmed.
      </div>
    );
  }
  if (verification != null && !isRenderableVerification(verification)) {
    return (
      <div className="claim-verification">
        <strong>Verification: data not recognised (unsupported version or malformed); not displayed.</strong> This is an AI claim; it is not analyst-confirmed.
      </div>
    );
  }
  if (!verification && report) {
    return (
      <div className="claim-verification">
        <strong>Verification not included in this historical report or for this claim</strong> (no persisted verification result, or the claim had no
        structured assertions). Nothing is inferred from its grounding status. This is an AI claim; it is not analyst-confirmed.
      </div>
    );
  }
  if (!verification) {
    return (
      <div className="claim-verification">
        <strong>Verification: Not machine-checkable</strong> (legacy claim with no structured assertions). This is an AI claim; it is not analyst-confirmed.
      </div>
    );
  }
  const v = verification;
  return (
    <div className="claim-verification">
      <strong>Verification: {VERIFICATION_LABEL[v.outcome] ?? 'Not machine-checkable'}</strong>{' '}
      (checks {v.assertions_evaluated} of {v.assertions_total} listed assertion{v.assertions_total === 1 ? '' : 's'} only, not the whole sentence;
      this is an AI claim, not analyst-confirmed).
      <details>
        <summary>Why this result?</summary>
        <p>{v.reason}</p>
        <ul>
          {v.results.map((r) => (
            <li key={r.index}>
              Assertion {r.index + 1} ({r.kind}): <strong>{VERIFICATION_LABEL[r.outcome] ?? r.outcome}</strong> - {r.reason}
              {r.values_withheld ? ' Values withheld for privacy.' : ''}
              {!r.values_withheld && r.expected != null ? ` Expected ${r.expected}; observed ${r.observed ?? 'none'}.` : ''}
            </li>
          ))}
        </ul>
        {v.assertions_truncated && <p>Some assertions were not evaluated (limit reached).</p>}
      </details>
    </div>
  );
};
