/**
 * Evidence class marker (constitution A4: a square marker plus the word, never a filled pill and never colour alone).
 * The class comes only from the `trust_class` the backend returns for each record; nothing is derived or invented here.
 * Each class has its own glyph SHAPE (solid, hollow, dashed, dotted, diamond), drawn with existing text tokens, so the classes stay
 * distinguishable without colour. The glyph is decorative (aria-hidden); the visible word carries the meaning for every reader.
 */

import React from 'react';

/** Visible wording per backend trust class. */
export const TRUST: Record<string, string> = {
  raw_observed: 'Observed (collector record)',
  tool_asserted: 'Tool-asserted (forensic tool interpretation)',
  analyst_observation: 'Analyst statement (context only)',
  ti_context: 'External intelligence (context only)',
  derived: 'Derived',
  model_inference: 'AI inference',
  analyst_confirmed: 'Analyst confirmed',
};

/** One plain sentence per class for the legend. Describes what the class means in AISOP; adds no claim about any record. */
export const TRUST_MEANING: Record<string, string> = {
  raw_observed: 'A record produced by a collector or log source.',
  tool_asserted: 'A forensic tool\'s interpretation of an artefact, not a raw observation.',
  analyst_observation: 'A person\'s statement. Context only; it never corroborates machine evidence.',
  ti_context: 'General intelligence about an indicator. It is not evidence from this case.',
  derived: 'Computed from observations, for example a relationship in the graph.',
  model_inference: 'Output of a language model. It is never observed evidence.',
  analyst_confirmed: 'Set only by an explicit analyst decision.',
};

export const ClassGlyph: React.FC<{ cls: string }> = ({ cls }) => (
  <span className={`class-glyph class-glyph--${cls in TRUST ? cls : 'unknown'}`} aria-hidden="true" />
);

export const EvidenceClassMark: React.FC<{ cls: string }> = ({ cls }) => (
  <span className="class-mark" title={TRUST_MEANING[cls]}>
    <ClassGlyph cls={cls} />
    {TRUST[cls] ?? cls}
  </span>
);

/** Native disclosure (keyboard and screen reader friendly), closed by default so it adds no noise to the table. */
export const EvidenceClassLegend: React.FC = () => (
  <details className="class-legend">
    <summary>How to read the evidence classes</summary>
    <ul>
      {Object.keys(TRUST).map((cls) => (
        <li key={cls}>
          <EvidenceClassMark cls={cls} /> <span>{TRUST_MEANING[cls]}</span>
        </li>
      ))}
    </ul>
  </details>
);
