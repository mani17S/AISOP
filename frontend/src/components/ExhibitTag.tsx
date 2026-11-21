/**
 * Short exhibit reference derived from a record's own identifier (first four hex characters).
 * The same tag is used wherever that record appears, so an analyst can follow it from the alert queue to a case
 * to a report. It is a label, not a new identifier: the full UUID stays the source of truth.
 */

import React from 'react';

export const exhibitRef = (id: string): string => `E-${id.replace(/[^0-9a-fA-F]/g, '').slice(0, 4).toLowerCase()}`;

export const ExhibitTag: React.FC<{ id: string }> = ({ id }) => (
  <span className="exhibit-tag" title={`Record ${id}`}>
    {exhibitRef(id)}
  </span>
);
