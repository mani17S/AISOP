/**
 * Plain-language explanations for fixed backend codes (demo path, UX review items U6 and U7).
 *
 * The codes themselves stay visible next to the sentence so an analyst can quote them. Nothing here invents data: each text
 * restates what the code means in the backend (`normalize.py`, `evidence_domains/adapters.py`, `schemas/sufficiency.py`).
 * Unknown codes fall back to the code itself.
 */

const REJECTED: Record<string, string> = {
  TIMESTAMP_MISSING_OR_INVALID: 'The record has no usable event time. It was kept as evidence but not placed on the timeline, because no time was invented.',
  NO_ADAPTER: 'No parser recognises this record, so it was not analysed.',
  NOT_AN_OBJECT: 'The record is not a JSON object, so it could not be read.',
  RECORD_TOO_DEEP: 'The record is nested too deeply to process safely.',
  RECORD_TOO_LARGE: 'The record is larger than the size limit.',
  RECORD_NOT_SERIALIZABLE: 'The record could not be converted to a stable form for hashing.',
  SCHEMA_VERSION_UNSUPPORTED: 'The record declares an evidence schema version this system does not support.',
  EVIDENCE_TYPE_INVALID: 'The evidence type is missing or not in the accepted format.',
  RECORD_MALFORMED: 'The record is malformed and could not be parsed.',
};

const FIELD_PREFIXES: Record<string, (field: string) => string> = {
  FIELD_INVALID: (f) => `The field "${f}" has a value in an invalid format.`,
  FIELD_MISSING: (f) => `The required field "${f}" is missing.`,
  FIELD_TOO_LONG: (f) => `The field "${f}" is longer than allowed.`,
};

/** One sentence for a rejected or quarantined record code. */
export function explainRecordCode(code: string): string {
  const exact = REJECTED[code];
  if (exact) return exact;
  const parts = code.split(':');
  const head = parts[0] ?? '';
  const tail = parts[1];
  if (head === 'ADAPTER_ERROR') return 'The parser failed on this record, so it was not analysed.';
  const field = FIELD_PREFIXES[head];
  if (field && tail) return field(tail);
  return code;
}

/** What evidence would move a LIMITED or INSUFFICIENT verdict, by sufficiency reason code. Empty when nothing would change it. */
const RAISE: Record<string, string> = {
  NO_EVIDENCE: 'Link evidence to the case.',
  NO_RELEVANT_EVIDENCE: 'Link evidence that relates to the question under investigation.',
  EVIDENCE_TRUNCATED: 'Narrow the evidence linked to the case so all of it is analysed.',
  ROOT_ABSENT: 'Link the record that started the activity (for example the process creation or the first alert).',
  ROOT_PROVENANCE_MISSING: 'The starting record needs a stored raw digest; re-ingest it through the normal intake.',
  PROVENANCE_UNVERIFIED_ALL: 'Re-ingest the records through the normal intake so each has a stored raw digest.',
  PROVENANCE_PARTIAL: 'Re-ingest the records that lack a stored raw digest.',
  UNCORROBORATED_QUESTION: 'Add a second, independent source that shares a specific artefact with the first, such as a file hash, a public address, a domain or a logon session.',
  TEMPORAL_ANOMALY: 'Check the event times of the flagged records; they fall outside the window or in the future.',
  CONTRADICTORY_EVIDENCE: 'Resolve the conflict: find a record that explains which statement is correct.',
  MISSING_REQUIRED_FIELD: 'Supply the missing field in the source record and ingest it again.',
  WEAK_LINK_ONLY: 'Records are related only by host, user, internal address or process name. Add evidence that shares a specific artefact.',
  REPEATED_OBSERVATION_ONLY: 'The same observation was repeated. Add evidence from a different source or a different observation.',
  SAME_VANTAGE_ONLY: 'All the corroborating records were seen from one vantage point (one source type at one host). Add evidence from a different source or a different host.',
  DUPLICATE_EVIDENCE_COLLAPSED: '',
  IRRELEVANT_EVIDENCE_EXCLUDED: '',
  GATE_EVALUATION_ERROR: 'The sufficiency check failed internally. Run the investigation again; if it repeats, report it.',
};

/** Distinct, ordered "what would raise it" sentences for a list of reason codes (qualifiers after ":" are ignored). */
export function whatWouldRaiseVerdict(reasonCodes: readonly string[]): string[] {
  const out: string[] = [];
  for (const full of reasonCodes) {
    const text = RAISE[full.split(':')[0] ?? ''];
    if (text && !out.includes(text)) out.push(text);
  }
  return out;
}
