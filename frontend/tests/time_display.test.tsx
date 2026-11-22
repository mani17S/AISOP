/**
 * Event time versus ingestion time, and time zones.
 *
 * An alert generated at 22:00 IST and ingested at 02:00 the next day (IST) must show BOTH times, name the zone every time, and
 * say it arrived late. A time the source never supplied must show as unknown, never as the ingestion time.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { formatInstant, describeIngestionLag, zoneLabel, ZONES } from '../src/utils/time';

// 22:00 IST on 10 November 2026 is 16:30 UTC.
const GENERATED = '2026-11-10T16:30:00Z';

describe('formatInstant', () => {
  it('shows the same instant in UTC and in IST, always naming the zone', () => {
    assert.strictEqual(formatInstant(GENERATED, 'UTC'), '2026-11-10 16:30:00 UTC');
    assert.strictEqual(formatInstant(GENERATED, 'IST'), '2026-11-10 22:00:00 IST');
  });

  it('shows the next day in IST when the instant crosses midnight there', () => {
    assert.strictEqual(formatInstant('2026-11-10T20:30:00Z', 'IST'), '2026-11-11 02:00:00 IST');
  });

  it('formats in the viewer\'s own zone and names it', () => {
    const local = formatInstant(GENERATED, 'LOCAL');
    assert.match(local, /^2026-11-1[01] \d\d:\d\d:\d\d \S+/);
  });

  it('does not invent a time for a missing or unparseable value', () => {
    assert.strictEqual(formatInstant(null, 'UTC'), 'Unknown');
    assert.strictEqual(formatInstant(undefined, 'IST'), 'Unknown');
    assert.strictEqual(formatInstant('not a time', 'UTC'), 'Unknown');
    assert.strictEqual(formatInstant('', 'UTC'), 'Unknown');
  });

  it('labels each zone for the selector', () => {
    assert.deepStrictEqual(ZONES, ['UTC', 'IST', 'LOCAL']);
    assert.strictEqual(zoneLabel('UTC'), 'UTC');
    assert.strictEqual(zoneLabel('IST'), 'IST (UTC+05:30)');
    assert.match(zoneLabel('LOCAL'), /^My time zone/);
  });
});

describe('describeIngestionLag', () => {
  it('flags an alert generated at 22:00 IST and ingested at 02:00 IST as a late arrival of 4 hours', () => {
    const lag = describeIngestionLag(GENERATED, '2026-11-10T20:30:00Z');
    assert.strictEqual(lag.kind, 'late');
    assert.strictEqual(lag.seconds, 4 * 3600);
    assert.strictEqual(lag.text, 'Arrived 4 h 0 min after it was generated');
  });

  it('calls a small gap ordinary', () => {
    const lag = describeIngestionLag(GENERATED, '2026-11-10T16:34:10Z');
    assert.strictEqual(lag.kind, 'normal');
    assert.strictEqual(lag.text, 'Arrived 4 min after it was generated');
  });

  it('reports sub-minute gaps in seconds', () => {
    assert.strictEqual(describeIngestionLag(GENERATED, '2026-11-10T16:30:42Z').text, 'Arrived 42 s after it was generated');
  });

  it('warns about clock skew when the event time is later than the ingestion time', () => {
    const lag = describeIngestionLag('2026-11-10T16:40:00Z', '2026-11-10T16:30:00Z');
    assert.strictEqual(lag.kind, 'skew');
    assert.match(lag.text, /later than the time it was ingested/i);
    assert.match(lag.text, /clock/i);
  });

  it('tolerates a few minutes of clock difference without a warning', () => {
    assert.strictEqual(describeIngestionLag('2026-11-10T16:33:00Z', '2026-11-10T16:30:00Z').kind, 'normal');
  });

  it('expresses days for very late alerts', () => {
    assert.strictEqual(describeIngestionLag('2026-11-08T16:30:00Z', '2026-11-10T20:30:00Z').text, 'Arrived 2 d 4 h after it was generated');
  });

  it('says unknown when either time is missing, and never substitutes one for the other', () => {
    assert.strictEqual(describeIngestionLag(null, '2026-11-10T20:30:00Z').kind, 'unknown');
    assert.strictEqual(describeIngestionLag(GENERATED, undefined).kind, 'unknown');
    assert.strictEqual(describeIngestionLag('bad', 'worse').text, 'Gap unknown');
  });
});
