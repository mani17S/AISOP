/**
 * Time display helpers.
 *
 * The server stores and returns every instant in UTC. Two different times matter on an alert: when the source generated it
 * (the event time) and when AISOP ingested it. They are never merged and neither is ever substituted for the other. This
 * module only changes how an instant is written (UTC, IST or the viewer's own zone), always naming the zone, and describes
 * the gap between the two times.
 */

export type DisplayZone = 'UTC' | 'IST' | 'LOCAL';
export const ZONES: DisplayZone[] = ['UTC', 'IST', 'LOCAL'];
export const DEFAULT_ZONE: DisplayZone = 'UTC';

/** A gap at or above this is called a late arrival. */
export const LATE_ARRIVAL_SECONDS = 3600;
/** Event times this far after the ingestion time are tolerated as ordinary clock difference. */
export const CLOCK_SKEW_TOLERANCE_SECONDS = 300;

const UNKNOWN = 'Unknown';

function parse(value: string | null | undefined): Date | null {
  if (!value || typeof value !== 'string') return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function parts(d: Date, timeZone?: string): { text: string; zoneName: string } {
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    timeZoneName: 'short',
  });
  const p: Record<string, string> = {};
  for (const x of fmt.formatToParts(d)) p[x.type] = x.value;
  return { text: `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`, zoneName: p.timeZoneName ?? '' };
}

/** Write an instant in the chosen zone, with the zone named. A missing or unparseable value is "Unknown", never a made-up time. */
export function formatInstant(value: string | null | undefined, zone: DisplayZone): string {
  const d = parse(value);
  if (!d) return UNKNOWN;
  if (zone === 'UTC') return `${d.toISOString().replace('T', ' ').substring(0, 19)} UTC`;
  if (zone === 'IST') return `${parts(d, 'Asia/Kolkata').text} IST`;
  const local = parts(d);
  return `${local.text} ${local.zoneName}`.trim();
}

export function zoneLabel(zone: DisplayZone): string {
  if (zone === 'UTC') return 'UTC';
  if (zone === 'IST') return 'IST (UTC+05:30)';
  let name = '';
  try {
    name = Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    name = '';
  }
  return name ? `My time zone (${name})` : 'My time zone';
}

export type LagKind = 'normal' | 'late' | 'skew' | 'unknown';
export interface IngestionLag {
  kind: LagKind;
  /** Ingestion time minus event time, in seconds; null when either time is unknown. */
  seconds: number | null;
  text: string;
}

function duration(totalSeconds: number): string {
  const s = Math.floor(totalSeconds);
  if (s < 60) return `${s} s`;
  const minutes = Math.floor(s / 60);
  if (s < 3600) return `${minutes} min`;
  const hours = Math.floor(s / 3600);
  if (s < 86400) return `${hours} h ${minutes % 60} min`;
  const days = Math.floor(s / 86400);
  return `${days} d ${hours % 24} h`;
}

/** Describe the gap between when an alert was generated and when it was ingested. */
export function describeIngestionLag(eventTime: string | null | undefined, ingestedAt: string | null | undefined): IngestionLag {
  const event = parse(eventTime);
  const ingested = parse(ingestedAt);
  if (!event || !ingested) return { kind: 'unknown', seconds: null, text: 'Gap unknown' };
  const seconds = Math.round((ingested.getTime() - event.getTime()) / 1000);
  if (seconds < -CLOCK_SKEW_TOLERANCE_SECONDS) {
    return {
      kind: 'skew',
      seconds,
      text: `The event time is later than the time it was ingested (by ${duration(-seconds)}). Check the clock on the source.`,
    };
  }
  if (seconds < 0) return { kind: 'normal', seconds, text: 'Arrived at about the time it was generated' };
  return {
    kind: seconds >= LATE_ARRIVAL_SECONDS ? 'late' : 'normal',
    seconds,
    text: `Arrived ${duration(seconds)} after it was generated`,
  };
}
