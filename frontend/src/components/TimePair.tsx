/**
 * Two different times for one record: when the source generated it, and when AISOP ingested it. Both are always shown, in the
 * zone the viewer chose, with the zone named. A late arrival or a clock mismatch is written out in words, not only coloured.
 */

import React from 'react';
import { useTimeZone } from '../contexts/TimeZoneContext';
import { describeIngestionLag, formatInstant } from '../utils/time';

interface TimePairProps {
  eventTime?: string | null;
  ingestedAt?: string | null;
}

export const TimePair: React.FC<TimePairProps> = ({ eventTime, ingestedAt }) => {
  const { zone } = useTimeZone();
  const lag = describeIngestionLag(eventTime, ingestedAt);
  const utcTitle = `${lag.text}. Generated ${formatInstant(eventTime, 'UTC')}; ingested ${formatInstant(ingestedAt, 'UTC')}.`;
  return (
    <div className="time-pair" title={utcTitle}>
      <span className="time-row">
        <span className="time-label">Generated</span>
        <span>{formatInstant(eventTime, zone)}</span>
      </span>
      <span className="time-row">
        <span className="time-label">Ingested</span>
        <span>{formatInstant(ingestedAt, zone)}</span>
      </span>
      {lag.kind === 'late' && <span className="time-flag time-flag-late">{lag.text.replace('Arrived', 'Late: arrived')}</span>}
      {lag.kind === 'skew' && <span className="time-flag time-flag-skew">Event time is after ingestion. Check the source clock.</span>}
    </div>
  );
};
