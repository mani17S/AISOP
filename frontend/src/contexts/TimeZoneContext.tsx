/**
 * The zone in which times are written on screen. UTC is the default and the only zone the server uses; IST and the viewer's own
 * zone are display choices. The choice is remembered for this browser tab (a convenience, never sent to the server). Without a provider
 * (tests, isolated components) everything is written in UTC.
 */

import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { DEFAULT_ZONE, DisplayZone, ZONES } from '../utils/time';

const STORAGE_KEY = 'aisop_time_zone';

interface TimeZoneValue {
  zone: DisplayZone;
  setZone: (zone: DisplayZone) => void;
}

const TimeZoneContext = createContext<TimeZoneValue>({ zone: DEFAULT_ZONE, setZone: () => undefined });

function initialZone(): DisplayZone {
  try {
    const saved = window.sessionStorage.getItem(STORAGE_KEY);
    if (saved && (ZONES as string[]).includes(saved)) return saved as DisplayZone;
  } catch {
    /* storage unavailable: keep the default */
  }
  return DEFAULT_ZONE;
}

export const TimeZoneProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [zone, setZoneState] = useState<DisplayZone>(initialZone);
  const setZone = useCallback((next: DisplayZone) => {
    setZoneState(next);
    try {
      window.sessionStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* the choice still applies for this session */
    }
  }, []);
  const value = useMemo(() => ({ zone, setZone }), [zone, setZone]);
  return <TimeZoneContext.Provider value={value}>{children}</TimeZoneContext.Provider>;
};

export const useTimeZone = (): TimeZoneValue => useContext(TimeZoneContext);
