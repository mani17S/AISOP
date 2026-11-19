/**
 * Helpers for the WAI-ARIA tabs pattern (Phase 2). Tabs use roving tabindex and automatic activation:
 * ArrowLeft/ArrowRight (wrapping), Home and End move focus and select the tab.
 */

import type React from 'react';

export function nextTabIndex(key: string, current: number, count: number): number | null {
  if (count <= 0) return null;
  switch (key) {
    case 'ArrowRight':
      return (current + 1) % count;
    case 'ArrowLeft':
      return (current - 1 + count) % count;
    case 'Home':
      return 0;
    case 'End':
      return count - 1;
    default:
      return null;
  }
}

export const tabButtonId = (prefix: string, tab: string): string => `${prefix}-tab-${tab}`;
export const tabPanelId = (prefix: string): string => `${prefix}-tabpanel`;

/** onKeyDown for the element with role="tablist". */
export function handleTabListKeyDown<T extends string>(
  event: React.KeyboardEvent,
  tabs: readonly T[],
  current: T,
  select: (tab: T) => void,
  prefix: string,
): void {
  const next = nextTabIndex(event.key, tabs.indexOf(current), tabs.length);
  if (next === null) return;
  const target = tabs[next];
  if (target === undefined) return;
  event.preventDefault();
  select(target);
  document.getElementById(tabButtonId(prefix, target))?.focus();
}
