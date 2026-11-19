/**
 * jsdom environment for DOM-simulated tests (Phase 2.1). Import this module FIRST in a test file so that
 * react-dom sees a `window` when it loads. jsdom simulates the DOM and focus model; it does not render, lay out
 * or apply CSS, and it is not a real browser.
 */
import { JSDOM } from 'jsdom';

export const dom = new JSDOM('<!doctype html><html><body></body></html>', {
  url: 'http://localhost/',
  pretendToBeVisual: true,
});

const g = globalThis as Record<string, unknown>;
g.window = dom.window;
g.document = dom.window.document;
for (const name of [
  'HTMLElement',
  'HTMLInputElement',
  'HTMLButtonElement',
  'Element',
  'Node',
  'Event',
  'KeyboardEvent',
  'MouseEvent',
  'MutationObserver',
  'getComputedStyle',
  'requestAnimationFrame',
  'cancelAnimationFrame',
] as const) {
  g[name] = (dom.window as unknown as Record<string, unknown>)[name];
}
g.sessionStorage = dom.window.sessionStorage;
g.IS_REACT_ACT_ENVIRONMENT = true;
// React's scheduler would otherwise open real MessageChannel ports that keep the Node test process alive.
// This timer-based stand-in provides the same port1.onmessage / port2.postMessage contract it uses.
class TimerMessageChannel {
  port1: { onmessage: ((event: { data: unknown }) => void) | null } = { onmessage: null };
  port2 = { postMessage: (data: unknown) => { setTimeout(() => this.port1.onmessage?.({ data }), 0); } };
}
g.MessageChannel = TimerMessageChannel;
