/**
 * AISOP shared modal dialog primitive (Phase 2 accessibility).
 *
 * Replaces the hand-written `modal-backdrop` / `modal-dialog` wrappers. Header, body and footer markup stay with
 * the caller, so each modal keeps its own business logic. Provides:
 * - role="dialog" with aria-modal, an accessible name (aria-labelledby) and an optional description
 * - initial focus inside the dialog and focus restoration to the invoking element on close
 * - Tab / Shift+Tab focus trap and Escape to close (only when `dismissible`)
 * - background content made inert and hidden from assistive technology while open
 *   (works for nested dialogs: the most recently opened dialog is the only active one)
 *
 * No dependency, no portal (so it also renders in server-side markup tests).
 */

import React, { useEffect, useRef } from 'react';

const FOCUSABLE_SELECTOR =
  'a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

/**
 * Pure focus-trap decision. Returns the index to focus, `-1` to focus the dialog container itself,
 * or `null` when the browser's default Tab behaviour is already correct.
 */
export function trapTarget(count: number, activeIndex: number, shift: boolean): number | null {
  if (count <= 0) return -1;
  if (activeIndex < 0) return shift ? count - 1 : 0;
  if (!shift && activeIndex === count - 1) return 0;
  if (shift && activeIndex === 0) return count - 1;
  return null;
}

// The control that invoked the dialog. A control that disables itself while loading (for example a "View Details"
// button) loses focus before its dialog mounts, so `document.activeElement` is then `body`; some browsers also do not
// focus a button on click, and a page without window focus delivers no focus events. So the last interactive control
// that was focused OR activated (click, Enter, Space) is remembered as a fallback invoker.
let lastInvoker: HTMLElement | null = null;
const INTERACTIVE = 'button,a[href],[role="button"],summary,input,select,textarea';
if (typeof document !== 'undefined') {
  document.addEventListener(
    'focusin',
    (event) => {
      const target = event.target;
      if (target instanceof HTMLElement && !target.closest('[role="dialog"]')) lastInvoker = target;
    },
    true,
  );
  const remember = (event: Event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const control = target.closest<HTMLElement>(INTERACTIVE);
    if (control) lastInvoker = control;
  };
  document.addEventListener('click', remember, true);
  document.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') remember(event); }, true);
}
// Stack of open dialogs; only the last one reacts to the keyboard.
const openDialogs: object[] = [];

function makeBackgroundInert(dialog: HTMLElement): () => void {
  const changed: { node: HTMLElement; hadInert: boolean; ariaHidden: string | null }[] = [];
  let current: HTMLElement | null = dialog;
  while (current && current.parentElement) {
    for (const sibling of Array.from(current.parentElement.children)) {
      if (sibling === current || !(sibling instanceof HTMLElement)) continue;
      if (sibling.tagName === 'SCRIPT' || sibling.tagName === 'STYLE') continue;
      changed.push({ node: sibling, hadInert: sibling.hasAttribute('inert'), ariaHidden: sibling.getAttribute('aria-hidden') });
      // Attribute form works in browsers (reflected as the inert property) and in DOM test environments.
      sibling.setAttribute('inert', '');
      sibling.setAttribute('aria-hidden', 'true');
    }
    current = current.parentElement;
  }
  return () => {
    for (let i = changed.length - 1; i >= 0; i--) {
      const entry = changed[i]!;
      if (entry.hadInert) entry.node.setAttribute('inert', '');
      else entry.node.removeAttribute('inert');
      if (entry.ariaHidden === null) entry.node.removeAttribute('aria-hidden');
      else entry.node.setAttribute('aria-hidden', entry.ariaHidden);
    }
  };
}

export interface DialogProps {
  /** Called for Escape and backdrop click (only when `dismissible`). */
  onClose: () => void;
  /** id of the element that titles the dialog (required: every dialog needs an accessible name). */
  labelledBy: string;
  describedBy?: string;
  /** Escape and backdrop click close the dialog. Default true. */
  dismissible?: boolean;
  /** Use "alertdialog" only for an interruption that needs an immediate response. */
  role?: 'dialog' | 'alertdialog';
  className?: string;
  style?: React.CSSProperties;
  children: React.ReactNode;
}

export const Dialog: React.FC<DialogProps> = ({
  onClose,
  labelledBy,
  describedBy,
  dismissible = true,
  role = 'dialog',
  className = 'modal-dialog',
  style,
  children,
}) => {
  const dialogRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  const dismissibleRef = useRef(dismissible);
  onCloseRef.current = onClose;
  dismissibleRef.current = dismissible;

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return undefined;
    const token = {};
    const active = document.activeElement;
    const opener =
      active instanceof HTMLElement && active !== document.body ? active : lastInvoker;
    openDialogs.push(token);
    const restoreBackground = makeBackgroundInert(dialog);

    const initial =
      dialog.querySelector<HTMLElement>('[data-autofocus]') ??
      dialog.querySelector<HTMLElement>('.modal-body input:not([type="hidden"]):not([disabled]), .modal-body select:not([disabled]), .modal-body textarea:not([disabled])') ??
      dialog;
    initial.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (openDialogs[openDialogs.length - 1] !== token) return;
      if (event.key === 'Escape' && dismissibleRef.current) {
        event.preventDefault();
        event.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (event.key !== 'Tab') return;
      const focusables = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
      const target = trapTarget(focusables.length, focusables.indexOf(document.activeElement as HTMLElement), event.shiftKey);
      if (target === null) return;
      event.preventDefault();
      (target === -1 ? dialog : focusables[target]!).focus();
    };
    document.addEventListener('keydown', onKeyDown, true);

    return () => {
      document.removeEventListener('keydown', onKeyDown, true);
      const index = openDialogs.indexOf(token);
      if (index >= 0) openDialogs.splice(index, 1);
      restoreBackground();
      if (opener && opener.isConnected) opener.focus();
    };
  }, []);

  return (
    <div
      className="modal-backdrop"
      onClick={(event) => {
        if (dismissible && event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className={className}
        style={style}
        role={role}
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        tabIndex={-1}
      >
        {children}
      </div>
    </div>
  );
};
