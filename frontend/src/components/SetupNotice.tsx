/**
 * One component for the "no usable API key" state, used on every screen.
 * A missing or rejected key is a setup step, not a fault, and the recovery is to set the key, so the action is
 * here beside the message. A failed load must never be rendered as a count of zero.
 */

import React from 'react';
import { useAuth } from '../contexts/AuthContext';

export const isAuthMessage = (message: string | null | undefined): boolean =>
  Boolean(message) && /authenticat|credential|api key|\b401\b|invalid_token/i.test(message as string);

export const SetupNotice: React.FC<{ message?: string }> = ({ message }) => {
  const { setKeyDialogOpen } = useAuth();
  return (
    <div className="alert-box alert-info setup-notice" role="status">
      <div>
        <strong>An API key is needed to load data.</strong>
        <p>{message ?? 'Requests are rejected until a key is set. Nothing has been filtered out.'}</p>
      </div>
      <button className="btn btn-primary" onClick={() => setKeyDialogOpen(true)}>
        Set API key
      </button>
    </div>
  );
};
