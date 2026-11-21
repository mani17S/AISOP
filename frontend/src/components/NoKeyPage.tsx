/**
 * Shown for every workbench screen until an API key is set. No data requests are made while this is shown, so no
 * screen can report an empty list, a zero count or a missing case assignment for a request that was never allowed.
 */

import React from 'react';
import { useAuth } from '../contexts/AuthContext';

export const NoKeyPage: React.FC = () => {
  const { setKeyDialogOpen } = useAuth();
  return (
    <div className="no-key">
      <h1>API key needed</h1>
      <p>
        The workbench loads alerts, cases and evidence from the AISOP server, which accepts requests only with an API
        key. Keys are issued by the operator of this deployment.
      </p>
      <button className="btn btn-primary" onClick={() => setKeyDialogOpen(true)}>
        Set API key
      </button>
      <p className="no-key-note">The key is kept for this browser tab only and is cleared when you close it.</p>
    </div>
  );
};
