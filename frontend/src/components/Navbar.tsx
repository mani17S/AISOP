/**
 * AISOP Navigation Header Component.
 *
 * Provides view routing, live backend health status, active RBAC role selection,
 * and secure credential entry.
 */

import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { GlobalRole, HealthResponse } from '../types';
import { api } from '../services/api';
import { Dialog } from './Dialog';
import { apiKeyShapeHint, normalizeApiKey } from '../utils/apiKey';

interface NavbarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
}

const UtcClock: React.FC = () => {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 30000);
    return () => clearInterval(id);
  }, []);
  return (
    <span className="utc-clock" title="Current time in UTC">
      UTC {now.toISOString().slice(11, 16)}
    </span>
  );
};

export const Navbar: React.FC<NavbarProps> = ({ currentTab, onSelectTab }) => {
  const { globalRole, setRole, apiKey, setApiKey, keyDialogOpen: isKeyModalOpen, setKeyDialogOpen: setIsKeyModalOpen } = useAuth();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [keyInput, setKeyInput] = useState(apiKey);
  const [showKey, setShowKey] = useState(false);
  const keyHint = apiKeyShapeHint(keyInput);

  useEffect(() => {
    if (isKeyModalOpen) setKeyInput(apiKey);
  }, [isKeyModalOpen, apiKey]);

  useEffect(() => {
    let isMounted = true;

    const checkHealth = async () => {
      try {
        const res = await api.getHealth();
        if (isMounted) setHealth(res);
      } catch {
        if (isMounted) {
          setHealth({
            status: 'degraded',
            app: 'AISOP',
            version: '1.0.0',
          });
        }
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleSaveKey = () => {
    const cleaned = normalizeApiKey(keyInput);
    setKeyInput(cleaned);
    setApiKey(cleaned);
    setIsKeyModalOpen(false);
  };

  const getHealthClass = (): string => {
    if (!health) return 'down';
    return health.status === 'ok' ? 'ok' : 'degraded';
  };

  return (
    <>
      <header className="navbar">
        <div className="navbar-brand">
          <span>AISOP</span>
        </div>

        <nav className="nav-links" aria-label="Primary">
          <button
            className={`nav-item ${currentTab === 'dashboard' ? 'active' : ''}`}
            aria-current={currentTab === 'dashboard' ? 'page' : undefined}
            onClick={() => onSelectTab('dashboard')}
          >
            Dashboard
          </button>
          <button
            className={`nav-item ${currentTab === 'alerts' ? 'active' : ''}`}
            aria-current={currentTab === 'alerts' ? 'page' : undefined}
            onClick={() => onSelectTab('alerts')}
          >
            Alerts
          </button>
          <button
            className={`nav-item ${currentTab === 'cases' ? 'active' : ''}`}
            aria-current={currentTab === 'cases' ? 'page' : undefined}
            onClick={() => onSelectTab('cases')}
          >
            Cases
          </button>
          <button
            className={`nav-item ${currentTab === 'evidence' ? 'active' : ''}`}
            aria-current={currentTab === 'evidence' ? 'page' : undefined}
            onClick={() => onSelectTab('evidence')}
          >
            Evidence
          </button>
          <button
            className={`nav-item ${currentTab === 'reports' ? 'active' : ''}`}
            aria-current={currentTab === 'reports' ? 'page' : undefined}
            onClick={() => onSelectTab('reports')}
          >
            Reports
          </button>
        </nav>

        <div className="nav-controls">
          <div className="health-badge" title="Backend Health Status">
            <span className={`status-dot ${getHealthClass()}`} />
            <span>{health ? (health.status === 'ok' ? 'Online' : 'Degraded') : 'Connecting...'}</span>
          </div>

          <UtcClock />

          <div className="role-selector" title="Client-side UI simulation only. Backend independently enforces actual permissions based on the authenticated principal / token.">
            <span className="field-label" aria-hidden="true">View as</span>
            <span className="visually-hidden">UI Preview Role - Does not change backend permissions</span>
            <select
              className="select-input"
              value={globalRole}
              onChange={(e) => setRole(e.target.value as GlobalRole)}
              title="Select role to preview client UI views. Backend authorization is enforced independently on all API requests."
            >
              <option value="security_admin">Security Admin</option>
              <option value="analyst_tier_2">Tier-2 Analyst (Lead)</option>
              <option value="analyst_tier_1">Tier-1 Analyst (Investigator)</option>
              <option value="auditor_viewer">Auditor (Viewer)</option>
            </select>
          </div>

          <button
            className="btn btn-secondary"
            style={{ padding: '6px 12px', fontSize: '12px' }}
            onClick={() => {
              setKeyInput(apiKey);
              setIsKeyModalOpen(true);
            }}
          >
            {apiKey ? 'Change key' : 'Set API key'}
          </button>
        </div>
      </header>

      {isKeyModalOpen && (
        <Dialog onClose={() => setIsKeyModalOpen(false)} labelledBy="dlg-api-key-title">
            <div className="modal-header">
              <h3 className="modal-title" id="dlg-api-key-title">API key</h3>
              <button
                className="btn btn-secondary"
                style={{ padding: '2px 8px' }}
                aria-label="Close dialog"
                onClick={() => setIsKeyModalOpen(false)}
              >
                Close
              </button>
            </div>
            <div className="modal-body">
              <div className="alert-box alert-info">
                Keys are issued by the operator of this deployment. The key is kept for this browser tab only and is cleared when you close it.
              </div>
              <div className="form-group">
                <label className="form-label">API key</label>
                <input
                  type={showKey ? 'text' : 'password'}
                  className="input-field"
                  placeholder="Paste your API key"
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                  aria-describedby="api-key-hint"
                  autoComplete="off"
                  spellCheck={false}
                />
                <label style={{ display: 'flex', gap: '8px', alignItems: 'center', marginTop: '8px', fontSize: '13px' }}>
                  <input type="checkbox" checked={showKey} onChange={(e) => setShowKey(e.target.checked)} />
                  Show key
                </label>
                <div id="api-key-hint" role="status" style={{ marginTop: '8px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                  {keyHint ?? (keyInput.trim() ? `${normalizeApiKey(keyInput).length} characters` : '')}
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={() => {
                  setKeyInput('');
                  setApiKey('');
                  setIsKeyModalOpen(false);
                }}
              >
                Clear key
              </button>
              <button className="btn btn-primary" onClick={handleSaveKey}>
                Save key
              </button>
            </div>
        </Dialog>
      )}
    </>
  );
};

