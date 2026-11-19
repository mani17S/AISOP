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

interface NavbarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, onSelectTab }) => {
  const { globalRole, setRole, apiKey, setApiKey } = useAuth();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);
  const [keyInput, setKeyInput] = useState(apiKey);

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
    setApiKey(keyInput);
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
          <span className="brand-badge">SOC CORE</span>
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
            Evidence & Telemetry
          </button>
          <button
            className={`nav-item ${currentTab === 'reports' ? 'active' : ''}`}
            aria-current={currentTab === 'reports' ? 'page' : undefined}
            onClick={() => onSelectTab('reports')}
          >
            Investigation Reports
          </button>
        </nav>

        <div className="nav-controls">
          <div className="health-badge" title="Backend Health Status">
            <span className={`status-dot ${getHealthClass()}`} />
            <span>{health ? (health.status === 'ok' ? 'Online' : 'Degraded') : 'Connecting...'}</span>
          </div>

          <div className="role-selector" title="Client-side UI simulation only. Backend independently enforces actual permissions based on the authenticated principal / token.">
            <span>UI Preview Role - Does not change backend permissions</span>
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
            {apiKey ? 'Key Configured' : 'Set API Key'}
          </button>

          <div className="legal-links">
            <a href="/privacy">Privacy</a>
            <a href="/terms">Terms</a>
          </div>
        </div>
      </header>

      {isKeyModalOpen && (
        <Dialog onClose={() => setIsKeyModalOpen(false)} labelledBy="dlg-api-key-title">
            <div className="modal-header">
              <h3 className="modal-title" id="dlg-api-key-title">API Authentication Key</h3>
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
                Credentials are held in-memory / session storage only and never written to localStorage or sent to third-party endpoints. Backend independently authorizes all operations based on the active key.
              </div>
              <div className="form-group">
                <label className="form-label">X-API-Key or Bearer Token</label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="Enter backend API key..."
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                />
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
                Clear Key
              </button>
              <button className="btn btn-primary" onClick={handleSaveKey}>
                Save Key
              </button>
            </div>
        </Dialog>
      )}
    </>
  );
};

