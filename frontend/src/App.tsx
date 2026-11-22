/**
 * AISOP Root Application Component (Phase 4).
 *
 * Enforces role-based views, local state management, and strict zero-leakage security invariants.
 */

import React, { useState } from 'react';
import { AuthProvider } from './contexts/AuthContext';
import { TimeZoneProvider } from './contexts/TimeZoneContext';
import { Navbar } from './components/Navbar';
import { Dashboard } from './pages/Dashboard';
import { Alerts } from './pages/Alerts';
import { Cases } from './pages/Cases';
import { Evidence } from './pages/Evidence';
import { Reports } from './pages/Reports';
import { ErrorBoundary } from './components/ErrorBoundary';
import { PrivacyPolicy, TermsOfService } from './pages/Legal';
import { Landing } from './pages/Landing';
import { NoKeyPage } from './components/NoKeyPage';
import { RoleStrip } from './components/RoleStrip';
import { useAuth } from './contexts/AuthContext';

const ShellBody: React.FC = () => {
  const { apiKey } = useAuth();
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [selectedCaseIdForReport, setSelectedCaseIdForReport] = useState<string | null>(null);
  const [selectedCaseIdForWorkspace, setSelectedCaseIdForWorkspace] = useState<string | null>(null);
  const [initialOpenCreateCase, setInitialOpenCreateCase] = useState<boolean>(false);

  const handleNavigateToReport = (caseId: string) => {
    setSelectedCaseIdForReport(caseId);
    setCurrentTab('reports');
  };

  const handleNavigateToCase = (caseId?: string) => {
    setSelectedCaseIdForWorkspace(caseId || null);
    setInitialOpenCreateCase(false);
    setCurrentTab('cases');
  };

  const handleCreateIncidentFromDashboard = () => {
    setSelectedCaseIdForWorkspace(null);
    setInitialOpenCreateCase(true);
    setCurrentTab('cases');
  };

  const handleSelectTab = (tab: string) => {
    if (tab === 'cases') {
      // Reset workspace to queue when clicking cases tab directly
      setSelectedCaseIdForWorkspace(null);
      setInitialOpenCreateCase(false);
    }
    setCurrentTab(tab);
  };

  return (
    <>
      <div className="app-container">
        <Navbar currentTab={currentTab} onSelectTab={handleSelectTab} />
        <RoleStrip />

        <main className="main-content">
          <ErrorBoundary fallbackTitle="Application view error">
            {!apiKey && <NoKeyPage />}
            {apiKey && currentTab === 'dashboard' && (
              <Dashboard
                onNavigate={setCurrentTab}
                onCreateIncident={handleCreateIncidentFromDashboard}
                onNavigateToCase={handleNavigateToCase}
              />
            )}
            {apiKey && currentTab === 'alerts' && <Alerts onNavigateToCase={handleNavigateToCase} />}
            {apiKey && currentTab === 'cases' && (
              <Cases
                onNavigateToReport={handleNavigateToReport}
                initialCaseId={selectedCaseIdForWorkspace}
                initialOpenCreate={initialOpenCreateCase}
                onClearInitialOpenCreate={() => setInitialOpenCreateCase(false)}
              />
            )}
            {apiKey && currentTab === 'evidence' && <Evidence />}
            {apiKey && currentTab === 'reports' && <Reports initialCaseId={selectedCaseIdForReport} />}
          </ErrorBoundary>
        </main>

        <footer className="app-footer">
          <span>AISOP</span>
          <a href="/privacy">Privacy</a>
          <a href="/terms">Terms</a>
        </footer>
      </div>
    </>
  );
};

const AppShell: React.FC = () => (
  <AuthProvider>
    <TimeZoneProvider>
      <ShellBody />
    </TimeZoneProvider>
  </AuthProvider>
);

export const App: React.FC = () => {
  const path = typeof window !== 'undefined' ? window.location.pathname.replace(/\/+$/, '') : '';
  if (path === '/privacy') return <PrivacyPolicy />;
  if (path === '/terms') return <TermsOfService />;
  if (path === '/app') return <AppShell />;
  return <Landing />;
};

export default App;

