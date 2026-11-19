/**
 * AISOP Root Application Component (Phase 4).
 *
 * Enforces role-based views, local state management, and strict zero-leakage security invariants.
 */

import React, { useState } from 'react';
import { AuthProvider } from './contexts/AuthContext';
import { Navbar } from './components/Navbar';
import { Dashboard } from './pages/Dashboard';
import { Alerts } from './pages/Alerts';
import { Cases } from './pages/Cases';
import { Evidence } from './pages/Evidence';
import { Reports } from './pages/Reports';
import { ErrorBoundary } from './components/ErrorBoundary';
import { PrivacyPolicy, TermsOfService } from './pages/Legal';

const AppShell: React.FC = () => {
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
    <AuthProvider>
      <div className="app-container">
        <Navbar currentTab={currentTab} onSelectTab={handleSelectTab} />

        <main className="main-content">
          <ErrorBoundary fallbackTitle="Application View Error">
            {currentTab === 'dashboard' && (
              <Dashboard
                onNavigate={setCurrentTab}
                onCreateIncident={handleCreateIncidentFromDashboard}
                onNavigateToCase={handleNavigateToCase}
              />
            )}
            {currentTab === 'alerts' && <Alerts onNavigateToCase={handleNavigateToCase} />}
            {currentTab === 'cases' && (
              <Cases
                onNavigateToReport={handleNavigateToReport}
                initialCaseId={selectedCaseIdForWorkspace}
                initialOpenCreate={initialOpenCreateCase}
                onClearInitialOpenCreate={() => setInitialOpenCreateCase(false)}
              />
            )}
            {currentTab === 'evidence' && <Evidence />}
            {currentTab === 'reports' && <Reports initialCaseId={selectedCaseIdForReport} />}
          </ErrorBoundary>
        </main>
      </div>
    </AuthProvider>
  );
};

export const App: React.FC = () => {
  const path = typeof window !== 'undefined' ? window.location.pathname.replace(/\/+$/, '') : '';
  if (path === '/privacy') return <PrivacyPolicy />;
  if (path === '/terms') return <TermsOfService />;
  return <AppShell />;
};

export default App;

