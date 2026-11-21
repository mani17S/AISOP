/**
 * AISOP Role-Based Access Control & User Context.
 *
 * Implements client-side role scoping for UI element visibility only (preview/presentation).
 *
 * SECURITY INVARIANT:
 * This context is strictly a presentation-layer convenience. The backend is the sole
 * authority for all authentication and authorization decisions. The client role switcher
 * does NOT transmit roles to the backend, nor can it elevate privileges on the API.
 * All API access decisions are evaluated on the server using the authenticated principal's token.
 */

import React, { createContext, useContext, useState, ReactNode } from 'react';
import { GlobalRole } from '../types';
import { api } from '../services/api';

interface AuthContextType {
  username: string;
  globalRole: GlobalRole;
  apiKey: string;
  isAuthenticated: boolean;
  setRole: (role: GlobalRole) => void;
  setUsername: (name: string) => void;
  setApiKey: (key: string) => void;
  keyDialogOpen: boolean;
  setKeyDialogOpen: (open: boolean) => void;
  canCreateCase: () => boolean;
  canCloseCase: () => boolean;
  canManageAssignments: () => boolean;
  canTriageEvents: () => boolean;
  canSynthesizeReports: () => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [username, setUsername] = useState<string>('lead_analyst');
  const [globalRole, setRole] = useState<GlobalRole>('analyst_tier_2');
  const [apiKey, setApiKeyState] = useState<string>(() => api.getApiKey());
  const [keyDialogOpen, setKeyDialogOpen] = useState<boolean>(false);

  const handleSetApiKey = (key: string) => {
    setApiKeyState(key);
    api.setApiKey(key, true);
  };

  const canCreateCase = (): boolean => {
    return globalRole === 'security_admin' || globalRole === 'analyst_tier_2' || globalRole === 'analyst_tier_1';
  };

  const canCloseCase = (): boolean => {
    return globalRole === 'security_admin' || globalRole === 'analyst_tier_2';
  };

  const canManageAssignments = (): boolean => {
    return globalRole === 'security_admin' || globalRole === 'analyst_tier_2';
  };

  const canTriageEvents = (): boolean => {
    return globalRole !== 'auditor_viewer';
  };

  const canSynthesizeReports = (): boolean => {
    return globalRole !== 'auditor_viewer';
  };

  return (
    <AuthContext.Provider
      value={{
        username,
        globalRole,
        apiKey,
        isAuthenticated: Boolean(apiKey),
        setRole,
        setUsername,
        setApiKey: handleSetApiKey,
        keyDialogOpen,
        setKeyDialogOpen,
        canCreateCase,
        canCloseCase,
        canManageAssignments,
        canTriageEvents,
        canSynthesizeReports,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

