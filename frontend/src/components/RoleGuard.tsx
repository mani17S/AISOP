/**
 * AISOP RoleGuard Component.
 *
 * Enforces declarative role-based gating for sensitive UI views and operational actions.
 */

import React, { ReactNode } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { GlobalRole } from '../types';

interface RoleGuardProps {
  allowedRoles: GlobalRole[];
  children: ReactNode;
  fallback?: ReactNode;
}

export const RoleGuard: React.FC<RoleGuardProps> = ({
  allowedRoles,
  children,
  fallback = null,
}) => {
  const { globalRole } = useAuth();

  if (!allowedRoles.includes(globalRole)) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
};

