/**
 * AISOP Error Boundary Component.
 *
 * Catches unhandled runtime exceptions in UI components to prevent
 * full-page whiteout and provides analysts with graceful recovery actions.
 */

import { Component, ErrorInfo, ReactNode } from 'react';

export interface ErrorBoundaryProps {
  children: ReactNode;
  fallbackTitle?: string;
}

export interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  public state: ErrorBoundaryState = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('Unhandled UI exception caught by ErrorBoundary:', error, errorInfo);
  }

  public render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '32px', textAlign: 'center' }}>
          <div
            className="alert-box alert-error"
            style={{ display: 'inline-block', maxWidth: '640px', textAlign: 'left' }}
          >
            <h3 style={{ marginBottom: '8px', fontSize: '16px', fontWeight: 600 }}>
              {this.props.fallbackTitle || 'Component Render Error'}
            </h3>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '12px', fontSize: '13px' }}>
              An unexpected interface error occurred. Telemetry and platform state remain secure.
            </p>
            {this.state.error?.message && (
              <pre
                style={{
                  background: 'var(--bg-primary)',
                  padding: '8px 12px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  overflowX: 'auto',
                  border: '1px solid var(--border-color)',
                }}
              >
                {this.state.error.message}
              </pre>
            )}
            <div style={{ marginTop: '16px' }}>
              <button
                className="btn btn-secondary"
                onClick={() => this.setState({ hasError: false, error: null })}
              >
                Retry View
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
