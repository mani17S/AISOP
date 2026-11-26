/**
 * AISOP Case Management Page.
 *
 * Implements case creation, listing, detail inspection, and lifecycle transitions
 * with anti-enumeration protections and role-based action gating.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { CaseResponse, CaseSeverity } from '../types';
import { useAuth } from '../contexts/AuthContext';
import { SetupNotice, isAuthMessage } from '../components/SetupNotice';
import { InvestigationWorkspace } from '../components/InvestigationWorkspace';
import { Dialog } from '../components/Dialog';
import { CloseIcon } from '../components/Icons';
import { VerdictBadge } from '../components/VerdictBadge';

interface CasesProps {
  onNavigateToReport?: (caseId: string) => void;
  initialCaseId?: string | null;
  initialOpenCreate?: boolean;
  onClearInitialOpenCreate?: () => void;
}

export const Cases: React.FC<CasesProps> = ({
  onNavigateToReport,
  initialCaseId,
  initialOpenCreate,
  onClearInitialOpenCreate,
}) => {
  const { canCreateCase, canCloseCase } = useAuth();
  const [cases, setCases] = useState<CaseResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Active workspace state
  const [selectedWorkspaceCaseId, setSelectedWorkspaceCaseId] = useState<string | null>(initialCaseId || null);

  useEffect(() => {
    if (initialCaseId) {
      setSelectedWorkspaceCaseId(initialCaseId);
    }
  }, [initialCaseId]);

  // Selected case for detail view
  const [selectedCase, setSelectedCase] = useState<CaseResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);

  // Create modal state
  const [isCreateOpen, setIsCreateOpen] = useState<boolean>(initialOpenCreate ?? false);

  useEffect(() => {
    if (initialOpenCreate) {
      setIsCreateOpen(true);
      onClearInitialOpenCreate?.();
    }
  }, [initialOpenCreate, onClearInitialOpenCreate]);
  const [newTitle, setNewTitle] = useState<string>('');
  const [newDescription, setNewDescription] = useState<string>('');
  const [newSeverity, setNewSeverity] = useState<CaseSeverity>('medium');
  const [createSubmitting, setCreateSubmitting] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Close case state
  const [closureReason, setClosureReason] = useState<string>('');
  const [isCloseModalOpen, setIsCloseModalOpen] = useState<boolean>(false);
  const [closeError, setCloseError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const fetchCases = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getCases({
        page,
        limit: 10,
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
      });
      setCases(res.items);
      setTotal(res.total);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve cases. Ensure API credentials are configured.');
      setCases([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter, severityFilter]);

  useEffect(() => {
    fetchCases();
  }, [fetchCases]);

  const handleOpenDetail = async (caseId: string) => {
    setDetailLoading(true);
    setDetailError(null);
    try {
      const detail = await api.getCaseDetail(caseId);
      setSelectedCase(detail);
    } catch (err: any) {
      setDetailError(err.message || 'Failed to inspect case details');
    } finally {
      setDetailLoading(false);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      setCreateError('Title is required');
      return;
    }
    setCreateSubmitting(true);
    setCreateError(null);
    try {
      await api.createCase({
        title: newTitle.trim(),
        description: newDescription.trim() || null,
        severity: newSeverity,
      });
      setIsCreateOpen(false);
      setNewTitle('');
      setNewDescription('');
      fetchCases();
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create case');
    } finally {
      setCreateSubmitting(false);
    }
  };

  const handleCloseCase = async () => {
    if (!selectedCase || !closureReason.trim()) return;
    setCloseError(null);
    try {
      const updated = await api.closeCase(selectedCase.id, closureReason.trim());
      setSelectedCase(updated);
      setIsCloseModalOpen(false);
      setClosureReason('');
      fetchCases();
    } catch (err: any) {
      setCloseError(err.message || 'Failed to close case');
    }
  };

  if (selectedWorkspaceCaseId) {
    return (
      <InvestigationWorkspace
        caseId={selectedWorkspaceCaseId}
        onBackToQueue={() => setSelectedWorkspaceCaseId(null)}
        onNavigateToReport={onNavigateToReport}
      />
    );
  }

  return (
    <div className="cases-page">
      <div className="page-header">
        <div>
          <h1>Cases</h1>
          <p className="page-header-sub">
            Cases you can access, by severity and status
          </p>
        </div>
        {canCreateCase() && (
          <button className="btn btn-primary" onClick={() => setIsCreateOpen(true)}>
            New case
          </button>
        )}
      </div>

      <div className="toolbar">
        <select
          className="select-input"
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">In progress</option>
          <option value="closed">Closed</option>
          <option value="archived">Archived</option>
        </select>

        <select
          className="select-input"
          value={severityFilter}
          onChange={(e) => {
            setSeverityFilter(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
      </div>

      {error && (isAuthMessage(error) ? <SetupNotice message={error} /> : <div className="alert-box alert-error" role="alert">{error}</div>)}
      {detailError && <div className="alert-box alert-error" role="alert">{detailError}</div>}

      <div className="table-container">
        <div className="table-header-bar">
          <div className="table-header-title">{error ? 'Cases' : `Cases (${total})`}</div>
        </div>

        {loading ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            Loading case records...
          </div>
        ) : error ? null : cases.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            {statusFilter || severityFilter ? (
              'No cases match these filters.'
            ) : (
              <>
                <p>No cases are assigned to you.</p>
                <p style={{ marginTop: '8px', fontSize: '13px' }}>
                  Case access follows assignment. A lead assigns analysts to a case, and only assigned people see it here.
                </p>
              </>
            )}
          </div>
        ) : (
          <table className="data-table table-stack">
            <thead>
              <tr>
                <th>Case number</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Evidence</th>
                <th>Created (UTC)</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => (
                <tr key={c.id}>
                  <td data-label="Case" className="font-mono">{c.case_number}</td>
                  <td data-label="Title" style={{ fontWeight: 500 }}>{c.title}</td>
                  <td data-label="Severity">
                    <span className={`badge badge-${c.severity}`}>{c.severity}</span>
                  </td>
                  <td data-label="Status">
                    <span className={`badge badge-${c.status}`}>{c.status}</span>
                  </td>
                  <td data-label="Evidence">
                    <VerdictBadge item={c} />
                  </td>
                  <td data-label="Created (UTC)" style={{ color: 'var(--text-muted)' }}>
                    {new Date(c.created_at).toISOString().replace('T', ' ').slice(0, 19)}
                  </td>
                  <td data-label="Actions">
                    <button
                      className="btn btn-primary"
                      style={{ padding: '4px 10px', fontSize: '12px', marginRight: '6px' }}
                      onClick={() => setSelectedWorkspaceCaseId(c.id)}
                    >
                      Investigate
                    </button>
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 10px', fontSize: '12px' }}
                      disabled={detailLoading}
                      onClick={() => handleOpenDetail(c.id)}
                    >
                      {detailLoading ? 'Loading...' : 'View Details'}
                    </button>
                    {onNavigateToReport && (
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '4px 8px', fontSize: '12px', marginLeft: '6px' }}
                        onClick={() => onNavigateToReport(c.id)}
                      >
                        Report
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Detail Modal */}
      {selectedCase && (
        <Dialog onClose={() => setSelectedCase(null)} labelledBy="dlg-case-detail-title">
            <div className="modal-header">
              <h3 className="modal-title font-mono" id="dlg-case-detail-title">{selectedCase.case_number}</h3>
              <button className="btn btn-secondary" aria-label="Close dialog" onClick={() => setSelectedCase(null)}><CloseIcon /></button>
            </div>
            <div className="modal-body">
              <h2 style={{ fontSize: '18px', fontWeight: 600, marginBottom: '12px' }}>
                {selectedCase.title}
              </h2>

              <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
                <span className={`badge badge-${selectedCase.severity}`}>{selectedCase.severity}</span>
                <span className={`badge badge-${selectedCase.status}`}>{selectedCase.status}</span>
              </div>

              <div className="form-group">
                <label className="form-label">Briefing & Notes</label>
                <div style={{ background: 'var(--bg-input)', padding: '12px', borderRadius: '6px', fontSize: '13px' }}>
                  {selectedCase.description || 'No briefing recorded.'}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                <div>Lead analyst: <span className="font-mono">{selectedCase.lead_analyst_id}</span></div>
                <div>Created: <span>{new Date(selectedCase.created_at).toLocaleString()}</span></div>
              </div>
            </div>
            <div className="modal-footer">
              <button
                className="btn btn-primary"
                onClick={() => {
                  const id = selectedCase.id;
                  setSelectedCase(null);
                  setSelectedWorkspaceCaseId(id);
                }}
              >
                Open Investigation Workspace
              </button>
              {onNavigateToReport && (
                <button
                  className="btn btn-secondary"
                  onClick={() => {
                    const id = selectedCase.id;
                    setSelectedCase(null);
                    onNavigateToReport(id);
                  }}
                >
                  View / Synthesize Report
                </button>
              )}
              {canCloseCase() && selectedCase.status !== 'closed' && selectedCase.status !== 'archived' && (
                <button
                  className="btn btn-danger"
                  onClick={() => {
                    setCloseError(null);
                    setIsCloseModalOpen(true);
                  }}
                >
                  Close case
                </button>
              )}
              <button className="btn btn-secondary" onClick={() => setSelectedCase(null)}>
                Close Window
              </button>
            </div>
        </Dialog>
      )}

      {/* Create Modal */}
      {isCreateOpen && (
        <Dialog onClose={() => setIsCreateOpen(false)} labelledBy="dlg-case-create-title">
            <form onSubmit={handleCreateCase}>
              <div className="modal-header">
                <h3 className="modal-title" id="dlg-case-create-title">New case</h3>
                <button type="button" className="btn btn-secondary" aria-label="Close dialog" onClick={() => setIsCreateOpen(false)}><CloseIcon /></button>
              </div>
              <div className="modal-body">
                {createError && <div className="alert-box alert-error" role="alert">{createError}</div>}
                <div className="form-group">
                  <label className="form-label">Title *</label>
                  <input
                    type="text"
                    className="input-field"
                    required
                    minLength={3}
                    maxLength={200}
                    placeholder="e.g. Suspicious PowerShell Execution on DC-01"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Severity Tier *</label>
                  <select
                    className="select-input"
                    style={{ width: '100%' }}
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as CaseSeverity)}
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="informational">Informational</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Description</label>
                  <textarea
                    className="input-field"
                    rows={4}
                    maxLength={2000}
                    placeholder="Provide context, host identifiers, and initial observations..."
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                  />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setIsCreateOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={createSubmitting}>
                  {createSubmitting ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
        </Dialog>
      )}

      {/* Close Modal */}
      {isCloseModalOpen && (
        <Dialog onClose={() => setIsCloseModalOpen(false)} labelledBy="dlg-case-close-title">
            <div className="modal-header">
              <h3 className="modal-title" id="dlg-case-close-title">Close case {selectedCase?.case_number}</h3>
              <button className="btn btn-secondary" aria-label="Close dialog" onClick={() => setIsCloseModalOpen(false)}><CloseIcon /></button>
            </div>
            <div className="modal-body">
              {closeError && <div className="alert-box alert-error" role="alert">{closeError}</div>}
              <div className="form-group">
                <label className="form-label">Closure Reason (Mandatory Audit Trail) *</label>
                <textarea
                  className="input-field"
                  rows={3}
                  required
                  placeholder="Explain remediation actions taken or false-positive rationale..."
                  value={closureReason}
                  onChange={(e) => setClosureReason(e.target.value)}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setIsCloseModalOpen(false)}>
                Cancel
              </button>
              <button
                className="btn btn-danger"
                disabled={!closureReason.trim()}
                onClick={handleCloseCase}
              >
                Confirm Closure
              </button>
            </div>
        </Dialog>
      )}
    </div>
  );
};

