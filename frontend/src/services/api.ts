/**
 * AISOP Centralized API Client Service.
 *
 * Security Invariants:
 * - Pure in-memory / sessionStorage API credential management (zero long-lived localStorage persistence).
 * - Storage Boundary Notice: sessionStorage is used exclusively for tab-scoped convenience
 *   persistence across page refreshes. sessionStorage is accessible to any script in the
 *   origin context and is NOT an XSS mitigation boundary. Primary defense against XSS is
 *   enforced via strict server-side CSP, React JSX contextual output encoding, and zero innerHTML usage.
 * - Sanitized client-side error normalization (defense-in-depth against backend information disclosure).
 * - Zero token/key logging in error handlers or console output.
 * - Typed request/response contracts for all endpoints.
 * - Rate-limit retry-after awareness (RFC 6585).
 */

import {
  AlertAdaptersResponse,
  AlertDetailResponse,
  AlertIngestRequest,
  AlertIngestResponse,
  AlertSummaryItem,
  CaseAuditEventItem,
  CaseCreateRequest,
  CaseInvestigationSynthesizeRequest,
  CaseResponse,
  CaseScopedEvidenceItem,
  CaseSeverity,
  HealthResponse,
  InvestigationReportBundle,
  InvestigationValidationResult,
  DomainImportResult,
  MultiSourceInvestigation,
  MultiSourceReview,
  MultiSourceReviewRequest,
  MultiSourceSectionName,
  MultiSourceStartRequest,
  NormalizedEventSummary,
  PaginatedResponse,
  ReportExportResponse,
} from '../types';

import { normalizeApiKey } from '../utils/apiKey';
import { apiErrorFromResponse, networkApiError, safeRequestId, unreadableResponseError } from './errors';

class ApiClient {
  private inMemoryApiKey: string = '';
  /** Empty in development (the Vite proxy forwards /api). Set VITE_API_BASE_URL at build time for a hosted backend. */
  private baseUrl: string = (
    (import.meta as unknown as { env?: Record<string, string | undefined> }).env?.VITE_API_BASE_URL ?? ''
  ).replace(/\/+$/, '');

  constructor() {
    // Check sessionStorage only (cleared on browser tab close)
    try {
      const stored = sessionStorage.getItem('aisop_api_key');
      if (stored) {
        this.inMemoryApiKey = stored;
      }
    } catch {
      // Storage access blocked or unavailable
    }
  }

  public setApiKey(key: string, persistSession: boolean = false): void {
    this.inMemoryApiKey = normalizeApiKey(key);
    try {
      if (persistSession && this.inMemoryApiKey) {
        sessionStorage.setItem('aisop_api_key', this.inMemoryApiKey);
      } else {
        sessionStorage.removeItem('aisop_api_key');
      }
    } catch {
      // Silently handle storage exceptions
    }
  }

  public getApiKey(): string {
    return this.inMemoryApiKey;
  }

  public clearApiKey(): void {
    this.inMemoryApiKey = '';
    try {
      sessionStorage.removeItem('aisop_api_key');
    } catch {
      // Silently handle storage exceptions
    }
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    if (this.inMemoryApiKey) {
      // AISOP backend accepts either X-API-Key or Authorization: Bearer
      headers['X-API-Key'] = this.inMemoryApiKey;
    }
    return headers;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      ...this.getHeaders(),
      ...(options.headers as Record<string, string> | undefined),
    };

    let response: Response;
    try {
      response = await fetch(url, {
        ...options,
        headers,
      });
    } catch {
      // Never surface the runtime's raw network error text.
      throw networkApiError();
    }

    const requestIdHeader = response.headers.get('X-Request-ID');

    if (!response.ok) {
      let errorBody: unknown;
      try {
        errorBody = await response.json();
      } catch {
        // Body is not JSON: a status-based safe message is used.
      }
      throw apiErrorFromResponse(response.status, errorBody, requestIdHeader, response.headers.get('Retry-After'));
    }

    try {
      return (await response.json()) as T;
    } catch {
      throw unreadableResponseError(safeRequestId(requestIdHeader));
    }
  }

  // ── Health Probes ────────────────────────────────────────────────────────

  public async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/api/v1/health');
  }

  public async getReadiness(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/api/v1/health/ready');
  }

  // ── Evidence & Telemetry ─────────────────────────────────────────────────

  public async getEvents(params: {
    page?: number;
    limit?: number;
    eventType?: string;
    severity?: string;
    sourceIdentifier?: string;
  } = {}): Promise<PaginatedResponse<NormalizedEventSummary>> {
    const query = new URLSearchParams();
    if (params.page) query.append('page', params.page.toString());
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.eventType) query.append('event_type', params.eventType);
    if (params.severity) query.append('severity', params.severity);
    if (params.sourceIdentifier) query.append('source_identifier', params.sourceIdentifier);

    const queryString = query.toString();
    return this.request<PaginatedResponse<NormalizedEventSummary>>(
      `/api/v1/evidence/events${queryString ? `?${queryString}` : ''}`
    );
  }

  // ── Multi-Source Alert Ingestion & Triage ────────────────────────────────

  public async getAlerts(params: {
    page?: number;
    limit?: number;
    source_type?: string;
    severity?: string;
    category?: string;
    provider?: string;
    source_identifier?: string;
    start_time?: string;
    end_time?: string;
    search?: string;
  } = {}): Promise<PaginatedResponse<AlertSummaryItem>> {
    const query = new URLSearchParams();
    if (params.page) query.append('page', params.page.toString());
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.source_type) query.append('source_type', params.source_type);
    if (params.severity) query.append('severity', params.severity);
    if (params.category) query.append('category', params.category);
    if (params.provider) query.append('provider', params.provider);
    if (params.source_identifier) query.append('source_identifier', params.source_identifier);
    if (params.start_time) query.append('start_time', params.start_time);
    if (params.end_time) query.append('end_time', params.end_time);
    if (params.search) query.append('search', params.search);

    const queryString = query.toString();
    return this.request<PaginatedResponse<AlertSummaryItem>>(
      `/api/v1/alerts${queryString ? `?${queryString}` : ''}`
    );
  }

  public async getAlertDetail(alertId: string): Promise<AlertDetailResponse> {
    return this.request<AlertDetailResponse>(
      `/api/v1/alerts/${encodeURIComponent(alertId)}`
    );
  }

  public async getAlertAdapters(): Promise<AlertAdaptersResponse> {
    return this.request<AlertAdaptersResponse>('/api/v1/alerts/adapters');
  }

  public async ingestAlerts(payload: AlertIngestRequest): Promise<AlertIngestResponse> {
    return this.request<AlertIngestResponse>('/api/v1/alerts/ingest', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // ── Case Management ──────────────────────────────────────────────────────

  public async getCases(params: {
    page?: number;
    limit?: number;
    status?: string;
    severity?: string;
  } = {}): Promise<PaginatedResponse<CaseResponse>> {
    const query = new URLSearchParams();
    if (params.page) query.append('page', params.page.toString());
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.status) query.append('status', params.status);
    if (params.severity) query.append('severity', params.severity);

    const queryString = query.toString();
    return this.request<PaginatedResponse<CaseResponse>>(
      `/api/v1/cases${queryString ? `?${queryString}` : ''}`
    );
  }

  public async getCaseDetail(caseId: string): Promise<CaseResponse> {
    return this.request<CaseResponse>(`/api/v1/cases/${encodeURIComponent(caseId)}`);
  }

  public async createCase(data: CaseCreateRequest): Promise<CaseResponse> {
    return this.request<CaseResponse>('/api/v1/cases', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  public async updateCaseMetadata(
    caseId: string,
    data: { title?: string; description?: string; severity?: CaseSeverity }
  ): Promise<CaseResponse> {
    return this.request<CaseResponse>(`/api/v1/cases/${encodeURIComponent(caseId)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  public async closeCase(
    caseId: string,
    closureReason: string,
    targetStatus: 'closed' | 'archived' = 'closed'
  ): Promise<CaseResponse> {
    return this.request<CaseResponse>(`/api/v1/cases/${encodeURIComponent(caseId)}/close`, {
      method: 'POST',
      body: JSON.stringify({
        status: targetStatus,
        closure_reason: closureReason,
      }),
    });
  }

  public async getCaseEvidence(
    caseId: string,
    params: { page?: number; limit?: number } = {}
  ): Promise<PaginatedResponse<CaseScopedEvidenceItem>> {
    const query = new URLSearchParams();
    if (params.page) query.append('page', params.page.toString());
    if (params.limit) query.append('limit', params.limit.toString());
    const queryString = query.toString();

    return this.request<PaginatedResponse<CaseScopedEvidenceItem>>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/evidence${queryString ? `?${queryString}` : ''}`
    );
  }

  public async linkCaseEvidence(
    caseId: string,
    evidenceId: string
  ): Promise<{ id: string; case_id: string; evidence_id: string }> {
    return this.request<{ id: string; case_id: string; evidence_id: string }>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/evidence`,
      {
        method: 'POST',
        body: JSON.stringify({ evidence_id: evidenceId }),
      }
    );
  }

  public async getCaseActivity(caseId: string): Promise<CaseAuditEventItem[]> {
    return this.request<CaseAuditEventItem[]>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/activity`
    );
  }

  // ── Multi-source investigation (Stage 4, ADR-010) ───────────────────────

  /** Human-initiated; the deterministic workflow needs no model. 201 = stored, 200 = identical evidence reused. */
  public async startMultiSourceInvestigation(
    caseId: string,
    params: MultiSourceStartRequest = {},
    signal?: AbortSignal
  ): Promise<MultiSourceInvestigation> {
    return this.request<MultiSourceInvestigation>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/investigations/multisource`,
      { method: 'POST', body: JSON.stringify(params), signal }
    );
  }

  /** Record the case lead's review (approve or reject) of the latest investigation. Lead only; bound to the fingerprint the reviewer saw. */
  public async reviewMultiSourceInvestigation(caseId: string, body: MultiSourceReviewRequest): Promise<MultiSourceReview> {
    return this.request<MultiSourceReview>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/investigations/multisource/review`,
      { method: 'POST', body: JSON.stringify(body) }
    );
  }

  /** Released report for the latest investigation. The server refuses (409) unless the case lead approved this exact result. */
  public async exportMultiSourceReport(caseId: string): Promise<{ filename: string; markdown: string; evidence_fingerprint: string }> {
    return this.request(`/api/v1/cases/${encodeURIComponent(caseId)}/investigations/multisource/export`);
  }

  /** Import aisop.evidence/1 envelopes into a case. The server validates every record; malformed ones are quarantined. */
  public async importDomainEvidence(caseId: string, records: unknown[]): Promise<DomainImportResult> {
    return this.request<DomainImportResult>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/evidence/domain`,
      { method: 'POST', body: JSON.stringify({ records }) }
    );
  }

  public async getMultiSourceSection<T = Record<string, unknown>>(
    caseId: string,
    section: MultiSourceSectionName
  ): Promise<T> {
    return this.request<T>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/investigations/multisource/${section}`
    );
  }

  // ── Investigation & Reporting ────────────────────────────────────────────

  public async synthesizeCaseInvestigation(
    caseId: string,
    params: CaseInvestigationSynthesizeRequest = {}
  ): Promise<InvestigationValidationResult> {
    return this.request<InvestigationValidationResult>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/investigations/synthesize`,
      {
        method: 'POST',
        body: JSON.stringify(params),
      }
    );
  }

  public async synthesizeCaseReports(
    caseId: string,
    params: CaseInvestigationSynthesizeRequest = {}
  ): Promise<InvestigationReportBundle> {
    return this.request<InvestigationReportBundle>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/reports/synthesize`,
      {
        method: 'POST',
        body: JSON.stringify(params),
      }
    );
  }

  public async exportCaseReport(
    caseId: string,
    params: {
      format?: 'markdown' | 'json';
      view?: 'bundle' | 'executive' | 'technical' | 'detection';
    } = {}
  ): Promise<ReportExportResponse> {
    const query = new URLSearchParams();
    if (params.format) query.append('format', params.format);
    if (params.view) query.append('view', params.view);
    const queryString = query.toString();
    return this.request<ReportExportResponse>(
      `/api/v1/cases/${encodeURIComponent(caseId)}/reports/export${queryString ? `?${queryString}` : ''}`
    );
  }

  public async formatReport(payload: {
    validation_result: any;
    context?: any;
    case_id?: string;
  }): Promise<InvestigationReportBundle> {
    return this.request<InvestigationReportBundle>('/api/v1/reports/format', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }
}

export const api = new ApiClient();

