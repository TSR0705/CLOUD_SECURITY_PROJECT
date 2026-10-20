/**
 * @sug/sdk - SugClient Implementation
 * TypeScript Client for Secure Upload Gateway API
 */

import { SugApiError, type ProblemDetailsData } from './errors.js';
import type {
  SugClientConfig,
  CreateUploadSessionParams,
  UploadSessionResponse,
  UploadOptions,
  UploadResult,
  UploadWorkflowParams,
  UploadWorkflowResult,
  ScanResultResponse,
  DecisionResponse,
  ReviewDecisionParams,
  ReviewDecisionResponse,
  FileMetadataResponse,
  DownloadFileResponse,
  SecurityEventsQuery,
  SecurityEventsResponse,
  AuditVerifyResponse,
} from './types.js';

export class SugClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string | undefined;
  private readonly userToken?: string | undefined;
  private readonly timeoutMs: number;
  private readonly defaultHeaders: Record<string, string>;

  constructor(config: SugClientConfig) {
    if (!config.baseUrl) {
      throw new Error('SugClient requires a non-empty baseUrl');
    }
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.userToken = config.userToken;
    this.timeoutMs = config.timeoutMs ?? 30_000;
    this.defaultHeaders = config.headers ?? {};
  }

  /**
   * Internal helper for executing JSON HTTP requests.
   */
  private async requestJson<T>(
    path: string,
    options: RequestInit & {
      authMode?: 'apiKey' | 'userToken' | 'uploadToken' | 'none' | undefined;
      tokenOverride?: string | undefined;
    } = {},
  ): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const headers = new Headers(this.defaultHeaders);

    // Merge supplied headers
    if (options.headers) {
      const extra = new Headers(options.headers);
      extra.forEach((val, key) => headers.set(key, val));
    }

    if (!headers.has('Accept')) {
      headers.set('Accept', 'application/json, application/problem+json');
    }

    // Set authorization based on authMode
    const authMode = options.authMode ?? 'apiKey';
    if (authMode === 'apiKey') {
      const key = options.tokenOverride ?? this.apiKey;
      if (key) {
        headers.set('Authorization', `Bearer ${key}`);
      }
    } else if (authMode === 'userToken') {
      const token = options.tokenOverride ?? this.userToken;
      if (token) {
        headers.set('Authorization', `Bearer ${token}`);
      }
    } else if (authMode === 'uploadToken' && options.tokenOverride) {
      headers.set('Authorization', `Bearer ${options.tokenOverride}`);
    }

    const timeout = this.timeoutMs;
    const signal = options.signal ?? AbortSignal.timeout(timeout);

    let response: Response;
    try {
      response = await fetch(url, {
        ...options,
        headers,
        signal,
      });
    } catch (err: unknown) {
      if (
        (err as { name?: string }).name === 'TimeoutError' ||
        (err as { name?: string }).name === 'AbortError'
      ) {
        throw new SugApiError(408, {
          title: 'Request Timeout',
          detail: `Request to '${path}' timed out after ${timeout}ms`,
          type: 'urn:sug:error:timeout',
        });
      }
      throw err;
    }

    if (!response.ok) {
      let problem: ProblemDetailsData = {};
      try {
        problem = (await response.json()) as ProblemDetailsData;
      } catch {
        problem = {
          title: response.statusText,
          detail: await response.text().catch(() => response.statusText),
          status: response.status,
        };
      }
      throw new SugApiError(response.status, problem);
    }

    if (response.status === 204) {
      return undefined as unknown as T;
    }

    return (await response.json()) as T;
  }

  // =========================================================================
  // 1. Upload Sessions
  // =========================================================================

  /**
   * Creates a single-use upload session pinned to the active policy.
   */
  public async createUploadSession(
    params: CreateUploadSessionParams,
    apiKeyOverride?: string,
  ): Promise<UploadSessionResponse> {
    return this.requestJson<UploadSessionResponse>('/api/v1/upload/session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(params),
      authMode: 'apiKey',
      tokenOverride: apiKeyOverride,
    });
  }

  /**
   * Retrieves an upload session's current status and policy pinning metadata.
   */
  public async getUploadSession(
    sessionId: string,
    apiKeyOverride?: string,
  ): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>(`/api/v1/upload/${sessionId}/status`, {
      method: 'GET',
      authMode: 'apiKey',
      tokenOverride: apiKeyOverride,
    });
  }

  /**
   * Aborts an existing upload session.
   */
  public async abortUploadSession(sessionId: string, apiKeyOverride?: string): Promise<void> {
    await this.requestJson<void>(`/api/v1/upload/sessions/${sessionId}/abort`, {
      method: 'POST',
      authMode: 'apiKey',
      tokenOverride: apiKeyOverride,
    });
  }

  // =========================================================================
  // 2. Streaming Upload
  // =========================================================================

  /**
   * Streams raw octet-stream bytes directly into quarantine storage using an upload token.
   */
  public async upload(
    sessionId: string,
    uploadToken: string,
    payload: Buffer | Uint8Array | string,
    options?: UploadOptions,
  ): Promise<UploadResult> {
    const url = `${this.baseUrl}/api/v1/upload/${sessionId}`;
    const headers = new Headers(this.defaultHeaders);

    headers.set('Authorization', `Bearer ${uploadToken}`);
    headers.set('Content-Type', options?.contentType ?? 'application/octet-stream');
    headers.set('Accept', 'application/json, application/problem+json');

    const bodyData = typeof payload === 'string' ? Buffer.from(payload) : payload;
    headers.set('Content-Length', String(bodyData.byteLength));

    const timeout = options?.timeoutMs ?? this.timeoutMs;
    const signal = AbortSignal.timeout(timeout);

    let response: Response;
    try {
      response = await fetch(url, {
        method: 'PUT',
        headers,
        body: bodyData,
        signal,
      });
    } catch (err: unknown) {
      if (
        (err as { name?: string }).name === 'TimeoutError' ||
        (err as { name?: string }).name === 'AbortError'
      ) {
        throw new SugApiError(408, {
          title: 'Request Timeout',
          detail: `Upload to '${sessionId}' timed out after ${timeout}ms`,
          type: 'urn:sug:error:timeout',
        });
      }
      throw err;
    }

    if (!response.ok) {
      let problem: ProblemDetailsData = {};
      try {
        problem = (await response.json()) as ProblemDetailsData;
      } catch {
        problem = {
          title: response.statusText,
          detail: await response.text().catch(() => response.statusText),
          status: response.status,
        };
      }
      throw new SugApiError(response.status, problem);
    }

    return (await response.json()) as UploadResult;
  }

  /**
   * High-level convenience method: creates session and performs streaming upload in one call.
   */
  public async uploadFile(
    params: UploadWorkflowParams,
    apiKeyOverride?: string,
  ): Promise<UploadWorkflowResult> {
    const rawPayload =
      typeof params.payload === 'string' ? Buffer.from(params.payload) : params.payload;
    const declaredSize = params.declaredSize ?? rawPayload.byteLength;

    const session = await this.createUploadSession(
      {
        filename: params.filename,
        declaredSize,
        declaredMime: params.declaredMime ?? 'application/octet-stream',
        declaredSha256: params.declaredSha256,
        clientRef: params.clientRef,
      },
      apiKeyOverride,
    );

    const uploadRes = await this.upload(session.sessionId, session.uploadToken, rawPayload, {
      contentType: params.declaredMime ?? 'application/octet-stream',
    });

    return {
      ...uploadRes,
      sessionId: session.sessionId,
    };
  }

  // =========================================================================
  // 3. Scans & Decisions
  // =========================================================================

  /**
   * Retrieves scan job progress, check outcomes, and findings.
   */
  public async getScan(scanJobId: string, apiKeyOverride?: string): Promise<ScanResultResponse> {
    const raw = await this.requestJson<ScanResultResponse & { id?: string; status?: string }>(
      `/api/v1/scans/${scanJobId}`,
      {
        method: 'GET',
        authMode: 'apiKey',
        tokenOverride: apiKeyOverride,
      },
    );
    return {
      ...raw,
      scanJobId: raw.scanJobId ?? raw.id ?? scanJobId,
      scanStatus: (raw.scanStatus ?? raw.status ?? 'SUCCEEDED') as ScanResultResponse['scanStatus'],
    };
  }

  /**
   * Retrieves deterministic security decision for a file version.
   */
  public async getDecision(decisionId: string, apiKeyOverride?: string): Promise<DecisionResponse> {
    return this.requestJson<DecisionResponse>(`/api/v1/security-decisions/${decisionId}`, {
      method: 'GET',
      authMode: 'apiKey',
      tokenOverride: apiKeyOverride,
    });
  }

  /**
   * Submits a manual human review override (ALLOW or BLOCK with justification).
   * Requires an authenticated analyst or admin user token.
   */
  public async reviewDecision(
    decisionId: string,
    params: ReviewDecisionParams,
    userTokenOverride?: string,
  ): Promise<ReviewDecisionResponse> {
    return this.requestJson<ReviewDecisionResponse>(
      `/api/v1/security-decisions/${decisionId}/review`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(params),
        authMode: 'userToken',
        tokenOverride: userTokenOverride,
      },
    );
  }

  // =========================================================================
  // 4. File Operations & Downloads
  // =========================================================================

  /**
   * Retrieves metadata for a file.
   */
  public async getFileMetadata(
    fileId: string,
    apiKeyOverride?: string,
  ): Promise<FileMetadataResponse> {
    return this.requestJson<FileMetadataResponse>(`/api/v1/files/${fileId}/metadata`, {
      method: 'GET',
      authMode: 'apiKey',
      tokenOverride: apiKeyOverride,
    });
  }

  /**
   * Downloads a promoted file with verify-before-release.
   */
  public async downloadFile(
    fileId: string,
    apiKeyOverride?: string,
  ): Promise<DownloadFileResponse> {
    const url = `${this.baseUrl}/api/v1/files/${fileId}`;
    const headers = new Headers(this.defaultHeaders);

    const key = apiKeyOverride ?? this.apiKey;
    if (key) {
      headers.set('Authorization', `Bearer ${key}`);
    }

    const signal = AbortSignal.timeout(this.timeoutMs);
    let response: Response;
    try {
      response = await fetch(url, {
        method: 'GET',
        headers,
        signal,
      });
    } catch (err: unknown) {
      if (
        (err as { name?: string }).name === 'TimeoutError' ||
        (err as { name?: string }).name === 'AbortError'
      ) {
        throw new SugApiError(408, {
          title: 'Request Timeout',
          detail: `Download of '${fileId}' timed out`,
          type: 'urn:sug:error:timeout',
        });
      }
      throw err;
    }

    if (!response.ok) {
      let problem: ProblemDetailsData = {};
      try {
        problem = (await response.json()) as ProblemDetailsData;
      } catch {
        problem = {
          title: response.statusText,
          detail: await response.text().catch(() => response.statusText),
          status: response.status,
        };
      }
      throw new SugApiError(response.status, problem);
    }

    const arrayBuf = await response.arrayBuffer();
    const data = Buffer.from(arrayBuf);
    const contentType = response.headers.get('content-type') || 'application/octet-stream';
    const contentLength = data.byteLength;
    const sha256 =
      response.headers.get('x-payload-sha256') || response.headers.get('x-sha256') || '';
    const contentDisposition = response.headers.get('content-disposition');
    const contentSecurityPolicy = response.headers.get('content-security-policy');

    return {
      data,
      contentType,
      contentLength,
      sha256,
      contentDisposition,
      contentSecurityPolicy,
    };
  }

  /**
   * Soft-deletes a file.
   */
  public async deleteFile(fileId: string, apiKeyOverride?: string): Promise<void> {
    await this.requestJson<void>(`/api/v1/files/${fileId}`, {
      method: 'DELETE',
      authMode: 'apiKey',
      tokenOverride: apiKeyOverride,
    });
  }

  // =========================================================================
  // 5. Audit & Hash-Chain Verification
  // =========================================================================

  /**
   * Queries audit events scoped to tenant or across tenants for auditors.
   */
  public async getSecurityEvents(
    query?: SecurityEventsQuery,
    tokenOverride?: string,
    authMode: 'apiKey' | 'userToken' = 'apiKey',
  ): Promise<SecurityEventsResponse> {
    const params = new URLSearchParams();
    if (query) {
      if (query.limit !== undefined) params.set('limit', String(query.limit));
      if (query.cursor !== undefined) params.set('cursor', query.cursor);
      if (query.action !== undefined) params.set('action', query.action);
      if (query.actor_type !== undefined) params.set('actor_type', query.actor_type);
      if (query.actor_id !== undefined) params.set('actor_id', query.actor_id);
      if (query.file_id !== undefined) params.set('file_id', query.file_id);
      if (query.application_id !== undefined) params.set('application_id', query.application_id);
    }

    const qs = params.toString();
    const path = qs ? `/api/v1/security-events?${qs}` : '/api/v1/security-events';

    return this.requestJson<SecurityEventsResponse>(path, {
      method: 'GET',
      authMode,
      tokenOverride,
    });
  }

  /**
   * Verifies the cryptographic integrity of the PostgreSQL audit log hash chain.
   */
  public async verifyAuditChain(
    query?: { fromSeq?: number; toSeq?: number },
    userTokenOverride?: string,
  ): Promise<AuditVerifyResponse> {
    const params = new URLSearchParams();
    if (query?.fromSeq !== undefined) params.set('fromSeq', String(query.fromSeq));
    if (query?.toSeq !== undefined) params.set('toSeq', String(query.toSeq));

    const qs = params.toString();
    const path = qs ? `/api/v1/audit/verify?${qs}` : '/api/v1/audit/verify';

    return this.requestJson<AuditVerifyResponse>(path, {
      method: 'GET',
      authMode: 'userToken',
      tokenOverride: userTokenOverride,
    });
  }
}
