/**
 * @sug/sdk - Type Definitions
 * Contracts for the Secure Upload Gateway Client SDK
 */

export interface SugClientConfig {
  /**
   * Base URL of the Secure Upload Gateway API (e.g. 'http://127.0.0.1:3000')
   */
  baseUrl: string;

  /**
   * Client Application API Key (format: sug_<env>_<prefix8>_<secret43>)
   */
  apiKey?: string | undefined;

  /**
   * User JWT for administrative/analyst operations (e.g., human review overrides)
   */
  userToken?: string | undefined;

  /**
   * Default timeout in milliseconds (default: 30,000 ms)
   */
  timeoutMs?: number | undefined;

  /**
   * Additional custom headers sent with all requests
   */
  headers?: Record<string, string> | undefined;
}

export interface CreateUploadSessionParams {
  filename: string;
  declaredSize?: number | undefined;
  declaredMime?: string | undefined;
  declaredSha256?: string | undefined;
  clientRef?: string | undefined;
}

export interface UploadSessionResponse {
  sessionId: string;
  uploadToken: string;
  tokenJti: string;
  expiresAt: string;
  expiresInSeconds: number;
  quarantineKey: string;
  policy?: {
    id: string;
    version: number;
    documentSha256: string;
  };
  precheck?: {
    allowed: boolean;
    normalizedFilename: string;
  };
}

export interface UploadOptions {
  contentType?: string | undefined;
  timeoutMs?: number | undefined;
  onProgress?: ((bytesUploaded: number) => void) | undefined;
}

export interface UploadResult {
  fileId: string;
  fileVersionId: string;
  scanJobId: string;
  status: string;
  versionId: string;
  size: number;
  sha256: string;
  identity?: Record<string, unknown> | undefined;
}

export interface UploadWorkflowParams extends CreateUploadSessionParams {
  payload: Buffer | Uint8Array | string;
}

export interface UploadWorkflowResult extends UploadResult {
  sessionId: string;
}

export interface ScanFinding {
  checkId: string;
  engine: string;
  engineVersion?: string;
  signatureVersion?: string;
  outcome: 'PASS' | 'FAIL' | 'SUSPICIOUS' | 'ERROR' | 'SKIPPED';
  reasonCode?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';
  evidence?: Record<string, unknown>;
}

export interface ScanResultResponse {
  scanJobId: string;
  scanStatus: 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'DEAD';
  fileVersionId: string;
  applicationId: string;
  findings: ScanFinding[];
  createdAt?: string;
  finishedAt?: string | null;
}

export interface DecisionResponse {
  id: string;
  fileVersionId: string;
  policyId: string;
  decision: 'ALLOW' | 'BLOCK' | 'REVIEW_REQUIRED';
  primaryReason: string;
  severity: string;
  confidence: string;
  riskScore: number;
  policyResult: string;
  scannerResult: string;
  integrityResult: string;
  authorizationResult: string;
  boundBucket: string;
  boundKey: string;
  boundStorageVersionId: string;
  boundSha256: string;
  boundSize: number;
  record: Record<string, unknown>;
  engineVersion: string;
  decidedBy: string;
  supersedesId?: string | null;
  createdAt: string;
}

export interface ReviewDecisionParams {
  action: 'ALLOW' | 'BLOCK';
  justification: string;
}

export interface ReviewDecisionResponse {
  id: string;
  decision: string;
  action: string;
  fileVersionId: string;
  justification: string;
  decidedBy: string;
  supersedesId: string;
  promotionJobId?: string | null;
}

export interface FileMetadataResponse {
  id: string;
  applicationId: string;
  displayFilename: string;
  status: string;
  fileVersionId?: string | null;
  storageVersionId?: string | null;
  sizeBytes?: number | string | null;
  sha256?: string | null;
  cleanStorageVersionId?: string | null;
  cleanSizeBytes?: number | string | null;
  sha256Plain?: string | null;
}

export interface DownloadFileResponse {
  data: Buffer;
  contentType: string;
  contentLength: number;
  sha256: string;
  contentDisposition?: string | null;
  contentSecurityPolicy?: string | null;
}

export interface SecurityEventsQuery {
  limit?: number | undefined;
  cursor?: string | undefined;
  action?: string | undefined;
  actor_type?: string | undefined;
  actor_id?: string | undefined;
  file_id?: string | undefined;
  application_id?: string | undefined;
}

export interface SecurityEventsResponse {
  events: Array<{
    seq: number;
    id: string;
    occurred_at: string;
    actor_type: string;
    actor_id: string;
    action: string;
    application_id: string | null;
    file_id: string | null;
    file_version_id: string | null;
    decision_id: string | null;
    request_id: string | null;
    details: Record<string, unknown>;
    prev_hash: string;
    event_hash: string;
  }>;
  pagination: {
    limit: number;
    has_more: boolean;
    next_cursor?: string | null;
  };
}

export interface AuditVerifyResponse {
  verified: boolean;
  totalEvents: number;
  startSeq?: number;
  endSeq?: number;
  chainHash?: string;
  error?: string;
}
