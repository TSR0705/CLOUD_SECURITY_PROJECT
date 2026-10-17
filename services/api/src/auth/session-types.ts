/**
 * Core type definitions for Phase P7 Upload Authorization Foundation & Session Security.
 */

export type UploadSessionStatus = 'CREATED' | 'UPLOADING' | 'UPLOADED' | 'FAILED' | 'EXPIRED';

export interface UploadSessionRecord {
  id: string;
  application_id: string;
  api_key_id: string;
  policy_id: string;
  client_ref: string | null;
  original_filename: string;
  declared_mime: string;
  declared_size: number;
  declared_sha256: Buffer | null;
  status: UploadSessionStatus;
  token_jti: string;
  expires_at: Date;
  client_ip: string | null;
  created_at: Date;
  completed_at: Date | null;
}

export interface SecurityPolicyRecord {
  id: string;
  application_id: string;
  version: number;
  document: Record<string, unknown>;
  document_sha256: Buffer;
  created_by: string;
  created_at: Date;
}

export interface CreateUploadSessionOptions {
  applicationId: string;
  apiKeyId: string;
  filename: string;
  declaredSize: number;
  declaredMime: string;
  policyId?: string | undefined;
  declaredSha256?: string | undefined;
  clientRef?: string | undefined;
  durationSeconds?: number | undefined;
  clientIp?: string | undefined;
  requestId?: string | undefined;
}

export interface CreateUploadSessionResult {
  sessionId: string;
  applicationId: string;
  status: UploadSessionStatus;
  quarantineKey: string;
  tokenJti: string;
  policyId: string;
  expiresAt: string;
  maxFileSize: number;
  declaredSize: number;
  declaredMime: string;
}

export interface AuthorizeSessionResult {
  isAuthorized: boolean;
  session?: UploadSessionRecord | undefined;
  reason?: 'NOT_FOUND' | 'EXPIRED' | 'ALREADY_CLAIMED' | 'INVALID_STATE' | undefined;
}
