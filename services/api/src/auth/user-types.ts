export type UserRole = 'admin' | 'analyst' | 'auditor';

export interface UserRecord {
  id: string;
  email: string;
  password_hash: string;
  role: UserRole;
  is_active: boolean;
  failed_logins: number;
  locked_until: Date | null;
  created_at: Date;
  last_login_at: Date | null;
}

export interface SafeUser {
  id: string;
  email: string;
  role: UserRole;
}

export interface RefreshTokenRecord {
  id: string;
  user_id: string;
  token_hash: Buffer;
  expires_at: Date;
  revoked_at: Date | null;
  replaced_by: string | null;
}

export interface DashboardJwtPayload {
  iss: 'sug-api';
  aud: 'sug-dashboard';
  sub: string;
  role: UserRole;
  email: string;
  iat?: number | undefined;
  exp?: number | undefined;
  typ?: 'JWT' | undefined;
}

export interface LoginResult {
  success: boolean;
  user?: SafeUser | undefined;
  locked?: boolean | undefined;
  reason?: 'INVALID_CREDENTIALS' | 'ACCOUNT_LOCKED' | 'USER_INACTIVE' | undefined;
}

export interface RotateResult {
  success: boolean;
  user?: SafeUser | undefined;
  newRawToken?: string | undefined;
  reason?:
    | 'INVALID_REFRESH_TOKEN'
    | 'TOKEN_EXPIRED'
    | 'TOKEN_REUSE_DETECTED'
    | 'USER_INACTIVE'
    | undefined;
  reuseDetected?: boolean | undefined;
}

export interface LoginRequestBody {
  email: string;
  password: string;
}

export interface LoginResponseData {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  user: SafeUser;
}

export interface RefreshResponseData {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}
