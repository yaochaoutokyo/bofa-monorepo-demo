export type Role = 'CUSTOMER' | 'TELLER' | 'BRANCH_MANAGER' | 'COMPLIANCE_OFFICER' | 'ADMIN';

export type Permission =
  | 'account:read'
  | 'account:write'
  | 'transaction:create'
  | 'transaction:approve'
  | 'pii:view'
  | 'pii:export'
  | 'audit:read'
  | 'user:manage';

export interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  salt: string;
  roles: Role[];
  mfaEnabled: boolean;
  mfaSecret?: string;
  status: 'ACTIVE' | 'LOCKED' | 'DISABLED' | 'PENDING_VERIFICATION';
  passwordChangedAt: number;
  createdAt: number;
  lastLoginAt?: number;
}

export interface Credentials {
  username: string;
  password: string;
  mfaCode?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface AuthResult {
  success: boolean;
  userId?: string;
  token?: string;
  refreshToken?: string;
  reason?: string;
  requiresMfa?: boolean;
  requiresPasswordReset?: boolean;
}

export interface TokenPayload {
  sub: string;
  roles: Role[];
  iat: number;
  exp: number;
  jti: string;
  sessionId: string;
}

export interface Session {
  id: string;
  userId: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
  ipAddress: string;
  userAgent: string;
  revoked: boolean;
  revokedReason?: string;
}

export interface AuditEvent {
  timestamp: number;
  actor: string;
  action: string;
  outcome: 'SUCCESS' | 'FAILURE';
  details: Record<string, string>;
}

export class AuthError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}
