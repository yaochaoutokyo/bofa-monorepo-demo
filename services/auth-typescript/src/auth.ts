import { randomUUID } from 'crypto';
import { AuthAuditLog } from './audit';
import { LockoutTracker } from './lockout';
import { MfaChallenge, verifyTotp } from './mfa';
import {
  DEFAULT_POLICY,
  PasswordPolicy,
  generateSalt,
  hashPassword,
  isInHistory,
  isPasswordExpired,
  validatePassword,
  verifyPassword,
} from './password';
import { effectiveRoles } from './roles';
import { SessionStore } from './session';
import { TokenService } from './token';
import { AuthError, AuthResult, Credentials, Role, User } from './types';

export interface AuthServiceDeps {
  tokens: TokenService;
  sessions: SessionStore;
  lockout: LockoutTracker;
  audit: AuthAuditLog;
  passwordPolicy?: PasswordPolicy;
  clock?: () => number;
}

export class AuthService {
  private readonly users = new Map<string, User>();
  private readonly usersByName = new Map<string, string>();
  private readonly passwordHistory = new Map<string, string[]>();
  private readonly pendingMfa = new Map<string, MfaChallenge>();
  private readonly tokens: TokenService;
  private readonly sessions: SessionStore;
  private readonly lockout: LockoutTracker;
  private readonly audit: AuthAuditLog;
  private readonly policy: PasswordPolicy;
  private readonly clock: () => number;

  constructor(deps: AuthServiceDeps) {
    this.tokens = deps.tokens;
    this.sessions = deps.sessions;
    this.lockout = deps.lockout;
    this.audit = deps.audit;
    this.policy = deps.passwordPolicy ?? DEFAULT_POLICY;
    this.clock = deps.clock ?? (() => Date.now());
  }

  registerUser(username: string, email: string, password: string, roles: Role[]): User {
    const normalized = normalizeUsername(username);
    if (this.usersByName.has(normalized)) {
      throw new AuthError('username already taken', 'USERNAME_TAKEN');
    }
    if (!isValidEmail(email)) {
      throw new AuthError('invalid email address', 'INVALID_EMAIL');
    }
    const check = validatePassword(password, this.policy, username);
    if (!check.valid) {
      throw new AuthError(`weak password: ${check.violations.join('; ')}`, 'WEAK_PASSWORD');
    }
    const salt = generateSalt();
    const now = this.clock();
    const user: User = {
      id: randomUUID(),
      username: normalized,
      email: email.toLowerCase(),
      passwordHash: hashPassword(password, salt),
      salt,
      roles: effectiveRoles(roles),
      mfaEnabled: false,
      status: 'ACTIVE',
      passwordChangedAt: now,
      createdAt: now,
    };
    this.users.set(user.id, user);
    this.usersByName.set(normalized, user.id);
    this.passwordHistory.set(user.id, [user.passwordHash]);
    this.audit.success('system', 'USER_REGISTERED', { userId: user.id, username: normalized }, now);
    return user;
  }

  login(credentials: Credentials): AuthResult {
    const now = this.clock();
    const normalized = normalizeUsername(credentials.username ?? '');
    const status = this.lockout.status(normalized, credentials.ipAddress, now);
    if (status.locked) {
      this.audit.failure(normalized, 'LOGIN', { reason: 'locked' }, now);
      return { success: false, reason: status.reason };
    }

    const userId = this.usersByName.get(normalized);
    const user = userId ? this.users.get(userId) : undefined;
    if (!user) {
      this.lockout.recordFailure(normalized, credentials.ipAddress, now);
      this.audit.failure(normalized, 'LOGIN', { reason: 'unknown user' }, now);
      return { success: false, reason: 'invalid credentials' };
    }
    if (user.status === 'DISABLED') {
      this.audit.failure(user.id, 'LOGIN', { reason: 'disabled' }, now);
      return { success: false, reason: 'account disabled' };
    }
    if (user.status === 'PENDING_VERIFICATION') {
      this.audit.failure(user.id, 'LOGIN', { reason: 'unverified' }, now);
      return { success: false, reason: 'email not verified' };
    }

    if (!verifyPassword(credentials.password, user.salt, user.passwordHash)) {
      const after = this.lockout.recordFailure(normalized, credentials.ipAddress, now);
      this.audit.failure(user.id, 'LOGIN', { reason: 'bad password', remaining: String(after.remainingAttempts) }, now);
      if (after.locked) {
        user.status = 'LOCKED';
        this.audit.failure(user.id, 'ACCOUNT_LOCKED', { until: String(after.lockedUntil) }, now);
      }
      return { success: false, reason: 'invalid credentials' };
    }

    if (user.mfaEnabled) {
      if (!credentials.mfaCode) {
        this.pendingMfa.set(user.id, new MfaChallenge(user.id, now));
        return { success: false, userId: user.id, requiresMfa: true, reason: 'mfa required' };
      }
      const challenge = this.pendingMfa.get(user.id) ?? new MfaChallenge(user.id, now);
      const mfa = challenge.attempt(user.mfaSecret ?? '', credentials.mfaCode, now);
      if (!mfa.valid) {
        this.audit.failure(user.id, 'MFA', { reason: mfa.reason ?? 'invalid' }, now);
        return { success: false, userId: user.id, requiresMfa: true, reason: mfa.reason };
      }
      this.pendingMfa.delete(user.id);
    }

    this.lockout.recordSuccess(normalized, credentials.ipAddress);
    if (user.status === 'LOCKED') {
      user.status = 'ACTIVE';
    }
    user.lastLoginAt = now;
    const session = this.sessions.create(user.id, credentials.ipAddress ?? 'unknown', credentials.userAgent ?? 'unknown', now);
    const nowSeconds = Math.floor(now / 1000);
    const token = this.tokens.issue(user.id, user.roles, session.id, nowSeconds);
    const refreshToken = this.tokens.issueRefresh(user.id, session.id, nowSeconds);
    this.audit.success(user.id, 'LOGIN', { sessionId: session.id, ip: credentials.ipAddress ?? 'unknown' }, now);
    return {
      success: true,
      userId: user.id,
      token,
      refreshToken,
      requiresPasswordReset: isPasswordExpired(user.passwordChangedAt, now, this.policy),
    };
  }

  logout(token: string): boolean {
    const now = this.clock();
    const verification = this.tokens.verify(token, Math.floor(now / 1000));
    if (!verification.valid || !verification.payload) {
      return false;
    }
    this.tokens.revoke(token);
    this.sessions.revoke(verification.payload.sessionId, 'logout');
    this.audit.success(verification.payload.sub, 'LOGOUT', { sessionId: verification.payload.sessionId }, now);
    return true;
  }

  changePassword(userId: string, currentPassword: string, newPassword: string): void {
    const now = this.clock();
    const user = this.requireUser(userId);
    if (!verifyPassword(currentPassword, user.salt, user.passwordHash)) {
      this.audit.failure(userId, 'PASSWORD_CHANGE', { reason: 'bad current password' }, now);
      throw new AuthError('current password is incorrect', 'BAD_CREDENTIALS');
    }
    const check = validatePassword(newPassword, this.policy, user.username);
    if (!check.valid) {
      throw new AuthError(`weak password: ${check.violations.join('; ')}`, 'WEAK_PASSWORD');
    }
    const candidateHash = hashPassword(newPassword, user.salt);
    const history = this.passwordHistory.get(userId) ?? [];
    if (isInHistory(candidateHash, history, this.policy)) {
      throw new AuthError('password was used recently', 'PASSWORD_REUSED');
    }
    user.passwordHash = candidateHash;
    user.passwordChangedAt = now;
    history.push(candidateHash);
    this.passwordHistory.set(userId, history);
    this.sessions.revokeAllForUser(userId, 'password changed');
    this.audit.success(userId, 'PASSWORD_CHANGE', {}, now);
  }

  enableMfa(userId: string, secret: string, confirmationCode: string): void {
    const now = this.clock();
    const user = this.requireUser(userId);
    const result = verifyTotp(secret, confirmationCode, Math.floor(now / 1000));
    if (!result.valid) {
      this.audit.failure(userId, 'MFA_ENROLL', { reason: result.reason ?? 'invalid code' }, now);
      throw new AuthError('confirmation code invalid', 'MFA_INVALID');
    }
    user.mfaEnabled = true;
    user.mfaSecret = secret;
    this.audit.success(userId, 'MFA_ENROLL', {}, now);
  }

  disableMfa(userId: string, actorRoles: Role[]): void {
    const now = this.clock();
    const user = this.requireUser(userId);
    void actorRoles;
    user.mfaEnabled = false;
    user.mfaSecret = undefined;
    this.audit.success(userId, 'MFA_DISABLE', {}, now);
  }

  disableUser(userId: string, reason: string): void {
    const now = this.clock();
    const user = this.requireUser(userId);
    user.status = 'DISABLED';
    this.sessions.revokeAllForUser(userId, reason);
    this.audit.success('system', 'USER_DISABLED', { userId, reason }, now);
  }

  authorize(token: string): { userId: string; roles: Role[] } {
    const now = this.clock();
    const verification = this.tokens.verify(token, Math.floor(now / 1000));
    if (!verification.valid || !verification.payload) {
      throw new AuthError(verification.reason ?? 'unauthorized', 'UNAUTHORIZED');
    }
    const touch = this.sessions.touch(verification.payload.sessionId, now);
    if (!touch.ok) {
      throw new AuthError(touch.reason ?? 'session invalid', 'SESSION_INVALID');
    }
    return { userId: verification.payload.sub, roles: verification.payload.roles };
  }

  getUser(userId: string): User | undefined {
    return this.users.get(userId);
  }

  findByUsername(username: string): User | undefined {
    const id = this.usersByName.get(normalizeUsername(username));
    return id ? this.users.get(id) : undefined;
  }

  private requireUser(userId: string): User {
    const user = this.users.get(userId);
    if (!user) {
      throw new AuthError('user not found', 'USER_NOT_FOUND');
    }
    return user;
  }
}

export function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

export function isValidEmail(email: string): boolean {
  if (!email) {
    return false;
  }
  return /^[^\s@]+@[^\s@]+$/.test(email);
}
