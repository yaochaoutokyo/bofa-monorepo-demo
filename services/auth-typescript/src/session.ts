import { randomUUID } from 'crypto';
import { Session } from './types';

export const DEFAULT_IDLE_TIMEOUT_MS = 15 * 60 * 1000;
export const DEFAULT_ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;
export const MAX_CONCURRENT_SESSIONS = 3;

export interface SessionPolicy {
  idleTimeoutMs: number;
  absoluteTimeoutMs: number;
  maxConcurrent: number;
  bindToIp: boolean;
}

export const DEFAULT_SESSION_POLICY: SessionPolicy = {
  idleTimeoutMs: DEFAULT_IDLE_TIMEOUT_MS,
  absoluteTimeoutMs: DEFAULT_ABSOLUTE_TIMEOUT_MS,
  maxConcurrent: MAX_CONCURRENT_SESSIONS,
  bindToIp: true,
};

export interface TouchResult {
  ok: boolean;
  session?: Session;
  reason?: string;
}

export class SessionStore {
  private readonly sessions = new Map<string, Session>();

  constructor(private readonly policy: SessionPolicy = DEFAULT_SESSION_POLICY) {}

  create(userId: string, ipAddress: string, userAgent: string, now: number): Session {
    if (!userId) {
      throw new Error('userId is required');
    }
    const active = this.activeForUser(userId, now);
    if (active.length >= this.policy.maxConcurrent) {
      const oldest = active.sort((a, b) => a.createdAt - b.createdAt)[0];
      this.revoke(oldest.id, 'concurrent session limit');
    }
    const session: Session = {
      id: randomUUID(),
      userId,
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + this.policy.absoluteTimeoutMs,
      ipAddress,
      userAgent,
      revoked: false,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  get(sessionId: string): Session | undefined {
    return this.sessions.get(sessionId);
  }

  touch(sessionId: string, now: number, ipAddress?: string): TouchResult {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return { ok: false, reason: 'unknown session' };
    }
    if (session.revoked) {
      return { ok: false, reason: `session revoked: ${session.revokedReason ?? 'unspecified'}` };
    }
    if (now >= session.expiresAt) {
      this.revoke(sessionId, 'absolute timeout');
      return { ok: false, reason: 'session expired' };
    }
    if (now - session.createdAt > this.policy.idleTimeoutMs && session.lastSeenAt === session.createdAt) {
      this.revoke(sessionId, 'idle timeout');
      return { ok: false, reason: 'session idle' };
    }
    if (this.policy.bindToIp && ipAddress && ipAddress !== session.ipAddress) {
      this.revoke(sessionId, 'ip address changed');
      return { ok: false, reason: 'session bound to different address' };
    }
    session.lastSeenAt = now;
    return { ok: true, session };
  }

  isValid(sessionId: string, now: number): boolean {
    const session = this.sessions.get(sessionId);
    if (!session || session.revoked) {
      return false;
    }
    if (now >= session.expiresAt) {
      return false;
    }
    return now - session.lastSeenAt <= this.policy.idleTimeoutMs;
  }

  revoke(sessionId: string, reason: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session || session.revoked) {
      return false;
    }
    session.revoked = true;
    session.revokedReason = reason;
    return true;
  }

  revokeAllForUser(userId: string, reason: string): number {
    let count = 0;
    for (const session of this.sessions.values()) {
      if (session.userId === userId && !session.revoked) {
        session.revoked = true;
        session.revokedReason = reason;
        count++;
      }
    }
    return count;
  }

  activeForUser(userId: string, now: number): Session[] {
    const result: Session[] = [];
    for (const session of this.sessions.values()) {
      if (session.userId === userId && this.isValid(session.id, now)) {
        result.push(session);
      }
    }
    return result;
  }

  purgeExpired(now: number): number {
    let removed = 0;
    for (const [id, session] of this.sessions.entries()) {
      if (session.revoked || now >= session.expiresAt) {
        this.sessions.delete(id);
        removed++;
      }
    }
    return removed;
  }

  extend(sessionId: string, additionalMs: number, now: number): boolean {
    const session = this.sessions.get(sessionId);
    if (!session || session.revoked || additionalMs <= 0) {
      return false;
    }
    const cap = session.createdAt + this.policy.absoluteTimeoutMs * 2;
    session.expiresAt = Math.min(session.expiresAt + additionalMs, cap);
    session.lastSeenAt = now;
    return true;
  }

  count(): number {
    return this.sessions.size;
  }
}
