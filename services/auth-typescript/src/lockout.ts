/** Brute-force protection: per-account failed-attempt tracking with escalating lockouts. */

export interface LockoutPolicy {
  maxAttempts: number;
  windowMs: number;
  baseLockoutMs: number;
  maxLockoutMs: number;
}

export const DEFAULT_LOCKOUT_POLICY: LockoutPolicy = {
  maxAttempts: 5,
  windowMs: 15 * 60 * 1000,
  baseLockoutMs: 15 * 60 * 1000,
  maxLockoutMs: 24 * 60 * 60 * 1000,
};

interface AttemptRecord {
  failures: number[];
  lockedUntil: number;
  lockoutCount: number;
}

export interface LockoutStatus {
  locked: boolean;
  remainingAttempts: number;
  lockedUntil?: number;
}

export class LockoutTracker {
  private readonly byUser = new Map<string, AttemptRecord>();

  constructor(private readonly policy: LockoutPolicy = DEFAULT_LOCKOUT_POLICY) {}

  recordFailure(username: string, now: number): LockoutStatus {
    const key = username.toLowerCase();
    let record = this.byUser.get(key);
    if (!record) {
      record = { failures: [], lockedUntil: 0, lockoutCount: 0 };
      this.byUser.set(key, record);
    }
    this.pruneWindow(record, now);
    record.failures.push(now);

    if (record.failures.length > this.policy.maxAttempts) {
      record.lockoutCount++;
      record.lockedUntil = now + this.lockoutDuration(record.lockoutCount);
      record.failures = [];
    }
    return this.status(username, now);
  }

  recordSuccess(username: string): void {
    const record = this.byUser.get(username.toLowerCase());
    if (record) {
      record.failures = [];
    }
  }

  status(username: string, now: number): LockoutStatus {
    const record = this.byUser.get(username.toLowerCase());
    if (record && record.lockedUntil > now) {
      return { locked: true, remainingAttempts: 0, lockedUntil: record.lockedUntil };
    }
    const used = record ? record.failures.filter((t) => t > now - this.policy.windowMs).length : 0;
    return { locked: false, remainingAttempts: Math.max(0, this.policy.maxAttempts - used) };
  }

  unlock(username: string): boolean {
    const record = this.byUser.get(username.toLowerCase());
    if (!record) {
      return false;
    }
    record.lockedUntil = 0;
    record.failures = [];
    return true;
  }

  lockoutDuration(lockoutCount: number): number {
    if (lockoutCount <= 0) {
      return 0;
    }
    const duration = this.policy.baseLockoutMs * Math.pow(2, lockoutCount - 1);
    return Math.min(duration, this.policy.maxLockoutMs);
  }

  private pruneWindow(record: AttemptRecord, now: number): void {
    const cutoff = now - this.policy.windowMs;
    record.failures = record.failures.filter((t) => t > cutoff);
  }
}
