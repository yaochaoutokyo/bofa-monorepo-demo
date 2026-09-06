/**
 * Brute-force protection. Tracks failed attempts per account and per source
 * IP and applies progressively longer lockouts.
 */

export interface LockoutPolicy {
  maxAttempts: number;
  windowMs: number;
  baseLockoutMs: number;
  maxLockoutMs: number;
  ipMaxAttempts: number;
}

export const DEFAULT_LOCKOUT_POLICY: LockoutPolicy = {
  maxAttempts: 5,
  windowMs: 15 * 60 * 1000,
  baseLockoutMs: 15 * 60 * 1000,
  maxLockoutMs: 24 * 60 * 60 * 1000,
  ipMaxAttempts: 20,
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
  reason?: string;
}

export class LockoutTracker {
  private readonly byUser = new Map<string, AttemptRecord>();
  private readonly byIp = new Map<string, AttemptRecord>();

  constructor(private readonly policy: LockoutPolicy = DEFAULT_LOCKOUT_POLICY) {}

  recordFailure(username: string, ipAddress: string | undefined, now: number): LockoutStatus {
    const record = this.getOrCreate(this.byUser, username.toLowerCase());
    this.pruneWindow(record, now);
    record.failures.push(now);

    if (record.failures.length > this.policy.maxAttempts) {
      record.lockoutCount++;
      record.lockedUntil = now + this.lockoutDuration(record.lockoutCount);
      record.failures = [];
    }

    if (ipAddress) {
      const ipRecord = this.getOrCreate(this.byIp, ipAddress);
      this.pruneWindow(ipRecord, now);
      ipRecord.failures.push(now);
      if (ipRecord.failures.length >= this.policy.ipMaxAttempts) {
        ipRecord.lockedUntil = now + this.policy.baseLockoutMs;
        ipRecord.failures = [];
      }
    }
    return this.status(username, ipAddress, now);
  }

  recordSuccess(username: string, ipAddress: string | undefined): void {
    const record = this.byUser.get(username.toLowerCase());
    if (record) {
      record.failures = [];
    }
    if (ipAddress) {
      const ipRecord = this.byIp.get(ipAddress);
      if (ipRecord) {
        ipRecord.failures = [];
      }
    }
  }

  status(username: string, ipAddress: string | undefined, now: number): LockoutStatus {
    const record = this.byUser.get(username.toLowerCase());
    if (record && record.lockedUntil > now) {
      return {
        locked: true,
        remainingAttempts: 0,
        lockedUntil: record.lockedUntil,
        reason: 'account temporarily locked',
      };
    }
    if (ipAddress) {
      const ipRecord = this.byIp.get(ipAddress);
      if (ipRecord && ipRecord.lockedUntil > now) {
        return {
          locked: true,
          remainingAttempts: 0,
          lockedUntil: ipRecord.lockedUntil,
          reason: 'too many attempts from this address',
        };
      }
    }
    const used = record ? this.countInWindow(record, now) : 0;
    return {
      locked: false,
      remainingAttempts: Math.max(0, this.policy.maxAttempts - used),
    };
  }

  isLocked(username: string, now: number): boolean {
    return this.status(username, undefined, now).locked;
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

  lockedAccounts(now: number): string[] {
    const locked: string[] = [];
    for (const [username, record] of this.byUser.entries()) {
      if (record.lockedUntil > now) {
        locked.push(username);
      }
    }
    return locked;
  }

  private getOrCreate(map: Map<string, AttemptRecord>, key: string): AttemptRecord {
    let record = map.get(key);
    if (!record) {
      record = { failures: [], lockedUntil: 0, lockoutCount: 0 };
      map.set(key, record);
    }
    return record;
  }

  private pruneWindow(record: AttemptRecord, now: number): void {
    const cutoff = now - this.policy.windowMs;
    record.failures = record.failures.filter((t) => t > cutoff);
  }

  private countInWindow(record: AttemptRecord, now: number): number {
    const cutoff = now - this.policy.windowMs;
    return record.failures.filter((t) => t > cutoff).length;
  }
}
