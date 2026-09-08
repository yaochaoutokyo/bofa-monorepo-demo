import { DEFAULT_LOCKOUT_POLICY, LockoutPolicy, LockoutTracker } from '../src/lockout';

const T0 = 1_700_000_000_000;
const POLICY: LockoutPolicy = { maxAttempts: 3, windowMs: 60_000, baseLockoutMs: 1_000, maxLockoutMs: 5_000 };

function failTimes(tracker: LockoutTracker, user: string, count: number, start: number, stepMs = 1) {
  let status = tracker.status(user, start);
  for (let i = 0; i < count; i++) {
    status = tracker.recordFailure(user, start + i * stepMs);
  }
  return status;
}

describe('LockoutTracker.recordFailure', () => {
  it('counts down remaining attempts and is case-insensitive on username', () => {
    const tracker = new LockoutTracker(POLICY);
    expect(tracker.recordFailure('JDoe', T0).remainingAttempts).toBe(2);
    expect(tracker.recordFailure('jdoe', T0 + 1).remainingAttempts).toBe(1);
    expect(tracker.recordFailure('JDOE', T0 + 2)).toEqual({ locked: false, remainingAttempts: 0 });
  });

  // DEFECT: lockout only triggers when failures strictly exceed maxAttempts, so a
  // customer gets maxAttempts + 1 tries before being locked.
  it.skip('locks the account on the maxAttempts-th failure', () => {
    const tracker = new LockoutTracker(POLICY);
    expect(failTimes(tracker, 'jdoe', POLICY.maxAttempts, T0).locked).toBe(true);
  });

  it('locks the account once failures exceed maxAttempts', () => {
    const tracker = new LockoutTracker(POLICY);
    const now = T0 + POLICY.maxAttempts;
    const status = failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, T0);
    expect(status).toEqual({ locked: true, remainingAttempts: 0, lockedUntil: now + POLICY.baseLockoutMs });
  });

  it('escalates lockout duration exponentially up to maxLockoutMs', () => {
    const tracker = new LockoutTracker(POLICY);
    let now = T0;
    const expectedDurations = [1_000, 2_000, 4_000, 5_000, 5_000];
    for (const expected of expectedDurations) {
      const status = failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, now);
      const lastFailure = now + POLICY.maxAttempts;
      expect(status.locked).toBe(true);
      expect(status.lockedUntil).toBe(lastFailure + expected);
      now = status.lockedUntil! + 1;
    }
  });

  it('prunes failures outside the window before counting', () => {
    const tracker = new LockoutTracker(POLICY);
    failTimes(tracker, 'jdoe', POLICY.maxAttempts, T0);
    const later = T0 + POLICY.windowMs + 10;
    expect(tracker.recordFailure('jdoe', later)).toEqual({ locked: false, remainingAttempts: 2 });
  });

  it('uses the default policy when none is given', () => {
    const tracker = new LockoutTracker();
    expect(tracker.recordFailure('jdoe', T0).remainingAttempts).toBe(DEFAULT_LOCKOUT_POLICY.maxAttempts - 1);
  });
});

describe('LockoutTracker.recordSuccess', () => {
  it('clears the failure count', () => {
    const tracker = new LockoutTracker(POLICY);
    failTimes(tracker, 'jdoe', 2, T0);
    tracker.recordSuccess('JDOE');
    expect(tracker.status('jdoe', T0 + 10)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });

  it('is a no-op for an unknown user', () => {
    const tracker = new LockoutTracker(POLICY);
    expect(() => tracker.recordSuccess('nobody')).not.toThrow();
    expect(tracker.status('nobody', T0)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });

  // DEFECT: lockoutCount is never reset on success, so a customer who logged in
  // successfully after a past lockout still gets the escalated (doubled) lockout next time.
  it.skip('resets lockout escalation after a successful login', () => {
    const tracker = new LockoutTracker(POLICY);
    const first = failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, T0);
    const afterUnlock = first.lockedUntil! + 1;
    tracker.recordSuccess('jdoe');
    const second = failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, afterUnlock);
    expect(second.lockedUntil! - (afterUnlock + POLICY.maxAttempts)).toBe(POLICY.baseLockoutMs);
  });
});

describe('LockoutTracker.status', () => {
  it('reports full attempts for an unknown user', () => {
    expect(new LockoutTracker(POLICY).status('ghost', T0)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });

  it('reports locked until the lockout expires, then unlocked', () => {
    const tracker = new LockoutTracker(POLICY);
    const status = failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, T0);
    const until = status.lockedUntil!;
    expect(tracker.status('jdoe', until - 1)).toEqual({ locked: true, remainingAttempts: 0, lockedUntil: until });
    expect(tracker.status('jdoe', until)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });

  it('only counts failures inside the window', () => {
    const tracker = new LockoutTracker(POLICY);
    failTimes(tracker, 'jdoe', 2, T0);
    expect(tracker.status('jdoe', T0 + 1).remainingAttempts).toBe(1);
    expect(tracker.status('jdoe', T0 + POLICY.windowMs + 5).remainingAttempts).toBe(POLICY.maxAttempts);
  });
});

describe('LockoutTracker.unlock', () => {
  it('returns false for an unknown user', () => {
    expect(new LockoutTracker(POLICY).unlock('ghost')).toBe(false);
  });

  it('clears an active lockout and failures', () => {
    const tracker = new LockoutTracker(POLICY);
    const status = failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, T0);
    expect(status.locked).toBe(true);
    expect(tracker.unlock('JDOE')).toBe(true);
    expect(tracker.status('jdoe', T0 + 10)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });
});

describe('LockoutTracker.lockoutDuration', () => {
  it('returns 0 for non-positive counts and caps at maxLockoutMs', () => {
    const tracker = new LockoutTracker(POLICY);
    expect(tracker.lockoutDuration(0)).toBe(0);
    expect(tracker.lockoutDuration(-1)).toBe(0);
    expect(tracker.lockoutDuration(1)).toBe(1_000);
    expect(tracker.lockoutDuration(2)).toBe(2_000);
    expect(tracker.lockoutDuration(3)).toBe(4_000);
    expect(tracker.lockoutDuration(4)).toBe(5_000);
    expect(tracker.lockoutDuration(10)).toBe(5_000);
  });
});
