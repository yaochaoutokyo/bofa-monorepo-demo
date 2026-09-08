import { DEFAULT_LOCKOUT_POLICY, LockoutPolicy, LockoutTracker } from '../src/lockout';

const T0 = 1_700_000_000_000;
const MINUTE = 60 * 1000;

const POLICY: LockoutPolicy = {
  maxAttempts: 3,
  windowMs: 10 * MINUTE,
  baseLockoutMs: 5 * MINUTE,
  maxLockoutMs: 15 * MINUTE,
};

function failTimes(tracker: LockoutTracker, user: string, count: number, start: number) {
  let status;
  for (let i = 0; i < count; i++) {
    status = tracker.recordFailure(user, start + i);
  }
  return status!;
}

describe('LockoutTracker.recordFailure', () => {
  it('decrements remaining attempts up to maxAttempts without locking', () => {
    const tracker = new LockoutTracker(POLICY);
    expect(tracker.recordFailure('jdoe', T0).remainingAttempts).toBe(2);
    expect(tracker.recordFailure('jdoe', T0 + 1).remainingAttempts).toBe(1);
    const third = tracker.recordFailure('jdoe', T0 + 2);
    expect(third).toEqual({ locked: false, remainingAttempts: 0 });
  });

  it('locks once failures exceed maxAttempts within the window', () => {
    const tracker = new LockoutTracker(POLICY);
    const status = failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, T0);
    expect(status.locked).toBe(true);
    expect(status.remainingAttempts).toBe(0);
    expect(status.lockedUntil).toBe(T0 + POLICY.maxAttempts + POLICY.baseLockoutMs);
  });

  it('escalates lockout duration on repeated lockouts', () => {
    const tracker = new LockoutTracker(POLICY);
    const first = failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, T0);
    expect(first.lockedUntil! - (T0 + POLICY.maxAttempts)).toBe(tracker.lockoutDuration(1));

    const afterFirst = first.lockedUntil! + 1;
    const second = failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, afterFirst);
    expect(second.locked).toBe(true);
    expect(second.lockedUntil! - (afterFirst + POLICY.maxAttempts)).toBe(tracker.lockoutDuration(2));
    expect(tracker.lockoutDuration(2)).toBe(2 * POLICY.baseLockoutMs);
  });

  it('treats usernames case-insensitively', () => {
    const tracker = new LockoutTracker(POLICY);
    tracker.recordFailure('JDoe', T0);
    expect(tracker.recordFailure('jdoe', T0 + 1).remainingAttempts).toBe(1);
  });

  it('tracks users independently', () => {
    const tracker = new LockoutTracker(POLICY);
    failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, T0);
    expect(tracker.status('asmith', T0 + 10)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });

  it('uses the default policy when none is given', () => {
    const tracker = new LockoutTracker();
    expect(tracker.recordFailure('jdoe', T0).remainingAttempts).toBe(DEFAULT_LOCKOUT_POLICY.maxAttempts - 1);
  });
});

describe('LockoutTracker.recordSuccess', () => {
  it('clears accumulated failures so remaining attempts reset', () => {
    const tracker = new LockoutTracker(POLICY);
    tracker.recordFailure('jdoe', T0);
    tracker.recordFailure('jdoe', T0 + 1);
    tracker.recordSuccess('jdoe');
    expect(tracker.status('jdoe', T0 + 2)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });

  it('is a no-op for unknown users', () => {
    const tracker = new LockoutTracker(POLICY);
    expect(() => tracker.recordSuccess('nobody')).not.toThrow();
    expect(tracker.status('nobody', T0)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });
});

describe('LockoutTracker.status', () => {
  it('reports full attempts for an unknown user', () => {
    const tracker = new LockoutTracker(POLICY);
    expect(tracker.status('nobody', T0)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });

  it('reports locked while lockedUntil is in the future and unlocked after', () => {
    const tracker = new LockoutTracker(POLICY);
    const { lockedUntil } = failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, T0);
    expect(tracker.status('jdoe', lockedUntil! - 1)).toEqual({ locked: true, remainingAttempts: 0, lockedUntil });
    expect(tracker.status('jdoe', lockedUntil!)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });

  it('counts only failures inside the window', () => {
    const tracker = new LockoutTracker(POLICY);
    tracker.recordFailure('jdoe', T0);
    tracker.recordFailure('jdoe', T0 + 5 * MINUTE);
    expect(tracker.status('jdoe', T0 + 6 * MINUTE).remainingAttempts).toBe(1);
    expect(tracker.status('jdoe', T0 + POLICY.windowMs).remainingAttempts).toBe(2);
    expect(tracker.status('jdoe', T0 + 5 * MINUTE + POLICY.windowMs).remainingAttempts).toBe(3);
  });
});

describe('LockoutTracker.unlock', () => {
  it('returns false for an unknown user', () => {
    expect(new LockoutTracker(POLICY).unlock('nobody')).toBe(false);
  });

  it('returns true and clears the lock and failures for a known user', () => {
    const tracker = new LockoutTracker(POLICY);
    failTimes(tracker, 'jdoe', POLICY.maxAttempts + 1, T0);
    expect(tracker.status('jdoe', T0 + 10).locked).toBe(true);
    expect(tracker.unlock('JDOE')).toBe(true);
    expect(tracker.status('jdoe', T0 + 10)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });
});

describe('LockoutTracker.lockoutDuration', () => {
  const tracker = new LockoutTracker(POLICY);

  it('returns 0 for a non-positive count', () => {
    expect(tracker.lockoutDuration(0)).toBe(0);
    expect(tracker.lockoutDuration(-1)).toBe(0);
  });

  it('doubles from the base duration', () => {
    expect(tracker.lockoutDuration(1)).toBe(5 * MINUTE);
    expect(tracker.lockoutDuration(2)).toBe(10 * MINUTE);
  });

  it('caps at maxLockoutMs', () => {
    expect(tracker.lockoutDuration(3)).toBe(15 * MINUTE);
    expect(tracker.lockoutDuration(10)).toBe(15 * MINUTE);
  });
});

describe('LockoutTracker window pruning', () => {
  it('does not lock when old failures have aged out of the window', () => {
    const tracker = new LockoutTracker(POLICY);
    failTimes(tracker, 'jdoe', POLICY.maxAttempts, T0);
    const later = T0 + POLICY.windowMs + POLICY.maxAttempts;
    const status = tracker.recordFailure('jdoe', later);
    expect(status).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts - 1 });
  });

  it('still locks when failures are within the window', () => {
    const tracker = new LockoutTracker(POLICY);
    failTimes(tracker, 'jdoe', POLICY.maxAttempts, T0);
    const status = tracker.recordFailure('jdoe', T0 + POLICY.windowMs - 1);
    expect(status.locked).toBe(true);
  });
});
