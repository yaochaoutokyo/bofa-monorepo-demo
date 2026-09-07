import { DEFAULT_LOCKOUT_POLICY, LockoutTracker } from '../src/lockout';

const NOW = 1_700_000_000_000;
const { maxAttempts, windowMs, baseLockoutMs, maxLockoutMs } = DEFAULT_LOCKOUT_POLICY;

function lockOut(tracker: LockoutTracker, user: string, now: number) {
  let status = tracker.recordFailure(user, now);
  for (let i = 0; i < maxAttempts; i++) {
    status = tracker.recordFailure(user, now);
  }
  return status;
}

describe('LockoutTracker.recordFailure', () => {
  it('decrements remaining attempts and locks after exceeding maxAttempts', () => {
    const tracker = new LockoutTracker();
    for (let i = 1; i <= maxAttempts; i++) {
      const status = tracker.recordFailure('jdoe', NOW);
      expect(status.locked).toBe(false);
      expect(status.remainingAttempts).toBe(maxAttempts - i);
    }
    const locked = tracker.recordFailure('JDoe', NOW);
    expect(locked).toEqual({ locked: true, remainingAttempts: 0, lockedUntil: NOW + baseLockoutMs });
  });

  it('escalates the lockout duration on repeated lockouts', () => {
    const tracker = new LockoutTracker();
    const first = lockOut(tracker, 'jdoe', NOW);
    const afterFirst = first.lockedUntil! + 1;
    const second = lockOut(tracker, 'jdoe', afterFirst);
    expect(second.lockedUntil).toBe(afterFirst + baseLockoutMs * 2);
  });

  it('prunes failures outside the window before counting', () => {
    const tracker = new LockoutTracker();
    for (let i = 0; i < maxAttempts; i++) {
      tracker.recordFailure('jdoe', NOW);
    }
    const status = tracker.recordFailure('jdoe', NOW + windowMs + 1);
    expect(status.locked).toBe(false);
    expect(status.remainingAttempts).toBe(maxAttempts - 1);
  });
});

describe('LockoutTracker.recordSuccess', () => {
  it('clears failures so remaining attempts reset', () => {
    const tracker = new LockoutTracker();
    tracker.recordFailure('jdoe', NOW);
    tracker.recordFailure('jdoe', NOW);
    tracker.recordSuccess('JDOE');
    expect(tracker.status('jdoe', NOW).remainingAttempts).toBe(maxAttempts);
  });

  it('is a no-op for unknown users', () => {
    const tracker = new LockoutTracker();
    expect(() => tracker.recordSuccess('nobody')).not.toThrow();
    expect(tracker.status('nobody', NOW)).toEqual({ locked: false, remainingAttempts: maxAttempts });
  });
});

describe('LockoutTracker.status', () => {
  it('reports full attempts for unknown users', () => {
    expect(new LockoutTracker().status('ghost', NOW)).toEqual({ locked: false, remainingAttempts: maxAttempts });
  });

  it('reports locked while lockedUntil is in the future and unlocks once it passes', () => {
    const tracker = new LockoutTracker();
    const locked = lockOut(tracker, 'jdoe', NOW);
    expect(tracker.status('jdoe', NOW + 1)).toEqual({ locked: true, remainingAttempts: 0, lockedUntil: locked.lockedUntil });
    expect(tracker.status('jdoe', locked.lockedUntil!)).toEqual({ locked: false, remainingAttempts: maxAttempts });
  });

  it('ignores failures older than the window', () => {
    const tracker = new LockoutTracker();
    tracker.recordFailure('jdoe', NOW);
    tracker.recordFailure('jdoe', NOW + 1000);
    expect(tracker.status('jdoe', NOW + 500).remainingAttempts).toBe(maxAttempts - 2);
    expect(tracker.status('jdoe', NOW + windowMs + 500).remainingAttempts).toBe(maxAttempts - 1);
    expect(tracker.status('jdoe', NOW + windowMs + 2000).remainingAttempts).toBe(maxAttempts);
  });
});

describe('LockoutTracker.unlock', () => {
  it('returns false for an unknown user', () => {
    expect(new LockoutTracker().unlock('ghost')).toBe(false);
  });

  it('returns true and clears the lockout for a locked user', () => {
    const tracker = new LockoutTracker();
    lockOut(tracker, 'jdoe', NOW);
    expect(tracker.unlock('JDOE')).toBe(true);
    expect(tracker.status('jdoe', NOW)).toEqual({ locked: false, remainingAttempts: maxAttempts });
  });
});

describe('LockoutTracker.lockoutDuration', () => {
  const tracker = new LockoutTracker();

  it('returns 0 for non-positive counts', () => {
    expect(tracker.lockoutDuration(0)).toBe(0);
    expect(tracker.lockoutDuration(-1)).toBe(0);
  });

  it('grows exponentially', () => {
    expect(tracker.lockoutDuration(1)).toBe(baseLockoutMs);
    expect(tracker.lockoutDuration(2)).toBe(baseLockoutMs * 2);
    expect(tracker.lockoutDuration(3)).toBe(baseLockoutMs * 4);
  });

  it('caps at maxLockoutMs', () => {
    expect(tracker.lockoutDuration(20)).toBe(maxLockoutMs);
  });

  it('honours a custom policy', () => {
    const custom = new LockoutTracker({ maxAttempts: 2, windowMs: 1000, baseLockoutMs: 100, maxLockoutMs: 150 });
    expect(custom.lockoutDuration(1)).toBe(100);
    expect(custom.lockoutDuration(2)).toBe(150);
    custom.recordFailure('u', NOW);
    custom.recordFailure('u', NOW);
    expect(custom.recordFailure('u', NOW)).toEqual({ locked: true, remainingAttempts: 0, lockedUntil: NOW + 100 });
  });
});
