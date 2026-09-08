import { DEFAULT_LOCKOUT_POLICY, LockoutTracker } from '../src/lockout';

const NOW = 1_700_000_000_000;
const { maxAttempts, windowMs, baseLockoutMs, maxLockoutMs } = DEFAULT_LOCKOUT_POLICY;

function failUntilLocked(tracker: LockoutTracker, user: string, now: number) {
  let status = tracker.status(user, now);
  for (let i = 0; i <= maxAttempts && !status.locked; i++) {
    status = tracker.recordFailure(user, now + i);
  }
  return status;
}

describe('LockoutTracker.recordFailure', () => {
  it('decrements remaining attempts and locks the account once attempts are exhausted', () => {
    const tracker = new LockoutTracker();
    for (let i = 1; i <= maxAttempts; i++) {
      const status = tracker.recordFailure('jdoe', NOW + i);
      expect(status.locked).toBe(false);
      expect(status.remainingAttempts).toBe(maxAttempts - i);
    }
    const locked = tracker.recordFailure('JDoe', NOW + maxAttempts + 1);
    expect(locked.locked).toBe(true);
    expect(locked.remainingAttempts).toBe(0);
    expect(locked.lockedUntil).toBe(NOW + maxAttempts + 1 + baseLockoutMs);
  });

  it('escalates the lockout duration on repeated lockouts', () => {
    const tracker = new LockoutTracker();
    const first = failUntilLocked(tracker, 'jdoe', NOW);
    const firstDuration = first.lockedUntil! - (NOW + maxAttempts);

    const later = first.lockedUntil! + 1;
    const second = failUntilLocked(tracker, 'jdoe', later);
    const secondDuration = second.lockedUntil! - (later + maxAttempts);

    expect(firstDuration).toBe(baseLockoutMs);
    expect(secondDuration).toBe(baseLockoutMs * 2);
  });

  it('forgets failures that fall outside the window', () => {
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
  it('clears recorded failures', () => {
    const tracker = new LockoutTracker();
    tracker.recordFailure('jdoe', NOW);
    tracker.recordFailure('jdoe', NOW);
    tracker.recordSuccess('JDOE');
    expect(tracker.status('jdoe', NOW)).toEqual({ locked: false, remainingAttempts: maxAttempts });
  });

  it('is a no-op for an unknown user', () => {
    const tracker = new LockoutTracker();
    expect(() => tracker.recordSuccess('nobody')).not.toThrow();
    expect(tracker.status('nobody', NOW)).toEqual({ locked: false, remainingAttempts: maxAttempts });
  });
});

describe('LockoutTracker.status', () => {
  it('reports locked while lockedUntil is in the future and unlocked afterwards', () => {
    const tracker = new LockoutTracker();
    const locked = failUntilLocked(tracker, 'jdoe', NOW);
    expect(tracker.status('jdoe', locked.lockedUntil! - 1)).toEqual({
      locked: true,
      remainingAttempts: 0,
      lockedUntil: locked.lockedUntil,
    });
    expect(tracker.status('jdoe', locked.lockedUntil!)).toEqual({ locked: false, remainingAttempts: maxAttempts });
  });

  it('only counts failures inside the window towards remaining attempts', () => {
    const tracker = new LockoutTracker();
    tracker.recordFailure('jdoe', NOW);
    tracker.recordFailure('jdoe', NOW + 1000);
    expect(tracker.status('jdoe', NOW + 2000).remainingAttempts).toBe(maxAttempts - 2);
    expect(tracker.status('jdoe', NOW + windowMs + 500).remainingAttempts).toBe(maxAttempts - 1);
    expect(tracker.status('jdoe', NOW + windowMs + 2000).remainingAttempts).toBe(maxAttempts);
  });

  it('reports full attempts for an unknown user', () => {
    expect(new LockoutTracker().status('nobody', NOW)).toEqual({ locked: false, remainingAttempts: maxAttempts });
  });
});

describe('LockoutTracker.unlock', () => {
  it('returns false for an unknown user', () => {
    expect(new LockoutTracker().unlock('nobody')).toBe(false);
  });

  it('clears a locked account', () => {
    const tracker = new LockoutTracker();
    const locked = failUntilLocked(tracker, 'jdoe', NOW);
    expect(locked.locked).toBe(true);
    expect(tracker.unlock('JDOE')).toBe(true);
    expect(tracker.status('jdoe', NOW + maxAttempts)).toEqual({ locked: false, remainingAttempts: maxAttempts });
  });
});

describe('LockoutTracker.lockoutDuration', () => {
  const tracker = new LockoutTracker();

  it('returns 0 for a non-positive count', () => {
    expect(tracker.lockoutDuration(0)).toBe(0);
    expect(tracker.lockoutDuration(-1)).toBe(0);
  });

  it('doubles with each lockout', () => {
    expect(tracker.lockoutDuration(1)).toBe(baseLockoutMs);
    expect(tracker.lockoutDuration(2)).toBe(baseLockoutMs * 2);
    expect(tracker.lockoutDuration(3)).toBe(baseLockoutMs * 4);
  });

  it('caps at maxLockoutMs', () => {
    expect(tracker.lockoutDuration(20)).toBe(maxLockoutMs);
  });

  it('honours a custom policy', () => {
    const custom = new LockoutTracker({ maxAttempts: 2, windowMs: 1000, baseLockoutMs: 100, maxLockoutMs: 250 });
    expect(custom.lockoutDuration(1)).toBe(100);
    expect(custom.lockoutDuration(2)).toBe(200);
    expect(custom.lockoutDuration(3)).toBe(250);
  });
});
