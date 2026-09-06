import { DEFAULT_LOCKOUT_POLICY, LockoutPolicy, LockoutTracker } from '../src/lockout';

const POLICY: LockoutPolicy = {
  maxAttempts: 2,
  windowMs: 1000,
  baseLockoutMs: 100,
  maxLockoutMs: 350,
};

const T0 = 1_700_000_000_000;

function lockAccount(tracker: LockoutTracker, user: string, now: number): number {
  let status = tracker.status(user, now);
  while (!status.locked) {
    status = tracker.recordFailure(user, now);
  }
  return status.lockedUntil as number;
}

describe('recordFailure', () => {
  it('leaves the account unlocked after a single failure', () => {
    const tracker = new LockoutTracker();
    expect(tracker.recordFailure('jdoe', T0)).toEqual({
      locked: false,
      remainingAttempts: DEFAULT_LOCKOUT_POLICY.maxAttempts - 1,
    });
  });

  it('locks the account when maxAttempts is exceeded', () => {
    const tracker = new LockoutTracker(POLICY);
    expect(tracker.recordFailure('jdoe', T0).remainingAttempts).toBe(1);
    expect(tracker.recordFailure('jdoe', T0).remainingAttempts).toBe(0);
    const status = tracker.recordFailure('JDoe', T0);
    expect(status).toEqual({ locked: true, remainingAttempts: 0, lockedUntil: T0 + POLICY.baseLockoutMs });
  });

  it('escalates lockout duration and caps at maxLockoutMs', () => {
    const tracker = new LockoutTracker(POLICY);
    let now = T0;
    const durations: number[] = [];
    for (let i = 0; i < 4; i++) {
      const lockedUntil = lockAccount(tracker, 'jdoe', now);
      durations.push(lockedUntil - now);
      now = lockedUntil + 1;
    }
    expect(durations).toEqual([100, 200, 350, 350]);
  });
});

describe('lockoutDuration', () => {
  const tracker = new LockoutTracker(POLICY);

  it('returns 0 for count <= 0', () => {
    expect(tracker.lockoutDuration(0)).toBe(0);
    expect(tracker.lockoutDuration(-1)).toBe(0);
  });

  it('doubles per lockout and caps', () => {
    expect(tracker.lockoutDuration(1)).toBe(100);
    expect(tracker.lockoutDuration(2)).toBe(200);
    expect(tracker.lockoutDuration(3)).toBe(350);
    expect(tracker.lockoutDuration(10)).toBe(350);
  });
});

describe('recordSuccess', () => {
  it('clears failures for a known user', () => {
    const tracker = new LockoutTracker(POLICY);
    tracker.recordFailure('jdoe', T0);
    tracker.recordSuccess('JDOE');
    expect(tracker.status('jdoe', T0).remainingAttempts).toBe(POLICY.maxAttempts);
  });

  it('is a no-op for an unknown user', () => {
    const tracker = new LockoutTracker(POLICY);
    expect(() => tracker.recordSuccess('ghost')).not.toThrow();
    expect(tracker.status('ghost', T0)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });
});

describe('status', () => {
  it('reports locked while lockedUntil > now and unlocked afterwards', () => {
    const tracker = new LockoutTracker(POLICY);
    const lockedUntil = lockAccount(tracker, 'jdoe', T0);
    expect(tracker.status('jdoe', lockedUntil - 1)).toEqual({ locked: true, remainingAttempts: 0, lockedUntil });
    expect(tracker.status('jdoe', lockedUntil)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });

  it('prunes failures outside the window', () => {
    const tracker = new LockoutTracker(POLICY);
    tracker.recordFailure('jdoe', T0);
    expect(tracker.status('jdoe', T0).remainingAttempts).toBe(1);
    expect(tracker.status('jdoe', T0 + POLICY.windowMs - 1).remainingAttempts).toBe(1);
    expect(tracker.status('jdoe', T0 + POLICY.windowMs).remainingAttempts).toBe(POLICY.maxAttempts);
  });

  it('prunes old failures before counting a new one', () => {
    const tracker = new LockoutTracker(POLICY);
    tracker.recordFailure('jdoe', T0);
    tracker.recordFailure('jdoe', T0);
    const status = tracker.recordFailure('jdoe', T0 + POLICY.windowMs + 1);
    expect(status).toEqual({ locked: false, remainingAttempts: 1 });
  });

  it('returns full attempts for an unknown user', () => {
    const tracker = new LockoutTracker(POLICY);
    expect(tracker.status('nobody', T0)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });
});

describe('unlock', () => {
  it('returns false for an unknown user', () => {
    expect(new LockoutTracker(POLICY).unlock('ghost')).toBe(false);
  });

  it('returns true and clears the lock for a known user', () => {
    const tracker = new LockoutTracker(POLICY);
    lockAccount(tracker, 'jdoe', T0);
    expect(tracker.unlock('JDOE')).toBe(true);
    expect(tracker.status('jdoe', T0)).toEqual({ locked: false, remainingAttempts: POLICY.maxAttempts });
  });
});
