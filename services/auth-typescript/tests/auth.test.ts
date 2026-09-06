import { LockoutTracker } from '../src/lockout';
import { validatePassword } from '../src/password';
import { maskEmail } from '../src/pii';

describe('password', () => {
  it('accepts a compliant password', () => {
    expect(validatePassword('Str0ng!Passw0rd#2024').valid).toBe(true);
  });
});

describe('pii', () => {
  it('masks the local part of an email address', () => {
    expect(maskEmail('jane.doe@example.com')).toBe('ja******@example.com');
  });
});

describe('lockout', () => {
  it('leaves an account unlocked after a single failure', () => {
    const tracker = new LockoutTracker();
    const status = tracker.recordFailure('jdoe', 1_700_000_000_000);
    expect(status.locked).toBe(false);
    expect(status.remainingAttempts).toBe(4);
  });
});
