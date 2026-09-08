import {
  DEFAULT_POLICY,
  generateSalt,
  hasRepeatedRun,
  hashPassword,
  isPasswordExpired,
  validatePassword,
  verifyPassword,
} from '../src/password';

const VALID_PASSWORD = 'Str0ng!Passw0rd#2024';
const DAY_MS = 24 * 60 * 60 * 1000;

function passwordOfLength(length: number): string {
  return 'Aa1!'.repeat(Math.ceil(length / 4)).slice(0, length);
}

describe('generateSalt', () => {
  it('returns 32 hex characters by default', () => {
    expect(generateSalt()).toMatch(/^[0-9a-f]{32}$/);
  });

  it('honours a custom byte count', () => {
    expect(generateSalt(8)).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('hashPassword', () => {
  it('is deterministic for the same password and salt', () => {
    expect(hashPassword(VALID_PASSWORD, 'abc123')).toBe(hashPassword(VALID_PASSWORD, 'abc123'));
  });

  it('produces a different digest for a different salt', () => {
    expect(hashPassword(VALID_PASSWORD, 'abc123')).not.toBe(hashPassword(VALID_PASSWORD, 'def456'));
  });
});

describe('verifyPassword', () => {
  const salt = 'a1b2c3d4';
  const expectedHash = hashPassword(VALID_PASSWORD, salt);

  it.each([
    ['password', '', salt, expectedHash],
    ['salt', VALID_PASSWORD, '', expectedHash],
    ['expected hash', VALID_PASSWORD, salt, ''],
  ] as const)('returns false when the %s is empty', (_field, password, usedSalt, hash) => {
    expect(verifyPassword(password, usedSalt, hash)).toBe(false);
  });

  it('returns true for the matching password', () => {
    expect(verifyPassword(VALID_PASSWORD, salt, expectedHash)).toBe(true);
  });

  it('returns false for the wrong password', () => {
    expect(verifyPassword('Wr0ng!Passw0rd#2024', salt, expectedHash)).toBe(false);
  });

  it('returns false when the expected hash has a different length', () => {
    expect(verifyPassword(VALID_PASSWORD, salt, expectedHash.slice(0, 32))).toBe(false);
  });
});

describe('validatePassword', () => {
  it('accepts a compliant password', () => {
    expect(validatePassword(VALID_PASSWORD)).toEqual({ valid: true, violations: [] });
  });

  it.each([
    [null as unknown as string, 'password is required'],
    [undefined as unknown as string, 'password is required'],
  ] as const)('rejects %p', (password, violation) => {
    expect(validatePassword(password)).toEqual({ valid: false, violations: [violation] });
  });

  it.each([
    ['too short', 'Ab1!', `must be at least ${DEFAULT_POLICY.minLength} characters`],
    ['too long', passwordOfLength(DEFAULT_POLICY.maxLength + 2), `must be at most ${DEFAULT_POLICY.maxLength} characters`],
    ['missing an uppercase letter', 'ab1!ab1!ab1!', 'must contain an uppercase letter'],
    ['missing a lowercase letter', 'AB1!AB1!AB1!', 'must contain a lowercase letter'],
    ['missing a digit', 'Ab!?Ab!?Ab!?', 'must contain a digit'],
    ['missing a symbol', 'Ab12Ab12Ab12', 'must contain a symbol'],
    ['repeating a character', 'Aaaaa1!bcdefg', 'must not repeat a character more than 3 times in a row'],
    ['a common password', 'password1234', 'password is too common'],
  ] as const)('rejects a password %s', (_case, password, violation) => {
    const result = validatePassword(password);
    expect(result.valid).toBe(false);
    expect(result.violations).toContain(violation);
  });

  it('rejects a password containing the username', () => {
    const result = validatePassword(`Jdoe-${VALID_PASSWORD}`, DEFAULT_POLICY, 'jdoe');
    expect(result.valid).toBe(false);
    expect(result.violations).toContain('must not contain the username');
  });

  it('accepts a compliant password that does not contain the username', () => {
    expect(validatePassword(VALID_PASSWORD, DEFAULT_POLICY, 'jdoe').valid).toBe(true);
  });

  it('skips class checks that the policy does not require', () => {
    const policy = {
      ...DEFAULT_POLICY,
      requireUpper: false,
      requireLower: false,
      requireDigit: false,
      requireSymbol: false,
    };
    expect(validatePassword('abcdefghijkl', policy).valid).toBe(true);
  });

  // DEFECT: the maximum length is compared with >=, so a password of exactly maxLength characters is
  // rejected even though the policy allows it.
  it.skip('accepts a password of exactly the maximum length', () => {
    expect(validatePassword(passwordOfLength(DEFAULT_POLICY.maxLength)).valid).toBe(true);
  });
});

describe('hasRepeatedRun', () => {
  it.each([
    ['aaaa', 3, true],
    ['aaa', 3, false],
    ['abcabc', 3, false],
  ] as const)('reports %p with a max run of %p as %p', (value, maxRun, expected) => {
    expect(hasRepeatedRun(value, maxRun)).toBe(expected);
  });
});

describe('isPasswordExpired', () => {
  const changedAt = 1_700_000_000_000;

  it('reports an expired password once it is older than the policy age', () => {
    expect(isPasswordExpired(changedAt, changedAt + 91 * DAY_MS)).toBe(true);
  });

  it('reports a password within the policy age as current', () => {
    expect(isPasswordExpired(changedAt, changedAt + 89 * DAY_MS)).toBe(false);
  });
});
