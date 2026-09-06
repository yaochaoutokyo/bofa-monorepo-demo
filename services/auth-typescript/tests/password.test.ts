import {
  DEFAULT_POLICY,
  generateSalt,
  hashPassword,
  hasRepeatedRun,
  isPasswordExpired,
  PasswordPolicy,
  validatePassword,
  verifyPassword,
} from '../src/password';

const LENIENT: PasswordPolicy = {
  minLength: 1,
  maxLength: 1000,
  requireUpper: false,
  requireLower: false,
  requireDigit: false,
  requireSymbol: false,
  maxRepeatedChars: 100,
  maxAgeDays: 90,
};

describe('generateSalt', () => {
  it('returns 32 hex chars by default', () => {
    const salt = generateSalt();
    expect(salt).toMatch(/^[0-9a-f]{32}$/);
  });

  it('honours a custom byte length', () => {
    expect(generateSalt(8)).toHaveLength(16);
  });

  it('differs across calls', () => {
    expect(generateSalt()).not.toBe(generateSalt());
  });
});

describe('hashPassword', () => {
  it('is deterministic for the same salt and password', () => {
    expect(hashPassword('secret', 'abc')).toBe(hashPassword('secret', 'abc'));
  });

  it('differs for different salts', () => {
    expect(hashPassword('secret', 'abc')).not.toBe(hashPassword('secret', 'abd'));
  });
});

describe('verifyPassword', () => {
  const salt = generateSalt();
  const hash = hashPassword('Correct!Horse1', salt);

  it('returns true for a matching hash', () => {
    expect(verifyPassword('Correct!Horse1', salt, hash)).toBe(true);
  });

  it('returns false for a wrong password', () => {
    expect(verifyPassword('Wrong!Horse1', salt, hash)).toBe(false);
  });

  it('returns false when any input is empty', () => {
    expect(verifyPassword('', salt, hash)).toBe(false);
    expect(verifyPassword('Correct!Horse1', '', hash)).toBe(false);
    expect(verifyPassword('Correct!Horse1', salt, '')).toBe(false);
  });

  it('returns false when hash lengths differ', () => {
    expect(verifyPassword('Correct!Horse1', salt, hash.slice(0, 10))).toBe(false);
  });
});

describe('validatePassword', () => {
  it('rejects null/undefined passwords', () => {
    expect(validatePassword(undefined as unknown as string)).toEqual({ valid: false, violations: ['password is required'] });
    expect(validatePassword(null as unknown as string)).toEqual({ valid: false, violations: ['password is required'] });
  });

  it('flags too short', () => {
    expect(validatePassword('Ab1!').violations).toContain('must be at least 12 characters');
  });

  it('flags too long (>= maxLength)', () => {
    const pw = 'Ab1!'.repeat(32);
    expect(pw.length).toBe(DEFAULT_POLICY.maxLength);
    expect(validatePassword(pw).violations).toContain('must be at most 128 characters');
  });

  it('flags missing uppercase', () => {
    expect(validatePassword('abcdefgh1234!@#$').violations).toContain('must contain an uppercase letter');
  });

  it('flags missing lowercase', () => {
    expect(validatePassword('ABCDEFGH1234!@#$').violations).toContain('must contain a lowercase letter');
  });

  it('flags missing digit', () => {
    expect(validatePassword('Abcdefghijkl!@#$').violations).toContain('must contain a digit');
  });

  it('flags missing symbol', () => {
    expect(validatePassword('Abcdefghijkl1234').violations).toContain('must contain a symbol');
  });

  it('flags repeated-character runs', () => {
    expect(validatePassword('Aaaaab1!xyzQ2@').violations).toContain('must not repeat a character more than 3 times in a row');
  });

  it('flags common passwords', () => {
    expect(validatePassword('Password1234', LENIENT).violations).toContain('password is too common');
  });

  it('flags passwords containing the username', () => {
    expect(validatePassword('Xjdoe!Secure123', DEFAULT_POLICY, 'JDoe').violations).toContain('must not contain the username');
  });

  it('does not flag username when it is not contained', () => {
    expect(validatePassword('Str0ng!Passw0rd#2024', DEFAULT_POLICY, 'jdoe').violations).not.toContain('must not contain the username');
  });

  it('skips character-class checks when the policy disables them', () => {
    expect(validatePassword('aaaa', LENIENT)).toEqual({ valid: true, violations: [] });
  });

  it('accepts a fully compliant password', () => {
    expect(validatePassword('Str0ng!Passw0rd#2024')).toEqual({ valid: true, violations: [] });
  });
});

describe('hasRepeatedRun', () => {
  it('detects a run longer than maxRun', () => {
    expect(hasRepeatedRun('abbbbc', 3)).toBe(true);
  });

  it('returns false when runs stay within the limit', () => {
    expect(hasRepeatedRun('aabbcc', 2)).toBe(false);
  });

  it('resets the run when characters differ', () => {
    expect(hasRepeatedRun('aabaab', 2)).toBe(false);
  });

  it('handles empty and single-char strings', () => {
    expect(hasRepeatedRun('', 1)).toBe(false);
    expect(hasRepeatedRun('a', 1)).toBe(false);
  });
});

describe('isPasswordExpired', () => {
  const day = 24 * 60 * 60 * 1000;

  it('returns false within the max age', () => {
    expect(isPasswordExpired(0, 89 * day)).toBe(false);
  });

  it('returns true beyond the max age', () => {
    expect(isPasswordExpired(0, 91 * day)).toBe(true);
  });
});
