import {
  DEFAULT_POLICY,
  generateSalt,
  hashPassword,
  hasRepeatedRun,
  isPasswordExpired,
  validatePassword,
  verifyPassword,
} from '../src/password';

describe('validatePassword', () => {
  it('rejects null and undefined passwords', () => {
    expect(validatePassword(undefined as unknown as string)).toEqual({ valid: false, violations: ['password is required'] });
    expect(validatePassword(null as unknown as string)).toEqual({ valid: false, violations: ['password is required'] });
  });

  it('rejects passwords shorter than minLength', () => {
    const result = validatePassword('Sh0rt!a');
    expect(result.valid).toBe(false);
    expect(result.violations).toContain(`must be at least ${DEFAULT_POLICY.minLength} characters`);
  });

  it('rejects passwords at or over maxLength', () => {
    const result = validatePassword('Aa1!' + 'x'.repeat(DEFAULT_POLICY.maxLength));
    expect(result.violations).toContain(`must be at most ${DEFAULT_POLICY.maxLength} characters`);
  });

  it('rejects missing uppercase', () => {
    expect(validatePassword('str0ng!passw0rd#2024').violations).toContain('must contain an uppercase letter');
  });

  it('rejects missing lowercase', () => {
    expect(validatePassword('STR0NG!PASSW0RD#2024').violations).toContain('must contain a lowercase letter');
  });

  it('rejects missing digit', () => {
    expect(validatePassword('Strong!Password#Abcd').violations).toContain('must contain a digit');
  });

  it('rejects missing symbol', () => {
    expect(validatePassword('Str0ngPassw0rd2024ab').violations).toContain('must contain a symbol');
  });

  it('rejects repeated character runs beyond maxRepeatedChars', () => {
    expect(validatePassword('Str0ng!Passsssw0rd#1').violations).toContain(
      `must not repeat a character more than ${DEFAULT_POLICY.maxRepeatedChars} times in a row`,
    );
  });

  it('rejects common passwords case-insensitively', () => {
    expect(validatePassword('BankOfAmerica').violations).toContain('password is too common');
  });

  it('rejects passwords containing the username', () => {
    const result = validatePassword('Str0ng!JDoe#Passw0rd', DEFAULT_POLICY, 'jdoe');
    expect(result.valid).toBe(false);
    expect(result.violations).toEqual(['must not contain the username']);
  });

  it('skips optional character requirements when the policy disables them', () => {
    const relaxed = { ...DEFAULT_POLICY, requireUpper: false, requireLower: false, requireDigit: false, requireSymbol: false };
    expect(validatePassword('abcdefghijkl', relaxed).valid).toBe(true);
  });
});

describe('hashPassword / generateSalt', () => {
  it('produces a deterministic hash for the same salt and password', () => {
    expect(hashPassword('secret', 'salt')).toBe(hashPassword('secret', 'salt'));
  });

  it('produces different hashes for different salts', () => {
    expect(hashPassword('secret', 'salt-a')).not.toBe(hashPassword('secret', 'salt-b'));
  });

  it('generates a hex salt of the expected length', () => {
    expect(generateSalt()).toMatch(/^[0-9a-f]{32}$/);
    expect(generateSalt(8)).toMatch(/^[0-9a-f]{16}$/);
    expect(generateSalt()).not.toBe(generateSalt());
  });
});

describe('verifyPassword', () => {
  const salt = generateSalt();
  const hash = hashPassword('Correct!Horse1', salt);

  it('returns true for the correct password', () => {
    expect(verifyPassword('Correct!Horse1', salt, hash)).toBe(true);
  });

  it('returns false for the wrong password', () => {
    expect(verifyPassword('Wrong!Horse1', salt, hash)).toBe(false);
  });

  it('returns false for empty or missing arguments', () => {
    expect(verifyPassword('', salt, hash)).toBe(false);
    expect(verifyPassword('Correct!Horse1', '', hash)).toBe(false);
    expect(verifyPassword('Correct!Horse1', salt, '')).toBe(false);
  });

  it('returns false when the expected hash has a different length', () => {
    expect(verifyPassword('Correct!Horse1', salt, 'abcd')).toBe(false);
  });
});

describe('isPasswordExpired', () => {
  const day = 24 * 60 * 60 * 1000;
  const changedAt = 1_700_000_000_000;

  it('is expired once the age exceeds maxAgeDays', () => {
    expect(isPasswordExpired(changedAt, changedAt + DEFAULT_POLICY.maxAgeDays * day + 1)).toBe(true);
  });

  it('is not expired within maxAgeDays', () => {
    expect(isPasswordExpired(changedAt, changedAt + DEFAULT_POLICY.maxAgeDays * day)).toBe(false);
    expect(isPasswordExpired(changedAt, changedAt + 5 * day, { ...DEFAULT_POLICY, maxAgeDays: 10 })).toBe(false);
  });
});

describe('hasRepeatedRun', () => {
  it('detects a run longer than maxRun', () => {
    expect(hasRepeatedRun('aaaa', 3)).toBe(true);
    expect(hasRepeatedRun('xaaab', 2)).toBe(true);
  });

  it('allows runs up to maxRun', () => {
    expect(hasRepeatedRun('aaa', 3)).toBe(false);
    expect(hasRepeatedRun('abab', 1)).toBe(false);
    expect(hasRepeatedRun('', 1)).toBe(false);
  });
});
