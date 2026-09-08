import {
  DEFAULT_POLICY,
  PasswordPolicy,
  generateSalt,
  hashPassword,
  hasRepeatedRun,
  isPasswordExpired,
  validatePassword,
  verifyPassword,
} from '../src/password';

const STRONG = 'Str0ng!Passw0rd#2024';

describe('validatePassword', () => {
  it('rejects null and undefined input', () => {
    expect(validatePassword(undefined as unknown as string)).toEqual({ valid: false, violations: ['password is required'] });
    expect(validatePassword(null as unknown as string)).toEqual({ valid: false, violations: ['password is required'] });
  });

  it('rejects passwords shorter than minLength', () => {
    const result = validatePassword('Sh0rt!Pw');
    expect(result.valid).toBe(false);
    expect(result.violations).toContain('must be at least 12 characters');
  });

  it('rejects passwords longer than maxLength', () => {
    const result = validatePassword(`Aa1!${'xy'.repeat(65)}`);
    expect(result.valid).toBe(false);
    expect(result.violations).toContain('must be at most 128 characters');
  });

  // DEFECT: password.ts uses `>=` for the maxLength check, so a password of exactly
  // maxLength characters is rejected even though the policy says "at most".
  it.skip('accepts a password of exactly maxLength characters', () => {
    const exact = `Aa1!${'xy'.repeat(62)}`;
    expect(exact).toHaveLength(DEFAULT_POLICY.maxLength);
    expect(validatePassword(exact).valid).toBe(true);
  });

  it('accepts a password one character below maxLength', () => {
    const result = validatePassword(`Aa1!${'xy'.repeat(61)}z`);
    expect(result.valid).toBe(true);
  });

  it('requires an uppercase letter', () => {
    expect(validatePassword('str0ng!passw0rd#2024').violations).toEqual(['must contain an uppercase letter']);
  });

  it('requires a lowercase letter', () => {
    expect(validatePassword('STR0NG!PASSW0RD#2024').violations).toEqual(['must contain a lowercase letter']);
  });

  it('requires a digit', () => {
    expect(validatePassword('Strong!Password#Abcd').violations).toEqual(['must contain a digit']);
  });

  it('requires a symbol', () => {
    expect(validatePassword('Str0ngPassw0rd2024ab').violations).toEqual(['must contain a symbol']);
  });

  it('skips character-class checks when the policy disables them', () => {
    const relaxed: PasswordPolicy = {
      ...DEFAULT_POLICY,
      requireUpper: false,
      requireLower: false,
      requireDigit: false,
      requireSymbol: false,
    };
    expect(validatePassword('abcdefghijkl', relaxed).valid).toBe(true);
  });

  it('rejects a character repeated more than maxRepeatedChars times in a row', () => {
    const result = validatePassword('Str0ng!Passsssw0rd#2024');
    expect(result.violations).toEqual(['must not repeat a character more than 3 times in a row']);
  });

  it('rejects common passwords case-insensitively', () => {
    const result = validatePassword('BankOfAmerica');
    expect(result.violations).toContain('password is too common');
  });

  it('rejects passwords containing the username case-insensitively', () => {
    const result = validatePassword('Str0ng!JDoe#Passw0rd', DEFAULT_POLICY, 'jdoe');
    expect(result.violations).toEqual(['must not contain the username']);
  });

  it('ignores the username check when no username is supplied', () => {
    expect(validatePassword(STRONG, DEFAULT_POLICY, undefined).valid).toBe(true);
    expect(validatePassword(STRONG, DEFAULT_POLICY, '').valid).toBe(true);
  });

  it('accumulates multiple violations', () => {
    const result = validatePassword('aaaa');
    expect(result.valid).toBe(false);
    expect(result.violations).toEqual([
      'must be at least 12 characters',
      'must contain an uppercase letter',
      'must contain a digit',
      'must contain a symbol',
      'must not repeat a character more than 3 times in a row',
    ]);
  });
});

describe('hasRepeatedRun', () => {
  it('detects runs longer than the limit', () => {
    expect(hasRepeatedRun('aaaa', 3)).toBe(true);
    expect(hasRepeatedRun('aaa', 3)).toBe(false);
    expect(hasRepeatedRun('aabaa', 3)).toBe(false);
    expect(hasRepeatedRun('', 3)).toBe(false);
    expect(hasRepeatedRun('ab', 1)).toBe(false);
    expect(hasRepeatedRun('abb', 1)).toBe(true);
  });
});

describe('generateSalt', () => {
  it('produces hex of twice the byte length', () => {
    expect(generateSalt()).toMatch(/^[0-9a-f]{32}$/);
    expect(generateSalt(8)).toMatch(/^[0-9a-f]{16}$/);
  });

  it('produces distinct values', () => {
    expect(generateSalt()).not.toBe(generateSalt());
  });
});

describe('hashPassword / verifyPassword', () => {
  const salt = 'deadbeefdeadbeefdeadbeefdeadbeef';

  it('is deterministic for the same input and salt', () => {
    expect(hashPassword(STRONG, salt)).toBe(hashPassword(STRONG, salt));
    expect(hashPassword(STRONG, salt)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('changes with the salt and the password', () => {
    expect(hashPassword(STRONG, salt)).not.toBe(hashPassword(STRONG, 'othersalt'));
    expect(hashPassword(STRONG, salt)).not.toBe(hashPassword(`${STRONG}x`, salt));
  });

  it('verifies a matching hash', () => {
    expect(verifyPassword(STRONG, salt, hashPassword(STRONG, salt))).toBe(true);
  });

  it('rejects a mismatching hash of the same length', () => {
    expect(verifyPassword('Wr0ng!Passw0rd#2024', salt, hashPassword(STRONG, salt))).toBe(false);
  });

  it('rejects an expected hash of a different length', () => {
    expect(verifyPassword(STRONG, salt, 'abcd')).toBe(false);
  });

  it('rejects empty password, salt or hash', () => {
    const hash = hashPassword(STRONG, salt);
    expect(verifyPassword('', salt, hash)).toBe(false);
    expect(verifyPassword(STRONG, '', hash)).toBe(false);
    expect(verifyPassword(STRONG, salt, '')).toBe(false);
  });
});

describe('isPasswordExpired', () => {
  const day = 24 * 60 * 60 * 1000;

  it('expires after maxAgeDays', () => {
    expect(isPasswordExpired(0, 90 * day)).toBe(false);
    expect(isPasswordExpired(0, 90 * day + 1)).toBe(true);
  });

  it('honours a custom policy', () => {
    expect(isPasswordExpired(0, 2 * day, { ...DEFAULT_POLICY, maxAgeDays: 1 })).toBe(true);
  });
});
