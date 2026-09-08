import {
  DEFAULT_POLICY,
  generateSalt,
  hashPassword,
  hasRepeatedRun,
  isPasswordExpired,
  validatePassword,
  verifyPassword,
} from '../src/password';

const RELAXED = { ...DEFAULT_POLICY, requireUpper: false, requireLower: false, requireDigit: false, requireSymbol: false };

describe('validatePassword', () => {
  it('rejects null or undefined passwords', () => {
    expect(validatePassword(null as unknown as string)).toEqual({ valid: false, violations: ['password is required'] });
    expect(validatePassword(undefined as unknown as string)).toEqual({ valid: false, violations: ['password is required'] });
  });

  it('flags passwords shorter than minLength', () => {
    const result = validatePassword('Sh0rt!Pw');
    expect(result.valid).toBe(false);
    expect(result.violations).toContain(`must be at least ${DEFAULT_POLICY.minLength} characters`);
  });

  it('flags passwords at or above maxLength', () => {
    const result = validatePassword(`Aa1!${'x'.repeat(DEFAULT_POLICY.maxLength)}`);
    expect(result.violations).toContain(`must be at most ${DEFAULT_POLICY.maxLength} characters`);
  });

  it('flags a missing uppercase letter', () => {
    expect(validatePassword('str0ng!passw0rd#2024').violations).toEqual(['must contain an uppercase letter']);
  });

  it('flags a missing lowercase letter', () => {
    expect(validatePassword('STR0NG!PASSW0RD#2024').violations).toEqual(['must contain a lowercase letter']);
  });

  it('flags a missing digit', () => {
    expect(validatePassword('Strong!Password#Word').violations).toEqual(['must contain a digit']);
  });

  it('flags a missing symbol', () => {
    expect(validatePassword('Str0ngPassw0rd2024x').violations).toEqual(['must contain a symbol']);
  });

  it('flags a character repeated too many times in a row', () => {
    expect(validatePassword('Str0ng!Paaaassw0rd#').violations).toEqual([
      `must not repeat a character more than ${DEFAULT_POLICY.maxRepeatedChars} times in a row`,
    ]);
  });

  it('flags a common password', () => {
    expect(validatePassword('BankOfAmerica', RELAXED).violations).toEqual(['password is too common']);
  });

  it('flags a password containing the username', () => {
    expect(validatePassword('Str0ng!JDoePassw0rd#', DEFAULT_POLICY, 'jdoe').violations).toEqual(['must not contain the username']);
  });

  it('does not check the username when none is supplied', () => {
    expect(validatePassword('Str0ng!JDoePassw0rd#').valid).toBe(true);
  });

  it('skips character-class checks when the policy disables them', () => {
    expect(validatePassword('justlowercaseletters', RELAXED).valid).toBe(true);
  });
});

describe('hashPassword / verifyPassword', () => {
  it('is deterministic for the same salt and password', () => {
    expect(hashPassword('pw', 'salt')).toBe(hashPassword('pw', 'salt'));
    expect(hashPassword('pw', 'salt')).toMatch(/^[0-9a-f]{64}$/);
    expect(hashPassword('pw', 'other')).not.toBe(hashPassword('pw', 'salt'));
  });

  it('verifies a matching password', () => {
    const hash = hashPassword('Correct!Horse1', 'salt');
    expect(verifyPassword('Correct!Horse1', 'salt', hash)).toBe(true);
  });

  it('rejects a wrong password', () => {
    const hash = hashPassword('Correct!Horse1', 'salt');
    expect(verifyPassword('Wrong!Horse1', 'salt', hash)).toBe(false);
  });

  it('rejects empty or missing arguments', () => {
    const hash = hashPassword('pw', 'salt');
    expect(verifyPassword('', 'salt', hash)).toBe(false);
    expect(verifyPassword('pw', '', hash)).toBe(false);
    expect(verifyPassword('pw', 'salt', '')).toBe(false);
  });

  it('rejects a hash of a different length', () => {
    expect(verifyPassword('pw', 'salt', 'abcd')).toBe(false);
  });
});

describe('generateSalt', () => {
  it('returns hex of twice the byte length', () => {
    expect(generateSalt()).toMatch(/^[0-9a-f]{32}$/);
    expect(generateSalt(8)).toMatch(/^[0-9a-f]{16}$/);
  });

  it('differs across calls', () => {
    expect(generateSalt()).not.toBe(generateSalt());
  });
});

describe('isPasswordExpired', () => {
  const DAY_MS = 24 * 60 * 60 * 1000;
  const now = 1_700_000_000_000;

  it('is expired when older than maxAgeDays', () => {
    expect(isPasswordExpired(now - (DEFAULT_POLICY.maxAgeDays * DAY_MS + 1), now)).toBe(true);
  });

  it('is not expired within the window', () => {
    expect(isPasswordExpired(now - DEFAULT_POLICY.maxAgeDays * DAY_MS, now)).toBe(false);
    expect(isPasswordExpired(now - 5 * DAY_MS, now, { ...DEFAULT_POLICY, maxAgeDays: 10 })).toBe(false);
  });
});

describe('hasRepeatedRun', () => {
  it('detects a run longer than maxRun', () => {
    expect(hasRepeatedRun('abbbba', 3)).toBe(true);
  });

  it('allows runs up to maxRun', () => {
    expect(hasRepeatedRun('abbba', 3)).toBe(false);
    expect(hasRepeatedRun('', 3)).toBe(false);
    expect(hasRepeatedRun('abab', 1)).toBe(false);
  });
});
