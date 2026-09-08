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

const HEX = /^[0-9a-f]+$/;

describe('generateSalt', () => {
  it('returns 32 hex chars for the default 16 bytes', () => {
    const salt = generateSalt();
    expect(salt).toHaveLength(32);
    expect(salt).toMatch(HEX);
  });

  it('honours a custom byte length', () => {
    expect(generateSalt(8)).toHaveLength(16);
    expect(generateSalt(32)).toHaveLength(64);
  });

  it('produces different salts on successive calls', () => {
    expect(generateSalt()).not.toBe(generateSalt());
  });
});

describe('hashPassword', () => {
  it('is deterministic for the same password and salt', () => {
    expect(hashPassword('Secret!123', 'abc')).toBe(hashPassword('Secret!123', 'abc'));
  });

  it('returns a 64-char hex sha256 digest', () => {
    const hash = hashPassword('Secret!123', 'abc');
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(HEX);
  });

  it('differs when the salt differs', () => {
    expect(hashPassword('Secret!123', 'abc')).not.toBe(hashPassword('Secret!123', 'abd'));
  });

  it('differs when the password differs', () => {
    expect(hashPassword('Secret!123', 'abc')).not.toBe(hashPassword('Secret!124', 'abc'));
  });
});

describe('verifyPassword', () => {
  const salt = 'deadbeefdeadbeefdeadbeefdeadbeef';
  const hash = hashPassword('Correct#Horse9', salt);

  it('returns true for a matching triple', () => {
    expect(verifyPassword('Correct#Horse9', salt, hash)).toBe(true);
  });

  it('returns false for the wrong password', () => {
    expect(verifyPassword('Wrong#Horse9', salt, hash)).toBe(false);
  });

  it('returns false for the wrong salt', () => {
    expect(verifyPassword('Correct#Horse9', 'other', hash)).toBe(false);
  });

  it('returns false for empty inputs', () => {
    expect(verifyPassword('', salt, hash)).toBe(false);
    expect(verifyPassword('Correct#Horse9', '', hash)).toBe(false);
    expect(verifyPassword('Correct#Horse9', salt, '')).toBe(false);
  });

  it('returns false when hash lengths differ', () => {
    expect(verifyPassword('Correct#Horse9', salt, hash.slice(0, 32))).toBe(false);
  });
});

describe('validatePassword', () => {
  const compliant = 'Str0ng!Passw0rd#2024';

  it('accepts a compliant password with no violations', () => {
    expect(validatePassword(compliant)).toEqual({ valid: true, violations: [] });
  });

  it('rejects null/undefined passwords', () => {
    expect(validatePassword(undefined as unknown as string)).toEqual({ valid: false, violations: ['password is required'] });
    expect(validatePassword(null as unknown as string)).toEqual({ valid: false, violations: ['password is required'] });
  });

  it('flags passwords shorter than minLength', () => {
    const result = validatePassword('Sh0rt!x');
    expect(result.valid).toBe(false);
    expect(result.violations).toContain('must be at least 12 characters');
  });

  it('flags passwords exceeding maxLength', () => {
    const policy: PasswordPolicy = { ...DEFAULT_POLICY, maxLength: 20 };
    const result = validatePassword('Str0ng!Passw0rd#2024-extra', policy);
    expect(result.valid).toBe(false);
    expect(result.violations).toContain('must be at most 20 characters');
  });

  it('flags a missing uppercase letter', () => {
    expect(validatePassword('str0ng!passw0rd#2024').violations).toContain('must contain an uppercase letter');
  });

  it('flags a missing lowercase letter', () => {
    expect(validatePassword('STR0NG!PASSW0RD#2024').violations).toContain('must contain a lowercase letter');
  });

  it('flags a missing digit', () => {
    expect(validatePassword('Strong!Password#Abcd').violations).toContain('must contain a digit');
  });

  it('flags a missing symbol', () => {
    expect(validatePassword('Str0ngPassw0rd2024ab').violations).toContain('must contain a symbol');
  });

  it('flags a repeated character run', () => {
    expect(validatePassword('Str0ng!Passsssw0rd#2024').violations).toContain(
      'must not repeat a character more than 3 times in a row',
    );
  });

  it('flags common passwords case-insensitively', () => {
    const result = validatePassword('BankOfAmerica');
    expect(result.valid).toBe(false);
    expect(result.violations).toContain('password is too common');
  });

  it('flags passwords containing the username case-insensitively', () => {
    const result = validatePassword('Str0ng!JDoe#Passw0rd', DEFAULT_POLICY, 'jdoe');
    expect(result.valid).toBe(false);
    expect(result.violations).toContain('must not contain the username');
  });

  it('does not flag the username when it is absent from the password', () => {
    expect(validatePassword(compliant, DEFAULT_POLICY, 'jdoe').valid).toBe(true);
  });

  it('skips character-class checks the policy disables', () => {
    const policy: PasswordPolicy = {
      ...DEFAULT_POLICY,
      requireUpper: false,
      requireLower: false,
      requireDigit: false,
      requireSymbol: false,
    };
    expect(validatePassword('abcdefghijklmnop', policy)).toEqual({ valid: true, violations: [] });
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
  it('returns true when a char repeats more than maxRun times in a row', () => {
    expect(hasRepeatedRun('abcccc', 3)).toBe(true);
    expect(hasRepeatedRun('aa', 1)).toBe(true);
  });

  it('returns false when no run exceeds maxRun', () => {
    expect(hasRepeatedRun('abccc', 3)).toBe(false);
    expect(hasRepeatedRun('abcabc', 1)).toBe(false);
    expect(hasRepeatedRun('', 1)).toBe(false);
    expect(hasRepeatedRun('a', 1)).toBe(false);
  });

  it('resets the run when the character changes', () => {
    expect(hasRepeatedRun('aabaab', 2)).toBe(false);
  });
});

describe('isPasswordExpired', () => {
  const DAY_MS = 24 * 60 * 60 * 1000;
  const changedAt = 1_700_000_000_000;

  it('returns false within the max-age window', () => {
    expect(isPasswordExpired(changedAt, changedAt + 89 * DAY_MS)).toBe(false);
    expect(isPasswordExpired(changedAt, changedAt + 90 * DAY_MS)).toBe(false);
  });

  it('returns true once max age is exceeded', () => {
    expect(isPasswordExpired(changedAt, changedAt + 90 * DAY_MS + 1)).toBe(true);
  });

  it('respects a custom maxAgeDays', () => {
    const policy: PasswordPolicy = { ...DEFAULT_POLICY, maxAgeDays: 1 };
    expect(isPasswordExpired(changedAt, changedAt + DAY_MS, policy)).toBe(false);
    expect(isPasswordExpired(changedAt, changedAt + DAY_MS + 1, policy)).toBe(true);
  });
});
