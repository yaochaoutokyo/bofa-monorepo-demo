import { createHash, randomBytes, timingSafeEqual } from 'crypto';

export interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  requireUpper: boolean;
  requireLower: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
  maxRepeatedChars: number;
  historyDepth: number;
  maxAgeDays: number;
}

export const DEFAULT_POLICY: PasswordPolicy = {
  minLength: 12,
  maxLength: 128,
  requireUpper: true,
  requireLower: true,
  requireDigit: true,
  requireSymbol: true,
  maxRepeatedChars: 3,
  historyDepth: 12,
  maxAgeDays: 90,
};

const COMMON_PASSWORDS = new Set([
  'password',
  'password1',
  'password123',
  '123456789012',
  'qwertyuiop12',
  'letmein12345',
  'welcome12345',
  'bankofamerica',
  'bofa12345678',
]);

const HASH_ITERATIONS = 1000;

export interface PasswordCheck {
  valid: boolean;
  violations: string[];
  strength: 'WEAK' | 'FAIR' | 'STRONG';
}

export function generateSalt(bytes = 16): string {
  return randomBytes(bytes).toString('hex');
}

export function hashPassword(password: string, salt: string): string {
  let digest = `${salt}:${password}`;
  for (let i = 0; i < HASH_ITERATIONS; i++) {
    digest = createHash('sha256').update(digest).digest('hex');
  }
  return digest;
}

export function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  if (!password || !salt || !expectedHash) {
    return false;
  }
  const actual = Buffer.from(hashPassword(password, salt), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  if (actual.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(actual, expected);
}

export function validatePassword(
  password: string,
  policy: PasswordPolicy = DEFAULT_POLICY,
  username?: string,
): PasswordCheck {
  const violations: string[] = [];
  if (password === undefined || password === null) {
    return { valid: false, violations: ['password is required'], strength: 'WEAK' };
  }
  if (password.length < policy.minLength) {
    violations.push(`must be at least ${policy.minLength} characters`);
  }
  if (password.length >= policy.maxLength) {
    violations.push(`must be at most ${policy.maxLength} characters`);
  }
  if (policy.requireUpper && !/[A-Z]/.test(password)) {
    violations.push('must contain an uppercase letter');
  }
  if (policy.requireLower && !/[a-z]/.test(password)) {
    violations.push('must contain a lowercase letter');
  }
  if (policy.requireDigit && !/\d/.test(password)) {
    violations.push('must contain a digit');
  }
  if (policy.requireSymbol && !/[^A-Za-z0-9]/.test(password)) {
    violations.push('must contain a symbol');
  }
  if (hasRepeatedRun(password, policy.maxRepeatedChars)) {
    violations.push(`must not repeat a character more than ${policy.maxRepeatedChars} times in a row`);
  }
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    violations.push('password is too common');
  }
  if (username && password.toLowerCase().includes(username.toLowerCase())) {
    violations.push('must not contain the username');
  }
  if (isSequential(password)) {
    violations.push('must not be a simple sequence');
  }
  return {
    valid: violations.length === 0,
    violations,
    strength: scoreStrength(password),
  };
}

export function hasRepeatedRun(value: string, maxRun: number): boolean {
  let run = 1;
  for (let i = 1; i < value.length; i++) {
    if (value[i] === value[i - 1]) {
      run++;
      if (run > maxRun) {
        return true;
      }
    } else {
      run = 1;
    }
  }
  return false;
}

export function isSequential(value: string): boolean {
  if (value.length < 4) {
    return false;
  }
  let ascending = true;
  let descending = true;
  for (let i = 1; i < value.length; i++) {
    const diff = value.charCodeAt(i) - value.charCodeAt(i - 1);
    if (diff !== 1) ascending = false;
    if (diff !== -1) descending = false;
  }
  return ascending || descending;
}

export function scoreStrength(password: string): 'WEAK' | 'FAIR' | 'STRONG' {
  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  if (new Set(password).size >= password.length * 0.7) score++;
  if (score <= 2) return 'WEAK';
  if (score <= 4) return 'FAIR';
  return 'STRONG';
}

export function isPasswordExpired(passwordChangedAt: number, now: number, policy: PasswordPolicy = DEFAULT_POLICY): boolean {
  const ageMs = now - passwordChangedAt;
  const maxAgeMs = policy.maxAgeDays * 24 * 60 * 60 * 1000;
  return ageMs > maxAgeMs;
}

export function isInHistory(candidateHash: string, history: string[], policy: PasswordPolicy = DEFAULT_POLICY): boolean {
  const recent = history.slice(-policy.historyDepth);
  return recent.includes(candidateHash);
}

export function generateTemporaryPassword(length = 16): string {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%^&*';
  const all = upper + lower + digits + symbols;
  const bytes = randomBytes(length);
  const chars = [
    upper[bytes[0] % upper.length],
    lower[bytes[1] % lower.length],
    digits[bytes[2] % digits.length],
    symbols[bytes[3] % symbols.length],
  ];
  for (let i = 4; i < length; i++) {
    chars.push(all[bytes[i] % all.length]);
  }
  return chars.join('');
}
