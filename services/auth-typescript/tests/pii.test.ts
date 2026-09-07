import {
  PiiKind,
  detectPii,
  isValidEmail,
  luhnCheck,
  maskAccountNumber,
  maskByKind,
  maskCardNumber,
  maskEmail,
  maskSsn,
  redactText,
} from '../src/pii';

describe('maskSsn', () => {
  it('returns empty string for empty input', () => {
    expect(maskSsn('')).toBe('');
  });

  it('passes through values that are not 11 characters', () => {
    expect(maskSsn('123456789')).toBe('123456789');
  });

  it('masks a formatted SSN leaving the last four', () => {
    expect(maskSsn('123-45-6789')).toBe('***-**-6789');
  });
});

describe('maskCardNumber', () => {
  it('throws for too few or too many digits', () => {
    expect(() => maskCardNumber('4111 1111 111')).toThrow('invalid card number length');
    expect(() => maskCardNumber('4'.repeat(20))).toThrow('invalid card number length');
  });

  it('masks all but the last four digits, ignoring separators', () => {
    expect(maskCardNumber('4111 1111 1111 1111')).toBe('************1111');
    expect(maskCardNumber('4111-1111-1111')).toBe('********1111');
  });
});

describe('maskEmail', () => {
  it('returns the input unchanged when there is no local part', () => {
    expect(maskEmail('nobody')).toBe('nobody');
    expect(maskEmail('@example.com')).toBe('@example.com');
  });

  it('keeps one character for short local parts', () => {
    expect(maskEmail('ab@example.com')).toBe('a*@example.com');
    expect(maskEmail('a@example.com')).toBe('a*@example.com');
  });
});

describe('maskAccountNumber', () => {
  it('passes through empty and short values', () => {
    expect(maskAccountNumber('')).toBe('');
    expect(maskAccountNumber('1234')).toBe('1234');
  });

  it('masks longer values leaving the last four', () => {
    expect(maskAccountNumber('9876543210')).toBe('******3210');
  });
});

describe('luhnCheck', () => {
  it('accepts valid card numbers', () => {
    expect(luhnCheck('4111 1111 1111 1111')).toBe(true);
    expect(luhnCheck('79927398713')).toBe(true);
  });

  it('rejects invalid card numbers', () => {
    expect(luhnCheck('4111111111111112')).toBe(false);
  });

  it('treats empty input as valid', () => {
    expect(luhnCheck('')).toBe(true);
    expect(luhnCheck('--')).toBe(true);
  });
});

describe('detectPii', () => {
  it('detects SSN, card, and email with offsets sorted by start', () => {
    const text = 'mail jane@example.com card 4111 1111 1111 1111 ssn 123-45-6789';
    const matches = detectPii(text);
    expect(matches).toEqual([
      { kind: 'EMAIL', value: 'jane@example.com', start: 5, end: 21 },
      { kind: 'CARD', value: '4111 1111 1111 1111', start: 27, end: 46 },
      { kind: 'SSN', value: '123-45-6789', start: 51, end: 62 },
    ]);
  });

  it('returns an empty array when there is no PII', () => {
    expect(detectPii('nothing to see here')).toEqual([]);
  });

  it('is stateless across calls with global regexes', () => {
    expect(detectPii('123-45-6789')).toHaveLength(1);
    expect(detectPii('123-45-6789')).toHaveLength(1);
  });
});

describe('maskByKind', () => {
  it('dispatches to the correct masker per kind', () => {
    expect(maskByKind('SSN', '123-45-6789')).toBe('***-**-6789');
    expect(maskByKind('CARD', '4111111111111111')).toBe('************1111');
    expect(maskByKind('EMAIL', 'jane.doe@example.com')).toBe('ja******@example.com');
    expect(maskByKind('ACCOUNT', '9876543210')).toBe('******3210');
  });

  it('falls back to [REDACTED] for unknown kinds', () => {
    expect(maskByKind('PASSPORT' as PiiKind, 'X1234567')).toBe('[REDACTED]');
  });
});

describe('redactText', () => {
  it('returns text without PII unchanged', () => {
    expect(redactText('hello world')).toBe('hello world');
  });

  it('redacts mixed PII in place', () => {
    const text = 'ssn 123-45-6789, card 4111-1111-1111-1111, email jane.doe@example.com end';
    expect(redactText(text)).toBe('ssn ***-**-6789, card ************1111, email ja******@example.com end');
  });
});

describe('isValidEmail', () => {
  it('accepts a well-formed email', () => {
    expect(isValidEmail('jane@example.com')).toBe(true);
  });

  it('rejects emails over 254 characters', () => {
    expect(isValidEmail(`${'a'.repeat(250)}@x.io`)).toBe(false);
  });

  it('rejects malformed emails', () => {
    expect(isValidEmail('jane')).toBe(false);
    expect(isValidEmail('jane@@example.com')).toBe(false);
    expect(isValidEmail('jane doe@example.com')).toBe(false);
  });
});
