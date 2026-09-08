import {
  detectPii,
  isValidEmail,
  luhnCheck,
  maskAccountNumber,
  maskByKind,
  maskCardNumber,
  maskEmail,
  maskSsn,
  PiiKind,
  redactText,
} from '../src/pii';

describe('maskSsn', () => {
  it('returns an empty string for empty input', () => {
    expect(maskSsn('')).toBe('');
  });

  it('passes through input that is not 11 characters', () => {
    expect(maskSsn('123456789')).toBe('123456789');
  });

  it('masks all but the last four digits', () => {
    expect(maskSsn('123-45-6789')).toBe('***-**-6789');
  });
});

describe('maskCardNumber', () => {
  it('throws when fewer than 12 digits', () => {
    expect(() => maskCardNumber('4111 1111 111')).toThrow('invalid card number length');
  });

  it('throws when more than 19 digits', () => {
    expect(() => maskCardNumber('1'.repeat(20))).toThrow('invalid card number length');
  });

  it('masks a valid PAN keeping the last four digits', () => {
    expect(maskCardNumber('4111 1111 1111 1111')).toBe('************1111');
  });
});

describe('maskEmail', () => {
  it('returns the input unchanged when there is no local part', () => {
    expect(maskEmail('no-at-sign')).toBe('no-at-sign');
    expect(maskEmail('@example.com')).toBe('@example.com');
  });

  it('keeps only the first character for short local parts', () => {
    expect(maskEmail('ab@example.com')).toBe('a*@example.com');
    expect(maskEmail('a@example.com')).toBe('a*@example.com');
  });
});

describe('maskAccountNumber', () => {
  it('passes through empty and short account numbers', () => {
    expect(maskAccountNumber('')).toBe('');
    expect(maskAccountNumber('1234')).toBe('1234');
  });

  it('masks all but the last four characters', () => {
    expect(maskAccountNumber('987654321')).toBe('*****4321');
  });
});

describe('luhnCheck', () => {
  it('returns true for an empty string', () => {
    expect(luhnCheck('')).toBe(true);
  });

  it('returns true for a valid card number', () => {
    expect(luhnCheck('4111 1111 1111 1111')).toBe(true);
    expect(luhnCheck('79927398713')).toBe(true);
  });

  it('returns false for an invalid card number', () => {
    expect(luhnCheck('4111111111111112')).toBe(false);
  });
});

describe('detectPii', () => {
  it('finds SSN, card and email matches sorted by position', () => {
    const text = 'email jane@example.com ssn 123-45-6789 card 4111-1111-1111-1111';
    const matches = detectPii(text);
    expect(matches.map((m) => m.kind)).toEqual(['EMAIL', 'SSN', 'CARD']);
    expect(matches[0]).toEqual({ kind: 'EMAIL', value: 'jane@example.com', start: 6, end: 22 });
    expect(matches[1].value).toBe('123-45-6789');
    expect(matches[2].value).toBe('4111-1111-1111-1111');
    for (let i = 1; i < matches.length; i++) {
      expect(matches[i].start).toBeGreaterThan(matches[i - 1].start);
    }
  });

  it('returns an empty array when there is nothing to find', () => {
    expect(detectPii('')).toEqual([]);
    expect(detectPii('nothing sensitive here')).toEqual([]);
  });
});

describe('maskByKind', () => {
  it('dispatches to the masker for each kind', () => {
    expect(maskByKind('SSN', '123-45-6789')).toBe('***-**-6789');
    expect(maskByKind('CARD', '4111111111111111')).toBe('************1111');
    expect(maskByKind('EMAIL', 'jane.doe@example.com')).toBe('ja******@example.com');
    expect(maskByKind('ACCOUNT', '987654321')).toBe('*****4321');
  });

  it('falls back to [REDACTED] for an unknown kind', () => {
    expect(maskByKind('PASSPORT' as PiiKind, 'X1234567')).toBe('[REDACTED]');
  });
});

describe('redactText', () => {
  it('returns text without PII unchanged', () => {
    expect(redactText('no pii here')).toBe('no pii here');
  });

  it('redacts every PII item in the text', () => {
    const text = 'jane.doe@example.com paid with 4111 1111 1111 1111, ssn 123-45-6789.';
    expect(redactText(text)).toBe('ja******@example.com paid with ************1111, ssn ***-**-6789.');
  });
});

describe('isValidEmail', () => {
  it('accepts a well-formed email', () => {
    expect(isValidEmail('jane@example.com')).toBe(true);
  });

  it('rejects an email longer than 254 characters', () => {
    expect(isValidEmail(`${'a'.repeat(250)}@x.io`)).toBe(false);
  });

  it('rejects malformed emails', () => {
    expect(isValidEmail('jane@')).toBe(false);
    expect(isValidEmail('jane example.com')).toBe(false);
    expect(isValidEmail('jane@@example.com')).toBe(false);
  });
});
