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
  it('returns empty string for empty input', () => {
    expect(maskSsn('')).toBe('');
  });

  it('returns input unchanged when not 11 chars', () => {
    expect(maskSsn('123456789')).toBe('123456789');
    expect(maskSsn('123-45-67890')).toBe('123-45-67890');
  });

  it('masks a valid dashed SSN keeping the last four', () => {
    expect(maskSsn('123-45-6789')).toBe('***-**-6789');
  });
});

describe('maskCardNumber', () => {
  it('masks plain 16-digit numbers keeping the last four', () => {
    expect(maskCardNumber('4111111111111111')).toBe('************1111');
  });

  it('accepts 12- and 19-digit boundaries', () => {
    expect(maskCardNumber('123456789012')).toBe('********9012');
    expect(maskCardNumber('1234567890123456789')).toBe('***************6789');
  });

  it('strips spaces and dashes before masking', () => {
    expect(maskCardNumber('4111 1111 1111 1111')).toBe('************1111');
    expect(maskCardNumber('4111-1111-1111-1111')).toBe('************1111');
  });

  it('throws for too-short or too-long digit counts', () => {
    expect(() => maskCardNumber('12345678901')).toThrow('invalid card number length');
    expect(() => maskCardNumber('12345678901234567890')).toThrow('invalid card number length');
    expect(() => maskCardNumber('')).toThrow('invalid card number length');
  });
});

describe('maskEmail', () => {
  it('masks the local part keeping two visible chars', () => {
    expect(maskEmail('jane.doe@example.com')).toBe('ja******@example.com');
  });

  it('keeps one visible char for short local parts', () => {
    expect(maskEmail('ab@example.com')).toBe('a*@example.com');
    expect(maskEmail('a@example.com')).toBe('a*@example.com');
  });

  it('returns input unchanged when there is no local part', () => {
    expect(maskEmail('not-an-email')).toBe('not-an-email');
    expect(maskEmail('@example.com')).toBe('@example.com');
  });
});

describe('maskAccountNumber', () => {
  it('returns short values unchanged', () => {
    expect(maskAccountNumber('')).toBe('');
    expect(maskAccountNumber('1234')).toBe('1234');
  });

  it('masks longer values keeping the last four', () => {
    expect(maskAccountNumber('12345')).toBe('*2345');
    expect(maskAccountNumber('0011223344')).toBe('******3344');
  });
});

describe('luhnCheck', () => {
  it('returns true for known valid card numbers', () => {
    expect(luhnCheck('4111111111111111')).toBe(true);
    expect(luhnCheck('4111 1111 1111 1111')).toBe(true);
    expect(luhnCheck('378282246310005')).toBe(true);
  });

  it('returns false for invalid card numbers', () => {
    expect(luhnCheck('4111111111111112')).toBe(false);
    expect(luhnCheck('1234567890123456')).toBe(false);
  });

  it('returns true for an empty string', () => {
    expect(luhnCheck('')).toBe(true);
    expect(luhnCheck('--')).toBe(true);
  });
});

describe('detectPii', () => {
  it('returns an empty array when no PII is present', () => {
    expect(detectPii('hello world 42')).toEqual([]);
  });

  it('detects an SSN', () => {
    expect(detectPii('ssn 123-45-6789 ok')).toEqual([{ kind: 'SSN', value: '123-45-6789', start: 4, end: 15 }]);
  });

  it('detects card numbers with and without separators', () => {
    expect(detectPii('card 4111 1111 1111 1111')).toEqual([
      { kind: 'CARD', value: '4111 1111 1111 1111', start: 5, end: 24 },
    ]);
    expect(detectPii('4111111111111111')[0].kind).toBe('CARD');
  });

  it('detects an email', () => {
    expect(detectPii('mail jane@example.com')).toEqual([{ kind: 'EMAIL', value: 'jane@example.com', start: 5, end: 21 }]);
  });

  it('returns mixed matches sorted by start offset', () => {
    const text = 'jane@example.com 4111-1111-1111-1111 123-45-6789';
    const kinds = detectPii(text).map((m) => m.kind);
    expect(kinds).toEqual(['EMAIL', 'CARD', 'SSN']);
    const starts = detectPii(text).map((m) => m.start);
    expect(starts).toEqual([...starts].sort((a, b) => a - b));
  });

  it('is safe to call repeatedly (global regex state is reset)', () => {
    expect(detectPii('123-45-6789')).toHaveLength(1);
    expect(detectPii('123-45-6789')).toHaveLength(1);
  });
});

describe('maskByKind', () => {
  it('routes each kind to its masker', () => {
    expect(maskByKind('SSN', '123-45-6789')).toBe('***-**-6789');
    expect(maskByKind('CARD', '4111111111111111')).toBe('************1111');
    expect(maskByKind('EMAIL', 'jane.doe@example.com')).toBe('ja******@example.com');
    expect(maskByKind('ACCOUNT', '0011223344')).toBe('******3344');
  });

  it('returns [REDACTED] for an unknown kind', () => {
    expect(maskByKind('PHONE' as PiiKind, '555-1234')).toBe('[REDACTED]');
  });
});

describe('redactText', () => {
  it('returns text unchanged when no PII is present', () => {
    expect(redactText('nothing to see here')).toBe('nothing to see here');
  });

  it('replaces every detected span in a mixed string', () => {
    const text = 'user jane.doe@example.com ssn 123-45-6789 card 4111 1111 1111 1111 end';
    expect(redactText(text)).toBe('user ja******@example.com ssn ***-**-6789 card ************1111 end');
  });

  it('handles PII at the very start and end of the text', () => {
    expect(redactText('123-45-6789 and jane@example.com')).toBe('***-**-6789 and ja**@example.com');
  });
});

describe('isValidEmail', () => {
  it('accepts a simple valid email', () => {
    expect(isValidEmail('jane@example.com')).toBe(true);
  });

  it('rejects an address without @', () => {
    expect(isValidEmail('jane.example.com')).toBe(false);
  });

  it('rejects whitespace and multiple @', () => {
    expect(isValidEmail('jane doe@example.com')).toBe(false);
    expect(isValidEmail('jane@@example.com')).toBe(false);
  });

  it('rejects addresses longer than 254 chars', () => {
    const long = `${'a'.repeat(250)}@b.co`;
    expect(long.length).toBeGreaterThan(254);
    expect(isValidEmail(long)).toBe(false);
  });
});
