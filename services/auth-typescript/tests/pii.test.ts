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

  it('returns non-11-length input unchanged', () => {
    expect(maskSsn('123456789')).toBe('123456789');
  });

  it('masks a valid SSN', () => {
    expect(maskSsn('123-45-6789')).toBe('***-**-6789');
  });
});

describe('maskCardNumber', () => {
  it('throws for too-short card', () => {
    expect(() => maskCardNumber('4111 1111 111')).toThrow('invalid card number length');
  });

  it('throws for too-long card', () => {
    expect(() => maskCardNumber('1'.repeat(20))).toThrow('invalid card number length');
  });

  it('masks a valid card keeping last 4', () => {
    expect(maskCardNumber('4111-1111-1111-1111')).toBe('************1111');
  });
});

describe('maskEmail', () => {
  it('masks the local part', () => {
    expect(maskEmail('jane.doe@example.com')).toBe('ja******@example.com');
  });

  it('handles short local parts', () => {
    expect(maskEmail('ab@example.com')).toBe('a*@example.com');
    expect(maskEmail('a@example.com')).toBe('a*@example.com');
  });

  it('returns unchanged without @ or with @ at position 0', () => {
    expect(maskEmail('not-an-email')).toBe('not-an-email');
    expect(maskEmail('@example.com')).toBe('@example.com');
  });
});

describe('maskAccountNumber', () => {
  it('returns empty/short input unchanged', () => {
    expect(maskAccountNumber('')).toBe('');
    expect(maskAccountNumber('1234')).toBe('1234');
  });

  it('masks longer account numbers keeping last 4', () => {
    expect(maskAccountNumber('123456789')).toBe('*****6789');
  });
});

describe('luhnCheck', () => {
  it('returns true for empty digits', () => {
    expect(luhnCheck('')).toBe(true);
    expect(luhnCheck('abc')).toBe(true);
  });

  it('returns true for a known valid card number', () => {
    expect(luhnCheck('4111 1111 1111 1111')).toBe(true);
    expect(luhnCheck('79927398713')).toBe(true);
  });

  it('returns false for an invalid card number', () => {
    expect(luhnCheck('4111111111111112')).toBe(false);
    expect(luhnCheck('79927398710')).toBe(false);
  });
});

describe('detectPii', () => {
  it('detects SSN, CARD and EMAIL sorted by start index', () => {
    const text = 'email jane@example.com ssn 123-45-6789 card 4111 1111 1111 1111 end';
    const matches = detectPii(text);
    expect(matches.map((m) => m.kind)).toEqual(['EMAIL', 'SSN', 'CARD']);
    expect(matches.map((m) => m.value)).toEqual(['jane@example.com', '123-45-6789', '4111 1111 1111 1111']);
    for (const m of matches) {
      expect(text.slice(m.start, m.end)).toBe(m.value);
    }
  });

  it('returns empty for clean text', () => {
    expect(detectPii('nothing to see here')).toEqual([]);
  });
});

describe('maskByKind', () => {
  it('dispatches on kind', () => {
    expect(maskByKind('SSN', '123-45-6789')).toBe('***-**-6789');
    expect(maskByKind('CARD', '4111111111111111')).toBe('************1111');
    expect(maskByKind('EMAIL', 'jane.doe@example.com')).toBe('ja******@example.com');
    expect(maskByKind('ACCOUNT', '123456789')).toBe('*****6789');
  });

  it('redacts unknown kinds', () => {
    expect(maskByKind('PHONE' as unknown as PiiKind, '555-1234')).toBe('[REDACTED]');
  });
});

describe('redactText', () => {
  it('returns text unchanged when no PII is present', () => {
    expect(redactText('hello world')).toBe('hello world');
  });

  it('masks every match in place', () => {
    expect(redactText('ssn 123-45-6789 mail jane.doe@example.com.')).toBe('ssn ***-**-6789 mail ja******@example.com.');
  });
});

describe('isValidEmail', () => {
  it('accepts a simple email', () => {
    expect(isValidEmail('a@b.co')).toBe(true);
  });

  it('rejects malformed or overlong emails', () => {
    expect(isValidEmail('a b@c')).toBe(false);
    expect(isValidEmail('nope')).toBe(false);
    expect(isValidEmail(`${'a'.repeat(250)}@b.co`)).toBe(false);
  });
});
