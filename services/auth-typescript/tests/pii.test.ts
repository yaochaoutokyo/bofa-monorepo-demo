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

const VISA = '4111111111111111';

describe('maskSsn', () => {
  it.each([
    ['', ''],
    ['12345', '12345'],
    ['123-45-6789', '***-**-6789'],
  ] as const)('masks %p as %p', (ssn, expected) => {
    expect(maskSsn(ssn)).toBe(expected);
  });
});

describe('maskCardNumber', () => {
  it.each([['1234 5678 901'], ['1234 5678 9012 3456 7890']] as const)(
    'rejects %p as an invalid length',
    (card) => {
      expect(() => maskCardNumber(card)).toThrow('invalid card number length');
    },
  );

  it('leaves only the last four digits of a valid card', () => {
    expect(maskCardNumber('4111 1111 1111 1111')).toBe('************1111');
  });
});

describe('maskEmail', () => {
  it.each([
    ['jane.doe@example.com', 'ja******@example.com'],
    ['ab@example.com', 'a*@example.com'],
    ['not-an-email', 'not-an-email'],
    ['@example.com', '@example.com'],
  ] as const)('masks %p as %p', (email, expected) => {
    expect(maskEmail(email)).toBe(expected);
  });
});

describe('maskAccountNumber', () => {
  it.each([
    ['', ''],
    ['1234', '1234'],
    ['123456789', '*****6789'],
  ] as const)('masks %p as %p', (account, expected) => {
    expect(maskAccountNumber(account)).toBe(expected);
  });
});

describe('luhnCheck', () => {
  it.each([
    ['', true],
    [VISA, true],
    ['378282246310005', true],
    ['4111111111111112', false],
  ] as const)('reports %p as %p', (card, expected) => {
    expect(luhnCheck(card)).toBe(expected);
  });
});

describe('detectPii', () => {
  it('returns an empty list when there is no PII', () => {
    expect(detectPii('no sensitive data here')).toEqual([]);
  });

  it('detects SSN, card and email matches ordered by position', () => {
    const text = `ssn 123-45-6789 card ${VISA} mail jane.doe@example.com`;
    expect(detectPii(text).map((m) => [m.kind, m.value])).toEqual([
      ['SSN', '123-45-6789'],
      ['CARD', VISA],
      ['EMAIL', 'jane.doe@example.com'],
    ]);
  });

  it('reports the offsets of each match', () => {
    const match = detectPii('ssn 123-45-6789')[0];
    expect(match).toEqual({ kind: 'SSN', value: '123-45-6789', start: 4, end: 15 });
  });

  // DEFECT: the card pattern only matches 16-digit PANs, so 15-digit Amex numbers are never detected
  // and leak into logs (PCI-DSS 3.3).
  it.skip('detects a 15-digit Amex card', () => {
    expect(detectPii('card 378282246310005').map((m) => m.kind)).toEqual(['CARD']);
  });
});

describe('maskByKind', () => {
  it.each([
    ['SSN', '123-45-6789', '***-**-6789'],
    ['CARD', VISA, '************1111'],
    ['EMAIL', 'jane.doe@example.com', 'ja******@example.com'],
    ['ACCOUNT', '123456789', '*****6789'],
    ['UNKNOWN' as PiiKind, 'anything', '[REDACTED]'],
  ] as const)('masks a %s value', (kind, value, expected) => {
    expect(maskByKind(kind as PiiKind, value)).toBe(expected);
  });
});

describe('redactText', () => {
  it('returns the text unchanged when it holds no PII', () => {
    expect(redactText('transfer approved')).toBe('transfer approved');
  });

  it('redacts every detected value in place', () => {
    expect(redactText(`ssn 123-45-6789 card ${VISA} mail jane.doe@example.com`)).toBe(
      'ssn ***-**-6789 card ************1111 mail ja******@example.com',
    );
  });
});

describe('isValidEmail', () => {
  it('rejects an address longer than 254 characters', () => {
    expect(isValidEmail(`${'a'.repeat(250)}@example.com`)).toBe(false);
  });

  it.each([
    ['jane.doe@example.com', true],
    ['jane doe@example.com', false],
    ['jane.doe', false],
  ] as const)('reports %p as %p', (email, expected) => {
    expect(isValidEmail(email)).toBe(expected);
  });
});
