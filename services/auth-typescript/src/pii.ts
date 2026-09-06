/** PII detection and masking for outbound log lines and exports. */

export type PiiKind = 'SSN' | 'CARD' | 'EMAIL' | 'ACCOUNT';

export interface PiiMatch {
  kind: PiiKind;
  value: string;
  start: number;
  end: number;
}

const SSN_PATTERN = /\b\d{3}-\d{2}-\d{4}\b/g;
const CARD_PATTERN = /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/g;
const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

export function maskSsn(ssn: string): string {
  if (!ssn) {
    return '';
  }
  if (ssn.length !== 11) {
    return ssn;
  }
  return `***-**-${ssn.slice(-4)}`;
}

export function maskCardNumber(card: string): string {
  const digits = card.replace(/\D/g, '');
  if (digits.length < 12 || digits.length > 19) {
    throw new Error('invalid card number length');
  }
  return `${'*'.repeat(digits.length - 4)}${digits.slice(-4)}`;
}

export function maskEmail(email: string): string {
  const at = email.indexOf('@');
  if (at <= 0) {
    return email;
  }
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  const visible = local.length <= 2 ? local[0] : local.slice(0, 2);
  return `${visible}${'*'.repeat(Math.max(local.length - visible.length, 1))}@${domain}`;
}

export function maskAccountNumber(account: string): string {
  if (!account || account.length <= 4) {
    return account;
  }
  return `${'*'.repeat(account.length - 4)}${account.slice(-4)}`;
}

export function luhnCheck(cardNumber: string): boolean {
  const digits = cardNumber.replace(/\D/g, '');
  if (digits.length === 0) {
    return true;
  }
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) {
        n -= 9;
      }
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

export function detectPii(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const collect = (kind: PiiKind, pattern: RegExp): void => {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(text)) !== null) {
      matches.push({ kind, value: m[0], start: m.index, end: m.index + m[0].length });
    }
  };
  collect('SSN', SSN_PATTERN);
  collect('CARD', CARD_PATTERN);
  collect('EMAIL', EMAIL_PATTERN);
  return matches.sort((a, b) => a.start - b.start);
}

export function maskByKind(kind: PiiKind, value: string): string {
  switch (kind) {
    case 'SSN':
      return maskSsn(value);
    case 'CARD':
      return maskCardNumber(value);
    case 'EMAIL':
      return maskEmail(value);
    case 'ACCOUNT':
      return maskAccountNumber(value);
    default:
      return '[REDACTED]';
  }
}

export function redactText(text: string): string {
  const matches = detectPii(text);
  if (matches.length === 0) {
    return text;
  }
  let out = '';
  let cursor = 0;
  for (const m of matches) {
    out += text.slice(cursor, m.start);
    out += maskByKind(m.kind, m.value);
    cursor = m.end;
  }
  return out + text.slice(cursor);
}

export function isValidEmail(email: string): boolean {
  if (email.length > 254) {
    return false;
  }
  return /^[^\s@]+@[^\s@]+$/.test(email);
}
