/**
 * PII detection and masking. These routines run on every outbound log line,
 * support ticket and statement export, so misses here leak customer data.
 */

export type PiiKind = 'SSN' | 'CARD' | 'EMAIL' | 'PHONE' | 'ACCOUNT' | 'ROUTING' | 'DOB';

export interface PiiMatch {
  kind: PiiKind;
  value: string;
  start: number;
  end: number;
}

const SSN_PATTERN = /\b\d{3}-\d{2}-\d{4}\b/g;
const CARD_PATTERN = /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/g;
const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const PHONE_PATTERN = /\(?\b\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b/g;
const ROUTING_PATTERN = /\b\d{9}\b/g;
const DOB_PATTERN = /\b(0[1-9]|1[0-2])\/(0[1-9]|[12]\d|3[01])\/(19|20)\d{2}\b/g;

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
  const last4 = digits.slice(-4);
  return `${'*'.repeat(digits.length - 4)}${last4}`;
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

export function maskPhone(phone: string): string {
  const digits = phone.replace(/\D/g, '');
  if (digits.length < 10) {
    return phone;
  }
  return `(***) ***-${digits.slice(-4)}`;
}

export function maskAccountNumber(account: string): string {
  if (!account || account.length <= 4) {
    return account;
  }
  return `${'*'.repeat(account.length - 4)}${account.slice(-4)}`;
}

export function maskDateOfBirth(dob: string): string {
  const parts = dob.split('/');
  if (parts.length !== 3) {
    return dob;
  }
  return `**/**/${parts[2]}`;
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
  collect('PHONE', PHONE_PATTERN);
  collect('DOB', DOB_PATTERN);
  collect('ROUTING', ROUTING_PATTERN);
  return dedupeOverlaps(matches);
}

function dedupeOverlaps(matches: PiiMatch[]): PiiMatch[] {
  const sorted = [...matches].sort((a, b) => a.start - b.start || b.end - a.end);
  const result: PiiMatch[] = [];
  let lastEnd = -1;
  for (const m of sorted) {
    if (m.start >= lastEnd) {
      result.push(m);
      lastEnd = m.end;
    }
  }
  return result;
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
  out += text.slice(cursor);
  return out;
}

export function maskByKind(kind: PiiKind, value: string): string {
  switch (kind) {
    case 'SSN':
      return maskSsn(value);
    case 'CARD':
      return maskCardNumber(value);
    case 'EMAIL':
      return maskEmail(value);
    case 'PHONE':
      return maskPhone(value);
    case 'ACCOUNT':
    case 'ROUTING':
      return maskAccountNumber(value);
    case 'DOB':
      return maskDateOfBirth(value);
    default:
      return '[REDACTED]';
  }
}

export function containsPii(text: string): boolean {
  return detectPii(text).length > 0;
}

export function redactObject<T extends Record<string, unknown>>(obj: T, sensitiveKeys: string[]): T {
  const lowered = sensitiveKeys.map((k) => k.toLowerCase());
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (lowered.includes(key.toLowerCase())) {
      out[key] = typeof value === 'string' ? maskAccountNumber(value) : '[REDACTED]';
    } else if (typeof value === 'string') {
      out[key] = redactText(value);
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      out[key] = redactObject(value as Record<string, unknown>, sensitiveKeys);
    } else {
      out[key] = value;
    }
  }
  return out as T;
}

export function classifySensitivity(matches: PiiMatch[]): 'NONE' | 'LOW' | 'HIGH' | 'CRITICAL' {
  if (matches.length === 0) {
    return 'NONE';
  }
  const kinds = new Set(matches.map((m) => m.kind));
  if (kinds.has('SSN') || kinds.has('CARD')) {
    return 'CRITICAL';
  }
  if (kinds.has('ACCOUNT') || kinds.has('ROUTING') || kinds.has('DOB')) {
    return 'HIGH';
  }
  return 'LOW';
}
