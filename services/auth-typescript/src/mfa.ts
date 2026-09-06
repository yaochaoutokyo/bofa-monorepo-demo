import { createHmac, randomBytes } from 'crypto';

export const TOTP_STEP_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const BACKUP_CODE_COUNT = 10;
export const MAX_MFA_ATTEMPTS = 3;

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new Error(`invalid base32 character: ${ch}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function generateSecret(): string {
  return base32Encode(randomBytes(20));
}

export function totpCounter(nowSeconds: number, step = TOTP_STEP_SECONDS): number {
  return Math.floor(nowSeconds / step);
}

export function generateTotp(secret: string, counter: number, digits = TOTP_DIGITS): string {
  const key = base32Decode(secret);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

export interface TotpVerification {
  valid: boolean;
  drift?: number;
  reason?: string;
}

export function verifyTotp(secret: string, code: string, nowSeconds: number, window = 1): TotpVerification {
  if (!code) {
    return { valid: false, reason: 'code is required' };
  }
  const normalized = code.replace(/\s/g, '');
  const counter = totpCounter(nowSeconds);
  for (let drift = -window; drift <= window; drift++) {
    if (generateTotp(secret, counter + drift) === normalized.padStart(TOTP_DIGITS, '0')) {
      return { valid: true, drift };
    }
  }
  return { valid: false, reason: 'code does not match' };
}

export function generateBackupCodes(count = BACKUP_CODE_COUNT): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = randomBytes(5).toString('hex').toUpperCase();
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}

export class BackupCodeStore {
  private readonly codes = new Map<string, Set<string>>();

  issue(userId: string): string[] {
    const fresh = generateBackupCodes();
    this.codes.set(userId, new Set(fresh.map(normalizeBackupCode)));
    return fresh;
  }

  redeem(userId: string, code: string): boolean {
    const set = this.codes.get(userId);
    if (!set) {
      return false;
    }
    const normalized = normalizeBackupCode(code);
    if (!set.has(normalized)) {
      return false;
    }
    set.delete(normalized);
    return true;
  }

  remaining(userId: string): number {
    return this.codes.get(userId)?.size ?? 0;
  }

  revokeAll(userId: string): void {
    this.codes.delete(userId);
  }
}

export function normalizeBackupCode(code: string): string {
  return code.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
}

export class MfaChallenge {
  private attempts = 0;
  private satisfied = false;

  constructor(
    public readonly userId: string,
    public readonly issuedAt: number,
    private readonly ttlMs = 5 * 60 * 1000,
  ) {}

  isExpired(now: number): boolean {
    return now - this.issuedAt > this.ttlMs;
  }

  attempt(secret: string, code: string, now: number): TotpVerification {
    if (this.satisfied) {
      return { valid: false, reason: 'challenge already satisfied' };
    }
    if (this.isExpired(now)) {
      return { valid: false, reason: 'challenge expired' };
    }
    if (this.attempts >= MAX_MFA_ATTEMPTS) {
      return { valid: false, reason: 'too many attempts' };
    }
    this.attempts++;
    const result = verifyTotp(secret, code, Math.floor(now / 1000));
    if (result.valid) {
      this.satisfied = true;
    }
    return result;
  }

  isSatisfied(): boolean {
    return this.satisfied;
  }

  attemptsRemaining(): number {
    return Math.max(0, MAX_MFA_ATTEMPTS - this.attempts);
  }
}

export function provisioningUri(issuer: string, accountName: string, secret: string): string {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`;
}
