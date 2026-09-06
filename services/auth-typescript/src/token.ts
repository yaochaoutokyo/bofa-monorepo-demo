import { createHmac, randomUUID, timingSafeEqual } from 'crypto';

export const DEFAULT_ACCESS_TTL_SECONDS = 15 * 60;
export const CLOCK_SKEW_SECONDS = 30;

export interface TokenPayload {
  sub: string;
  roles: string[];
  iat: number;
  exp: number;
  jti: string;
}

export interface TokenVerification {
  valid: boolean;
  payload?: TokenPayload;
  reason?: string;
}

function base64UrlEncode(input: string | Buffer): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(input: string): Buffer {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (input.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

export class TokenService {
  private readonly revokedJtis = new Set<string>();

  constructor(private readonly secret: string) {
    if (!secret || secret.length < 32) {
      throw new Error('token secret must be at least 32 characters');
    }
  }

  issue(userId: string, roles: string[], nowSeconds: number, ttlSeconds = DEFAULT_ACCESS_TTL_SECONDS): string {
    if (!userId) {
      throw new Error('userId is required');
    }
    if (ttlSeconds <= 0) {
      throw new Error('ttl must be positive');
    }
    const payload: TokenPayload = { sub: userId, roles, iat: nowSeconds, exp: nowSeconds + ttlSeconds, jti: randomUUID() };
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const body = base64UrlEncode(JSON.stringify(payload));
    return `${header}.${body}.${this.sign(`${header}.${body}`)}`;
  }

  verify(token: string, nowSeconds: number): TokenVerification {
    if (!token || typeof token !== 'string') {
      return { valid: false, reason: 'missing token' };
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, reason: 'malformed token' };
    }
    const [header, body, signature] = parts;
    if (!constantTimeEquals(signature, this.sign(`${header}.${body}`))) {
      return { valid: false, reason: 'invalid signature' };
    }
    let payload: TokenPayload;
    try {
      payload = JSON.parse(base64UrlDecode(body).toString('utf8')) as TokenPayload;
    } catch {
      return { valid: false, reason: 'malformed payload' };
    }
    if (!payload.sub || typeof payload.exp !== 'number' || typeof payload.iat !== 'number') {
      return { valid: false, reason: 'incomplete payload' };
    }
    if (payload.exp + CLOCK_SKEW_SECONDS < nowSeconds) {
      return { valid: false, reason: 'token expired' };
    }
    if (payload.iat > nowSeconds + CLOCK_SKEW_SECONDS) {
      return { valid: false, reason: 'token issued in the future' };
    }
    if (this.revokedJtis.has(payload.jti)) {
      return { valid: false, reason: 'token revoked' };
    }
    return { valid: true, payload };
  }

  revoke(token: string): boolean {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return false;
    }
    try {
      const payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf8')) as TokenPayload;
      if (!payload.jti) {
        return false;
      }
      this.revokedJtis.add(payload.jti);
      return true;
    } catch {
      return false;
    }
  }

  private sign(data: string): string {
    return base64UrlEncode(createHmac('sha256', this.secret).update(data).digest());
  }
}

export function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}
