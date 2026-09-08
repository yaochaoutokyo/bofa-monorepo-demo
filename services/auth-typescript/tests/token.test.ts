import { createHmac } from 'crypto';
import { CLOCK_SKEW_SECONDS, constantTimeEquals, DEFAULT_ACCESS_TTL_SECONDS, TokenPayload, TokenService } from '../src/token';

const SECRET = 'a-very-long-and-sufficiently-secret-key-0123456789';
const NOW = 1_700_000_000;

function decodePayload(token: string): TokenPayload {
  const body = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(Buffer.from(body, 'base64').toString('utf8')) as TokenPayload;
}

describe('TokenService constructor', () => {
  it('accepts a secret of at least 32 chars', () => {
    expect(() => new TokenService('x'.repeat(32))).not.toThrow();
  });

  it('throws for a missing or short secret', () => {
    expect(() => new TokenService('')).toThrow('token secret must be at least 32 characters');
    expect(() => new TokenService('x'.repeat(31))).toThrow('token secret must be at least 32 characters');
  });
});

describe('TokenService.issue', () => {
  const service = new TokenService(SECRET);

  it('returns a three-part dot-delimited token', () => {
    const token = service.issue('user-1', ['teller'], NOW);
    expect(token.split('.')).toHaveLength(3);
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it('encodes the expected payload with the default TTL', () => {
    const payload = decodePayload(service.issue('user-1', ['teller', 'admin'], NOW));
    expect(payload.sub).toBe('user-1');
    expect(payload.roles).toEqual(['teller', 'admin']);
    expect(payload.iat).toBe(NOW);
    expect(payload.exp).toBe(NOW + DEFAULT_ACCESS_TTL_SECONDS);
    expect(payload.jti).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('honours a custom TTL', () => {
    expect(decodePayload(service.issue('user-1', [], NOW, 60)).exp).toBe(NOW + 60);
  });

  it('throws for an empty userId', () => {
    expect(() => service.issue('', [], NOW)).toThrow('userId is required');
  });

  it('throws for a non-positive TTL', () => {
    expect(() => service.issue('user-1', [], NOW, 0)).toThrow('ttl must be positive');
    expect(() => service.issue('user-1', [], NOW, -5)).toThrow('ttl must be positive');
  });
});

describe('TokenService.verify', () => {
  const service = new TokenService(SECRET);

  it('round-trips a freshly issued token', () => {
    const token = service.issue('user-1', ['teller'], NOW, 300);
    const result = service.verify(token, NOW + 10);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload).toMatchObject({ sub: 'user-1', roles: ['teller'], iat: NOW, exp: NOW + 300 });
  });

  it('rejects a missing token', () => {
    expect(service.verify('', NOW)).toEqual({ valid: false, reason: 'missing token' });
    expect(service.verify(undefined as unknown as string, NOW)).toEqual({ valid: false, reason: 'missing token' });
  });

  it('rejects a malformed token with the wrong part count', () => {
    expect(service.verify('a.b', NOW)).toEqual({ valid: false, reason: 'malformed token' });
    expect(service.verify('a.b.c.d', NOW)).toEqual({ valid: false, reason: 'malformed token' });
  });

  it('rejects a tampered token', () => {
    const [header, body, sig] = service.issue('user-1', ['teller'], NOW).split('.');
    const tamperedBody = Buffer.from(JSON.stringify({ sub: 'user-2', roles: ['admin'], iat: NOW, exp: NOW + 60, jti: 'x' }))
      .toString('base64')
      .replace(/=+$/, '');
    expect(service.verify(`${header}.${tamperedBody}.${sig}`, NOW)).toEqual({ valid: false, reason: 'invalid signature' });
    expect(service.verify(`${header}.${body}.${sig.slice(0, -1)}`, NOW)).toEqual({ valid: false, reason: 'invalid signature' });
  });

  it('rejects a token signed with a different secret', () => {
    const other = new TokenService('another-completely-different-secret-key-98765');
    expect(service.verify(other.issue('user-1', [], NOW), NOW).reason).toBe('invalid signature');
  });

  it('rejects an expired token beyond the clock-skew allowance', () => {
    const token = service.issue('user-1', [], NOW, 60);
    expect(service.verify(token, NOW + 60 + CLOCK_SKEW_SECONDS).valid).toBe(true);
    expect(service.verify(token, NOW + 60 + CLOCK_SKEW_SECONDS + 1)).toEqual({ valid: false, reason: 'token expired' });
  });

  it('rejects a token issued in the future beyond the clock-skew allowance', () => {
    const token = service.issue('user-1', [], NOW);
    expect(service.verify(token, NOW - CLOCK_SKEW_SECONDS).valid).toBe(true);
    expect(service.verify(token, NOW - CLOCK_SKEW_SECONDS - 1)).toEqual({ valid: false, reason: 'token issued in the future' });
  });

  it('rejects a correctly signed token whose payload is not JSON or is incomplete', () => {
    const sign = (data: string) =>
      createHmac('sha256', SECRET).update(data).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const header = service.issue('user-1', [], NOW).split('.')[0];
    const b64 = (s: string) => Buffer.from(s).toString('base64').replace(/=+$/, '');

    const badJson = `${header}.${b64('not json')}`;
    expect(service.verify(`${badJson}.${sign(badJson)}`, NOW)).toEqual({ valid: false, reason: 'malformed payload' });

    const incomplete = `${header}.${b64(JSON.stringify({ sub: 'user-1', iat: NOW }))}`;
    expect(service.verify(`${incomplete}.${sign(incomplete)}`, NOW)).toEqual({ valid: false, reason: 'incomplete payload' });
  });

  it('rejects a revoked token', () => {
    const token = service.issue('user-1', [], NOW);
    expect(service.revoke(token)).toBe(true);
    expect(service.verify(token, NOW)).toEqual({ valid: false, reason: 'token revoked' });
  });
});

describe('TokenService.revoke', () => {
  const service = new TokenService(SECRET);

  it('returns true for an issued token and only affects that token', () => {
    const a = service.issue('user-1', [], NOW);
    const b = service.issue('user-1', [], NOW);
    expect(service.revoke(a)).toBe(true);
    expect(service.verify(a, NOW).reason).toBe('token revoked');
    expect(service.verify(b, NOW).valid).toBe(true);
  });

  it('returns false for a malformed token', () => {
    expect(service.revoke('not-a-token')).toBe(false);
    expect(service.revoke('a.b')).toBe(false);
  });

  it('returns false when the payload is not decodable JSON', () => {
    expect(service.revoke('a.!!!.c')).toBe(false);
  });

  it('returns false when the payload lacks a jti', () => {
    const body = Buffer.from(JSON.stringify({ sub: 'user-1' })).toString('base64').replace(/=+$/, '');
    expect(service.revoke(`a.${body}.c`)).toBe(false);
  });
});

describe('constantTimeEquals', () => {
  it('returns true for equal strings', () => {
    expect(constantTimeEquals('abc', 'abc')).toBe(true);
    expect(constantTimeEquals('', '')).toBe(true);
  });

  it('returns false for differing lengths', () => {
    expect(constantTimeEquals('abc', 'abcd')).toBe(false);
  });

  it('returns false for same-length differing content', () => {
    expect(constantTimeEquals('abc', 'abd')).toBe(false);
  });
});
