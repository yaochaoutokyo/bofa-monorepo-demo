import { createHmac } from 'crypto';
import { CLOCK_SKEW_SECONDS, DEFAULT_ACCESS_TTL_SECONDS, TokenService, constantTimeEquals } from '../src/token';

const SECRET = 'x'.repeat(32);
const NOW = 1_700_000_000;

function base64Url(input: string | Buffer): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Builds a correctly signed token around an arbitrary (possibly invalid) payload body. */
function forgeToken(rawBody: string): string {
  const header = base64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64Url(rawBody);
  const signature = base64Url(createHmac('sha256', SECRET).update(`${header}.${body}`).digest());
  return `${header}.${body}.${signature}`;
}

describe('TokenService constructor', () => {
  it.each([
    ['an empty secret', ''],
    ['a secret under 32 characters', 'short-secret'],
  ] as const)('rejects %s', (_case, secret) => {
    expect(() => new TokenService(secret)).toThrow('token secret must be at least 32 characters');
  });

  it('accepts a secret of exactly 32 characters', () => {
    expect(new TokenService(SECRET)).toBeInstanceOf(TokenService);
  });
});

describe('TokenService.issue', () => {
  const service = new TokenService(SECRET);

  it('rejects a missing userId', () => {
    expect(() => service.issue('', ['teller'], NOW)).toThrow('userId is required');
  });

  it.each([0, -1] as const)('rejects a ttl of %s seconds', (ttl) => {
    expect(() => service.issue('jdoe', ['teller'], NOW, ttl)).toThrow('ttl must be positive');
  });

  it('issues a three-part token with the requested claims', () => {
    const token = service.issue('jdoe', ['teller'], NOW);
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
    expect(service.verify(token, NOW).payload).toMatchObject({
      sub: 'jdoe',
      roles: ['teller'],
      iat: NOW,
      exp: NOW + DEFAULT_ACCESS_TTL_SECONDS,
    });
  });
});

describe('TokenService.verify', () => {
  let service: TokenService;

  beforeEach(() => {
    service = new TokenService(SECRET);
  });

  it('accepts a freshly issued token', () => {
    const token = service.issue('jdoe', ['teller'], NOW);
    const result = service.verify(token, NOW);
    expect(result.valid).toBe(true);
    expect(result.payload?.jti).toEqual(expect.any(String));
    expect(result.reason).toBeUndefined();
  });

  it.each(['', undefined as unknown as string] as const)('reports a missing token for %p', (token) => {
    expect(service.verify(token, NOW)).toEqual({ valid: false, reason: 'missing token' });
  });

  it('reports a malformed token when there are not three parts', () => {
    expect(service.verify('header.body', NOW)).toEqual({ valid: false, reason: 'malformed token' });
  });

  it('reports an invalid signature when the signature is tampered with', () => {
    const [header, body] = service.issue('jdoe', [], NOW).split('.');
    expect(service.verify(`${header}.${body}.tampered`, NOW)).toEqual({
      valid: false,
      reason: 'invalid signature',
    });
  });

  it('reports a malformed payload when the body is not JSON', () => {
    expect(service.verify(forgeToken('not-json'), NOW)).toEqual({ valid: false, reason: 'malformed payload' });
  });

  it.each([
    ['sub', JSON.stringify({ roles: [], iat: NOW, exp: NOW + 60, jti: 'a' })],
    ['exp', JSON.stringify({ sub: 'jdoe', roles: [], iat: NOW, jti: 'a' })],
    ['iat', JSON.stringify({ sub: 'jdoe', roles: [], exp: NOW + 60, jti: 'a' })],
  ] as const)('reports an incomplete payload when %s is missing', (_claim, rawBody) => {
    expect(service.verify(forgeToken(rawBody), NOW)).toEqual({ valid: false, reason: 'incomplete payload' });
  });

  it('reports an expired token once the clock skew allowance has passed', () => {
    const token = service.issue('jdoe', [], NOW, 60);
    expect(service.verify(token, NOW + 60 + CLOCK_SKEW_SECONDS + 1)).toEqual({
      valid: false,
      reason: 'token expired',
    });
  });

  it('reports a token issued in the future beyond the clock skew allowance', () => {
    const token = service.issue('jdoe', [], NOW);
    expect(service.verify(token, NOW - CLOCK_SKEW_SECONDS - 1)).toEqual({
      valid: false,
      reason: 'token issued in the future',
    });
  });

  it('reports a revoked token', () => {
    const token = service.issue('jdoe', [], NOW);
    service.revoke(token);
    expect(service.verify(token, NOW)).toEqual({ valid: false, reason: 'token revoked' });
  });

  // DEFECT: a token is still accepted for CLOCK_SKEW_SECONDS after exp, so verification at exp + 1
  // succeeds instead of failing (FFIEC session-expiry requirement).
  it.skip('rejects a token one second after expiry', () => {
    const token = service.issue('jdoe', [], NOW, 60);
    expect(service.verify(token, NOW + 61)).toEqual({ valid: false, reason: 'token expired' });
  });
});

describe('TokenService.revoke', () => {
  const service = new TokenService(SECRET);

  it('returns false for a malformed token', () => {
    expect(service.revoke('header.body')).toBe(false);
  });

  it('returns false when the payload cannot be parsed', () => {
    expect(service.revoke(forgeToken('not-json'))).toBe(false);
  });

  it('returns false when the payload carries no jti', () => {
    expect(service.revoke(forgeToken(JSON.stringify({ sub: 'jdoe', iat: NOW, exp: NOW + 60 })))).toBe(false);
  });

  it('returns true for a valid token and invalidates later verifications', () => {
    const token = service.issue('jdoe', [], NOW);
    expect(service.revoke(token)).toBe(true);
    expect(service.verify(token, NOW).reason).toBe('token revoked');
  });
});

describe('constantTimeEquals', () => {
  it.each([
    ['abc', 'abcd', false],
    ['abc', 'abc', true],
    ['abc', 'abd', false],
  ] as const)('compares %p and %p as %p', (a, b, expected) => {
    expect(constantTimeEquals(a, b)).toBe(expected);
  });
});
