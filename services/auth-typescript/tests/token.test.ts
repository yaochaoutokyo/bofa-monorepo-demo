import { CLOCK_SKEW_SECONDS, DEFAULT_ACCESS_TTL_SECONDS, TokenService, constantTimeEquals } from '../src/token';

const SECRET = 'a-very-long-secret-key-with-at-least-32-chars';
const NOW = 1_700_000_000;

function b64url(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Re-signs a token with an arbitrary body using the service's own sign() for signature-valid payload tests. */
function forge(service: TokenService, body: string): string {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const encodedBody = b64url(body);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const signature = (service as any).sign(`${header}.${encodedBody}`) as string;
  return `${header}.${encodedBody}.${signature}`;
}

describe('TokenService constructor', () => {
  it('throws when the secret is missing', () => {
    expect(() => new TokenService('')).toThrow('token secret must be at least 32 characters');
  });

  it('throws when the secret is shorter than 32 characters', () => {
    expect(() => new TokenService('short-secret')).toThrow('token secret must be at least 32 characters');
  });

  it('accepts a 32+ character secret', () => {
    expect(() => new TokenService('x'.repeat(32))).not.toThrow();
  });
});

describe('TokenService.issue', () => {
  const service = new TokenService(SECRET);

  it('throws on empty userId', () => {
    expect(() => service.issue('', [], NOW)).toThrow('userId is required');
  });

  it('throws on zero or negative ttl', () => {
    expect(() => service.issue('u1', [], NOW, 0)).toThrow('ttl must be positive');
    expect(() => service.issue('u1', [], NOW, -5)).toThrow('ttl must be positive');
  });

  it('returns a three-part token with the expected payload and default ttl', () => {
    const token = service.issue('u1', ['admin'], NOW);
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    expect(payload.sub).toBe('u1');
    expect(payload.roles).toEqual(['admin']);
    expect(payload.iat).toBe(NOW);
    expect(payload.exp).toBe(NOW + DEFAULT_ACCESS_TTL_SECONDS);
    expect(typeof payload.jti).toBe('string');
  });
});

describe('TokenService.verify', () => {
  const service = new TokenService(SECRET);

  it('rejects a missing or non-string token', () => {
    expect(service.verify('', NOW)).toEqual({ valid: false, reason: 'missing token' });
    expect(service.verify(undefined as unknown as string, NOW)).toEqual({ valid: false, reason: 'missing token' });
    expect(service.verify(42 as unknown as string, NOW)).toEqual({ valid: false, reason: 'missing token' });
  });

  it('rejects a token with the wrong number of parts', () => {
    expect(service.verify('a.b', NOW)).toEqual({ valid: false, reason: 'malformed token' });
    expect(service.verify('a.b.c.d', NOW)).toEqual({ valid: false, reason: 'malformed token' });
  });

  it('rejects a token with an invalid signature', () => {
    const token = service.issue('u1', [], NOW);
    const [h, b] = token.split('.');
    expect(service.verify(`${h}.${b}.bad-signature`, NOW)).toEqual({ valid: false, reason: 'invalid signature' });
  });

  it('rejects a token signed by a different secret', () => {
    const other = new TokenService('another-secret-that-is-long-enough-1234');
    expect(service.verify(other.issue('u1', [], NOW), NOW).reason).toBe('invalid signature');
  });

  it('rejects a token whose body is not JSON', () => {
    expect(service.verify(forge(service, 'not-json'), NOW)).toEqual({ valid: false, reason: 'malformed payload' });
  });

  it('rejects a payload missing sub, exp or iat', () => {
    expect(service.verify(forge(service, JSON.stringify({ exp: NOW + 10, iat: NOW })), NOW).reason).toBe('incomplete payload');
    expect(service.verify(forge(service, JSON.stringify({ sub: 'u1', iat: NOW })), NOW).reason).toBe('incomplete payload');
    expect(service.verify(forge(service, JSON.stringify({ sub: 'u1', exp: NOW + 10 })), NOW).reason).toBe('incomplete payload');
  });

  it('rejects an expired token once past the clock skew allowance', () => {
    const token = service.issue('u1', [], NOW, 60);
    const exp = NOW + 60;
    expect(service.verify(token, exp + CLOCK_SKEW_SECONDS).valid).toBe(true);
    expect(service.verify(token, exp + CLOCK_SKEW_SECONDS + 1)).toEqual({ valid: false, reason: 'token expired' });
  });

  it('rejects a token issued in the future beyond the clock skew allowance', () => {
    const token = service.issue('u1', [], NOW);
    expect(service.verify(token, NOW - CLOCK_SKEW_SECONDS).valid).toBe(true);
    expect(service.verify(token, NOW - CLOCK_SKEW_SECONDS - 1)).toEqual({ valid: false, reason: 'token issued in the future' });
  });

  it('rejects a revoked token', () => {
    const token = service.issue('u1', [], NOW);
    expect(service.revoke(token)).toBe(true);
    expect(service.verify(token, NOW)).toEqual({ valid: false, reason: 'token revoked' });
  });

  it('accepts a valid token and returns its payload', () => {
    const token = service.issue('u1', ['teller'], NOW);
    const result = service.verify(token, NOW + 10);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.payload?.sub).toBe('u1');
    expect(result.payload?.roles).toEqual(['teller']);
  });
});

describe('TokenService.revoke', () => {
  const service = new TokenService(SECRET);

  it('returns false for a malformed token', () => {
    expect(service.revoke('not.a-token')).toBe(false);
  });

  it('returns false when the body is not JSON', () => {
    expect(service.revoke(`h.${b64url('garbage')}.s`)).toBe(false);
  });

  it('returns false when the payload has no jti', () => {
    expect(service.revoke(`h.${b64url(JSON.stringify({ sub: 'u1' }))}.s`)).toBe(false);
  });

  it('returns true on success', () => {
    expect(service.revoke(service.issue('u1', [], NOW))).toBe(true);
  });
});

describe('constantTimeEquals', () => {
  it('returns true for equal strings', () => {
    expect(constantTimeEquals('abc', 'abc')).toBe(true);
  });

  it('returns false for unequal strings of the same length', () => {
    expect(constantTimeEquals('abc', 'abd')).toBe(false);
  });

  it('returns false for strings of different lengths', () => {
    expect(constantTimeEquals('abc', 'abcd')).toBe(false);
  });
});
