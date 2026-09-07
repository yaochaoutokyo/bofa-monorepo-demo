import { CLOCK_SKEW_SECONDS, DEFAULT_ACCESS_TTL_SECONDS, TokenService, constantTimeEquals } from '../src/token';

const SECRET = 'a'.repeat(32);
const NOW = 1_700_000_000;

function b64url(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBody(token: string): Record<string, unknown> {
  const body = token.split('.')[1];
  const padded = body.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (body.length % 4)) % 4);
  return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
}

/** Re-sign an arbitrary body with the service's own key by issuing a real token and swapping the body via a forged service. */
function signedTokenWithBody(service: TokenService, body: string): string {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  // Access the private sign method for test purposes.
  const sign = (service as unknown as { sign(data: string): string }).sign.bind(service);
  return `${header}.${body}.${sign(`${header}.${body}`)}`;
}

describe('TokenService constructor', () => {
  it('throws when the secret is missing or too short', () => {
    expect(() => new TokenService('')).toThrow('token secret must be at least 32 characters');
    expect(() => new TokenService('short-secret')).toThrow('token secret must be at least 32 characters');
  });

  it('succeeds with a valid secret', () => {
    expect(new TokenService(SECRET)).toBeInstanceOf(TokenService);
  });
});

describe('TokenService.issue', () => {
  const service = new TokenService(SECRET);

  it('throws on empty userId', () => {
    expect(() => service.issue('', [], NOW)).toThrow('userId is required');
  });

  it('throws on non-positive ttl', () => {
    expect(() => service.issue('u1', [], NOW, 0)).toThrow('ttl must be positive');
    expect(() => service.issue('u1', [], NOW, -5)).toThrow('ttl must be positive');
  });

  it('returns a three-part token with the default ttl', () => {
    const token = service.issue('u1', ['admin'], NOW);
    expect(token.split('.')).toHaveLength(3);
    const body = decodeBody(token);
    expect(body.sub).toBe('u1');
    expect(body.roles).toEqual(['admin']);
    expect(body.iat).toBe(NOW);
    expect(body.exp).toBe(NOW + DEFAULT_ACCESS_TTL_SECONDS);
    expect(typeof body.jti).toBe('string');
  });
});

describe('TokenService.verify', () => {
  const service = new TokenService(SECRET);

  it('round-trips a valid token', () => {
    const token = service.issue('u1', ['teller'], NOW, 60);
    const result = service.verify(token, NOW + 10);
    expect(result.valid).toBe(true);
    expect(result.payload?.sub).toBe('u1');
    expect(result.payload?.roles).toEqual(['teller']);
    expect(result.reason).toBeUndefined();
  });

  it('rejects a missing token', () => {
    expect(service.verify('', NOW)).toEqual({ valid: false, reason: 'missing token' });
    expect(service.verify(undefined as unknown as string, NOW)).toEqual({ valid: false, reason: 'missing token' });
    expect(service.verify(123 as unknown as string, NOW)).toEqual({ valid: false, reason: 'missing token' });
  });

  it('rejects a malformed token', () => {
    expect(service.verify('a.b', NOW)).toEqual({ valid: false, reason: 'malformed token' });
    expect(service.verify('a.b.c.d', NOW)).toEqual({ valid: false, reason: 'malformed token' });
  });

  it('rejects a tampered signature', () => {
    const [h, b, s] = service.issue('u1', [], NOW).split('.');
    const flipped = s[0] === 'A' ? 'B' : 'A';
    expect(service.verify(`${h}.${b}.${flipped}${s.slice(1)}`, NOW)).toEqual({ valid: false, reason: 'invalid signature' });
    expect(service.verify(`${h}.${b}.${s}x`, NOW)).toEqual({ valid: false, reason: 'invalid signature' });
  });

  it('rejects a token signed with a different secret', () => {
    const other = new TokenService('b'.repeat(32));
    expect(service.verify(other.issue('u1', [], NOW), NOW).reason).toBe('invalid signature');
  });

  it('rejects a malformed payload', () => {
    const token = signedTokenWithBody(service, b64url('not-json'));
    expect(service.verify(token, NOW)).toEqual({ valid: false, reason: 'malformed payload' });
  });

  it('rejects an incomplete payload', () => {
    expect(service.verify(signedTokenWithBody(service, b64url(JSON.stringify({ exp: NOW, iat: NOW }))), NOW).reason).toBe(
      'incomplete payload',
    );
    expect(service.verify(signedTokenWithBody(service, b64url(JSON.stringify({ sub: 'u1', iat: NOW }))), NOW).reason).toBe(
      'incomplete payload',
    );
    expect(
      service.verify(signedTokenWithBody(service, b64url(JSON.stringify({ sub: 'u1', exp: NOW, iat: 'x' }))), NOW).reason,
    ).toBe('incomplete payload');
  });

  it('rejects an expired token beyond clock skew but tolerates skew', () => {
    const token = service.issue('u1', [], NOW, 60);
    expect(service.verify(token, NOW + 60 + CLOCK_SKEW_SECONDS).valid).toBe(true);
    expect(service.verify(token, NOW + 60 + CLOCK_SKEW_SECONDS + 1)).toEqual({ valid: false, reason: 'token expired' });
  });

  it('rejects a token issued in the future beyond clock skew', () => {
    const token = service.issue('u1', [], NOW + CLOCK_SKEW_SECONDS + 1, 60);
    expect(service.verify(token, NOW)).toEqual({ valid: false, reason: 'token issued in the future' });
    expect(service.verify(service.issue('u1', [], NOW + CLOCK_SKEW_SECONDS, 60), NOW).valid).toBe(true);
  });

  it('rejects a revoked token', () => {
    const token = service.issue('u1', [], NOW, 60);
    expect(service.revoke(token)).toBe(true);
    expect(service.verify(token, NOW)).toEqual({ valid: false, reason: 'token revoked' });
  });
});

describe('TokenService.revoke', () => {
  const service = new TokenService(SECRET);

  it('returns false for malformed tokens', () => {
    expect(service.revoke('a.b')).toBe(false);
    expect(service.revoke(`x.${b64url('not-json')}.y`)).toBe(false);
  });

  it('returns false for tokens without a jti', () => {
    expect(service.revoke(`x.${b64url(JSON.stringify({ sub: 'u1' }))}.y`)).toBe(false);
  });

  it('does not affect other tokens', () => {
    const a = service.issue('u1', [], NOW, 60);
    const b = service.issue('u1', [], NOW, 60);
    service.revoke(a);
    expect(service.verify(b, NOW).valid).toBe(true);
  });
});

describe('constantTimeEquals', () => {
  it('returns true for equal strings', () => {
    expect(constantTimeEquals('abc', 'abc')).toBe(true);
    expect(constantTimeEquals('', '')).toBe(true);
  });

  it('returns false for different lengths', () => {
    expect(constantTimeEquals('abc', 'abcd')).toBe(false);
  });

  it('returns false for same-length different strings', () => {
    expect(constantTimeEquals('abc', 'abd')).toBe(false);
  });
});
