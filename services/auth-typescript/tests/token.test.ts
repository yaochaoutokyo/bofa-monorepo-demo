import { createHmac } from 'crypto';
import { CLOCK_SKEW_SECONDS, DEFAULT_ACCESS_TTL_SECONDS, TokenPayload, TokenService, constantTimeEquals } from '../src/token';

const SECRET = 'a-very-long-secret-of-at-least-32-characters!!';
const NOW = 1_700_000_000;

function b64url(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodePayload(token: string): TokenPayload {
  const body = token.split('.')[1];
  const padded = body.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (body.length % 4)) % 4);
  return JSON.parse(Buffer.from(padded, 'base64').toString('utf8')) as TokenPayload;
}

/** Signs an arbitrary body with the same secret so only the payload differs from a real token. */
function forgeWithValidSignature(body: string): string {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const signature = createHmac('sha256', SECRET)
    .update(`${header}.${body}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `${header}.${body}.${signature}`;
}

describe('TokenService constructor', () => {
  it('rejects an empty or short secret', () => {
    expect(() => new TokenService('')).toThrow('token secret must be at least 32 characters');
    expect(() => new TokenService('short')).toThrow('token secret must be at least 32 characters');
    expect(() => new TokenService('x'.repeat(31))).toThrow('token secret must be at least 32 characters');
  });

  it('accepts a 32-character secret', () => {
    expect(() => new TokenService('x'.repeat(32))).not.toThrow();
  });
});

describe('TokenService.issue', () => {
  const service = new TokenService(SECRET);

  it('rejects an empty userId', () => {
    expect(() => service.issue('', ['user'], NOW)).toThrow('userId is required');
  });

  it('rejects a non-positive ttl', () => {
    expect(() => service.issue('u1', [], NOW, 0)).toThrow('ttl must be positive');
    expect(() => service.issue('u1', [], NOW, -5)).toThrow('ttl must be positive');
  });

  it('issues a three-part token with the expected payload', () => {
    const token = service.issue('u1', ['admin', 'user'], NOW);
    expect(token.split('.')).toHaveLength(3);
    const payload = decodePayload(token);
    expect(payload.sub).toBe('u1');
    expect(payload.roles).toEqual(['admin', 'user']);
    expect(payload.iat).toBe(NOW);
    expect(payload.exp).toBe(NOW + DEFAULT_ACCESS_TTL_SECONDS);
    expect(payload.jti).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('honours a custom ttl and unique jti per token', () => {
    const a = service.issue('u1', [], NOW, 60);
    const b = service.issue('u1', [], NOW, 60);
    expect(decodePayload(a).exp).toBe(NOW + 60);
    expect(decodePayload(a).jti).not.toBe(decodePayload(b).jti);
  });
});

describe('TokenService.verify', () => {
  const service = new TokenService(SECRET);

  it('rejects missing or non-string tokens', () => {
    expect(service.verify('', NOW)).toEqual({ valid: false, reason: 'missing token' });
    expect(service.verify(undefined as unknown as string, NOW)).toEqual({ valid: false, reason: 'missing token' });
    expect(service.verify(123 as unknown as string, NOW)).toEqual({ valid: false, reason: 'missing token' });
  });

  it('rejects a token without exactly three parts', () => {
    expect(service.verify('a.b', NOW)).toEqual({ valid: false, reason: 'malformed token' });
    expect(service.verify('a.b.c.d', NOW)).toEqual({ valid: false, reason: 'malformed token' });
  });

  it('rejects a tampered payload', () => {
    const token = service.issue('u1', ['user'], NOW);
    const [header, , signature] = token.split('.');
    const tampered = b64url(JSON.stringify({ ...decodePayload(token), roles: ['admin'] }));
    expect(service.verify(`${header}.${tampered}.${signature}`, NOW)).toEqual({ valid: false, reason: 'invalid signature' });
  });

  it('rejects a token signed with a different secret', () => {
    const other = new TokenService('another-very-long-secret-of-32-chars-or-more');
    expect(service.verify(other.issue('u1', [], NOW), NOW)).toEqual({ valid: false, reason: 'invalid signature' });
  });

  it('rejects a correctly signed but non-JSON payload', () => {
    const token = forgeWithValidSignature(b64url('not json'));
    expect(service.verify(token, NOW)).toEqual({ valid: false, reason: 'malformed payload' });
  });

  it('rejects a correctly signed payload missing required claims', () => {
    const noSub = forgeWithValidSignature(b64url(JSON.stringify({ exp: NOW + 10, iat: NOW })));
    const noExp = forgeWithValidSignature(b64url(JSON.stringify({ sub: 'u1', iat: NOW })));
    const noIat = forgeWithValidSignature(b64url(JSON.stringify({ sub: 'u1', exp: NOW + 10 })));
    expect(service.verify(noSub, NOW)).toEqual({ valid: false, reason: 'incomplete payload' });
    expect(service.verify(noExp, NOW)).toEqual({ valid: false, reason: 'incomplete payload' });
    expect(service.verify(noIat, NOW)).toEqual({ valid: false, reason: 'incomplete payload' });
  });

  it('accepts a token within the expiry clock skew and rejects it beyond', () => {
    const token = service.issue('u1', [], NOW, 60);
    const exp = NOW + 60;
    expect(service.verify(token, exp).valid).toBe(true);
    expect(service.verify(token, exp + CLOCK_SKEW_SECONDS).valid).toBe(true);
    expect(service.verify(token, exp + CLOCK_SKEW_SECONDS + 1)).toEqual({ valid: false, reason: 'token expired' });
  });

  it('rejects a token issued too far in the future, allowing clock skew', () => {
    const token = service.issue('u1', [], NOW + CLOCK_SKEW_SECONDS, 3600);
    expect(service.verify(token, NOW).valid).toBe(true);
    const future = service.issue('u1', [], NOW + CLOCK_SKEW_SECONDS + 1, 3600);
    expect(service.verify(future, NOW)).toEqual({ valid: false, reason: 'token issued in the future' });
  });

  it('rejects a revoked token but not a sibling token', () => {
    const revoked = service.issue('u1', [], NOW);
    const sibling = service.issue('u1', [], NOW);
    expect(service.revoke(revoked)).toBe(true);
    expect(service.verify(revoked, NOW)).toEqual({ valid: false, reason: 'token revoked' });
    expect(service.verify(sibling, NOW).valid).toBe(true);
  });

  it('returns the payload for a valid token', () => {
    const token = service.issue('u1', ['user'], NOW);
    const result = service.verify(token, NOW + 10);
    expect(result.valid).toBe(true);
    expect(result.payload).toEqual(decodePayload(token));
    expect(result.reason).toBeUndefined();
  });
});

describe('TokenService.revoke', () => {
  const service = new TokenService(SECRET);

  it('returns false for a malformed token', () => {
    expect(service.revoke('a.b')).toBe(false);
  });

  it('returns false for a non-JSON payload', () => {
    expect(service.revoke(`h.${b64url('nope')}.s`)).toBe(false);
  });

  it('returns false for a payload without a jti', () => {
    expect(service.revoke(`h.${b64url(JSON.stringify({ sub: 'u1' }))}.s`)).toBe(false);
  });

  it('returns true for a well-formed token even if unsigned', () => {
    expect(service.revoke(`h.${b64url(JSON.stringify({ jti: 'abc' }))}.s`)).toBe(true);
  });
});

describe('constantTimeEquals', () => {
  it('compares equal and unequal strings', () => {
    expect(constantTimeEquals('abc', 'abc')).toBe(true);
    expect(constantTimeEquals('abc', 'abd')).toBe(false);
    expect(constantTimeEquals('abc', 'abcd')).toBe(false);
    expect(constantTimeEquals('', '')).toBe(true);
  });
});
