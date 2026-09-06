import { CLOCK_SKEW_SECONDS, constantTimeEquals, DEFAULT_ACCESS_TTL_SECONDS, TokenService } from '../src/token';

const SECRET = 'a'.repeat(32);
const NOW = 1_700_000_000;

function b64url(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Builds a token with a custom body that is correctly signed by `svc`. */
function forge(svc: TokenService, body: string): string {
  const real = svc.issue('probe', [], NOW);
  const [header] = real.split('.');
  const signer = svc as unknown as { sign(data: string): string };
  return `${header}.${body}.${signer.sign(`${header}.${body}`)}`;
}

describe('TokenService constructor', () => {
  it('throws when the secret is missing', () => {
    expect(() => new TokenService('')).toThrow('token secret must be at least 32 characters');
  });

  it('throws when the secret is shorter than 32 chars', () => {
    expect(() => new TokenService('short')).toThrow('token secret must be at least 32 characters');
  });

  it('succeeds with a 32+ char secret', () => {
    expect(() => new TokenService(SECRET)).not.toThrow();
  });
});

describe('issue', () => {
  const svc = new TokenService(SECRET);

  it('throws on empty userId', () => {
    expect(() => svc.issue('', [], NOW)).toThrow('userId is required');
  });

  it('throws on non-positive ttl', () => {
    expect(() => svc.issue('u1', [], NOW, 0)).toThrow('ttl must be positive');
    expect(() => svc.issue('u1', [], NOW, -5)).toThrow('ttl must be positive');
  });

  it('returns a three-part token with the default ttl', () => {
    const token = svc.issue('u1', ['admin'], NOW);
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    expect(payload).toMatchObject({ sub: 'u1', roles: ['admin'], iat: NOW, exp: NOW + DEFAULT_ACCESS_TTL_SECONDS });
    expect(typeof payload.jti).toBe('string');
  });
});

describe('verify', () => {
  const svc = new TokenService(SECRET);

  it('round-trips a valid token', () => {
    const token = svc.issue('u1', ['teller'], NOW, 60);
    const result = svc.verify(token, NOW + 10);
    expect(result.valid).toBe(true);
    expect(result.payload).toMatchObject({ sub: 'u1', roles: ['teller'], iat: NOW, exp: NOW + 60 });
  });

  it('rejects missing or non-string token', () => {
    expect(svc.verify('', NOW)).toEqual({ valid: false, reason: 'missing token' });
    expect(svc.verify(undefined as unknown as string, NOW)).toEqual({ valid: false, reason: 'missing token' });
    expect(svc.verify(42 as unknown as string, NOW)).toEqual({ valid: false, reason: 'missing token' });
  });

  it('rejects malformed token', () => {
    expect(svc.verify('a.b', NOW)).toEqual({ valid: false, reason: 'malformed token' });
    expect(svc.verify('a.b.c.d', NOW)).toEqual({ valid: false, reason: 'malformed token' });
  });

  it('rejects invalid signature', () => {
    const token = svc.issue('u1', [], NOW);
    const [h, b] = token.split('.');
    expect(svc.verify(`${h}.${b}.bad`, NOW)).toEqual({ valid: false, reason: 'invalid signature' });
    const other = new TokenService('b'.repeat(32));
    expect(other.verify(token, NOW)).toEqual({ valid: false, reason: 'invalid signature' });
  });

  it('rejects tampered payload', () => {
    const token = svc.issue('u1', [], NOW);
    const [h, , s] = token.split('.');
    expect(svc.verify(`${h}.${b64url('{"sub":"admin"}')}.${s}`, NOW)).toEqual({ valid: false, reason: 'invalid signature' });
  });

  it('rejects malformed payload', () => {
    const token = forge(svc, b64url('not-json'));
    expect(svc.verify(token, NOW)).toEqual({ valid: false, reason: 'malformed payload' });
  });

  it('rejects incomplete payload', () => {
    expect(svc.verify(forge(svc, b64url(JSON.stringify({ exp: NOW, iat: NOW }))), NOW)).toEqual({ valid: false, reason: 'incomplete payload' });
    expect(svc.verify(forge(svc, b64url(JSON.stringify({ sub: 'u1', iat: NOW }))), NOW)).toEqual({ valid: false, reason: 'incomplete payload' });
    expect(svc.verify(forge(svc, b64url(JSON.stringify({ sub: 'u1', exp: NOW }))), NOW)).toEqual({ valid: false, reason: 'incomplete payload' });
  });

  it('rejects expired token, respecting clock skew', () => {
    const token = svc.issue('u1', [], NOW, 60);
    expect(svc.verify(token, NOW + 60 + CLOCK_SKEW_SECONDS).valid).toBe(true);
    expect(svc.verify(token, NOW + 60 + CLOCK_SKEW_SECONDS + 1)).toEqual({ valid: false, reason: 'token expired' });
  });

  it('rejects token issued in the future', () => {
    const token = svc.issue('u1', [], NOW, 600);
    expect(svc.verify(token, NOW - CLOCK_SKEW_SECONDS).valid).toBe(true);
    expect(svc.verify(token, NOW - CLOCK_SKEW_SECONDS - 1)).toEqual({ valid: false, reason: 'token issued in the future' });
  });

  it('rejects revoked token', () => {
    const token = svc.issue('u1', [], NOW);
    expect(svc.revoke(token)).toBe(true);
    expect(svc.verify(token, NOW)).toEqual({ valid: false, reason: 'token revoked' });
  });
});

describe('revoke', () => {
  const svc = new TokenService(SECRET);

  it('returns false for malformed token', () => {
    expect(svc.revoke('nope')).toBe(false);
  });

  it('returns false for undecodable payload', () => {
    expect(svc.revoke(`a.${b64url('not-json')}.c`)).toBe(false);
  });

  it('returns false for payload without jti', () => {
    expect(svc.revoke(`a.${b64url(JSON.stringify({ sub: 'u1' }))}.c`)).toBe(false);
  });

  it('returns true and causes verify to report revoked', () => {
    const token = svc.issue('u2', [], NOW);
    expect(svc.verify(token, NOW).valid).toBe(true);
    expect(svc.revoke(token)).toBe(true);
    expect(svc.verify(token, NOW).reason).toBe('token revoked');
  });
});

describe('constantTimeEquals', () => {
  it('returns true for equal strings', () => {
    expect(constantTimeEquals('abc', 'abc')).toBe(true);
  });

  it('returns false for different-length strings', () => {
    expect(constantTimeEquals('abc', 'abcd')).toBe(false);
  });

  it('returns false for equal-length but different strings', () => {
    expect(constantTimeEquals('abc', 'abd')).toBe(false);
  });
});
