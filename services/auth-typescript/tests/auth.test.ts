import { AuthService } from '../src/auth';
import { AuthAuditLog } from '../src/audit';
import { LockoutTracker } from '../src/lockout';
import { SessionStore } from '../src/session';
import { TokenService } from '../src/token';
import { maskEmail } from '../src/pii';

const SECRET = 'test-secret-that-is-at-least-32-characters-long';

function buildService() {
  const now = 1_700_000_000_000;
  return new AuthService({
    tokens: new TokenService(SECRET),
    sessions: new SessionStore(),
    lockout: new LockoutTracker(),
    audit: new AuthAuditLog(),
    clock: () => now,
  });
}

describe('AuthService', () => {
  it('registers a user with a compliant password', () => {
    const service = buildService();

    const user = service.registerUser('jdoe', 'jdoe@example.com', 'Str0ng!Passw0rd#2024', ['CUSTOMER']);

    expect(user.username).toBe('jdoe');
    expect(user.status).toBe('ACTIVE');
    expect(user.roles).toEqual(['CUSTOMER']);
    expect(service.findByUsername('JDoe')).toBe(user);
  });
});

describe('pii', () => {
  it('masks the local part of an email address', () => {
    expect(maskEmail('jane.doe@example.com')).toBe('ja******@example.com');
  });
});
