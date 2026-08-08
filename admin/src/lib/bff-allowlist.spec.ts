import { assertAllowedBackendPath } from './bff-allowlist';

describe('assertAllowedBackendPath (#135)', () => {
  it('allows dashboard prefixes', () => {
    expect(assertAllowedBackendPath(['users'])).toBeNull();
    expect(assertAllowedBackendPath(['users', 'me'])).toBeNull();
    expect(assertAllowedBackendPath(['metrics', 'dashboard'])).toBeNull();
    expect(assertAllowedBackendPath(['rbac', 'roles'])).toBeNull();
    expect(assertAllowedBackendPath(['audit', 'export'])).toBeNull();
    expect(assertAllowedBackendPath(['webhooks', 'endpoints'])).toBeNull();
    expect(assertAllowedBackendPath(['admin', 'config'])).toBeNull();
    expect(assertAllowedBackendPath(['api-keys'])).toBeNull();
    expect(assertAllowedBackendPath(['auth', 'me'])).toBeNull();
  });

  it('rejects non-allowlisted and traversal paths', () => {
    expect(assertAllowedBackendPath(['auth', 'login'])).toMatch(/not allowed/i);
    expect(assertAllowedBackendPath(['health', 'ready'])).toMatch(/not allowed/i);
    expect(assertAllowedBackendPath(['..', 'users'])).toMatch(/invalid/i);
    expect(assertAllowedBackendPath(['users', '..', 'auth'])).toMatch(/invalid/i);
    expect(assertAllowedBackendPath([])).toMatch(/missing/i);
  });
});
