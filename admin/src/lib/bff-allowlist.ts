/**
 * Nest path prefixes the admin console may call via `/api/backend/*` (#135).
 * Keep in sync with `admin/src/lib/api.ts` and dashboard pages.
 */
export const BFF_ALLOWED_PREFIXES = [
  'users',
  'metrics',
  'rbac',
  'audit',
  'webhooks',
  'admin/config',
  'api-keys',
  'auth/me',
] as const;

/** Returns an error message if the path must be rejected; otherwise null. */
export function assertAllowedBackendPath(segments: string[]): string | null {
  if (!segments.length) return 'Missing path';
  if (segments.some((s) => !s || s === '.' || s === '..' || s.includes('\\') || s.includes('\0'))) {
    return 'Invalid path segment';
  }
  const subpath = segments.join('/');
  // Reject absolute / scheme-ish tricks and encoded dots that survived decode
  if (subpath.startsWith('/') || subpath.includes('://')) {
    return 'Invalid path';
  }
  const allowed = BFF_ALLOWED_PREFIXES.some(
    (prefix) => subpath === prefix || subpath.startsWith(`${prefix}/`),
  );
  if (!allowed) return 'Path is not allowed through the admin BFF';
  return null;
}
