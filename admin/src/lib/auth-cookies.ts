import { NextResponse } from 'next/server';
import type { NextResponse as NextResponseType } from 'next/server';

export const ACCESS_COOKIE = 'ak_access';
export const REFRESH_COOKIE = 'ak_refresh';
/** Role hint cookie (httpOnly). Middleware prefers JWT roleName (#75). */
export const ROLE_COOKIE = 'ak_role';

export function backendUrl(): string {
  return (
    process.env.BACKEND_API_URL ??
    process.env.NEXT_PUBLIC_API_URL ??
    'http://localhost:3000/api/v1'
  );
}

/**
 * Cookie SameSite policy (#84).
 * - Default: Lax (OAuth / magic-link top-level redirects still send cookies)
 * - Set COOKIE_SAMESITE=strict for maximum CSRF resistance (breaks cross-site
 *   top-level navigations that need cookies on first hit — use with CSRF Origin checks)
 */
export function cookieSameSite(): 'lax' | 'strict' | 'none' {
  const raw = (process.env.COOKIE_SAMESITE || 'lax').toLowerCase();
  if (raw === 'strict' || raw === 'none' || raw === 'lax') return raw;
  return 'lax';
}

export function cookieOptions(opts: { maxAge: number; secure?: boolean }) {
  const sameSite = cookieSameSite();
  const secure =
    opts.secure ??
    (process.env.NODE_ENV === 'production' || sameSite === 'none');
  return {
    httpOnly: true,
    secure,
    sameSite,
    path: '/',
    maxAge: opts.maxAge,
  };
}

export function clearSessionCookies(res: NextResponseType) {
  res.cookies.set(ACCESS_COOKIE, '', { httpOnly: true, path: '/', maxAge: 0 });
  res.cookies.set(REFRESH_COOKIE, '', { httpOnly: true, path: '/', maxAge: 0 });
  res.cookies.set(ROLE_COOKIE, '', { path: '/', maxAge: 0 });
}

export function jsonError(message: string, status: number) {
  return NextResponse.json({ message }, { status });
}
