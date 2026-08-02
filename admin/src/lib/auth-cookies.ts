import { NextResponse } from 'next/server';
import type { NextResponse as NextResponseType } from 'next/server';

export const ACCESS_COOKIE = 'ak_access';
export const REFRESH_COOKIE = 'ak_refresh';
/** Readable role hint for middleware gating (not a secret). */
export const ROLE_COOKIE = 'ak_role';

export function backendUrl(): string {
  return (
    process.env.BACKEND_API_URL ??
    process.env.NEXT_PUBLIC_API_URL ??
    'http://localhost:3000/api/v1'
  );
}

export function cookieOptions(opts: { maxAge: number; secure?: boolean }) {
  return {
    httpOnly: true,
    secure: opts.secure ?? process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
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
