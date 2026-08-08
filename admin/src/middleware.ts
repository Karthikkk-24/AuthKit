import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const ACCESS_COOKIE = 'ak_access';
const ROLE_COOKIE = 'ak_role';

/**
 * Dashboard auth gate (#24, #75, #137).
 * Treat the access cookie as opaque and ask the BFF to verify it with Nest
 * (signature + admin role) — never trust a decode-only JWT payload.
 */
export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  if (!pathname.startsWith('/dashboard')) {
    return NextResponse.next();
  }

  const access = req.cookies.get(ACCESS_COOKIE)?.value;
  if (!access) {
    return redirectToLogin(req, pathname);
  }

  const sessionUrl = new URL('/api/auth/session', req.url);
  const sessionRes = await fetch(sessionUrl, {
    method: 'GET',
    headers: {
      cookie: req.headers.get('cookie') ?? '',
    },
    cache: 'no-store',
  }).catch(() => null);

  if (!sessionRes || !sessionRes.ok) {
    return redirectToLogin(req, pathname);
  }

  const data = await sessionRes.json().catch(() => null);
  if (!data?.ok) {
    return redirectToLogin(req, pathname);
  }

  return NextResponse.next();
}

function redirectToLogin(req: NextRequest, pathname: string) {
  const login = new URL('/login', req.url);
  login.searchParams.set('next', pathname);
  const res = NextResponse.redirect(login);
  res.cookies.set(ACCESS_COOKIE, '', { path: '/', maxAge: 0 });
  res.cookies.set(ROLE_COOKIE, '', { path: '/', maxAge: 0 });
  return res;
}

export const config = {
  matcher: ['/dashboard/:path*'],
};
