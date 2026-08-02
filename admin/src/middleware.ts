import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const ACCESS_COOKIE = 'ak_access';
const ROLE_COOKIE = 'ak_role';
const ADMIN_ROLES = new Set(['admin', 'superadmin']);

/**
 * Dashboard auth gate (#24). Requires an httpOnly access cookie and an
 * admin/superadmin role hint. Real authorization still happens on the API.
 */
export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  if (!pathname.startsWith('/dashboard')) {
    return NextResponse.next();
  }

  const access = req.cookies.get(ACCESS_COOKIE)?.value;
  const role = req.cookies.get(ROLE_COOKIE)?.value;

  if (!access || !role || !ADMIN_ROLES.has(role)) {
    const login = new URL('/login', req.url);
    login.searchParams.set('next', pathname);
    const res = NextResponse.redirect(login);
    // Clear stale cookies so the user isn't stuck in a redirect loop
    if (!access || !role) {
      res.cookies.set(ACCESS_COOKIE, '', { path: '/', maxAge: 0 });
      res.cookies.set(ROLE_COOKIE, '', { path: '/', maxAge: 0 });
    }
    return res;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*'],
};
