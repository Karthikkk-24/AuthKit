import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const ACCESS_COOKIE = 'ak_access';
const ROLE_COOKIE = 'ak_role';
const ADMIN_ROLES = new Set(['admin', 'superadmin']);

/** Decode JWT payload without verifying signature (API still verifies) (#75). */
function roleFromAccessJwt(token: string): string | null {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const json =
      typeof atob === 'function'
        ? atob(padded)
        : Buffer.from(padded, 'base64').toString('utf8');
    const payload = JSON.parse(json);
    return typeof payload.roleName === 'string' ? payload.roleName : null;
  } catch {
    return null;
  }
}

/**
 * Dashboard auth gate (#24, #75). Role is taken from the access JWT claim,
 * not the forgeable ak_role cookie.
 */
export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  if (!pathname.startsWith('/dashboard')) {
    return NextResponse.next();
  }

  const access = req.cookies.get(ACCESS_COOKIE)?.value;
  const roleFromJwt = access ? roleFromAccessJwt(access) : null;

  if (!access || !roleFromJwt || !ADMIN_ROLES.has(roleFromJwt)) {
    const login = new URL('/login', req.url);
    login.searchParams.set('next', pathname);
    const res = NextResponse.redirect(login);
    res.cookies.set(ACCESS_COOKIE, '', { path: '/', maxAge: 0 });
    res.cookies.set(ROLE_COOKIE, '', { path: '/', maxAge: 0 });
    return res;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*'],
};
