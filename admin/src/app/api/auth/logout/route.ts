import { NextRequest, NextResponse } from 'next/server';
import {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  ROLE_COOKIE,
  clearSessionCookies,
  backendUrl,
} from '@/lib/auth-cookies';

/** BFF logout (#24): revoke the Nest session then clear httpOnly cookies. */
export async function POST(req: NextRequest) {
  const access = req.cookies.get(ACCESS_COOKIE)?.value;

  if (access) {
    await fetch(`${backendUrl()}/auth/logout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${access}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    }).catch(() => {});
  }

  const res = NextResponse.json({ ok: true });
  clearSessionCookies(res);
  // Also clear the readable role hint
  res.cookies.set(ROLE_COOKIE, '', { path: '/', maxAge: 0 });
  res.cookies.set(ACCESS_COOKIE, '', { path: '/', maxAge: 0 });
  res.cookies.set(REFRESH_COOKIE, '', { path: '/', maxAge: 0 });
  return res;
}
