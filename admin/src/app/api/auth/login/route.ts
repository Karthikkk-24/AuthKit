import { NextRequest, NextResponse } from 'next/server';
import {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  ROLE_COOKIE,
  cookieOptions,
  backendUrl,
} from '@/lib/auth-cookies';

/**
 * BFF login (#24): exchange credentials with the Nest API and store tokens
 * in httpOnly cookies on the admin origin. The JWT never touches localStorage.
 */
export async function POST(req: NextRequest) {
  let body: { email?: string; password?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ message: 'Invalid JSON body' }, { status: 400 });
  }

  if (!body.email || !body.password) {
    return NextResponse.json({ message: 'Email and password are required' }, { status: 400 });
  }

  const upstream = await fetch(`${backendUrl()}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: body.email, password: body.password }),
  });

  const data = await upstream.json().catch(() => ({}));
  if (!upstream.ok) {
    return NextResponse.json(
      { message: data.message ?? 'Login failed' },
      { status: upstream.status },
    );
  }

  // MFA challenge — no tokens yet; surface to the client as-is
  if (data.requiresMfa) {
    return NextResponse.json(data, { status: 200 });
  }

  // MFA enrollment required for role — do not mint a console session
  if (data.mfaSetupRequired) {
    return NextResponse.json(
      {
        mfaSetupRequired: true,
        message:
          data.message ??
          'MFA enrollment is required before using the admin console. Configure MFA via the API, then sign in again.',
      },
      { status: 403 },
    );
  }

  if (!data.accessToken) {
    return NextResponse.json({ message: 'Unexpected login response' }, { status: 502 });
  }

  const roleName: string = data?.user?.role ?? '';
  if (!['admin', 'superadmin'].includes(roleName)) {
    return NextResponse.json(
      { message: 'Admin console access requires an admin or superadmin role' },
      { status: 403 },
    );
  }

  const res = NextResponse.json({
    ok: true,
    user: {
      id: data.user?.id,
      email: data.user?.email,
      name: data.user?.name,
      role: roleName,
    },
  });

  const secure = process.env.NODE_ENV === 'production';
  res.cookies.set(ACCESS_COOKIE, data.accessToken, cookieOptions({ maxAge: 60 * 15, secure }));
  if (data.refreshToken) {
    res.cookies.set(REFRESH_COOKIE, data.refreshToken, cookieOptions({ maxAge: 60 * 60 * 24 * 7, secure }));
  }
  // Non-httpOnly hint so middleware can gate on role without decoding the JWT
  res.cookies.set(ROLE_COOKIE, roleName, {
    httpOnly: false,
    secure,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 7,
  });

  return res;
}
