import { NextRequest, NextResponse } from 'next/server';
import {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  ROLE_COOKIE,
  cookieOptions,
  backendUrl,
} from '@/lib/auth-cookies';

/**
 * BFF login (#24, #105): exchange credentials with the Nest API and store tokens
 * in httpOnly cookies on the admin origin. The JWT never touches localStorage.
 * MFA-enrolled admins resubmit with `mfaCode` — forward it to Nest.
 */
export async function POST(req: NextRequest) {
  let body: { email?: string; password?: string; mfaCode?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ message: 'Invalid JSON body' }, { status: 400 });
  }

  if (!body.email || !body.password) {
    return NextResponse.json({ message: 'Email and password are required' }, { status: 400 });
  }

  const loginPayload: {
    email: string;
    password: string;
    mfaCode?: string;
  } = {
    email: body.email,
    password: body.password,
  };
  if (typeof body.mfaCode === 'string' && body.mfaCode.length > 0) {
    loginPayload.mfaCode = body.mfaCode;
  }

  const upstream = await fetch(`${backendUrl()}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(loginPayload),
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
  // #49 — refuse non-admin sessions before setting cookies (middleware is a second gate)
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

  // Let cookieOptions own Secure (forces Secure when COOKIE_SAMESITE=none) (#84)
  res.cookies.set(ACCESS_COOKIE, data.accessToken, cookieOptions({ maxAge: 60 * 15 }));
  if (data.refreshToken) {
    res.cookies.set(REFRESH_COOKIE, data.refreshToken, cookieOptions({ maxAge: 60 * 60 * 24 * 7 }));
  }
  // httpOnly role hint (no longer trusted by middleware — JWT claim is) (#75)
  res.cookies.set(ROLE_COOKIE, roleName, cookieOptions({ maxAge: 60 * 60 * 24 * 7 }));

  return res;
}
