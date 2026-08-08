import { NextRequest, NextResponse } from 'next/server';
import {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  ROLE_COOKIE,
  cookieOptions,
  backendUrl,
} from '@/lib/auth-cookies';
import { assertSameOrigin } from '@/lib/csrf';

/**
 * BFF MFA completion for OAuth / magic-link (#110).
 * After `/auth/oauth/exchange` returns `requiresMfa` + `mfaToken`, the admin UI
 * posts here so Nest can mint tokens and we set httpOnly cookies.
 */
export async function POST(req: NextRequest) {
  const csrf = assertSameOrigin(req);
  if (csrf) return csrf;

  let body: { mfaToken?: string; mfaCode?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ message: 'Invalid JSON body' }, { status: 400 });
  }

  if (!body.mfaToken || !body.mfaCode) {
    return NextResponse.json(
      { message: 'mfaToken and mfaCode are required' },
      { status: 400 },
    );
  }

  const upstream = await fetch(`${backendUrl()}/auth/mfa/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfaToken: body.mfaToken, mfaCode: body.mfaCode }),
  });

  const data = await upstream.json().catch(() => ({}));
  if (!upstream.ok) {
    return NextResponse.json(
      { message: data.message ?? 'MFA verification failed' },
      { status: upstream.status },
    );
  }

  if (!data.accessToken) {
    return NextResponse.json({ message: 'Unexpected MFA response' }, { status: 502 });
  }

  const roleName: string = data?.user?.role ?? '';
  if (!['admin', 'superadmin'].includes(roleName)) {
    return NextResponse.json(
      {
        ok: true,
        nonAdmin: true,
        message:
          'Sign-in succeeded, but the admin console requires an admin or superadmin role.',
        user: data.user,
      },
      { status: 200 },
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

  res.cookies.set(ACCESS_COOKIE, data.accessToken, cookieOptions({ maxAge: 60 * 15 }));
  if (data.refreshToken) {
    res.cookies.set(
      REFRESH_COOKIE,
      data.refreshToken,
      cookieOptions({ maxAge: 60 * 60 * 24 * 7 }),
    );
  }
  res.cookies.set(ROLE_COOKIE, roleName, cookieOptions({ maxAge: 60 * 60 * 24 * 7 }));

  return res;
}
