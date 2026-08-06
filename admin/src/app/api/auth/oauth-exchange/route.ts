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
 * BFF OAuth / magic-link code exchange (#71).
 * Sets httpOnly cookies when the user is admin/superadmin.
 */
export async function POST(req: NextRequest) {
  const csrf = assertSameOrigin(req);
  if (csrf) return csrf;

  let body: { code?: string; mfaCode?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ message: 'Invalid JSON body' }, { status: 400 });
  }

  if (!body.code) {
    return NextResponse.json({ message: 'code is required' }, { status: 400 });
  }

  const upstream = await fetch(`${backendUrl()}/auth/oauth/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: body.code, mfaCode: body.mfaCode }),
  });

  const data = await upstream.json().catch(() => ({}));
  if (!upstream.ok) {
    return NextResponse.json(
      { message: data.message ?? 'Exchange failed' },
      { status: upstream.status },
    );
  }

  if (data.requiresMfa || data.mfaSetupRequired) {
    return NextResponse.json(data, { status: 200 });
  }

  if (!data.accessToken) {
    return NextResponse.json({ message: 'Unexpected exchange response' }, { status: 502 });
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

  const secure = process.env.NODE_ENV === 'production';
  res.cookies.set(ACCESS_COOKIE, data.accessToken, cookieOptions({ maxAge: 60 * 15, secure }));
  if (data.refreshToken) {
    res.cookies.set(
      REFRESH_COOKIE,
      data.refreshToken,
      cookieOptions({ maxAge: 60 * 60 * 24 * 7, secure }),
    );
  }
  res.cookies.set(ROLE_COOKIE, roleName, {
    httpOnly: true,
    secure,
    sameSite: cookieOptions({ maxAge: 1 }).sameSite,
    path: '/',
    maxAge: 60 * 60 * 24 * 7,
  });

  return res;
}
