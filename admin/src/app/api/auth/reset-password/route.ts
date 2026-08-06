import { NextRequest, NextResponse } from 'next/server';
import { backendUrl } from '@/lib/auth-cookies';
import { assertSameOrigin } from '@/lib/csrf';

/** Public BFF proxy for password reset (#71). */
export async function POST(req: NextRequest) {
  const csrf = assertSameOrigin(req);
  if (csrf) return csrf;

  let body: { token?: string; newPassword?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ message: 'Invalid JSON body' }, { status: 400 });
  }

  if (!body.token || !body.newPassword) {
    return NextResponse.json(
      { message: 'token and newPassword are required' },
      { status: 400 },
    );
  }

  const upstream = await fetch(`${backendUrl()}/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: body.token,
      newPassword: body.newPassword,
    }),
  });

  const data = await upstream.json().catch(() => ({}));
  return NextResponse.json(
    data?.message ? data : { message: upstream.ok ? 'Password updated' : 'Reset failed' },
    { status: upstream.status },
  );
}
