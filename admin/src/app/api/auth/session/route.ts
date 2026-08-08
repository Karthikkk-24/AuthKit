import { NextRequest, NextResponse } from 'next/server';
import { ACCESS_COOKIE, backendUrl } from '@/lib/auth-cookies';

const ADMIN_ROLES = new Set(['admin', 'superadmin']);

/**
 * Verified session probe for middleware (#137).
 * Nest validates the JWT signature; middleware must not trust decode-only payloads.
 */
export async function GET(req: NextRequest) {
  const access = req.cookies.get(ACCESS_COOKIE)?.value;
  if (!access) {
    return NextResponse.json({ ok: false }, { status: 401 });
  }

  const upstream = await fetch(`${backendUrl()}/auth/me`, {
    method: 'GET',
    headers: { Authorization: `Bearer ${access}` },
    cache: 'no-store',
  }).catch(() => null);

  if (!upstream || !upstream.ok) {
    return NextResponse.json(
      { ok: false },
      { status: upstream?.status ?? 502 },
    );
  }

  const data = await upstream.json().catch(() => ({}));
  const role =
    typeof data.role === 'string'
      ? data.role
      : typeof data.roleName === 'string'
        ? data.roleName
        : null;

  if (!role || !ADMIN_ROLES.has(role)) {
    return NextResponse.json({ ok: false, role }, { status: 403 });
  }

  return NextResponse.json({ ok: true, role });
}
