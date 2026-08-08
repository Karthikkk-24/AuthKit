import { NextRequest, NextResponse } from 'next/server';
import {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  cookieOptions,
  backendUrl,
} from '@/lib/auth-cookies';
import { assertSameOrigin } from '@/lib/csrf';
import { assertAllowedBackendPath } from '@/lib/bff-allowlist';

/**
 * Same-origin BFF proxy (#24, #81, #135). Forwards allowlisted dashboard API
 * calls to Nest with the httpOnly access token attached as Authorization.
 * Mutating methods require same-origin Origin/Referer.
 */
async function proxy(req: NextRequest, pathSegments: string[]) {
  const csrf = assertSameOrigin(req);
  if (csrf) return csrf;

  const pathError = assertAllowedBackendPath(pathSegments);
  if (pathError) {
    return NextResponse.json({ message: pathError }, { status: 403 });
  }

  const access = req.cookies.get(ACCESS_COOKIE)?.value;
  if (!access) {
    return NextResponse.json({ message: 'Unauthorized' }, { status: 401 });
  }

  const subpath = pathSegments.join('/');
  const search = req.nextUrl.search;
  const url = `${backendUrl()}/${subpath}${search}`;

  const headers = new Headers();
  headers.set('Authorization', `Bearer ${access}`);
  const contentType = req.headers.get('content-type');
  if (contentType) headers.set('Content-Type', contentType);

  const init: RequestInit = {
    method: req.method,
    headers,
  };

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const body = await req.arrayBuffer();
    if (body.byteLength > 0) {
      (init as RequestInit & { duplex?: string }).duplex = 'half';
      init.body = body;
    }
  }

  let upstream = await fetch(url, init);

  // One silent refresh attempt on expired access token
  if (upstream.status === 401) {
    const refreshed = await tryRefresh(req);
    if (refreshed) {
      headers.set('Authorization', `Bearer ${refreshed.accessToken}`);
      upstream = await fetch(url, { ...init, headers });
      const res = await buildResponse(upstream);
      res.cookies.set(
        ACCESS_COOKIE,
        refreshed.accessToken,
        cookieOptions({ maxAge: 60 * 15 }),
      );
      if (refreshed.refreshToken) {
        res.cookies.set(
          REFRESH_COOKIE,
          refreshed.refreshToken,
          cookieOptions({ maxAge: 60 * 60 * 24 * 7 }),
        );
      }
      return res;
    }
  }

  return buildResponse(upstream);
}

async function tryRefresh(
  req: NextRequest,
): Promise<{ accessToken: string; refreshToken?: string } | null> {
  const refresh = req.cookies.get(REFRESH_COOKIE)?.value;
  if (!refresh) return null;
  const res = await fetch(`${backendUrl()}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken: refresh }),
  }).catch(() => null);
  if (!res || !res.ok) return null;
  const data = await res.json().catch(() => null);
  if (!data?.accessToken) return null;
  return data;
}

async function buildResponse(upstream: Response) {
  const buf = await upstream.arrayBuffer();
  const headers = new Headers();
  const ct = upstream.headers.get('content-type');
  if (ct) headers.set('content-type', ct);
  const cd = upstream.headers.get('content-disposition');
  if (cd) headers.set('content-disposition', cd);
  return new NextResponse(buf, { status: upstream.status, headers });
}

type Ctx = { params: Promise<{ path: string[] }> };

export async function GET(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return proxy(req, path);
}
export async function POST(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return proxy(req, path);
}
export async function PATCH(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return proxy(req, path);
}
export async function PUT(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return proxy(req, path);
}
export async function DELETE(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return proxy(req, path);
}
