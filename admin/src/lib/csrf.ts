/**
 * CSRF defense for cookie-authenticated BFF routes (#81).
 * SameSite=Lax already helps; Origin/Referer checks block cross-site POSTs.
 */
export function assertSameOrigin(req: Request): Response | null {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return null;
  }

  const origin = req.headers.get('origin');
  const referer = req.headers.get('referer');
  const host = req.headers.get('host');
  if (!host) {
    return Response.json({ message: 'Missing Host header' }, { status: 403 });
  }

  const allowed = new Set<string>();
  allowed.add(`https://${host}`);
  allowed.add(`http://${host}`);
  const appUrl = process.env.NEXT_PUBLIC_APP_URL || process.env.ADMIN_URL;
  if (appUrl) {
    try {
      const u = new URL(appUrl);
      allowed.add(u.origin);
    } catch {
      /* ignore */
    }
  }

  const candidate = origin || (referer ? safeOrigin(referer) : null);
  if (!candidate) {
    // Non-browser clients (curl) without Origin — allow only if no cookie auth?
    // Cookie-bearing mutating requests from browsers always send Origin.
    // Reject missing Origin on mutating methods to block CSRF.
    return Response.json({ message: 'Missing Origin' }, { status: 403 });
  }

  if (!allowed.has(candidate)) {
    return Response.json({ message: 'Cross-origin request blocked' }, { status: 403 });
  }

  return null;
}

function safeOrigin(referer: string): string | null {
  try {
    return new URL(referer).origin;
  } catch {
    return null;
  }
}
