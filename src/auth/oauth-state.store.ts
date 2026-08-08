import * as crypto from 'crypto';

const COOKIE_NAME = 'authkit_oauth_state';
const TTL_MS = 10 * 60 * 1000;

/**
 * Passport OAuth2 state store backed by a signed httpOnly cookie (#127).
 * Avoids NullStore (CSRF) without requiring express-session.
 */
export class SignedCookieOAuthStateStore {
  constructor(private readonly secret: string) {
    if (!secret || secret.length < 32) {
      throw new Error('OAuth state store requires a secret of at least 32 characters');
    }
  }

  /** passport-oauth2: store(req, callback) or store(req, meta, callback) */
  store(req: any, metaOrCb: any, maybeCb?: any): void {
    const cb = typeof metaOrCb === 'function' ? metaOrCb : maybeCb;
    try {
      const state = crypto.randomBytes(24).toString('hex');
      const exp = Date.now() + TTL_MS;
      const payload = `${state}.${exp}`;
      const sig = this.sign(payload);
      this.setCookie(req, `${payload}.${sig}`, Math.floor(TTL_MS / 1000));
      cb(null, state);
    } catch (err) {
      cb(err as Error);
    }
  }

  /** passport-oauth2: verify(req, providedState, callback) → callback(err, ok, state) */
  verify(
    req: any,
    providedState: string,
    cb: (err: any, ok?: boolean, state?: string) => void,
  ): void {
    try {
      const raw = this.readCookie(req);
      this.clearCookie(req);

      if (!raw || !providedState || typeof providedState !== 'string') {
        cb(null, false);
        return;
      }

      const lastDot = raw.lastIndexOf('.');
      if (lastDot <= 0) {
        cb(null, false);
        return;
      }
      const payload = raw.slice(0, lastDot);
      const sig = raw.slice(lastDot + 1);
      if (!this.sigsMatch(sig, this.sign(payload))) {
        cb(null, false);
        return;
      }

      const sep = payload.indexOf('.');
      if (sep <= 0) {
        cb(null, false);
        return;
      }
      const state = payload.slice(0, sep);
      const exp = Number(payload.slice(sep + 1));
      if (!state || !Number.isFinite(exp) || Date.now() > exp) {
        cb(null, false);
        return;
      }

      if (!this.stringsMatch(state, providedState)) {
        cb(null, false);
        return;
      }

      cb(null, true, providedState);
    } catch {
      cb(null, false);
    }
  }

  private sign(payload: string): string {
    return crypto.createHmac('sha256', this.secret).update(payload).digest('hex');
  }

  private sigsMatch(a: string, b: string): boolean {
    try {
      const ba = Buffer.from(a, 'hex');
      const bb = Buffer.from(b, 'hex');
      return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
    } catch {
      return false;
    }
  }

  private stringsMatch(a: string, b: string): boolean {
    const ba = Buffer.from(a);
    const bb = Buffer.from(b);
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  }

  private readCookie(req: any): string | null {
    if (req.cookies && typeof req.cookies[COOKIE_NAME] === 'string') {
      return req.cookies[COOKIE_NAME];
    }
    const header = req.headers?.cookie;
    if (!header || typeof header !== 'string') return null;
    for (const part of header.split(';')) {
      const idx = part.indexOf('=');
      if (idx < 0) continue;
      const name = part.slice(0, idx).trim();
      if (name !== COOKIE_NAME) continue;
      try {
        return decodeURIComponent(part.slice(idx + 1).trim());
      } catch {
        return part.slice(idx + 1).trim();
      }
    }
    return null;
  }

  private setCookie(req: any, value: string, maxAgeSec: number): void {
    const res = req.res;
    if (!res) throw new Error('OAuth state store requires res on request');
    const secure =
      process.env.NODE_ENV === 'production' ||
      process.env.COOKIE_SECURE === 'true';
    const cookie = [
      `${COOKIE_NAME}=${encodeURIComponent(value)}`,
      'HttpOnly',
      'Path=/',
      `Max-Age=${maxAgeSec}`,
      'SameSite=Lax',
      ...(secure ? ['Secure'] : []),
    ].join('; ');
    this.appendSetCookie(res, cookie);
  }

  private clearCookie(req: any): void {
    const res = req.res;
    if (!res) return;
    const secure =
      process.env.NODE_ENV === 'production' ||
      process.env.COOKIE_SECURE === 'true';
    const cookie = [
      `${COOKIE_NAME}=`,
      'HttpOnly',
      'Path=/',
      'Max-Age=0',
      'SameSite=Lax',
      ...(secure ? ['Secure'] : []),
    ].join('; ');
    this.appendSetCookie(res, cookie);
  }

  private appendSetCookie(res: any, cookie: string): void {
    if (typeof res.append === 'function') {
      res.append('Set-Cookie', cookie);
      return;
    }
    const prev = res.getHeader?.('Set-Cookie');
    if (!prev) {
      res.setHeader('Set-Cookie', cookie);
    } else if (Array.isArray(prev)) {
      res.setHeader('Set-Cookie', [...prev, cookie]);
    } else {
      res.setHeader('Set-Cookie', [prev, cookie]);
    }
  }
}

/** Resolve HMAC secret for OAuth CSRF state cookies. */
export function resolveOAuthStateSecret(): string {
  const dedicated = process.env.OAUTH_STATE_SECRET;
  if (dedicated && dedicated.length >= 32) return dedicated;

  const jwt = process.env.JWT_SECRET;
  if (jwt && jwt.length >= 32) return jwt;

  const authkit = process.env.AUTHKIT_SECRET_KEY;
  if (authkit && authkit.length >= 32) return authkit;

  if (
    process.env.NODE_ENV === 'production' ||
    process.env.AUTHKIT_STRICT_JWT === 'true'
  ) {
    throw new Error(
      'OAuth state requires OAUTH_STATE_SECRET or JWT_SECRET (min 32 chars)',
    );
  }

  return crypto.randomBytes(32).toString('hex');
}
