import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export type JwtKeyMaterial = {
  /** Private key (RS*) or shared secret (HS*) used for signing */
  secret: string | Buffer;
  /** Public key for RS* verify; same as secret for HS* */
  publicKey: string | Buffer;
  algorithm: string;
};

/** Process-wide cache so AuthModule + JwtStrategy share the same ephemeral keys. */
let cachedKeys: JwtKeyMaterial | null = null;

/**
 * Resolve JWT signing/verification keys without a hardcoded fallback secret.
 *
 * - RS256/RS384/RS512: requires ./keys/private.pem + public.pem (or fails in production)
 * - HS*: requires JWT_SECRET env (or fails in production)
 * - Development only: may generate ephemeral RSA keys or a random HS secret for the process
 */
export function resolveJwtKeys(algorithm: string): JwtKeyMaterial {
  if (cachedKeys && cachedKeys.algorithm === algorithm) {
    return cachedKeys;
  }

  const isRsa = algorithm.startsWith('RS');
  const isProd =
    process.env.NODE_ENV === 'production' ||
    process.env.AUTHKIT_STRICT_JWT === 'true';

  const privKeyPath = path.resolve(process.cwd(), 'keys', 'private.pem');
  const pubKeyPath = path.resolve(process.cwd(), 'keys', 'public.pem');

  let keys: JwtKeyMaterial;

  if (isRsa) {
    if (fs.existsSync(privKeyPath) && fs.existsSync(pubKeyPath)) {
      keys = {
        secret: fs.readFileSync(privKeyPath),
        publicKey: fs.readFileSync(pubKeyPath),
        algorithm,
      };
    } else if (isProd) {
      throw new Error(
        `JWT algorithm ${algorithm} requires RSA keys at ./keys/private.pem and ./keys/public.pem. ` +
          `Run: npm run keys:generate`,
      );
    } else {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });
      // eslint-disable-next-line no-console
      console.warn(
        '[AuthKit] RSA key files missing — using ephemeral in-memory RSA keys for development. ' +
          'Run `npm run keys:generate` for stable tokens across restarts.',
      );
      keys = {
        secret: privateKey.export({ type: 'pkcs8', format: 'pem' }),
        publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
        algorithm,
      };
    }
  } else {
    const envSecret = process.env.JWT_SECRET;
    if (envSecret && envSecret.length >= 32) {
      keys = { secret: envSecret, publicKey: envSecret, algorithm };
    } else if (isProd) {
      throw new Error(
        `JWT algorithm ${algorithm} requires JWT_SECRET (min 32 chars). ` +
          `Do not use hardcoded defaults.`,
      );
    } else {
      if (envSecret && envSecret.length < 32) {
        // eslint-disable-next-line no-console
        console.warn(
          '[AuthKit] JWT_SECRET is shorter than 32 characters — generating an ephemeral secret for development.',
        );
      } else {
        // eslint-disable-next-line no-console
        console.warn(
          '[AuthKit] JWT_SECRET not set — generating an ephemeral secret for development. ' +
            'Set JWT_SECRET (32+ chars) or use RS256 with ./keys/*.pem.',
        );
      }
      const ephemeral = crypto.randomBytes(48).toString('hex');
      keys = { secret: ephemeral, publicKey: ephemeral, algorithm };
    }
  }

  cachedKeys = keys;
  return keys;
}

/** Test-only helper to clear cached keys between cases. */
export function resetJwtKeysCacheForTests(): void {
  cachedKeys = null;
}
