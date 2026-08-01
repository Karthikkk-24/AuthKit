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

/**
 * Resolve JWT signing/verification keys without a hardcoded fallback secret.
 *
 * - RS256/RS384/RS512: requires ./keys/private.pem + public.pem (or fails in production)
 * - HS*: requires JWT_SECRET env (or fails in production)
 * - Development only: may generate ephemeral RSA keys or a random HS secret for the process
 */
export function resolveJwtKeys(algorithm: string): JwtKeyMaterial {
  const isRsa = algorithm.startsWith('RS');
  const isProd =
    process.env.NODE_ENV === 'production' ||
    process.env.AUTHKIT_STRICT_JWT === 'true';

  const privKeyPath = path.resolve(process.cwd(), 'keys', 'private.pem');
  const pubKeyPath = path.resolve(process.cwd(), 'keys', 'public.pem');

  if (isRsa) {
    if (fs.existsSync(privKeyPath) && fs.existsSync(pubKeyPath)) {
      return {
        secret: fs.readFileSync(privKeyPath),
        publicKey: fs.readFileSync(pubKeyPath),
        algorithm,
      };
    }

    if (isProd) {
      throw new Error(
        `JWT algorithm ${algorithm} requires RSA keys at ./keys/private.pem and ./keys/public.pem. ` +
          `Run: npm run keys:generate`,
      );
    }

    // Dev fallback: ephemeral in-memory RSA key pair (not persisted, not shared across restarts)
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });
    // eslint-disable-next-line no-console
    console.warn(
      '[AuthKit] RSA key files missing — using ephemeral in-memory RSA keys for development. ' +
        'Run `npm run keys:generate` for stable tokens across restarts.',
    );
    return {
      secret: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
      algorithm,
    };
  }

  // HMAC algorithms
  const envSecret = process.env.JWT_SECRET;
  if (envSecret && envSecret.length >= 32) {
    return { secret: envSecret, publicKey: envSecret, algorithm };
  }

  if (isProd) {
    throw new Error(
      `JWT algorithm ${algorithm} requires JWT_SECRET (min 32 chars). ` +
        `Do not use hardcoded defaults.`,
    );
  }

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
  return { secret: ephemeral, publicKey: ephemeral, algorithm };
}
