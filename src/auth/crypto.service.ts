import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

/**
 * Small at-rest encryption helper for secrets we must keep reversibly
 * encrypted (e.g. TOTP shared secrets). AES-256-GCM with an env-provided
 * key (AUTHKIT_SECRET_KEY) or, in non-production, a process-ephemeral key.
 */
@Injectable()
export class CryptoService {
  private readonly logger = new Logger(CryptoService.name);
  private key: Buffer | null = null;
  private warnedEphemeral = false;

  private getKey(): Buffer {
    if (this.key) return this.key;
    const hex = process.env.AUTHKIT_SECRET_KEY;
    const isProd =
      process.env.NODE_ENV === 'production' ||
      process.env.AUTHKIT_STRICT_JWT === 'true';

    if (hex && /^[0-9a-fA-F]{64}$/.test(hex)) {
      this.key = Buffer.from(hex, 'hex');
      return this.key;
    }

    if (isProd) {
      throw new Error(
        'AUTHKIT_SECRET_KEY must be a 64-char hex string (32 bytes) in production for encrypting secrets at rest. ' +
          'Generate with: openssl rand -hex 32',
      );
    }

    if (!this.warnedEphemeral) {
      this.logger.warn(
        'AUTHKIT_SECRET_KEY missing — using an ephemeral in-memory key. TOTP secrets encrypted now will not decrypt after restart. Set AUTHKIT_SECRET_KEY.',
      );
      this.warnedEphemeral = true;
    }
    this.key = crypto.randomBytes(32);
    return this.key;
  }

  /** Encrypt plaintext → base64 payload `iv.authTag.ciphertext`. */
  encrypt(plainText: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.getKey(), iv);
    const enc = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return [iv.toString('base64'), tag.toString('base64'), enc.toString('base64')].join('.');
  }

  /** Decrypt a payload produced by {@link encrypt}. */
  decrypt(payload: string): string {
    const parts = payload.split('.');
    if (parts.length !== 3) {
      throw new Error('Malformed encrypted payload');
    }
    const [ivB64, tagB64, dataB64] = parts;
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.getKey(),
      Buffer.from(ivB64, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    const dec = Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]);
    return dec.toString('utf8');
  }
}
