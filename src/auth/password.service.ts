import { Injectable, Logger } from '@nestjs/common';
import * as argon2 from 'argon2';
import { ConfigLoaderService } from '../config/config-loader.service';

@Injectable()
export class PasswordService {
  private readonly logger = new Logger(PasswordService.name);
  /** Cached Argon2id hash used to equalize login timing for unknown users (#128). */
  private dummyHashPromise: Promise<string> | null = null;

  constructor(private readonly config: ConfigLoaderService) {}

  /**
   * Hash a password using Argon2id
   */
  async hash(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,   // 64 MB
      timeCost: 3,
      parallelism: 4,
    });
  }

  /**
   * Verify a password against a stored hash
   */
  async verify(hash: string, password: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }

  /**
   * Run Argon2 verify against a dummy hash so missing/OAuth-only accounts
   * take similar time to password accounts (#128).
   */
  async verifyDummy(password: string): Promise<void> {
    if (!this.dummyHashPromise) {
      this.dummyHashPromise = this.hash('__authkit_timing_dummy__');
    }
    const dummy = await this.dummyHashPromise;
    await this.verify(dummy, password);
  }

  /**
   * Validate password strength against config rules
   */
  validateStrength(password: string): { valid: boolean; errors: string[] } {
    const cfg = this.config.get<any>('auth').password;
    const errors: string[] = [];

    if (password.length < cfg.minLength) {
      errors.push(`Password must be at least ${cfg.minLength} characters`);
    }
    if (password.length > cfg.maxLength) {
      errors.push(`Password must be at most ${cfg.maxLength} characters`);
    }
    if (cfg.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    if (cfg.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    if (cfg.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    if (cfg.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Check if a password has been compromised via HaveIBeenPwned k-anonymity API
   */
  async isPwned(password: string): Promise<boolean> {
    try {
      const crypto = require('crypto');
      const sha1 = crypto
        .createHash('sha1')
        .update(password)
        .digest('hex')
        .toUpperCase();
      const prefix = sha1.substring(0, 5);
      const suffix = sha1.substring(5);

      const response = await fetch(
        `https://api.pwnedpasswords.com/range/${prefix}`,
        { headers: { 'Add-Padding': 'true' } },
      );
      if (!response.ok) return false;

      const text = await response.text();
      const lines = text.split('\n');
      return lines.some((line) => {
        const [hash] = line.split(':');
        return hash.trim() === suffix;
      });
    } catch (err) {
      this.logger.warn('HaveIBeenPwned check failed (non-critical):', err);
      return false;
    }
  }
}
