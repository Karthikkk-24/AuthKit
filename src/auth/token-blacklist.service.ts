import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { InjectRedis } from '@nestjs-modules/ioredis';
import Redis from 'ioredis';

@Injectable()
export class TokenBlacklistService {
  private readonly logger = new Logger(TokenBlacklistService.name);
  private readonly PREFIX = 'blacklist:';

  constructor(@InjectRedis() private readonly redis: Redis) {}

  private get isStrict(): boolean {
    return (
      process.env.NODE_ENV === 'production' ||
      process.env.AUTHKIT_STRICT_REDIS === 'true'
    );
  }

  /**
   * Blacklist a token until its expiry time
   * @param token The raw JWT string
   * @param expiresInSeconds How many seconds until the token would expire
   */
  async blacklist(token: string, expiresInSeconds: number): Promise<void> {
    try {
      const key = this.PREFIX + this.hashToken(token);
      await this.redis.setex(key, Math.max(1, expiresInSeconds), '1');
    } catch (err) {
      this.logger.error('Failed to blacklist token', err);
      if (this.isStrict) {
        throw new ServiceUnavailableException(
          'Token revocation store unavailable',
        );
      }
    }
  }

  /**
   * Check if a token is blacklisted.
   * Production/strict: fail closed when Redis is unavailable.
   * Development: fail open so local DX is not blocked by Redis outages.
   */
  async isBlacklisted(token: string): Promise<boolean> {
    try {
      const key = this.PREFIX + this.hashToken(token);
      const result = await this.redis.get(key);
      return result === '1';
    } catch (err) {
      this.logger.error('Failed to check token blacklist', err);
      if (this.isStrict) {
        throw new ServiceUnavailableException(
          'Token revocation store unavailable',
        );
      }
      return false;
    }
  }

  /** Used by health checks */
  async ping(): Promise<boolean> {
    const pong = await this.redis.ping();
    return pong === 'PONG';
  }

  private hashToken(token: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}
