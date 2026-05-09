import { Injectable, Logger } from '@nestjs/common';
import { InjectRedis } from '@nestjs-modules/ioredis';
import Redis from 'ioredis';

@Injectable()
export class TokenBlacklistService {
  private readonly logger = new Logger(TokenBlacklistService.name);
  private readonly PREFIX = 'blacklist:';

  constructor(@InjectRedis() private readonly redis: Redis) {}

  /**
   * Blacklist a token until its expiry time
   * @param token The raw JWT string
   * @param expiresInSeconds How many seconds until the token would expire
   */
  async blacklist(token: string, expiresInSeconds: number): Promise<void> {
    try {
      const key = this.PREFIX + this.hashToken(token);
      await this.redis.setex(key, expiresInSeconds, '1');
    } catch (err) {
      this.logger.error('Failed to blacklist token', err);
    }
  }

  /**
   * Check if a token is blacklisted
   */
  async isBlacklisted(token: string): Promise<boolean> {
    try {
      const key = this.PREFIX + this.hashToken(token);
      const result = await this.redis.get(key);
      return result === '1';
    } catch (err) {
      this.logger.error('Failed to check token blacklist', err);
      // Fail open (don't block auth if Redis is temporarily down)
      return false;
    }
  }

  /**
   * Hash the token to keep Redis keys short and avoid storing sensitive data
   */
  private hashToken(token: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}
