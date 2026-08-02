import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { Reflector } from '@nestjs/core';
import { ConfigLoaderService } from '../../config/config-loader.service';
import { PrismaService } from '../../database/prisma/prisma.service';

/**
 * Enforces `security.ipAllowlist` and `security.ipBlocklist` from
 * authkit.config.json plus persisted, time-bounded IpBlock rows (#22).
 * Runs before authentication so blocked IPs are rejected cheaply.
 */
@Injectable()
export class IpListGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly config: ConfigLoaderService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Only applies to HTTP requests
    if (context.getType() !== 'http') return true;

    const request = context.switchToHttp().getRequest();
    const security = this.config.get<any>('security') ?? {};
    const allowlist: string[] = security.ipAllowlist ?? [];
    const blocklist: string[] = security.ipBlocklist ?? [];

    const ip: string | undefined =
      request.ip ||
      request.socket?.remoteAddress ||
      request.connection?.remoteAddress;

    if (!ip) return true; // unable to determine IP — let other guards decide
    const normalized = this.normalize(ip);

    // Non-empty allowlist is exclusive: only listed IPs may proceed (#22).
    if (allowlist.length > 0) {
      if (!this.matches(normalized, allowlist)) {
        throw new ForbiddenException('Access denied from this IP');
      }
      return true;
    }

    // Static blocklist
    if (blocklist.length > 0 && this.matches(normalized, blocklist)) {
      throw new ForbiddenException('Access denied from this IP');
    }

    // Dynamic blocks persisted in the DB (respect expirations)
    const blocked = await this.prisma.ipBlock.findFirst({
      where: {
        ip: normalized,
        OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
      },
      select: { id: true },
    });
    if (blocked) {
      throw new ForbiddenException('Access denied from this IP');
    }

    return true;
  }

  private normalize(ip: string): string {
    return ip.replace(/^::ffff:/, '');
  }

  private matches(ip: string, list: string[]): boolean {
    return list.some((entry) => {
      const e = entry.trim();
      if (!e) return false;
      if (e === ip) return true;
      // Simple prefix wildcard, e.g. "10.0." matches the 10.0.x.x range
      if (e.endsWith('.') && ip.startsWith(e)) return true;
      if (e.endsWith('*') && ip.startsWith(e.slice(0, -1))) return true;
      return false;
    });
  }
}
