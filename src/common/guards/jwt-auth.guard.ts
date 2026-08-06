import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { TokenBlacklistService } from '../../auth/token-blacklist.service';
import { ConfigLoaderService } from '../../config/config-loader.service';
import { PrismaService } from '../../database/prisma/prisma.service';
import * as crypto from 'crypto';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwtService: JwtService,
    private readonly tokenBlacklist: TokenBlacklistService,
    private readonly config: ConfigLoaderService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest();
    const bearerToken = this.extractBearerToken(request);

    if (bearerToken) {
      return this.authenticateJwt(request, bearerToken);
    }

    // Fall back to API key auth when no Bearer/cookie JWT is present (#14)
    const apiKey = this.extractApiKey(request);
    if (apiKey) {
      return this.authenticateApiKey(request, apiKey);
    }

    throw new UnauthorizedException('No authentication token provided');
  }

  private async authenticateJwt(request: any, token: string): Promise<boolean> {
    const isBlacklisted = await this.tokenBlacklist.isBlacklisted(token);
    if (isBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    let payload: any;
    try {
      const jwtConfig = this.config.get<any>('auth').jwt;
      payload = await this.jwtService.verifyAsync(token, {
        algorithms: [jwtConfig.algorithm],
        issuer: jwtConfig.issuer,
        audience: jwtConfig.audience,
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    if (!payload?.sub || typeof payload.sub !== 'string') {
      throw new UnauthorizedException('Invalid token payload');
    }

    // Reject locked / soft-deleted users and revoked sessions (#8)
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        email: true,
        roleId: true,
        isLocked: true,
        deletedAt: true,
      },
    });

    if (!user || user.deletedAt) {
      throw new UnauthorizedException('Account not found');
    }
    if (user.isLocked) {
      throw new ForbiddenException('Account is locked');
    }

    if (payload.sessionId) {
      const session = await this.prisma.session.findUnique({
        where: { id: payload.sessionId },
        select: {
          id: true,
          userId: true,
          isRevoked: true,
          expiresAt: true,
          lastActiveAt: true,
        },
      });
      if (
        !session ||
        session.userId !== user.id ||
        session.isRevoked ||
        session.expiresAt < new Date()
      ) {
        throw new UnauthorizedException('Session has been revoked');
      }

      // Auto-revoke sessions that have been idle longer than the configured
      // inactivity window (#31).
      const sessionCfg = this.config.get<any>('session') ?? {};
      if (sessionCfg.autoRevokeInactiveSessions && sessionCfg.inactivityTimeoutDays > 0) {
        const idleMs = Date.now() - session.lastActiveAt.getTime();
        const maxIdleMs = sessionCfg.inactivityTimeoutDays * 24 * 60 * 60 * 1000;
        if (idleMs > maxIdleMs) {
          await this.prisma.session
            .update({
              where: { id: session.id },
              data: { isRevoked: true, revokedAt: new Date() },
            })
            .catch(() => {});
          throw new UnauthorizedException('Session expired due to inactivity');
        }
      }

      this.prisma.session
        .update({
          where: { id: session.id },
          data: { lastActiveAt: new Date() },
        })
        .catch(() => {});
    }

    // Tokens minted for MFA enrollment are scope-limited (#23, #124).
    // Match pathname only — never raw request.url (query can contain "/auth/mfa/").
    if (payload.type === 'mfa_setup' && !this.isMfaSetupPathAllowed(request)) {
      throw new ForbiddenException('Token is restricted to MFA setup');
    }

    request['user'] = {
      ...payload,
      id: user.id,
      email: user.email,
      roleId: user.roleId,
      roleName: payload.roleName,
      sessionId: payload.sessionId,
      isApiKeyAuth: false,
    };

    return true;
  }

  private async authenticateApiKey(
    request: any,
    rawKey: string,
  ): Promise<boolean> {
    if (
      !this.config.isStrategyEnabled('apiKey') ||
      !this.config.isFeatureEnabled('apiKeys')
    ) {
      throw new UnauthorizedException('API key authentication is disabled');
    }

    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const apiKey = await this.prisma.apiKey.findUnique({
      where: { keyHash },
      include: {
        user: { include: { role: { include: { permissions: true } } } },
      },
    });

    if (!apiKey) throw new UnauthorizedException('Invalid API key');
    if (apiKey.isRevoked || apiKey.revokedAt) {
      throw new ForbiddenException('API key has been revoked');
    }
    if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
      throw new ForbiddenException('API key has expired');
    }
    if (!apiKey.user || apiKey.user.deletedAt) {
      throw new ForbiddenException('Associated user not found or deleted');
    }
    if (apiKey.user.isLocked) {
      throw new ForbiddenException('Account is locked');
    }

    this.prisma.apiKey
      .update({ where: { id: apiKey.id }, data: { lastUsedAt: new Date() } })
      .catch(() => {});

    request['user'] = {
      id: apiKey.user.id,
      email: apiKey.user.email,
      roleId: apiKey.user.roleId,
      roleName: apiKey.user.role?.name,
      apiKeyId: apiKey.id,
      apiKeyScopes: apiKey.scopes,
      isApiKeyAuth: true,
    };

    return true;
  }

  /**
   * Paths an `mfa_setup` JWT may call (#124). Compared against pathname only
   * (no query/hash), with optional `/api` global prefix.
   */
  private static readonly MFA_SETUP_PATHS = new Set([
    '/auth/me',
    '/api/auth/me',
    '/auth/mfa/totp/setup',
    '/api/auth/mfa/totp/setup',
    '/auth/mfa/totp/enable',
    '/api/auth/mfa/totp/enable',
    '/auth/mfa/email/send',
    '/api/auth/mfa/email/send',
    '/auth/mfa/email/verify',
    '/api/auth/mfa/email/verify',
  ]);

  private isMfaSetupPathAllowed(request: any): boolean {
    // Prefer Express `path` (query already stripped). Fall back to url/originalUrl.
    const raw: string =
      request.path || request.originalUrl || request.url || '';
    const pathname = String(raw).split('?')[0].split('#')[0];
    const normalized =
      pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
    return JwtAuthGuard.MFA_SETUP_PATHS.has(normalized);
  }

  private extractBearerToken(request: any): string | null {
    const authHeader = request.headers?.['authorization'];
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    // Cookie-based Nest sessions were never issued end-to-end (#51).
    // The admin console uses a same-origin BFF that stores httpOnly cookies
    // and proxies with Authorization: Bearer — do not accept raw cookies here.
    return null;
  }

  private extractApiKey(request: any): string | null {
    if (request.headers?.['x-api-key']) {
      return request.headers['x-api-key'];
    }
    const auth = request.headers?.['authorization'];
    if (auth?.startsWith('ApiKey ')) {
      return auth.substring(7);
    }
    // Reject query-param keys — they leak into logs, proxies, Referer (#69)
    if (request.query?.api_key) {
      throw new UnauthorizedException(
        'API keys must be sent via X-API-Key or Authorization: ApiKey header',
      );
    }
    return null;
  }
}
