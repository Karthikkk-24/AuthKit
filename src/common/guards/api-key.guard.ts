import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma/prisma.service';
import { TokenBlacklistService } from '../../auth/token-blacklist.service';
import * as crypto from 'crypto';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenBlacklist: TokenBlacklistService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const rawKey = this.extractApiKey(request);

    if (!rawKey) {
      throw new UnauthorizedException('API key required');
    }

    // Hash the provided key and look it up
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

    const apiKey = await this.prisma.apiKey.findUnique({
      where: { keyHash },
      include: { user: { include: { role: { include: { permissions: true } } } } },
    });

    if (!apiKey) throw new UnauthorizedException('Invalid API key');
    if (apiKey.isRevoked) throw new ForbiddenException('API key has been revoked');
    if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
      throw new ForbiddenException('API key has expired');
    }
    if (!apiKey.user || apiKey.user.deletedAt) {
      throw new ForbiddenException('Associated user not found or deleted');
    }

    // Update last used timestamp (non-blocking)
    this.prisma.apiKey
      .update({ where: { id: apiKey.id }, data: { lastUsedAt: new Date() } })
      .catch(() => {});

    // Attach user to request with scopes
    request['user'] = {
      ...apiKey.user,
      apiKeyScopes: apiKey.scopes,
      isApiKeyAuth: true,
    };

    return true;
  }

  private extractApiKey(request: any): string | null {
    // X-API-Key header
    if (request.headers?.['x-api-key']) {
      return request.headers['x-api-key'];
    }
    // Authorization: ApiKey <key>
    const auth = request.headers?.['authorization'];
    if (auth?.startsWith('ApiKey ')) {
      return auth.substring(7);
    }
    // Query param ?api_key=
    if (request.query?.api_key) {
      return request.query.api_key;
    }
    return null;
  }
}
