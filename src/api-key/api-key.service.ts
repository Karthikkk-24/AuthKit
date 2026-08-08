import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  UnauthorizedException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../database/prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { WebhookService } from '../webhook/webhook.service';
import { ConfigLoaderService } from '../config/config-loader.service';
import * as crypto from 'crypto';

@Injectable()
export class ApiKeyService {
  private readonly logger = new Logger(ApiKeyService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly webhooks: WebhookService,
    private readonly config: ConfigLoaderService,
  ) {}

  private assertFeatureEnabled() {
    if (!this.config.isFeatureEnabled('apiKeys')) {
      throw new NotFoundException('Not found');
    }
    if (!this.config.isStrategyEnabled('apiKey')) {
      throw new NotFoundException('Not found');
    }
  }

  private emitWebhook(event: 'apikey.created' | 'apikey.revoked', payload: Record<string, any>) {
    void this.webhooks.dispatch(event, payload).catch((err) => {
      this.logger.warn(`Webhook dispatch failed for ${event}: ${err?.message}`);
    });
  }

  /**
   * Cap API key scopes to the creator's effective permissions (#113).
   * Mirrors PermissionsGuard matching rules for resource:action scopes.
   */
  private async assertScopesWithinUserPermissions(
    userId: string,
    scopes: string[],
  ): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        role: {
          include: {
            permissions: true,
            parent: { include: { permissions: true } },
          },
        },
      },
    });
    if (!user?.role) {
      throw new ForbiddenException('Cannot create API key without a role');
    }

    const rolePerms = this.collectRolePermissions(user.role);
    const overrides = await this.prisma.userPermission.findMany({
      where: { userId },
      select: { action: true, resource: true, effect: true },
    });
    const denies = overrides.filter((o) => o.effect === 'deny');
    const grants = overrides.filter((o) => o.effect === 'grant');
    const allPerms = [
      ...rolePerms,
      ...grants.map((g) => ({ action: g.action, resource: g.resource })),
    ];

    const writeActions = new Set([
      'create',
      'update',
      'delete',
      'revoke',
      'lock',
      'export',
      'assign',
    ]);

    for (const raw of scopes) {
      const scope = raw.toLowerCase();

      const exceeds = (action: string, resource: string) => {
        const req = { action, resource };
        if (
          denies.some(
            (d) =>
              (d.action === action || d.action === '*') &&
              (d.resource === resource || d.resource === '*'),
          )
        ) {
          return true;
        }
        return !this.isPermissionGranted(allPerms, req);
      };

      if (scope === 'admin' || scope === '*:*' || scope === '*') {
        if (exceeds('*', '*')) {
          throw new BadRequestException(
            `Scope "${raw}" exceeds your permissions`,
          );
        }
        continue;
      }

      if (scope === 'read') {
        if (
          !allPerms.some(
            (p) => p.action === 'read' || p.action === '*',
          )
        ) {
          throw new BadRequestException(
            `Scope "${raw}" exceeds your permissions`,
          );
        }
        continue;
      }

      if (scope === 'write') {
        if (
          !allPerms.some(
            (p) => writeActions.has(p.action) || p.action === '*',
          )
        ) {
          throw new BadRequestException(
            `Scope "${raw}" exceeds your permissions`,
          );
        }
        continue;
      }

      const colon = scope.indexOf(':');
      if (colon <= 0) {
        throw new BadRequestException(`Invalid API key scope: ${raw}`);
      }
      const resource = scope.slice(0, colon);
      const action = scope.slice(colon + 1);

      if (action === 'manage' || action === '*') {
        if (exceeds('*', resource === '*' ? '*' : resource)) {
          throw new BadRequestException(
            `Scope "${raw}" exceeds your permissions`,
          );
        }
        continue;
      }

      if (exceeds(action, resource === '*' ? '*' : resource)) {
        throw new BadRequestException(
          `Scope "${raw}" exceeds your permissions`,
        );
      }
    }
  }

  private collectRolePermissions(
    role: any,
    visited = new Set<string>(),
  ): Array<{ action: string; resource: string }> {
    if (!role || visited.has(role.id)) return [];
    visited.add(role.id);
    const perms: Array<{ action: string; resource: string }> = [
      ...(role.permissions ?? []),
    ];
    if (role.parent) {
      perms.push(...this.collectRolePermissions(role.parent, visited));
    }
    return perms;
  }

  private isPermissionGranted(
    perms: Array<{ action: string; resource: string }>,
    req: { action: string; resource: string },
  ): boolean {
    return perms.some(
      (p) =>
        (p.action === req.action && p.resource === req.resource) ||
        (p.action === '*' && p.resource === req.resource) ||
        (p.action === req.action && p.resource === '*') ||
        (p.action === '*' && p.resource === '*'),
    );
  }

  private generateKey(): { raw: string; prefix: string; hashed: string } {
    const raw = `ak_${crypto.randomBytes(32).toString('hex')}`;
    const prefix = raw.slice(0, 8);
    const hashed = crypto.createHash('sha256').update(raw).digest('hex');
    return { raw, prefix, hashed };
  }

  async create(
    userId: string,
    dto: {
      name: string;
      scopes?: string[];
      expiresIn?: number; // days; undefined = never
    },
    req: any,
  ) {
    this.assertFeatureEnabled();

    // Deny-by-default (#113): empty scopes previously inherited full RBAC.
    const scopes = Array.isArray(dto.scopes)
      ? dto.scopes.map((s) => String(s).trim()).filter((s) => s.length > 0)
      : [];
    if (scopes.length === 0) {
      throw new BadRequestException(
        'API key scopes must be a non-empty list (e.g. ["users:read"])',
      );
    }
    await this.assertScopesWithinUserPermissions(userId, scopes);

    const { raw, prefix, hashed } = this.generateKey();
    const expiresAt = dto.expiresIn
      ? new Date(Date.now() + dto.expiresIn * 86_400_000)
      : null;

    const apiKey = await this.prisma.apiKey.create({
      data: {
        userId,
        name: dto.name,
        keyHash: hashed,
        prefix,
        scopes,
        expiresAt,
      },
    });

    await this.audit.log({
      action: 'apikey.created',
      userId,
      resourceId: apiKey.id,
      resourceType: 'apikey',
      metadata: { name: dto.name, scopes },
      ip: req?.ip,
      success: true,
    });

    this.emitWebhook('apikey.created', {
      userId,
      apiKeyId: apiKey.id,
      name: dto.name,
    });

    // Return raw key ONLY at creation time
    return { ...apiKey, key: raw };
  }

  async list(userId: string) {
    this.assertFeatureEnabled();
    return this.prisma.apiKey.findMany({
      where: { userId, revokedAt: null },
      select: {
        id: true,
        name: true,
        prefix: true,
        scopes: true,
        lastUsedAt: true,
        expiresAt: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async revoke(userId: string, keyId: string, req: any) {
    this.assertFeatureEnabled();
    const key = await this.prisma.apiKey.findFirst({
      where: { id: keyId, userId },
    });
    if (!key) throw new NotFoundException('API key not found');
    if (key.revokedAt) throw new ForbiddenException('API key already revoked');

    await this.prisma.apiKey.update({
      where: { id: keyId },
      data: { revokedAt: new Date(), isRevoked: true },
    });

    await this.audit.log({
      action: 'apikey.revoked',
      userId,
      resourceId: keyId,
      resourceType: 'apikey',
      ip: req?.ip,
      success: true,
    });

    this.emitWebhook('apikey.revoked', { userId, apiKeyId: keyId });

    return { message: 'API key revoked' };
  }

  async validate(rawKey: string): Promise<any> {
    const hashed = crypto.createHash('sha256').update(rawKey).digest('hex');

    const apiKey = await this.prisma.apiKey.findFirst({
      where: { keyHash: hashed, revokedAt: null, isRevoked: false },
      include: { user: { include: { role: { include: { permissions: true } } } } },
    });

    if (!apiKey) throw new UnauthorizedException('Invalid API key');
    if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
      throw new UnauthorizedException('API key expired');
    }
    if (apiKey.user.isLocked) throw new ForbiddenException('Account is locked');

    // Update last used
    await this.prisma.apiKey.update({
      where: { id: apiKey.id },
      data: { lastUsedAt: new Date() },
    });

    return {
      user: apiKey.user,
      scopes: apiKey.scopes,
      keyId: apiKey.id,
    };
  }
}
