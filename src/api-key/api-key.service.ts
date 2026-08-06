import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  UnauthorizedException,
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
        scopes: dto.scopes ?? [],
        expiresAt,
      },
    });

    await this.audit.log({
      action: 'apikey.created',
      userId,
      resourceId: apiKey.id,
      resourceType: 'apikey',
      metadata: { name: dto.name, scopes: dto.scopes },
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
