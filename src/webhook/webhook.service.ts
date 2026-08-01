import {
  Injectable,
  Logger,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../database/prisma/prisma.service';
import { ConfigLoaderService } from '../config/config-loader.service';
import * as crypto from 'crypto';
import * as dns from 'dns/promises';
import * as net from 'net';
import axios from 'axios';

export type WebhookEventType =
  | 'user.registered'
  | 'user.login'
  | 'user.logout'
  | 'user.password_changed'
  | 'user.email_verified'
  | 'user.locked'
  | 'user.unlocked'
  | 'user.deleted'
  | 'mfa.enabled'
  | 'mfa.disabled'
  | 'session.revoked'
  | 'apikey.created'
  | 'apikey.revoked'
  | 'role.assigned';

@Injectable()
export class WebhookService {
  private readonly logger = new Logger(WebhookService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigLoaderService,
  ) {}

  private isDispatchEnabled(): boolean {
    const wh = this.config.get<any>('webhooks');
    return Boolean(wh?.enabled || this.config.isFeatureEnabled('webhooks'));
  }

  async dispatch(event: WebhookEventType, payload: Record<string, any>) {
    if (!this.isDispatchEnabled()) return;

    const endpoints = await this.prisma.webhook.findMany({
      where: {
        isActive: true,
        events: { has: event },
      },
    });

    await Promise.allSettled(
      endpoints.map((ep) => this.deliver(ep, event, payload)),
    );
  }

  private async deliver(endpoint: any, event: string, payload: any) {
    try {
      await this.assertSafeWebhookUrl(endpoint.url);
    } catch (err: any) {
      this.logger.warn(
        `Skipping webhook delivery to unsafe URL ${endpoint.url}: ${err?.message}`,
      );
      return;
    }

    const body = JSON.stringify({
      event,
      timestamp: new Date().toISOString(),
      data: payload,
    });

    const signature = this.sign(endpoint.secret, body);

    try {
      const response = await axios.post(endpoint.url, body, {
        headers: {
          'Content-Type': 'application/json',
          'X-AuthKit-Event': event,
          'X-AuthKit-Signature': signature,
          'X-AuthKit-Timestamp': Date.now().toString(),
        },
        timeout: 10_000,
        maxRedirects: 0,
        validateStatus: (s) => s >= 200 && s < 300,
      });

      await this.prisma.webhookDelivery.create({
        data: {
          webhookId: endpoint.id,
          event,
          payload,
          statusCode: response.status,
          success: true,
        },
      });

      this.logger.log(`Webhook delivered: ${event} → ${endpoint.url}`);
    } catch (err: any) {
      this.logger.warn(
        `Webhook failed: ${event} → ${endpoint.url}: ${err?.message}`,
      );

      await this.prisma.webhookDelivery.create({
        data: {
          webhookId: endpoint.id,
          event,
          payload,
          statusCode: err.response?.status,
          responseBody: err.response?.data
            ? JSON.stringify(err.response.data)
            : null,
          success: false,
        },
      });
    }
  }

  private sign(secret: string, body: string): string {
    return `sha256=${crypto
      .createHmac('sha256', secret)
      .update(body)
      .digest('hex')}`;
  }

  /**
   * Block SSRF to private/link-local/metadata hosts (#11).
   * Re-checked at delivery time to mitigate DNS rebinding.
   */
  async assertSafeWebhookUrl(rawUrl: string): Promise<void> {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      throw new BadRequestException('Invalid webhook URL');
    }

    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new BadRequestException('Webhook URL must be http(s)');
    }

    // HTTPS required unless explicitly allowed for local/dev
    const allowHttp =
      process.env.NODE_ENV !== 'production' ||
      process.env.AUTHKIT_ALLOW_HTTP_WEBHOOKS === 'true';
    if (parsed.protocol === 'http:' && !allowHttp) {
      throw new BadRequestException('Webhook URL must use HTTPS');
    }

    if (parsed.username || parsed.password) {
      throw new BadRequestException('Webhook URL must not include credentials');
    }

    const hostname = parsed.hostname.toLowerCase();
    const blockedHosts = new Set([
      'localhost',
      'metadata.google.internal',
      'metadata.google.com',
    ]);
    if (
      blockedHosts.has(hostname) ||
      hostname.endsWith('.local') ||
      hostname.endsWith('.internal') ||
      hostname === '0.0.0.0'
    ) {
      throw new BadRequestException('Webhook URL host is not allowed');
    }

    // Literal IP in hostname
    if (net.isIP(hostname) && this.isPrivateIp(hostname)) {
      throw new BadRequestException('Webhook URL must not target private IPs');
    }

    // Resolve DNS and reject private answers
    try {
      const results = await dns.lookup(hostname, { all: true, verbatim: true });
      for (const r of results) {
        if (this.isPrivateIp(r.address)) {
          throw new BadRequestException(
            'Webhook URL resolves to a private or reserved IP',
          );
        }
      }
    } catch (err: any) {
      if (err instanceof BadRequestException) throw err;
      throw new BadRequestException('Unable to resolve webhook URL host');
    }
  }

  private isPrivateIp(ip: string): boolean {
    if (ip === '::1' || ip === '0.0.0.0') return true;
    if (ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) {
      return true; // ULA / link-local v6 (simplified)
    }

    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) {
      // Non-IPv4 (e.g. other IPv6) — treat unique local / link-local already handled
      return false;
    }
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    return false;
  }

  // ─── Endpoint management ───────────────────────────────────────────
  async registerEndpoint(
    userId: string,
    data: {
      url: string;
      events: WebhookEventType[];
      description?: string;
    },
  ) {
    await this.assertSafeWebhookUrl(data.url);

    const secret = crypto.randomBytes(32).toString('hex');
    const endpoint = await this.prisma.webhook.create({
      data: {
        url: data.url,
        events: data.events,
        userId,
        secret,
        isActive: true,
      },
    });
    return { ...endpoint, secret };
  }

  async listEndpoints(userId: string) {
    return this.prisma.webhook.findMany({
      where: { userId },
      select: {
        id: true,
        url: true,
        events: true,
        isActive: true,
        createdAt: true,
      },
    });
  }

  async toggleEndpoint(id: string, userId: string, isActive: boolean) {
    const result = await this.prisma.webhook.updateMany({
      where: { id, userId },
      data: { isActive },
    });
    if (result.count === 0) throw new NotFoundException('Webhook not found');
    return { id, isActive };
  }

  async deleteEndpoint(id: string, userId: string) {
    const result = await this.prisma.webhook.deleteMany({
      where: { id, userId },
    });
    if (result.count === 0) throw new NotFoundException('Webhook not found');
    return { message: 'Webhook deleted' };
  }

  async rotateSecret(id: string, userId: string) {
    const existing = await this.prisma.webhook.findFirst({
      where: { id, userId },
    });
    if (!existing) throw new NotFoundException('Webhook not found');

    const secret = crypto.randomBytes(32).toString('hex');
    await this.prisma.webhook.update({ where: { id }, data: { secret } });
    return { secret };
  }
}
