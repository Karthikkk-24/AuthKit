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
import * as http from 'http';
import * as https from 'https';
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

    // Tenant isolation (#61): only deliver to endpoints owned by the event
    // subject. Without this filter every active subscriber receives every
    // matching event platform-wide (cross-tenant leak).
    const ownerId = payload?.userId;
    if (!ownerId || typeof ownerId !== 'string') {
      this.logger.warn(
        `Skipping webhook dispatch for ${event}: payload missing userId`,
      );
      return;
    }

    const endpoints = await this.prisma.webhook.findMany({
      where: {
        isActive: true,
        events: { has: event },
        userId: ownerId,
      },
    });

    await Promise.allSettled(
      endpoints.map((ep) => this.deliver(ep, event, payload)),
    );
  }

  private async deliver(endpoint: any, event: string, payload: any) {
    let target: { url: URL; address: string; family: number };
    try {
      // Resolve + classify once, then pin that address on the socket (#111).
      target = await this.resolveSafeWebhookTarget(endpoint.url);
    } catch (err: any) {
      this.logger.warn(
        `Skipping webhook delivery to unsafe URL ${endpoint.url}: ${err?.message}`,
      );
      return;
    }

    const whCfg = this.config.get<any>('webhooks') ?? {};
    const timeout = Number(whCfg.timeout) > 0 ? Number(whCfg.timeout) : 10_000;
    const maxAttempts =
      Number(whCfg.retries) >= 0 ? Number(whCfg.retries) + 1 : 1;

    const body = JSON.stringify({
      event,
      timestamp: new Date().toISOString(),
      data: payload,
    });

    const signature = this.sign(endpoint.secret, body);
    const agent = this.createPinnedAgent(
      target.url.protocol,
      target.address,
      target.family,
    );

    let lastErr: any;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const response = await axios.post(endpoint.url, body, {
          headers: {
            'Content-Type': 'application/json',
            'X-AuthKit-Event': event,
            'X-AuthKit-Signature': signature,
            'X-AuthKit-Timestamp': Date.now().toString(),
          },
          timeout,
          maxRedirects: 0,
          validateStatus: (s) => s >= 200 && s < 300,
          ...(target.url.protocol === 'https:'
            ? { httpsAgent: agent }
            : { httpAgent: agent }),
        });

        await this.prisma.webhookDelivery.create({
          data: {
            webhookId: endpoint.id,
            event,
            payload,
            statusCode: response.status,
            success: true,
            attempts: attempt,
          },
        });

        this.logger.log(
          `Webhook delivered: ${event} → ${endpoint.url} (attempt ${attempt})`,
        );
        return;
      } catch (err: any) {
        lastErr = err;
        this.logger.warn(
          `Webhook attempt ${attempt}/${maxAttempts} failed: ${event} → ${endpoint.url}: ${err?.message}`,
        );
        if (attempt < maxAttempts) {
          // Exponential backoff: 500ms, 1s, 2s, …
          await new Promise((r) => setTimeout(r, 500 * 2 ** (attempt - 1)));
        }
      }
    }

    await this.prisma.webhookDelivery.create({
      data: {
        webhookId: endpoint.id,
        event,
        payload,
        statusCode: lastErr?.response?.status,
        responseBody: lastErr?.response?.data
          ? JSON.stringify(lastErr.response.data).slice(0, 4_000)
          : null,
        success: false,
        attempts: maxAttempts,
      },
    });
  }

  private sign(secret: string, body: string): string {
    return `sha256=${crypto
      .createHmac('sha256', secret)
      .update(body)
      .digest('hex')}`;
  }

  /**
   * Block SSRF to private/link-local/metadata hosts (#11).
   * Used at registration; delivery pins the resolved address (#111).
   */
  async assertSafeWebhookUrl(rawUrl: string): Promise<void> {
    await this.resolveSafeWebhookTarget(rawUrl);
  }

  /**
   * Validate URL policy, resolve DNS, and return a single safe address to pin
   * on the outbound socket so a later rebind cannot reach private IPs (#111).
   */
  async resolveSafeWebhookTarget(
    rawUrl: string,
  ): Promise<{ url: URL; address: string; family: number }> {
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

    // Literal IP in hostname — pin that address after classification
    const literalFamily = net.isIP(hostname);
    if (literalFamily) {
      if (this.isPrivateIp(hostname)) {
        throw new BadRequestException('Webhook URL must not target private IPs');
      }
      return { url: parsed, address: hostname, family: literalFamily };
    }

    // Resolve DNS; reject if any answer is private (attacker-controlled multi-A),
    // then pin the first public address for the TCP connect.
    try {
      const results = await dns.lookup(hostname, { all: true, verbatim: true });
      if (!results.length) {
        throw new BadRequestException('Unable to resolve webhook URL host');
      }
      for (const r of results) {
        if (this.isPrivateIp(r.address)) {
          throw new BadRequestException(
            'Webhook URL resolves to a private or reserved IP',
          );
        }
      }
      const chosen = results[0];
      return {
        url: parsed,
        address: chosen.address,
        family: chosen.family,
      };
    } catch (err: any) {
      if (err instanceof BadRequestException) throw err;
      throw new BadRequestException('Unable to resolve webhook URL host');
    }
  }

  /**
   * HTTP(S) agent whose DNS lookup always returns the pre-validated address,
   * closing the resolve-then-connect TOCTOU window (#111).
   */
  private createPinnedAgent(
    protocol: string,
    address: string,
    family: number,
  ): http.Agent | https.Agent {
    const lookup = (
      _hostname: string,
      options: any,
      callback?: (
        err: NodeJS.ErrnoException | null,
        address: string | Array<{ address: string; family: number }>,
        family?: number,
      ) => void,
    ) => {
      const cb = typeof options === 'function' ? options : callback!;

      if (this.isPrivateIp(address)) {
        cb(new Error('Refusing connection to private or reserved IP'));
        return;
      }

      if (typeof options === 'object' && options?.all) {
        cb(null, [{ address, family }]);
        return;
      }

      cb(null, address, family);
    };

    if (protocol === 'https:') {
      return new https.Agent({ lookup, keepAlive: false });
    }
    return new http.Agent({ lookup, keepAlive: false });
  }

  private isPrivateIp(ip: string): boolean {
    const normalized = ip.trim().toLowerCase();

    // IPv4-mapped IPv6 → check the embedded IPv4 (#81)
    const mapped = normalized.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (mapped) return this.isPrivateIp(mapped[1]);

    if (
      normalized === '::1' ||
      normalized === '0.0.0.0' ||
      normalized === '::'
    ) {
      return true;
    }

    // IPv6 ULA (fc00::/7), link-local (fe80::/10), multicast (ff00::/8),
    // documentation (2001:db8::/32), discard (100::/64)
    if (normalized.includes(':')) {
      if (
        normalized.startsWith('fc') ||
        normalized.startsWith('fd') ||
        normalized.startsWith('fe8') ||
        normalized.startsWith('fe9') ||
        normalized.startsWith('fea') ||
        normalized.startsWith('feb') ||
        normalized.startsWith('ff') ||
        normalized.startsWith('2001:db8:') ||
        normalized.startsWith('100:')
      ) {
        return true;
      }
      // Unspecified / loopback already handled; other global unicast OK
      return false;
    }

    const parts = normalized.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return true; // unparseable — treat as unsafe
    }
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 0) return true;
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
    const endpoints = await this.prisma.webhook.findMany({
      where: { userId },
      select: {
        id: true,
        url: true,
        events: true,
        isActive: true,
        createdAt: true,
        deliveries: {
          orderBy: { createdAt: 'desc' },
          take: 50,
          select: { success: true, createdAt: true },
        },
      },
    });

    return endpoints.map(({ deliveries, ...ep }) => {
      const failureCount = deliveries.filter((d) => !d.success).length;
      const lastSuccess = deliveries.find((d) => d.success);
      return {
        ...ep,
        failureCount,
        lastDeliveredAt: lastSuccess?.createdAt ?? null,
      };
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
