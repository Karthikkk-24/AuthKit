import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../database/prisma/prisma.service';
import * as crypto from 'crypto';
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

  constructor(private readonly prisma: PrismaService) {}

  async dispatch(event: WebhookEventType, payload: Record<string, any>) {
    const endpoints = await this.prisma.webhookEndpoint.findMany({
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
    const body = JSON.stringify({
      event,
      timestamp: new Date().toISOString(),
      data: payload,
    });

    const signature = this.sign(endpoint.secret, body);

    try {
      await axios.post(endpoint.url, body, {
        headers: {
          'Content-Type': 'application/json',
          'X-AuthKit-Event': event,
          'X-AuthKit-Signature': signature,
          'X-AuthKit-Timestamp': Date.now().toString(),
        },
        timeout: 10_000,
      });

      await this.prisma.webhookEndpoint.update({
        where: { id: endpoint.id },
        data: { lastDeliveredAt: new Date(), failureCount: 0 },
      });

      this.logger.log(`Webhook delivered: ${event} → ${endpoint.url}`);
    } catch (err) {
      this.logger.warn(`Webhook failed: ${event} → ${endpoint.url}: ${err?.message}`);

      await this.prisma.webhookEndpoint.update({
        where: { id: endpoint.id },
        data: { failureCount: { increment: 1 } },
      });
    }
  }

  private sign(secret: string, body: string): string {
    return `sha256=${crypto
      .createHmac('sha256', secret)
      .update(body)
      .digest('hex')}`;
  }

  // ─── Endpoint management ───────────────────────────────────────────
  async registerEndpoint(data: {
    url: string;
    events: WebhookEventType[];
    description?: string;
  }) {
    const secret = crypto.randomBytes(32).toString('hex');
    const endpoint = await this.prisma.webhookEndpoint.create({
      data: { ...data, secret, isActive: true },
    });
    // Return secret only on creation
    return { ...endpoint, secret };
  }

  async listEndpoints() {
    return this.prisma.webhookEndpoint.findMany({
      select: {
        id: true,
        url: true,
        events: true,
        description: true,
        isActive: true,
        failureCount: true,
        lastDeliveredAt: true,
        createdAt: true,
      },
    });
  }

  async toggleEndpoint(id: string, isActive: boolean) {
    return this.prisma.webhookEndpoint.update({
      where: { id },
      data: { isActive },
    });
  }

  async deleteEndpoint(id: string) {
    return this.prisma.webhookEndpoint.delete({ where: { id } });
  }

  async rotateSecret(id: string) {
    const secret = crypto.randomBytes(32).toString('hex');
    await this.prisma.webhookEndpoint.update({ where: { id }, data: { secret } });
    return { secret };
  }
}
