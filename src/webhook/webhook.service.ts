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
      this.logger.warn(`Webhook failed: ${event} → ${endpoint.url}: ${err?.message}`);

      await this.prisma.webhookDelivery.create({
        data: {
          webhookId: endpoint.id,
          event,
          payload,
          statusCode: err.response?.status,
          responseBody: err.response?.data ? JSON.stringify(err.response.data) : null,
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

  // ─── Endpoint management ───────────────────────────────────────────
  async registerEndpoint(userId: string, data: {
    url: string;
    events: WebhookEventType[];
    description?: string;
  }) {
    const secret = crypto.randomBytes(32).toString('hex');
    const endpoint = await this.prisma.webhook.create({
      data: { url: data.url, events: data.events, userId, secret, isActive: true },
    });
    // Return secret only on creation
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

  async toggleEndpoint(id: string, isActive: boolean) {
    return this.prisma.webhook.update({
      where: { id },
      data: { isActive },
    });
  }

  async deleteEndpoint(id: string) {
    return this.prisma.webhook.delete({ where: { id } });
  }

  async rotateSecret(id: string) {
    const secret = crypto.randomBytes(32).toString('hex');
    await this.prisma.webhook.update({ where: { id }, data: { secret } });
    return { secret };
  }
}
