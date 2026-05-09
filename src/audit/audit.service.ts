import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../database/prisma/prisma.service';

export interface AuditLogInput {
  action: string;
  userId?: string;
  resourceId?: string;
  resourceType?: string;
  metadata?: Record<string, any>;
  ip?: string;
  userAgent?: string;
  success: boolean;
  errorCode?: string;
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Non-fatal: logs to DB; if DB is unavailable falls back to logger.
   */
  async log(input: AuditLogInput): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data: {
          action: input.action,
          userId: input.userId,
          resourceId: input.resourceId,
          resourceType: input.resourceType,
          metadata: input.metadata ? JSON.stringify(input.metadata) : null,
          ipAddress: input.ip,
          userAgent: input.userAgent,
          success: input.success,
          errorCode: input.errorCode,
          timestamp: new Date(),
        },
      });
    } catch (err) {
      this.logger.error('Failed to write audit log', {
        action: input.action,
        error: err?.message,
      });
    }
  }

  async query(options: {
    userId?: string;
    action?: string;
    resource?: string;
    from?: Date;
    to?: Date;
    success?: boolean;
    page?: number;
    limit?: number;
  }) {
    const { userId, action, resource, from, to, success, page = 1, limit = 50 } = options;
    const where: any = {};

    if (userId) where.userId = userId;
    if (action) where.action = { contains: action, mode: 'insensitive' };
    if (resource) where.resourceType = resource;
    if (success !== undefined) where.success = success;
    if (from || to) {
      where.timestamp = {};
      if (from) where.timestamp.gte = from;
      if (to) where.timestamp.lte = to;
    }

    const [data, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      this.prisma.auditLog.count({ where }),
    ]);

    return { data, total, page, limit, pages: Math.ceil(total / limit) };
  }
}
