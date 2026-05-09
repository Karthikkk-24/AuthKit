import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma/prisma.service';

@Injectable()
export class MetricsService {
  constructor(private readonly prisma: PrismaService) {}

  async getDashboardStats() {
    const now = new Date();
    const dayAgo = new Date(now.getTime() - 86_400_000);
    const weekAgo = new Date(now.getTime() - 7 * 86_400_000);

    const [
      totalUsers,
      activeUsers24h,
      newUsers7d,
      lockedUsers,
      activeSessions,
      auditEvents24h,
      failedLogins24h,
      mfaEnabledCount,
    ] = await Promise.all([
      this.prisma.user.count({ where: { deletedAt: null } }),
      this.prisma.auditLog.groupBy({
        by: ['userId'],
        where: { action: 'auth.login', timestamp: { gte: dayAgo }, success: true },
      }).then((r) => r.length),
      this.prisma.user.count({ where: { createdAt: { gte: weekAgo }, deletedAt: null } }),
      this.prisma.user.count({ where: { isLocked: true, deletedAt: null } }),
      this.prisma.session.count({
        where: { isRevoked: false, expiresAt: { gt: now } },
      }),
      this.prisma.auditLog.count({ where: { timestamp: { gte: dayAgo } } }),
      this.prisma.auditLog.count({
        where: { action: { contains: 'login' }, success: false, timestamp: { gte: dayAgo } },
      }),
      this.prisma.user.count({ where: { mfaEnabled: true, deletedAt: null } }),
    ]);

    return {
      users: {
        total: totalUsers,
        active24h: activeUsers24h,
        new7d: newUsers7d,
        locked: lockedUsers,
        mfaEnabled: mfaEnabledCount,
        mfaAdoptionRate: totalUsers > 0 ? (mfaEnabledCount / totalUsers) * 100 : 0,
      },
      sessions: { active: activeSessions },
      audit: { events24h: auditEvents24h, failedLogins24h },
    };
  }

  async getUserGrowth(days = 30) {
    const from = new Date(Date.now() - days * 86_400_000);
    const logs = await this.prisma.user.findMany({
      where: { createdAt: { gte: from }, deletedAt: null },
      select: { createdAt: true },
      orderBy: { createdAt: 'asc' },
    });

    // Group by day
    const map: Record<string, number> = {};
    for (const user of logs) {
      const day = user.createdAt.toISOString().split('T')[0];
      map[day] = (map[day] ?? 0) + 1;
    }

    return Object.entries(map).map(([date, count]) => ({ date, count }));
  }

  async getEventTimeline(days = 7) {
    const from = new Date(Date.now() - days * 86_400_000);
    const logs = await this.prisma.auditLog.findMany({
      where: { timestamp: { gte: from } },
      select: { action: true, success: true, timestamp: true },
      orderBy: { timestamp: 'asc' },
    });

    const map: Record<string, { success: number; failure: number }> = {};
    for (const log of logs) {
      const day = log.timestamp.toISOString().split('T')[0];
      if (!map[day]) map[day] = { success: 0, failure: 0 };
      if (log.success) map[day].success++;
      else map[day].failure++;
    }

    return Object.entries(map).map(([date, counts]) => ({ date, ...counts }));
  }
}
