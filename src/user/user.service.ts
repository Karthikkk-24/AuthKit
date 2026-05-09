import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../database/prisma/prisma.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class UserService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async findById(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      include: { role: { include: { permissions: true } } },
    });
    if (!user || user.deletedAt) throw new NotFoundException('User not found');
    return this.sanitize(user);
  }

  async findAll(options: {
    search?: string;
    roleId?: string;
    isLocked?: boolean;
    page?: number;
    limit?: number;
  }) {
    const { search, roleId, isLocked, page = 1, limit = 20 } = options;
    const where: any = { deletedAt: null };
    if (search) {
      where.OR = [
        { email: { contains: search, mode: 'insensitive' } },
        { name: { contains: search, mode: 'insensitive' } },
      ];
    }
    if (roleId) where.roleId = roleId;
    if (isLocked !== undefined) where.isLocked = isLocked;

    const [data, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        include: { role: true },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      this.prisma.user.count({ where }),
    ]);

    return {
      data: data.map(this.sanitize),
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
    };
  }

  async updateProfile(userId: string, data: { name?: string; avatarUrl?: string }) {
    const user = await this.prisma.user.update({
      where: { id: userId },
      data,
      include: { role: true },
    });
    return this.sanitize(user);
  }

  async assignRole(userId: string, roleId: string, adminId: string, req: any) {
    const role = await this.prisma.role.findUnique({ where: { id: roleId } });
    if (!role) throw new NotFoundException('Role not found');

    await this.prisma.user.update({ where: { id: userId }, data: { roleId } });

    await this.audit.log({
      action: 'user.role_assigned',
      userId: adminId,
      resourceId: userId,
      resourceType: 'user',
      metadata: { roleId, roleName: role.name },
      ip: req?.ip,
      success: true,
    });

    return { message: 'Role assigned successfully' };
  }

  async lockUser(userId: string, reason: string, adminId: string, req: any) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { isLocked: true, lockedAt: new Date(), lockReason: reason },
    });

    await this.audit.log({
      action: 'admin.user_locked',
      userId: adminId,
      resourceId: userId,
      resourceType: 'user',
      metadata: { reason },
      ip: req?.ip,
      success: true,
    });

    return { message: 'User locked' };
  }

  async unlockUser(userId: string, adminId: string, req: any) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { isLocked: false, lockedAt: null, lockReason: null, failedLoginAttempts: 0 },
    });

    await this.audit.log({
      action: 'admin.user_unlocked',
      userId: adminId,
      resourceId: userId,
      resourceType: 'user',
      ip: req?.ip,
      success: true,
    });

    return { message: 'User unlocked' };
  }

  async softDelete(userId: string, adminId: string, req: any) {
    // Prevent deleting self
    if (userId === adminId) throw new ForbiddenException('Cannot delete your own account');

    await this.prisma.user.update({
      where: { id: userId },
      data: { deletedAt: new Date() },
    });

    // Revoke all sessions
    await this.prisma.session.updateMany({
      where: { userId },
      data: { isRevoked: true, revokedAt: new Date() },
    });

    await this.audit.log({
      action: 'admin.user_deleted',
      userId: adminId,
      resourceId: userId,
      resourceType: 'user',
      ip: req?.ip,
      success: true,
    });

    return { message: 'User deleted' };
  }

  async getSessions(userId: string) {
    return this.prisma.session.findMany({
      where: { userId, isRevoked: false, expiresAt: { gt: new Date() } },
      orderBy: { lastActiveAt: 'desc' },
    });
  }

  async revokeSession(userId: string, sessionId: string, req: any) {
    const session = await this.prisma.session.findFirst({
      where: { id: sessionId, userId },
    });
    if (!session) throw new NotFoundException('Session not found');

    await this.prisma.session.update({
      where: { id: sessionId },
      data: { isRevoked: true, revokedAt: new Date() },
    });

    await this.audit.log({
      action: 'session.revoked',
      userId,
      resourceId: sessionId,
      resourceType: 'session',
      ip: req?.ip,
      success: true,
    });

    return { message: 'Session revoked' };
  }

  async exportData(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        sessions: true,
        auditLogs: { orderBy: { timestamp: 'desc' }, take: 100 },
        apiKeys: { select: { name: true, prefix: true, scopes: true, createdAt: true } },
      },
    });
    if (!user) throw new NotFoundException('User not found');

    // GDPR: exclude sensitive fields
    const { passwordHash, googleId, githubId, ...safeUser } = user as any;
    return safeUser;
  }

  private sanitize(user: any) {
    const { passwordHash, googleId, githubId, ...safe } = user;
    return safe;
  }
}
