import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../database/prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { ConfigLoaderService } from '../config/config-loader.service';
import { PasswordService } from '../auth/password.service';
import { WebhookService, WebhookEventType } from '../webhook/webhook.service';
import {
  assertActorOutranksTarget,
  getRoleRank,
  permissionsSubsetOf,
} from '../common/role-hierarchy';

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly config: ConfigLoaderService,
    private readonly passwords: PasswordService,
    private readonly webhooks: WebhookService,
  ) {}

  private emitWebhook(event: WebhookEventType, payload: Record<string, any>) {
    void this.webhooks.dispatch(event, payload).catch((err) => {
      this.logger.warn(`Webhook dispatch failed for ${event}: ${err?.message}`);
    });
  }

  /**
   * Load actor + target and ensure the actor strictly outranks the target's
   * current role before any privileged mutation (#63).
   */
  private async assertCanManageUser(
    adminId: string,
    targetUserId: string,
    action: string,
  ) {
    if (adminId === targetUserId) {
      throw new ForbiddenException(`Cannot ${action} your own account`);
    }

    const [admin, target] = await Promise.all([
      this.prisma.user.findUnique({
        where: { id: adminId },
        include: { role: true },
      }),
      this.prisma.user.findUnique({
        where: { id: targetUserId },
        include: { role: true },
      }),
    ]);

    if (!admin?.role) throw new ForbiddenException('Admin not found');
    if (!target || target.deletedAt) throw new NotFoundException('User not found');
    if (!target.role) throw new ForbiddenException('Target user has no role');

    assertActorOutranksTarget(admin.role.name, target.role.name, action);
    return { admin, target };
  }

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
    const { admin, target } = await this.assertCanManageUser(
      adminId,
      userId,
      'change the role of',
    );

    const role = await this.prisma.role.findUnique({
      where: { id: roleId },
      include: {
        permissions: true,
        parent: { include: { permissions: true, parent: { include: { permissions: true } } } },
      },
    });
    if (!role) throw new NotFoundException('Role not found');

    const actorRank = getRoleRank(admin.role.name);
    const newRoleRank = getRoleRank(role.name);

    if (actorRank < 0) {
      throw new ForbiddenException('Unknown role hierarchy');
    }

    // Named hierarchy: cannot assign a role at or above your own (#10)
    if (newRoleRank >= 0) {
      if (newRoleRank >= actorRank) {
        throw new ForbiddenException(
          'Cannot assign a role at or above your own privilege level',
        );
      }
    } else {
      // Custom role: admin+ only, and role's effective perms must be ⊆ actor's (#63 review)
      if (actorRank < getRoleRank('admin')) {
        throw new ForbiddenException('Cannot assign custom roles');
      }
      const actorFull = await this.prisma.user.findUnique({
        where: { id: adminId },
        include: {
          role: {
            include: {
              permissions: true,
              parent: { include: { permissions: true } },
            },
          },
        },
      });
      const collect = (
        r: any,
        seen = new Set<string>(),
      ): Array<{ action: string; resource: string }> => {
        if (!r || seen.has(r.id)) return [];
        seen.add(r.id);
        const out = (r.permissions ?? []).map((p: any) => ({
          action: p.action,
          resource: p.resource,
        }));
        if (r.parent) out.push(...collect(r.parent, seen));
        return out;
      };
      const actorPerms = collect(actorFull?.role);
      const rolePerms = collect(role);
      if (!permissionsSubsetOf(rolePerms, actorPerms)) {
        throw new ForbiddenException(
          'Cannot assign a role whose permissions exceed your effective set',
        );
      }
    }

    void target;

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

    this.emitWebhook('role.assigned', {
      userId,
      roleId,
      roleName: role.name,
      adminId,
    });

    return { message: 'Role assigned successfully' };
  }

  async lockUser(userId: string, reason: string, adminId: string, req: any) {
    await this.assertCanManageUser(adminId, userId, 'lock');

    await this.prisma.user.update({
      where: { id: userId },
      data: { isLocked: true, lockedAt: new Date(), lockReason: reason },
    });

    // Invalidate all sessions so existing access JWTs fail session checks (#8)
    await this.prisma.session.updateMany({
      where: { userId, isRevoked: false },
      data: { isRevoked: true, revokedAt: new Date() },
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

    this.emitWebhook('user.locked', { userId, reason, adminId });

    return { message: 'User locked' };
  }

  async unlockUser(userId: string, adminId: string, req: any) {
    await this.assertCanManageUser(adminId, userId, 'unlock');

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

    this.emitWebhook('user.unlocked', { userId, adminId });

    return { message: 'User unlocked' };
  }

  async softDelete(userId: string, adminId: string, req: any) {
    await this.assertCanManageUser(adminId, userId, 'delete');

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

    this.emitWebhook('user.deleted', { userId, adminId });

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

    this.emitWebhook('session.revoked', { userId, sessionId });

    return { message: 'Session revoked' };
  }

  async exportData(userId: string) {
    if (!this.config.isFeatureEnabled('gdprTools')) {
      throw new ForbiddenException('GDPR data tools are disabled');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        sessions: {
          // Never export refreshTokenHash (#30) — only non-secret device metadata
          select: {
            id: true,
            ip: true,
            userAgent: true,
            deviceName: true,
            deviceType: true,
            browser: true,
            os: true,
            country: true,
            city: true,
            isRevoked: true,
            revokedAt: true,
            lastActiveAt: true,
            createdAt: true,
            expiresAt: true,
          },
        },
        auditLogs: {
          orderBy: { timestamp: 'desc' },
          take: 100,
          select: {
            id: true,
            action: true,
            resourceId: true,
            resourceType: true,
            metadata: true,
            ip: true,
            userAgent: true,
            success: true,
            timestamp: true,
          },
        },
        apiKeys: {
          select: {
            id: true,
            name: true,
            prefix: true,
            scopes: true,
            isRevoked: true,
            lastUsedAt: true,
            expiresAt: true,
            createdAt: true,
          },
        },
      },
    });
    if (!user) throw new NotFoundException('User not found');

    // GDPR: exclude credentials and third-party identifiers
    const { passwordHash, googleId, githubId, ...safeUser } = user as any;
    return safeUser;
  }

  async deleteAccount(userId: string, password: string | undefined, req: any) {
    if (!this.config.isFeatureEnabled('gdprTools')) {
      throw new ForbiddenException('GDPR data tools are disabled');
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.deletedAt) throw new NotFoundException('User not found');

    // Password accounts must confirm with their password; OAuth-only accounts
    // (no passwordHash) are authenticated by the JWT that authorized this call.
    if (user.passwordHash) {
      if (!password) throw new UnauthorizedException('Password is required to delete the account');
      const valid = await this.passwords.verify(user.passwordHash, password);
      if (!valid) throw new UnauthorizedException('Incorrect password');
    }

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: userId },
        data: { deletedAt: new Date() },
      }),
      this.prisma.session.updateMany({
        where: { userId, isRevoked: false },
        data: { isRevoked: true, revokedAt: new Date() },
      }),
    ]);

    await this.audit.log({
      action: 'user.self_deleted',
      userId,
      resourceId: userId,
      resourceType: 'user',
      ip: req?.ip,
      success: true,
    });

    this.emitWebhook('user.deleted', { userId, selfService: true });

    return { message: 'Account deleted' };
  }

  private sanitize(user: any) {
    const { passwordHash, googleId, githubId, ...safe } = user;
    return safe;
  }
}
