import {
  Injectable,
  NotFoundException,
  ConflictException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../database/prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import {
  assertActorOutranksTarget,
  getRoleRank,
  permissionsSubsetOf,
} from '../common/role-hierarchy';

export class CreateRoleDto {
  name: string;
  description?: string;
  parentId?: string;
  isSystem?: boolean;
}

export class CreatePermissionDto {
  roleId: string;
  resource: string;
  action: string;
  description?: string;
}

@Injectable()
export class RbacService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  /** Load actor user+role or throw. */
  private async loadActor(adminId: string) {
    const admin = await this.prisma.user.findUnique({
      where: { id: adminId },
      include: { role: { include: { permissions: true, parent: { include: { permissions: true } } } } },
    });
    if (!admin?.role) throw new ForbiddenException('Admin not found');
    return admin;
  }

  /** Collect role permissions walking parent hierarchy (same rules as PermissionsGuard). */
  private collectRolePermissions(
    role: any,
    visited = new Set<string>(),
  ): Array<{ action: string; resource: string }> {
    if (!role || visited.has(role.id)) return [];
    visited.add(role.id);
    const perms: Array<{ action: string; resource: string }> = [
      ...(role.permissions ?? []).map((p: any) => ({
        action: p.action,
        resource: p.resource,
      })),
    ];
    if (role.parent) {
      perms.push(...this.collectRolePermissions(role.parent, visited));
    }
    return perms;
  }

  /**
   * Effective permissions for an actor: role hierarchy + per-user grants
   * (denies are ignored here — we only check what they can grant).
   */
  private async getActorEffectivePermissions(adminId: string) {
    const admin = await this.loadActor(adminId);
    const rolePerms = this.collectRolePermissions(admin.role);
    const grants = await this.prisma.userPermission.findMany({
      where: { userId: adminId, effect: 'grant' },
      select: { action: true, resource: true },
    });
    return {
      admin,
      perms: [
        ...rolePerms,
        ...grants.map((g) => ({ action: g.action, resource: g.resource })),
      ],
    };
  }

  /**
   * Actor may only mutate roles they strictly outrank. System roles are
   * immutable for non-superadmins (#64, #86). Superadmin may mutate any
   * system role including their own.
   */
  private assertCanMutateRole(
    actorRoleName: string,
    targetRole: { name: string; isSystem: boolean },
    action: string,
  ) {
    if (targetRole.isSystem && actorRoleName !== 'superadmin') {
      throw new ForbiddenException(
        `Only superadmin can ${action} system role "${targetRole.name}"`,
      );
    }

    // Superadmin may manage all system roles (including peer "superadmin") (#64 review)
    if (actorRoleName === 'superadmin' && targetRole.isSystem) {
      return;
    }

    const targetRank = getRoleRank(targetRole.name);
    // Named hierarchy roles: must strictly outrank.
    if (targetRank >= 0) {
      assertActorOutranksTarget(actorRoleName, targetRole.name, action);
      return;
    }
    // Custom roles (unknown name): admin+ may mutate if not system (checked above).
    if (getRoleRank(actorRoleName) < getRoleRank('admin')) {
      throw new ForbiddenException(`Cannot ${action} this role`);
    }
  }

  // ─── ROLES ─────────────────────────────────────────────────────────
  async createRole(dto: CreateRoleDto, adminId: string, req: any) {
    const existing = await this.prisma.role.findUnique({ where: { name: dto.name } });
    if (existing) throw new ConflictException(`Role "${dto.name}" already exists`);

    // Never allow creating system roles or reserved hierarchy names via API
    if (dto.isSystem) {
      throw new ForbiddenException('Cannot create system roles via API');
    }
    if (getRoleRank(dto.name) >= 0) {
      throw new ForbiddenException(
        `Role name "${dto.name}" is reserved by the system hierarchy`,
      );
    }

    const { admin, perms: actorPerms } = await this.getActorEffectivePermissions(adminId);

    if (dto.parentId) {
      await this.assertParentAllowed(dto.parentId, admin.role.name, actorPerms);
    }

    const role = await this.prisma.role.create({
      data: {
        name: dto.name,
        description: dto.description,
        parentId: dto.parentId,
        isSystem: false,
      },
    });

    await this.audit.log({
      action: 'role.created',
      userId: adminId,
      resourceId: role.id,
      resourceType: 'role',
      metadata: { name: role.name },
      ip: req?.ip,
      success: true,
    });

    return role;
  }

  async getRoles() {
    return this.prisma.role.findMany({
      include: {
        permissions: true,
        _count: { select: { users: true } },
      },
      orderBy: { createdAt: 'asc' },
    });
  }

  async getRole(id: string) {
    const role = await this.prisma.role.findUnique({
      where: { id },
      include: {
        permissions: true,
        parent: true,
        children: true,
        _count: { select: { users: true } },
      },
    });
    if (!role) throw new NotFoundException('Role not found');
    return role;
  }

  async updateRole(
    id: string,
    data: Partial<CreateRoleDto>,
    adminId: string,
    req: any,
  ) {
    const role = await this.prisma.role.findUnique({ where: { id } });
    if (!role) throw new NotFoundException('Role not found');

    const { admin, perms: actorPerms } = await this.getActorEffectivePermissions(adminId);
    this.assertCanMutateRole(admin.role.name, role, 'update');

    // Never allow flipping isSystem via patch
    delete (data as any).isSystem;

    if (role.isSystem && data.name) {
      // System roles cannot be renamed
      delete data.name;
    }

    // Block renaming a custom role onto a reserved hierarchy name (#64 review)
    if (data.name && getRoleRank(data.name) >= 0) {
      throw new ForbiddenException(
        `Role name "${data.name}" is reserved by the system hierarchy`,
      );
    }

    // parentId changes (#86): block privilege inheritance escalation
    if (Object.prototype.hasOwnProperty.call(data, 'parentId')) {
      if (role.isSystem && admin.role.name !== 'superadmin') {
        throw new ForbiddenException(
          'Only superadmin can change parentId on system roles',
        );
      }
      if (data.parentId) {
        if (data.parentId === id) {
          throw new ForbiddenException('Role cannot be its own parent');
        }
        await this.assertParentAllowed(data.parentId, admin.role.name, actorPerms);
      }
    }

    const updated = await this.prisma.role.update({ where: { id }, data });

    await this.audit.log({
      action: 'role.updated',
      userId: adminId,
      resourceId: id,
      resourceType: 'role',
      metadata: data,
      ip: req?.ip,
      success: true,
    });

    return updated;
  }

  /**
   * Ensure attaching `parentId` would not grant the actor (or users on the
   * child role) permissions beyond what the actor already holds (#86).
   */
  private async assertParentAllowed(
    parentId: string,
    actorRoleName: string,
    actorPerms: Array<{ action: string; resource: string }>,
  ) {
    const parent = await this.prisma.role.findUnique({
      where: { id: parentId },
      include: {
        permissions: true,
        parent: { include: { permissions: true, parent: { include: { permissions: true } } } },
      },
    });
    if (!parent) throw new NotFoundException('Parent role not found');

    // Cannot attach a parent at or above actor rank (e.g. admin → superadmin)
    const parentRank = getRoleRank(parent.name);
    if (parentRank >= 0) {
      assertActorOutranksTarget(actorRoleName, parent.name, 'use as a parent role');
    } else if (parent.isSystem && actorRoleName !== 'superadmin') {
      throw new ForbiddenException('Cannot use a system role as parent');
    }

    const inherited = this.collectRolePermissions(parent);
    if (!permissionsSubsetOf(inherited, actorPerms)) {
      throw new ForbiddenException(
        'Cannot set parentId: parent role grants permissions beyond your effective set',
      );
    }
  }

  async deleteRole(id: string, adminId: string, req: any) {
    const role = await this.prisma.role.findUnique({
      where: { id },
      include: { _count: { select: { users: true } } },
    });
    if (!role) throw new NotFoundException('Role not found');
    if (role.isSystem) throw new ConflictException('Cannot delete a system role');
    if ((role as any)._count.users > 0) {
      throw new ConflictException('Cannot delete a role that has users assigned');
    }

    const admin = await this.loadActor(adminId);
    this.assertCanMutateRole(admin.role.name, role, 'delete');

    await this.prisma.role.delete({ where: { id } });

    await this.audit.log({
      action: 'role.deleted',
      userId: adminId,
      resourceId: id,
      resourceType: 'role',
      ip: req?.ip,
      success: true,
    });

    return { message: 'Role deleted' };
  }

  /**
   * Replace this role's permissions with the given action/resource pairs (#33).
   * Guarded by rank + system-role policy (#64). Grants cannot exceed actor perms.
   */
  async assignPermissionsToRole(
    roleId: string,
    permissions: Array<{ action: string; resource: string }>,
    adminId: string,
    req: any,
  ) {
    const role = await this.prisma.role.findUnique({ where: { id: roleId } });
    if (!role) throw new NotFoundException('Role not found');

    const { admin, perms: actorPerms } = await this.getActorEffectivePermissions(adminId);
    this.assertCanMutateRole(admin.role.name, role, 'update permissions on');

    const sanitized = (permissions ?? [])
      .filter((p) => p && typeof p.action === 'string' && typeof p.resource === 'string')
      .map((p) => ({ action: p.action.trim(), resource: p.resource.trim() }))
      .filter((p) => p.action && p.resource);

    if (!permissionsSubsetOf(sanitized, actorPerms)) {
      throw new ForbiddenException(
        'Cannot assign permissions beyond your own effective permission set',
      );
    }

    await this.prisma.$transaction([
      this.prisma.permission.deleteMany({ where: { roleId } }),
      ...(sanitized.length
        ? [
            this.prisma.permission.createMany({
              data: sanitized.map((p) => ({ ...p, roleId })),
              skipDuplicates: true,
            }),
          ]
        : []),
    ]);

    await this.audit.log({
      action: 'role.permissions_updated',
      userId: adminId,
      resourceId: roleId,
      resourceType: 'role',
      metadata: { permissions: sanitized },
      ip: req?.ip,
      success: true,
    });

    return { message: 'Permissions updated', count: sanitized.length };
  }

  // ─── PERMISSIONS ───────────────────────────────────────────────────
  async createPermission(dto: CreatePermissionDto, adminId: string, req?: any) {
    const role = await this.prisma.role.findUnique({ where: { id: dto.roleId } });
    if (!role) throw new NotFoundException('Role not found');

    const { admin, perms: actorPerms } = await this.getActorEffectivePermissions(adminId);
    this.assertCanMutateRole(admin.role.name, role, 'create permissions on');

    if (
      !permissionsSubsetOf(
        [{ action: dto.action, resource: dto.resource }],
        actorPerms,
      )
    ) {
      throw new ForbiddenException(
        'Cannot create a permission beyond your own effective permission set',
      );
    }

    const existing = await this.prisma.permission.findFirst({
      where: { resource: dto.resource, action: dto.action, roleId: dto.roleId },
    });
    if (existing) throw new ConflictException('Permission already exists');

    const created = await this.prisma.permission.create({ data: dto });

    await this.audit.log({
      action: 'permission.created',
      userId: adminId,
      resourceId: created.id,
      resourceType: 'permission',
      metadata: { roleId: dto.roleId, action: dto.action, resource: dto.resource },
      ip: req?.ip,
      success: true,
    });

    return created;
  }

  async getPermissions(resource?: string) {
    return this.prisma.permission.findMany({
      where: resource ? { resource } : undefined,
      orderBy: [{ resource: 'asc' }, { action: 'asc' }],
    });
  }

  async deletePermission(id: string) {
    await this.prisma.permission.findFirstOrThrow({ where: { id } });
    return this.prisma.permission.delete({ where: { id } });
  }

  // ─── PER-USER PERMISSION OVERRIDES (#26) ───────────────────────────
  async listUserPermissions(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');
    return this.prisma.userPermission.findMany({
      where: { userId },
      orderBy: { createdAt: 'asc' },
    });
  }

  async setUserPermissions(
    userId: string,
    entries: Array<{ action: string; resource: string; effect: 'grant' | 'deny' }>,
    adminId: string,
    req: any,
  ) {
    const target = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { role: true },
    });
    if (!target) throw new NotFoundException('User not found');
    if (!target.role) throw new ForbiddenException('Target user has no role');

    const { admin, perms: actorPerms } = await this.getActorEffectivePermissions(adminId);

    // Cannot elevate or rewrite overrides for users at/above actor rank (#63/#65)
    assertActorOutranksTarget(
      admin.role.name,
      target.role.name,
      'set permission overrides for',
    );

    // Self-targeting is already blocked by outrank (equal rank). Extra guard
    // for clarity if hierarchy ever allows peers (#65).
    if (userId === adminId) {
      throw new ForbiddenException('Cannot set permission overrides on your own account');
    }

    const sanitized = (entries ?? [])
      .filter(
        (e) =>
          e &&
          typeof e.action === 'string' &&
          typeof e.resource === 'string' &&
          (e.effect === 'grant' || e.effect === 'deny'),
      )
      .map((e) => ({
        action: e.action.trim(),
        resource: e.resource.trim(),
        effect: e.effect as 'grant' | 'deny',
      }))
      .filter((e) => e.action && e.resource);

    const grants = sanitized.filter((e) => e.effect === 'grant');
    if (!permissionsSubsetOf(grants, actorPerms)) {
      await this.audit.log({
        action: 'user.permissions_elevation_denied',
        userId: adminId,
        resourceId: userId,
        resourceType: 'user',
        metadata: { attemptedGrants: grants },
        ip: req?.ip,
        success: false,
      });
      throw new ForbiddenException(
        'Cannot grant permissions beyond your own effective permission set',
      );
    }

    await this.prisma.$transaction([
      this.prisma.userPermission.deleteMany({ where: { userId } }),
      ...(sanitized.length
        ? [
            this.prisma.userPermission.createMany({
              data: sanitized.map((e) => ({ ...e, userId, createdById: adminId })),
              skipDuplicates: true,
            }),
          ]
        : []),
    ]);

    await this.audit.log({
      action: 'user.permissions_updated',
      userId: adminId,
      resourceId: userId,
      resourceType: 'user',
      metadata: { overrides: sanitized },
      ip: req?.ip,
      success: true,
    });

    return { message: 'User permission overrides updated', count: sanitized.length };
  }
}
