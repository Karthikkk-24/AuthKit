import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../database/prisma/prisma.service';
import { AuditService } from '../audit/audit.service';

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

  // ─── ROLES ─────────────────────────────────────────────────────────
  async createRole(dto: CreateRoleDto, adminId: string, req: any) {
    const existing = await this.prisma.role.findUnique({ where: { name: dto.name } });
    if (existing) throw new ConflictException(`Role "${dto.name}" already exists`);

    const role = await this.prisma.role.create({ data: dto });

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
    if (role.isSystem && data.name) {
      // System roles cannot be renamed
      delete data.name;
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
   *
   * Permissions are role-owned rows (see schema); the previous
   * `permissions.set([{id}])` treated them like an M2M catalog and either
   * threw or silently detached rows from other roles. This version deletes
   * rows the caller removed and inserts new rows the caller added.
   */
  async assignPermissionsToRole(
    roleId: string,
    permissions: Array<{ action: string; resource: string }>,
    adminId: string,
    req: any,
  ) {
    const role = await this.prisma.role.findUnique({ where: { id: roleId } });
    if (!role) throw new NotFoundException('Role not found');

    const sanitized = (permissions ?? [])
      .filter((p) => p && typeof p.action === 'string' && typeof p.resource === 'string')
      .map((p) => ({ action: p.action.trim(), resource: p.resource.trim() }))
      .filter((p) => p.action && p.resource);

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
  async createPermission(dto: CreatePermissionDto) {
    const existing = await this.prisma.permission.findFirst({
      where: { resource: dto.resource, action: dto.action },
    });
    if (existing) throw new ConflictException('Permission already exists');

    return this.prisma.permission.create({ data: dto });
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

}
