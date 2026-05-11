import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  PERMISSIONS_KEY,
  PermissionRequirement,
} from '../decorators/permissions.decorator';
import { PrismaService } from '../../database/prisma/prisma.service';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const required = this.reflector.getAllAndOverride<PermissionRequirement[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!required || required.length === 0) return true;

    const { user } = context.switchToHttp().getRequest();
    if (!user) throw new UnauthorizedException();

    // Fetch role with permissions (using Prisma)
    const role = await this.prisma.role.findUnique({
      where: { id: user.roleId },
      include: { permissions: true, parent: { include: { permissions: true } } },
    });

    if (!role) throw new ForbiddenException('Role not found');

    // Collect all permissions including inherited from parent roles
    const allPerms = this.collectPermissions(role);

    // Check that ALL required permissions are satisfied
    const granted = required.every((req) =>
      this.isPermissionGranted(allPerms, req),
    );

    if (!granted) {
      throw new ForbiddenException(
        `Missing required permissions: ${required.map((p) => `${p.action}:${p.resource}`).join(', ')}`,
      );
    }

    return true;
  }

  private collectPermissions(
    role: any,
    visited = new Set<string>(),
  ): Array<{ action: string; resource: string }> {
    if (visited.has(role.id)) return [];
    visited.add(role.id);

    const perms: Array<{ action: string; resource: string }> = [
      ...role.permissions,
    ];

    // Walk up hierarchy
    if (role.parent) {
      perms.push(...this.collectPermissions(role.parent, visited));
    }

    return perms;
  }

  private isPermissionGranted(
    perms: Array<{ action: string; resource: string }>,
    req: PermissionRequirement,
  ): boolean {
    return perms.some(
      (p) =>
        // Exact match
        (p.action === req.action && p.resource === req.resource) ||
        // Wildcard action
        (p.action === '*' && p.resource === req.resource) ||
        // Wildcard resource
        (p.action === req.action && p.resource === '*') ||
        // Full wildcard (superadmin)
        (p.action === '*' && p.resource === '*'),
    );
  }
}
