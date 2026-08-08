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

    // Collect role permissions (incl. parent hierarchy), then apply
    // per-user grant/deny overrides (#26). A deny always wins.
    const rolePerms = this.collectPermissions(role);
    const overrides = await this.prisma.userPermission.findMany({
      where: { userId: user.id },
      select: { action: true, resource: true, effect: true },
    });

    const denies = overrides.filter((o) => o.effect === 'deny');
    const grants = overrides.filter((o) => o.effect === 'grant');
    const allPerms = [
      ...rolePerms,
      ...grants.map((g) => ({ action: g.action, resource: g.resource })),
    ];

    // Check that ALL required permissions are satisfied and none denied
    const granted = required.every(
      (req) =>
        !this.isPermissionGranted(
          denies.map((d) => ({ action: d.action, resource: d.resource })),
          req,
        ) && this.isPermissionGranted(allPerms, req),
    );

    if (!granted) {
      throw new ForbiddenException(
        `Missing required permissions: ${required.map((p) => `${p.action}:${p.resource}`).join(', ')}`,
      );
    }

    // API key scopes intersect RBAC (#66, #113). Empty scopes deny-by-default —
    // they must cover every required permission (no unrestricted legacy keys).
    if (user.isApiKeyAuth) {
      const scopes: string[] = Array.isArray(user.apiKeyScopes)
        ? user.apiKeyScopes
        : [];
      const missing = required.filter(
        (req) => !this.isScopeGranted(scopes, req),
      );
      if (missing.length > 0) {
        throw new ForbiddenException(
          `API key scopes do not allow: ${missing.map((p) => `${p.action}:${p.resource}`).join(', ')}`,
        );
      }
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
    req: { action: string; resource: string },
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

  /**
   * Scope strings use `resource:action` (same as seed grants / admin UI),
   * plus shorthand `read` / `write` / `admin` and `resource:manage`.
   */
  private isScopeGranted(
    scopes: string[],
    req: { action: string; resource: string },
  ): boolean {
    const writeActions = new Set([
      'create',
      'update',
      'delete',
      'revoke',
      'lock',
      'export',
      'assign',
    ]);

    for (const raw of scopes) {
      const scope = (raw || '').trim().toLowerCase();
      if (!scope) continue;

      if (scope === 'admin' || scope === '*:*' || scope === '*') return true;
      if (scope === 'read' && req.action === 'read') return true;
      if (scope === 'write' && writeActions.has(req.action)) return true;

      const colon = scope.indexOf(':');
      if (colon <= 0) continue;
      const resource = scope.slice(0, colon);
      const action = scope.slice(colon + 1);

      if (action === 'manage' || action === '*') {
        if (resource === '*' || resource === req.resource) return true;
        continue;
      }
      if (resource === '*' && action === req.action) return true;
      if (resource === req.resource && action === req.action) return true;
      if (resource === req.resource && action === '*') return true;
    }

    return false;
  }
}
