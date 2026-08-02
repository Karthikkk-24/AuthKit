import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';

/**
 * Role hierarchy (higher includes lower). A user with `admin` satisfies
 * `@Roles('user')` and `@Roles('moderator')` as well as `@Roles('admin')` (#39).
 * PermissionsGuard still owns fine-grained permission inheritance via parentId.
 */
const ROLE_RANK: Record<string, number> = {
  guest: 0,
  user: 1,
  moderator: 2,
  admin: 3,
  superadmin: 4,
};

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // No role restriction on this route
    if (!requiredRoles || requiredRoles.length === 0) return true;

    const { user } = context.switchToHttp().getRequest();
    if (!user) throw new ForbiddenException('Unauthorized');

    const userRole = user.role?.name ?? user.roleName ?? user.role;
    if (typeof userRole !== 'string' || !(userRole in ROLE_RANK)) {
      throw new ForbiddenException('Access denied. Unknown role.');
    }

    const userRank = ROLE_RANK[userRole];
    const hasRole = requiredRoles.some((role) => {
      if (user.roles?.includes(role)) return true;
      const requiredRank = ROLE_RANK[role];
      if (requiredRank === undefined) return userRole === role;
      // Hierarchical: caller rank must be >= required rank
      return userRank >= requiredRank;
    });

    if (!hasRole) {
      throw new ForbiddenException(
        `Access denied. Required role(s): ${requiredRoles.join(', ')}`,
      );
    }

    return true;
  }
}
