import { ForbiddenException } from '@nestjs/common';

/**
 * Canonical role hierarchy shared by RolesGuard, user admin ops, and RBAC (#39, #63).
 * Higher number = more privilege. Actor must strictly outrank a target to mutate them.
 */
export const ROLE_RANK: Record<string, number> = {
  guest: 0,
  user: 1,
  moderator: 2,
  admin: 3,
  superadmin: 4,
};

export function getRoleRank(roleName: string | null | undefined): number {
  if (!roleName || typeof roleName !== 'string') return -1;
  return ROLE_RANK[roleName] ?? -1;
}

/** True when actorRank is strictly greater than targetRank. */
export function outranks(actorRank: number, targetRank: number): boolean {
  return actorRank >= 0 && targetRank >= 0 && actorRank > targetRank;
}

/**
 * Throws if the actor cannot manage the target role (must strictly outrank).
 * Used for lock/unlock/delete/role-assign against another user (#63).
 *
 * Custom (unknown-rank) roles are manageable by admin+; named hierarchy
 * roles still require a strict outrank.
 */
export function assertActorOutranksTarget(
  actorRoleName: string,
  targetRoleName: string,
  action = 'manage this user',
): void {
  const actorRank = getRoleRank(actorRoleName);
  const targetRank = getRoleRank(targetRoleName);

  if (actorRank < 0) {
    throw new ForbiddenException('Unknown role hierarchy');
  }

  // Custom / unknown target role names: only admin+ may manage them.
  if (targetRank < 0) {
    if (actorRank < ROLE_RANK.admin) {
      throw new ForbiddenException(
        `Cannot ${action}: insufficient privilege for custom-role users`,
      );
    }
    return;
  }

  if (!outranks(actorRank, targetRank)) {
    throw new ForbiddenException(
      `Cannot ${action}: target role "${targetRoleName}" is at or above your privilege level`,
    );
  }
}

/**
 * True if `held` covers `needed` (exact or wildcards), matching PermissionsGuard.
 */
export function permissionCovers(
  held: Array<{ action: string; resource: string }>,
  needed: { action: string; resource: string },
): boolean {
  return held.some(
    (p) =>
      (p.action === needed.action && p.resource === needed.resource) ||
      (p.action === '*' && p.resource === needed.resource) ||
      (p.action === needed.action && p.resource === '*') ||
      (p.action === '*' && p.resource === '*'),
  );
}

/** True if every permission in `needed` is covered by `held`. */
export function permissionsSubsetOf(
  needed: Array<{ action: string; resource: string }>,
  held: Array<{ action: string; resource: string }>,
): boolean {
  return needed.every((n) => permissionCovers(held, n));
}
