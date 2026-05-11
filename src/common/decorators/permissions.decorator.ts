import { SetMetadata } from '@nestjs/common';

export const PERMISSIONS_KEY = 'permissions';

export interface PermissionRequirement {
  action: string;
  resource: string;
}

export const RequirePermissions = (...permissions: PermissionRequirement[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);
