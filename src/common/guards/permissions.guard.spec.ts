import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { PermissionsGuard } from './permissions.guard';

describe('PermissionsGuard', () => {
  const makeGuard = (opts: {
    required?: Array<{ action: string; resource: string }>;
    user?: any;
    rolePerms?: Array<{ action: string; resource: string }>;
    overrides?: Array<{ action: string; resource: string; effect: string }>;
  }) => {
    const reflector = {
      getAllAndOverride: jest.fn().mockReturnValue(opts.required ?? []),
    };
    const prisma = {
      role: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'role-1',
          permissions: opts.rolePerms ?? [
            { action: 'read', resource: 'users' },
            { action: 'create', resource: 'users' },
          ],
          parent: null,
        }),
      },
      userPermission: {
        findMany: jest.fn().mockResolvedValue(opts.overrides ?? []),
      },
    };
    const guard = new PermissionsGuard(reflector as any, prisma as any);
    const context = {
      getHandler: () => ({}),
      getClass: () => ({}),
      switchToHttp: () => ({
        getRequest: () => ({
          user: opts.user ?? {
            id: 'u1',
            roleId: 'role-1',
            isApiKeyAuth: false,
          },
        }),
      }),
    };
    return { guard, context, prisma };
  };

  it('allows when RBAC grants the permission', async () => {
    const { guard, context } = makeGuard({
      required: [{ action: 'read', resource: 'users' }],
    });
    await expect(guard.canActivate(context as any)).resolves.toBe(true);
  });

  it('intersects API key scopes with RBAC (#66)', async () => {
    const { guard, context } = makeGuard({
      required: [{ action: 'create', resource: 'users' }],
      user: {
        id: 'u1',
        roleId: 'role-1',
        isApiKeyAuth: true,
        apiKeyScopes: ['users:read'],
      },
    });
    await expect(guard.canActivate(context as any)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('allows scoped API key when scope covers required perm (#66)', async () => {
    const { guard, context } = makeGuard({
      required: [{ action: 'read', resource: 'users' }],
      user: {
        id: 'u1',
        roleId: 'role-1',
        isApiKeyAuth: true,
        apiKeyScopes: ['users:read'],
      },
    });
    await expect(guard.canActivate(context as any)).resolves.toBe(true);
  });

  it('denies API keys with empty scopes (#113)', async () => {
    const { guard, context } = makeGuard({
      required: [{ action: 'create', resource: 'users' }],
      user: {
        id: 'u1',
        roleId: 'role-1',
        isApiKeyAuth: true,
        apiKeyScopes: [],
      },
    });
    await expect(guard.canActivate(context as any)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('walks more than one parent level for permissions (#118)', async () => {
    const reflector = {
      getAllAndOverride: jest
        .fn()
        .mockReturnValue([{ action: 'export', resource: 'audit' }]),
    };
    const prisma = {
      role: {
        findUnique: jest
          .fn()
          // child
          .mockResolvedValueOnce({
            id: 'child',
            parentId: 'mid',
            permissions: [],
          })
          // mid
          .mockResolvedValueOnce({
            id: 'mid',
            parentId: 'root',
            permissions: [],
          })
          // root
          .mockResolvedValueOnce({
            id: 'root',
            parentId: null,
            permissions: [{ action: 'export', resource: 'audit' }],
          }),
      },
      userPermission: { findMany: jest.fn().mockResolvedValue([]) },
    };
    const guard = new PermissionsGuard(reflector as any, prisma as any);
    const context = {
      getHandler: () => ({}),
      getClass: () => ({}),
      switchToHttp: () => ({
        getRequest: () => ({
          user: { id: 'u1', roleId: 'child', isApiKeyAuth: false },
        }),
      }),
    };
    await expect(guard.canActivate(context as any)).resolves.toBe(true);
    expect(prisma.role.findUnique).toHaveBeenCalledTimes(3);
  });
    const reflector = {
      getAllAndOverride: jest
        .fn()
        .mockReturnValue([{ action: 'read', resource: 'users' }]),
    };
    const prisma = {
      role: { findUnique: jest.fn() },
      userPermission: { findMany: jest.fn() },
    };
    const guard = new PermissionsGuard(reflector as any, prisma as any);
    const context = {
      getHandler: () => ({}),
      getClass: () => ({}),
      switchToHttp: () => ({ getRequest: () => ({ user: undefined }) }),
    };
    await expect(guard.canActivate(context as any)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
