import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { RbacService } from './rbac.service';

describe('RbacService P1 guards (#64, #65, #86)', () => {
  function makeService() {
    const prisma = {
      role: {
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
      },
      permission: {
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
        createMany: jest.fn().mockResolvedValue({ count: 0 }),
      },
      user: {
        findUnique: jest.fn(),
      },
      userPermission: {
        findMany: jest.fn().mockResolvedValue([]),
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
        createMany: jest.fn().mockResolvedValue({ count: 0 }),
      },
      $transaction: jest.fn(async (ops: any[]) => {
        for (const op of ops) await op;
      }),
    };
    const audit = { log: jest.fn().mockResolvedValue(undefined) };
    const service = new RbacService(prisma as any, audit as any);
    return { service, prisma, audit };
  }

  const adminActor = {
    id: 'admin-1',
    role: {
      id: 'r-admin',
      name: 'admin',
      permissions: [
        { action: 'read', resource: 'users' },
        { action: 'update', resource: 'users' },
        { action: 'update', resource: 'roles' },
        { action: 'update', resource: 'permissions' },
      ],
      parent: null,
    },
  };

  const superadminActor = {
    id: 'sa-1',
    role: {
      id: 'r-sa',
      name: 'superadmin',
      permissions: [{ action: '*', resource: '*' }],
      parent: null,
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('assignPermissionsToRole (#64)', () => {
    it('blocks admin from rewriting superadmin permissions', async () => {
      const { service, prisma } = makeService();
      prisma.role.findUnique.mockResolvedValue({
        id: 'r-sa',
        name: 'superadmin',
        isSystem: true,
      });
      prisma.user.findUnique.mockResolvedValue(adminActor);

      await expect(
        service.assignPermissionsToRole(
          'r-sa',
          [{ action: 'read', resource: 'users' }],
          'admin-1',
          {},
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('blocks assigning permissions the actor does not hold', async () => {
      const { service, prisma } = makeService();
      prisma.role.findUnique.mockResolvedValue({
        id: 'r-mod',
        name: 'moderator',
        isSystem: true,
      });
      prisma.user.findUnique.mockResolvedValue(adminActor);

      await expect(
        service.assignPermissionsToRole(
          'r-mod',
          [{ action: '*', resource: '*' }],
          'admin-1',
          {},
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('allows admin to update a lower custom role with held permissions', async () => {
      const { service, prisma } = makeService();
      prisma.role.findUnique.mockResolvedValue({
        id: 'r-editor',
        name: 'editor',
        isSystem: false,
      });
      prisma.user.findUnique.mockResolvedValue(adminActor);

      await service.assignPermissionsToRole(
        'r-editor',
        [{ action: 'read', resource: 'users' }],
        'admin-1',
        { ip: '1.1.1.1' },
      );

      expect(prisma.permission.deleteMany).toHaveBeenCalled();
      expect(prisma.permission.createMany).toHaveBeenCalled();
    });

    it('blocks admin from updating system role permissions (superadmin-only)', async () => {
      const { service, prisma } = makeService();
      prisma.role.findUnique.mockResolvedValue({
        id: 'r-user',
        name: 'user',
        isSystem: true,
      });
      prisma.user.findUnique.mockResolvedValue(adminActor);

      await expect(
        service.assignPermissionsToRole(
          'r-user',
          [{ action: 'read', resource: 'users' }],
          'admin-1',
          {},
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('throws when role is missing', async () => {
      const { service, prisma } = makeService();
      prisma.role.findUnique.mockResolvedValue(null);
      await expect(
        service.assignPermissionsToRole('missing', [], 'admin-1', {}),
      ).rejects.toBeInstanceOf(NotFoundException);
    });
  });

  describe('setUserPermissions (#65)', () => {
    it('blocks self-elevation to *:*', async () => {
      const { service, prisma, audit } = makeService();
      // Target = admin themselves (same id) — outrank fails first
      prisma.user.findUnique
        .mockResolvedValueOnce({
          id: 'admin-1',
          role: { id: 'r-admin', name: 'admin' },
        })
        .mockResolvedValueOnce(adminActor);

      await expect(
        service.setUserPermissions(
          'admin-1',
          [{ action: '*', resource: '*', effect: 'grant' }],
          'admin-1',
          {},
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('blocks granting *:* to a lower user when actor lacks it', async () => {
      const { service, prisma, audit } = makeService();
      prisma.user.findUnique
        .mockResolvedValueOnce({
          id: 'user-1',
          role: { id: 'r-user', name: 'user' },
        })
        .mockResolvedValueOnce(adminActor);

      await expect(
        service.setUserPermissions(
          'user-1',
          [{ action: '*', resource: '*', effect: 'grant' }],
          'admin-1',
          {},
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);

      expect(audit.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'user.permissions_elevation_denied',
          success: false,
        }),
      );
    });

    it('allows granting a subset of actor permissions to a lower user', async () => {
      const { service, prisma } = makeService();
      prisma.user.findUnique
        .mockResolvedValueOnce({
          id: 'user-1',
          role: { id: 'r-user', name: 'user' },
        })
        .mockResolvedValueOnce(adminActor);

      await service.setUserPermissions(
        'user-1',
        [{ action: 'read', resource: 'users', effect: 'grant' }],
        'admin-1',
        {},
      );

      expect(prisma.userPermission.createMany).toHaveBeenCalled();
    });
  });

  describe('updateRole parentId (#86)', () => {
    it('blocks admin from parenting a role under superadmin', async () => {
      const { service, prisma } = makeService();
      prisma.user.findUnique.mockResolvedValue(adminActor);
      prisma.role.findUnique
        .mockResolvedValueOnce({
          id: 'r-custom',
          name: 'editor',
          isSystem: false,
        })
        .mockResolvedValueOnce({
          id: 'r-sa',
          name: 'superadmin',
          isSystem: true,
          permissions: [{ action: '*', resource: '*' }],
          parent: null,
        });

      await expect(
        service.updateRole('r-custom', { parentId: 'r-sa' }, 'admin-1', {}),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('allows superadmin to set parentId within policy', async () => {
      const { service, prisma } = makeService();
      prisma.user.findUnique.mockResolvedValue(superadminActor);
      prisma.role.findUnique
        .mockResolvedValueOnce({
          id: 'r-custom',
          name: 'editor',
          isSystem: false,
        })
        .mockResolvedValueOnce({
          id: 'r-admin',
          name: 'admin',
          isSystem: true,
          permissions: [{ action: 'read', resource: 'users' }],
          parent: null,
        });
      prisma.role.update.mockResolvedValue({ id: 'r-custom', parentId: 'r-admin' });

      await service.updateRole('r-custom', { parentId: 'r-admin' }, 'sa-1', {});
      expect(prisma.role.update).toHaveBeenCalled();
    });

    it('allows superadmin to update system role permissions', async () => {
      const { service, prisma } = makeService();
      prisma.role.findUnique.mockResolvedValue({
        id: 'r-sa',
        name: 'superadmin',
        isSystem: true,
      });
      prisma.user.findUnique.mockResolvedValue(superadminActor);

      await service.assignPermissionsToRole(
        'r-sa',
        [{ action: '*', resource: '*' }],
        'sa-1',
        {},
      );
      expect(prisma.permission.createMany).toHaveBeenCalled();
    });

    it('blocks renaming a custom role to a reserved hierarchy name', async () => {
      const { service, prisma } = makeService();
      prisma.user.findUnique.mockResolvedValue(adminActor);
      prisma.role.findUnique.mockResolvedValue({
        id: 'r-custom',
        name: 'editor',
        isSystem: false,
      });

      await expect(
        service.updateRole('r-custom', { name: 'superadmin' }, 'admin-1', {}),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('blocks createPermission onto system roles for admin', async () => {
      const { service, prisma } = makeService();
      prisma.role.findUnique.mockResolvedValue({
        id: 'r-sa',
        name: 'superadmin',
        isSystem: true,
      });
      prisma.user.findUnique.mockResolvedValue(adminActor);

      await expect(
        service.createPermission(
          { roleId: 'r-sa', action: 'read', resource: 'users' },
          'admin-1',
          {},
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });
  });
});
