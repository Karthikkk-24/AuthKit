import { NotFoundException } from '@nestjs/common';
import { RbacService } from './rbac.service';

describe('RbacService.assignPermissionsToRole (#33/#52)', () => {
  const prisma = {
    role: { findUnique: jest.fn() },
    permission: {
      deleteMany: jest.fn(),
      createMany: jest.fn(),
    },
    $transaction: jest.fn(async (ops: any[]) => {
      for (const op of ops) await op;
    }),
  };
  const audit = { log: jest.fn().mockResolvedValue(undefined) };
  const service = new RbacService(prisma as any, audit as any);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('replaces role-owned permission rows from action/resource pairs', async () => {
    prisma.role.findUnique.mockResolvedValue({ id: 'role-1', name: 'editor' });
    await service.assignPermissionsToRole(
      'role-1',
      [
        { action: 'read', resource: 'users' },
        { action: 'update', resource: 'users' },
      ],
      'admin-1',
      { ip: '127.0.0.1' },
    );

    expect(prisma.permission.deleteMany).toHaveBeenCalledWith({
      where: { roleId: 'role-1' },
    });
    expect(prisma.permission.createMany).toHaveBeenCalledWith({
      data: [
        { action: 'read', resource: 'users', roleId: 'role-1' },
        { action: 'update', resource: 'users', roleId: 'role-1' },
      ],
      skipDuplicates: true,
    });
    expect(audit.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'role.permissions_updated',
        userId: 'admin-1',
        resourceId: 'role-1',
        success: true,
      }),
    );
  });

  it('throws when role is missing', async () => {
    prisma.role.findUnique.mockResolvedValue(null);
    await expect(
      service.assignPermissionsToRole('missing', [], 'admin-1', {}),
    ).rejects.toBeInstanceOf(NotFoundException);
  });
});
