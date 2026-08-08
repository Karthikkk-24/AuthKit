import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { UserService } from './user.service';

describe('UserService hierarchy guards (#63)', () => {
  function makeService() {
    const prisma = {
      user: {
        findUnique: jest.fn(),
        update: jest.fn().mockResolvedValue({}),
      },
      session: {
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      role: {
        findUnique: jest.fn(),
      },
      $transaction: jest.fn(async (ops: any[]) => {
        const results = [];
        for (const op of ops) {
          results.push(await op);
        }
        return results;
      }),
    };
    const audit = { log: jest.fn().mockResolvedValue(undefined) };
    const config = {};
    const passwords = {};
    const auth = {};
    const webhooks = { dispatch: jest.fn().mockResolvedValue(undefined) };
    const service = new UserService(
      prisma as any,
      audit as any,
      config as any,
      passwords as any,
      auth as any,
      webhooks as any,
    );
    return { service, prisma, audit };
  }

  const admin = {
    id: 'admin-1',
    roleId: 'r-admin',
    role: { id: 'r-admin', name: 'admin' },
  };
  const superadmin = {
    id: 'sa-1',
    roleId: 'r-sa',
    role: { id: 'r-sa', name: 'superadmin' },
    deletedAt: null,
  };
  const regular = {
    id: 'user-1',
    roleId: 'r-user',
    role: { id: 'r-user', name: 'user' },
    deletedAt: null,
  };

  it('blocks admin from locking a superadmin', async () => {
    const { service, prisma } = makeService();
    prisma.user.findUnique
      .mockResolvedValueOnce(admin)
      .mockResolvedValueOnce(superadmin);

    await expect(
      service.lockUser('sa-1', 'nope', 'admin-1', {}),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(prisma.user.update).not.toHaveBeenCalled();
  });

  it('allows admin to lock a regular user', async () => {
    const { service, prisma } = makeService();
    prisma.user.findUnique
      .mockResolvedValueOnce(admin)
      .mockResolvedValueOnce(regular);

    await service.lockUser('user-1', 'abuse', 'admin-1', {});
    expect(prisma.user.update).toHaveBeenCalled();
  });

  it('blocks admin from demoting a superadmin via assignRole', async () => {
    const { service, prisma } = makeService();
    prisma.user.findUnique
      .mockResolvedValueOnce(admin)
      .mockResolvedValueOnce(superadmin);
    prisma.role.findUnique.mockResolvedValue({ id: 'r-user', name: 'user' });

    await expect(
      service.assignRole('sa-1', 'r-user', 'admin-1', {}),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('revokes sessions when role actually changes (#107)', async () => {
    const { service, prisma } = makeService();
    prisma.user.findUnique
      .mockResolvedValueOnce(admin)
      .mockResolvedValueOnce(regular);
    prisma.role.findUnique.mockResolvedValue({
      id: 'r-mod',
      name: 'moderator',
      permissions: [],
      parent: null,
    });

    await service.assignRole('user-1', 'r-mod', 'admin-1', {});

    expect(prisma.$transaction).toHaveBeenCalled();
    expect(prisma.session.updateMany).toHaveBeenCalledWith({
      where: { userId: 'user-1', isRevoked: false },
      data: { isRevoked: true, revokedAt: expect.any(Date) },
    });
  });

  it('blocks admin from deleting a superadmin', async () => {
    const { service, prisma } = makeService();
    prisma.user.findUnique
      .mockResolvedValueOnce(admin)
      .mockResolvedValueOnce(superadmin);

    await expect(
      service.softDelete('sa-1', 'admin-1', {}),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('blocks self-lock', async () => {
    const { service } = makeService();
    await expect(
      service.lockUser('admin-1', 'x', 'admin-1', {}),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('throws NotFound when target is missing', async () => {
    const { service, prisma } = makeService();
    prisma.user.findUnique
      .mockResolvedValueOnce(admin)
      .mockResolvedValueOnce(null);

    await expect(
      service.unlockUser('missing', 'admin-1', {}),
    ).rejects.toBeInstanceOf(NotFoundException);
  });
});
