import { BadRequestException } from '@nestjs/common';
import { ApiKeyService } from './api-key.service';

describe('ApiKeyService.create scopes (#113)', () => {
  function makeService(rolePerms: Array<{ action: string; resource: string }>) {
    const prisma = {
      user: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'u1',
          role: {
            id: 'role-1',
            permissions: rolePerms,
            parent: null,
          },
        }),
      },
      userPermission: {
        findMany: jest.fn().mockResolvedValue([]),
      },
      apiKey: {
        create: jest.fn().mockImplementation(({ data }) =>
          Promise.resolve({ id: 'key-1', ...data }),
        ),
      },
    };
    const audit = { log: jest.fn().mockResolvedValue(undefined) };
    const webhooks = { dispatch: jest.fn().mockResolvedValue(undefined) };
    const config = {
      isFeatureEnabled: jest.fn().mockReturnValue(true),
      isStrategyEnabled: jest.fn().mockReturnValue(true),
    };
    const service = new ApiKeyService(
      prisma as any,
      audit as any,
      webhooks as any,
      config as any,
    );
    return { service, prisma };
  }

  it('rejects empty scopes', async () => {
    const { service, prisma } = makeService([
      { action: 'read', resource: 'users' },
    ]);
    await expect(
      service.create('u1', { name: 'k', scopes: [] }, {}),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(prisma.apiKey.create).not.toHaveBeenCalled();
  });

  it('rejects omitted scopes', async () => {
    const { service } = makeService([{ action: 'read', resource: 'users' }]);
    await expect(
      service.create('u1', { name: 'k' }, {}),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects scopes beyond the creator’s permissions', async () => {
    const { service } = makeService([{ action: 'read', resource: 'users' }]);
    await expect(
      service.create('u1', { name: 'k', scopes: ['users:delete'] }, {}),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('creates when scopes are within permissions', async () => {
    const { service, prisma } = makeService([
      { action: 'read', resource: 'users' },
    ]);
    const result = await service.create(
      'u1',
      { name: 'k', scopes: ['users:read'] },
      {},
    );
    expect(prisma.apiKey.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ scopes: ['users:read'] }),
      }),
    );
    expect(result.key).toMatch(/^ak_/);
  });
});
