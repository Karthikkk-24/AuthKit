import { AuthService } from './auth.service';

describe('password recovery revokes API keys (#143)', () => {
  it('resetPassword revokes sessions and API keys in the same transaction', async () => {
    const tx = {
      passwordReset: {
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      user: { update: jest.fn().mockResolvedValue({}) },
      session: { updateMany: jest.fn().mockResolvedValue({ count: 1 }) },
      apiKey: { updateMany: jest.fn().mockResolvedValue({ count: 2 }) },
    };
    const prisma = {
      passwordReset: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'pr1',
          userId: 'u1',
          usedAt: null,
          expiresAt: new Date(Date.now() + 60_000),
        }),
      },
      $transaction: jest.fn(async (fn: any) => fn(tx)),
    };
    const passwords = {
      validateStrength: jest.fn().mockReturnValue({ valid: true, errors: [] }),
      hash: jest.fn().mockResolvedValue('new-hash'),
      isPwned: jest.fn(),
    };
    const config = {
      get: jest.fn().mockReturnValue({}),
      isFeatureEnabled: jest.fn().mockReturnValue(false),
    };
    const audit = { log: jest.fn().mockResolvedValue(undefined) };
    const service = new AuthService(
      prisma as any,
      {} as any,
      passwords as any,
      {} as any,
      {} as any,
      {} as any,
      audit as any,
      config as any,
      {} as any,
    );

    await service.resetPassword(
      { token: 'tok', newPassword: 'NewPassword1!' } as any,
      {},
    );

    expect(tx.apiKey.updateMany).toHaveBeenCalledWith({
      where: { userId: 'u1', isRevoked: false },
      data: { isRevoked: true, revokedAt: expect.any(Date) },
    });
  });

  it('changePassword revokes API keys', async () => {
    const prisma = {
      user: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'u1',
          passwordHash: 'old',
        }),
        update: jest.fn(),
      },
      session: { updateMany: jest.fn() },
      apiKey: { updateMany: jest.fn().mockResolvedValue({ count: 1 }) },
      $transaction: jest.fn(async (ops: any[]) => {
        for (const op of ops) await op;
      }),
    };
    const passwords = {
      verify: jest.fn().mockResolvedValue(true),
      validateStrength: jest.fn().mockReturnValue({ valid: true, errors: [] }),
      hash: jest.fn().mockResolvedValue('new-hash'),
      isPwned: jest.fn(),
    };
    const config = {
      get: jest.fn(),
      isFeatureEnabled: jest.fn().mockReturnValue(false),
    };
    const audit = { log: jest.fn().mockResolvedValue(undefined) };
    const webhooks = { dispatch: jest.fn().mockResolvedValue(undefined) };
    const service = new AuthService(
      prisma as any,
      {} as any,
      passwords as any,
      {} as any,
      {} as any,
      {} as any,
      audit as any,
      config as any,
      webhooks as any,
    );

    await service.changePassword(
      'u1',
      { currentPassword: 'old', newPassword: 'NewPassword1!' } as any,
      {},
      'sess-1',
    );

    expect(prisma.apiKey.updateMany).toHaveBeenCalledWith({
      where: { userId: 'u1', isRevoked: false },
      data: { isRevoked: true, revokedAt: expect.any(Date) },
    });
  });
});
