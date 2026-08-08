import { BadRequestException } from '@nestjs/common';
import { AuthService } from './auth.service';

describe('atomic one-time token claims (#108)', () => {
  it('claimOneTimeEmailToken rejects when updateMany count is 0', async () => {
    const prisma = {
      emailVerification: {
        updateMany: jest.fn().mockResolvedValue({ count: 0 }),
      },
    };
    const service = new AuthService(
      prisma as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      { get: jest.fn(), isFeatureEnabled: jest.fn(), isStrategyEnabled: jest.fn() } as any,
      {} as any,
    );

    await expect(
      (service as any).claimOneTimeEmailToken('ev-1', 'oauth_exchange'),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('claimOneTimeEmailToken succeeds when count is 1', async () => {
    const prisma = {
      emailVerification: {
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
    };
    const service = new AuthService(
      prisma as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      { get: jest.fn(), isFeatureEnabled: jest.fn(), isStrategyEnabled: jest.fn() } as any,
      {} as any,
    );

    await expect(
      (service as any).claimOneTimeEmailToken('ev-1', 'oauth_exchange'),
    ).resolves.toBeUndefined();
    expect(prisma.emailVerification.updateMany).toHaveBeenCalledWith({
      where: {
        id: 'ev-1',
        purpose: 'oauth_exchange',
        usedAt: null,
        expiresAt: { gt: expect.any(Date) },
      },
      data: { usedAt: expect.any(Date) },
    });
  });
});
