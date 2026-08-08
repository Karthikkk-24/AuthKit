import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

describe('disableMfa step-up (#109)', () => {
  function makeService(user: any) {
    const prisma = {
      user: {
        findUnique: jest.fn().mockResolvedValue(user),
        update: jest.fn().mockResolvedValue({}),
      },
      mfaCredential: {
        deleteMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      $transaction: jest.fn(async (ops: any[]) => {
        for (const op of ops) await op;
      }),
    };
    const passwords = {
      verify: jest.fn().mockResolvedValue(true),
    };
    const config = {
      get: jest.fn().mockReturnValue({ enabled: true, methods: ['totp', 'email'] }),
      isFeatureEnabled: jest.fn().mockReturnValue(true),
      isStrategyEnabled: jest.fn().mockReturnValue(true),
    };
    const webhooks = { dispatch: jest.fn().mockResolvedValue(undefined) };
    const service = new AuthService(
      prisma as any,
      {} as any,
      passwords as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      config as any,
      webhooks as any,
    );
    jest.spyOn(service as any, 'verifyMfaWithFallback').mockResolvedValue(true);
    return { service, passwords, prisma };
  }

  it('rejects password-only disable when MFA is enabled', async () => {
    const { service } = makeService({
      id: 'u1',
      passwordHash: 'hash',
      isMfaEnabled: true,
    });
    await expect(service.disableMfa('u1', 'pw')).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });

  it('disables when password and MFA code are both valid', async () => {
    const { service, prisma } = makeService({
      id: 'u1',
      passwordHash: 'hash',
      isMfaEnabled: true,
    });
    await service.disableMfa('u1', 'pw', '123456');
    expect((service as any).verifyMfaWithFallback).toHaveBeenCalledWith(
      'u1',
      '123456',
    );
    expect(prisma.$transaction).toHaveBeenCalled();
  });

  it('still requires MFA code for OAuth-only accounts', async () => {
    const { service } = makeService({
      id: 'u1',
      passwordHash: null,
      isMfaEnabled: true,
    });
    await expect(service.disableMfa('u1')).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });
});
