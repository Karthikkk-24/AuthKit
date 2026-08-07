import { UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

describe('verifyMfaWithFallback email enrollment gate (#146)', () => {
  function makeService(opts: {
    emailCred?: { isEnabled: boolean } | null;
    mfaMethods?: string[];
    featuresMfa?: boolean;
  }) {
    const prisma = {
      mfaCredential: {
        findUnique: jest.fn().mockImplementation(async ({ where }: any) => {
          if (where?.userId_type?.type === 'EMAIL') {
            return opts.emailCred === undefined
              ? null
              : opts.emailCred;
          }
          // TOTP lookups for verifyMfa — treat as not enrolled / invalid
          return null;
        }),
        update: jest.fn(),
      },
    };
    const config = {
      get: jest.fn((key: string) => {
        if (key === 'mfa') {
          return {
            enabled: true,
            methods: opts.mfaMethods ?? ['totp', 'email'],
          };
        }
        if (key === 'redis') return { prefix: 'authkit:' };
        return {};
      }),
      isFeatureEnabled: jest.fn().mockReturnValue(opts.featuresMfa !== false),
      isStrategyEnabled: jest.fn().mockReturnValue(true),
    };
    const redis = {
      get: jest.fn().mockResolvedValue(
        // sha256 of "123456"
        require('crypto').createHash('sha256').update('123456').digest('hex'),
      ),
      del: jest.fn().mockResolvedValue(1),
    };
    const service = new AuthService(
      prisma as any,
      {} as any,
      {} as any,
      {} as any,
      { redis } as any,
      {} as any,
      {} as any,
      config as any,
      {} as any,
    );
    return { service, prisma, redis };
  }

  it('rejects email OTP when EMAIL MFA is not enrolled', async () => {
    const { service, redis } = makeService({ emailCred: null });
    await expect(
      (service as any).verifyMfaWithFallback('u1', '123456'),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(redis.del).not.toHaveBeenCalled();
  });

  it('rejects email OTP when EMAIL credential exists but is disabled', async () => {
    const { service, redis } = makeService({
      emailCred: { isEnabled: false },
    });
    await expect(
      (service as any).verifyMfaWithFallback('u1', '123456'),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    expect(redis.del).not.toHaveBeenCalled();
  });

  it('accepts email OTP when EMAIL MFA is enrolled', async () => {
    const { service, redis } = makeService({
      emailCred: { isEnabled: true },
    });
    await expect(
      (service as any).verifyMfaWithFallback('u1', '123456'),
    ).resolves.toBe(true);
    expect(redis.del).toHaveBeenCalled();
  });
});
