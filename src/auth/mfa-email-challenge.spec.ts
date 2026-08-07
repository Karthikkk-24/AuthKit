import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

describe('sendEmailOtpForLoginChallenge (#106)', () => {
  const user = {
    id: 'user-1',
    email: 'a@b.com',
    name: 'Ada',
    deletedAt: null,
    isLocked: false,
  };

  function makeService(opts: {
    record?: any;
    emailCred?: any;
    mfaEnabled?: boolean;
    featuresMfa?: boolean;
  }) {
    const redis = {
      set: jest.fn().mockResolvedValue('OK'),
    };
    const prisma = {
      emailVerification: {
        findUnique: jest.fn().mockResolvedValue(
          opts.record === undefined
            ? {
                id: 'ev-1',
                purpose: 'mfa_login',
                usedAt: null,
                expiresAt: new Date(Date.now() + 60_000),
                user,
              }
            : opts.record,
        ),
      },
      mfaCredential: {
        findUnique: jest.fn().mockResolvedValue(
          opts.emailCred === undefined
            ? { isEnabled: true }
            : opts.emailCred,
        ),
      },
      user: {
        findUnique: jest.fn().mockResolvedValue(user),
      },
    };
    const email = {
      sendEmailOtp: jest.fn().mockResolvedValue(undefined),
    };
    const config = {
      get: jest.fn((key: string) => {
        if (key === 'mfa') {
          return {
            enabled: opts.mfaEnabled !== false,
            methods: ['totp', 'email'],
          };
        }
        if (key === 'redis') return { prefix: 'authkit:' };
        return {};
      }),
      isFeatureEnabled: jest.fn((f: string) =>
        f === 'mfa' ? opts.featuresMfa !== false : false,
      ),
      isStrategyEnabled: jest.fn().mockReturnValue(true),
    };
    const blacklist = { redis };

    const service = new AuthService(
      prisma as any,
      {} as any,
      {} as any,
      {} as any,
      blacklist as any,
      email as any,
      {} as any,
      config as any,
      {} as any,
    );

    return { service, prisma, email, redis };
  }

  it('sends OTP when mfaToken is valid and EMAIL MFA is enrolled', async () => {
    const { service, email, redis } = makeService({});
    const result = await service.sendEmailOtpForLoginChallenge('tok-hex');
    expect(result).toEqual({ message: 'Verification code sent' });
    expect(email.sendEmailOtp).toHaveBeenCalledWith('a@b.com', 'Ada', expect.any(String));
    expect(redis.set).toHaveBeenCalled();
  });

  it('rejects when EMAIL MFA is not enrolled', async () => {
    const { service, email } = makeService({ emailCred: { isEnabled: false } });
    await expect(
      service.sendEmailOtpForLoginChallenge('tok-hex'),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(email.sendEmailOtp).not.toHaveBeenCalled();
  });

  it('rejects invalid / wrong-purpose tokens', async () => {
    const { service } = makeService({
      record: {
        id: 'ev-1',
        purpose: 'magic_link',
        usedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
        user,
      },
    });
    await expect(
      service.sendEmailOtpForLoginChallenge('tok-hex'),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects locked accounts', async () => {
    const { service } = makeService({
      record: {
        id: 'ev-1',
        purpose: 'mfa_login',
        usedAt: null,
        expiresAt: new Date(Date.now() + 60_000),
        user: { ...user, isLocked: true },
      },
    });
    await expect(
      service.sendEmailOtpForLoginChallenge('tok-hex'),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
