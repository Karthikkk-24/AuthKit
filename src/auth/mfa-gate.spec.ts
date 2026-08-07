/**
 * Unit tests for the shared MFA gate on passwordless session minting (#60).
 * OAuth exchange and magic-link verify must not call createTokens when MFA is enrolled.
 */
describe('MFA gate on passwordless auth (#60)', () => {
  const userWithMfa = {
    id: 'user-mfa',
    email: 'mfa@example.com',
    name: 'MFA User',
    roleId: 'role-user',
    role: { name: 'user', permissions: [] },
    isMfaEnabled: true,
    deletedAt: null,
    isLocked: false,
  };

  const userNoMfa = {
    ...userWithMfa,
    id: 'user-plain',
    email: 'plain@example.com',
    isMfaEnabled: false,
  };

  function makeService(overrides: {
    user?: any;
    verifyMfaOk?: boolean;
    mfaConfig?: any;
  }) {
    const tokens = { accessToken: 'at', refreshToken: 'rt', user: overrides.user };
    const prisma = {
      emailVerification: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'ev-1',
          purpose: 'oauth_exchange',
          usedAt: null,
          expiresAt: new Date(Date.now() + 60_000),
          user: overrides.user ?? userWithMfa,
        }),
        update: jest.fn().mockResolvedValue({}),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        create: jest.fn().mockResolvedValue({}),
      },
      mfaCredential: {
        findUnique: jest.fn().mockResolvedValue(null),
      },
      session: {
        count: jest.fn().mockResolvedValue(0),
        findFirst: jest.fn(),
        create: jest.fn().mockResolvedValue({ id: 'sess-1' }),
      },
      user: {
        update: jest.fn().mockResolvedValue({}),
        findUnique: jest.fn().mockResolvedValue(overrides.user ?? userWithMfa),
      },
    };

    const config = {
      get: jest.fn((key: string) => {
        if (key === 'mfa') {
          return overrides.mfaConfig ?? { required: false, requiredForRoles: [] };
        }
        if (key === 'auth') {
          return {
            jwt: {
              accessTokenExpiry: '15m',
              refreshTokenExpiry: '7d',
              algorithm: 'HS256',
              issuer: 'authkit',
              audience: 'authkit-clients',
            },
            registration: { requireEmailVerification: false },
          };
        }
        if (key === 'session') {
          return { maxConcurrentSessions: 0 };
        }
        if (key === 'audit') return {};
        if (key === 'redis') return { prefix: 'authkit:' };
        return {};
      }),
      isStrategyEnabled: jest.fn().mockReturnValue(true),
      isFeatureEnabled: jest.fn((feature: string) =>
        feature === 'magicLink' || feature === 'mfa' || feature === 'registration',
      ),
    };

    const jwt = {
      signAsync: jest.fn().mockResolvedValue('jwt-token'),
    };

    const audit = { log: jest.fn().mockResolvedValue(undefined) };
    const webhooks = { dispatch: jest.fn().mockResolvedValue(undefined) };
    const blacklist = { blacklist: jest.fn() };
    const password = {};
    const email = {};
    const cryptoSvc = { encrypt: jest.fn(), decrypt: jest.fn() };

    const { AuthService } = require('./auth.service');
    const service = new AuthService(
      prisma as any,
      jwt as any,
      password as any,
      cryptoSvc as any,
      blacklist as any,
      email as any,
      audit as any,
      config as any,
      webhooks as any,
    );

    // Spy createTokens / MFA verify
    jest.spyOn(service as any, 'createTokens').mockResolvedValue(tokens);
    jest
      .spyOn(service as any, 'verifyMfaWithFallback')
      .mockImplementation(async () => {
        if (overrides.verifyMfaOk === false) {
          const { UnauthorizedException } = require('@nestjs/common');
          throw new UnauthorizedException('Invalid MFA code');
        }
        return true;
      });

    return { service, prisma, tokens };
  }

  it('exchangeOAuthCode returns MFA challenge and does not mint tokens when MFA enrolled', async () => {
    const { service, prisma } = makeService({ user: userWithMfa });

    const result: any = await service.exchangeOAuthCode('oauth-code', {});

    expect(result.requiresMfa).toBe(true);
    expect(result.mfaToken).toEqual(expect.any(String));
    expect((service as any).createTokens).not.toHaveBeenCalled();
    expect(prisma.emailVerification.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ purpose: 'mfa_login' }),
      }),
    );
  });

  it('exchangeOAuthCode mints tokens when MFA code is valid', async () => {
    const { service, tokens } = makeService({
      user: userWithMfa,
      verifyMfaOk: true,
    });

    const result = await service.exchangeOAuthCode('oauth-code', {}, '123456');

    expect(result).toBe(tokens);
    expect((service as any).createTokens).toHaveBeenCalled();
  });

  it('exchangeOAuthCode mints tokens without MFA when user has MFA disabled', async () => {
    const { service, tokens } = makeService({ user: userNoMfa });

    const result = await service.exchangeOAuthCode('oauth-code', {});

    expect(result).toBe(tokens);
    expect((service as any).createTokens).toHaveBeenCalled();
  });

  it('verifyMagicLink returns MFA challenge when MFA enrolled', async () => {
    const { service, prisma } = makeService({ user: userWithMfa });
    prisma.emailVerification.findUnique.mockResolvedValue({
      id: 'ev-ml',
      purpose: 'magic_link',
      usedAt: null,
      expiresAt: new Date(Date.now() + 60_000),
      user: userWithMfa,
    });

    const result: any = await service.verifyMagicLink('magic-token', {});

    expect(result.requiresMfa).toBe(true);
    expect(result.mfaToken).toEqual(expect.any(String));
    expect((service as any).createTokens).not.toHaveBeenCalled();
  });

  it('completeMfaLogin mints tokens after valid MFA code', async () => {
    const { service, prisma, tokens } = makeService({
      user: userWithMfa,
      verifyMfaOk: true,
    });
    prisma.emailVerification.findUnique.mockResolvedValue({
      id: 'ev-mfa',
      purpose: 'mfa_login',
      usedAt: null,
      expiresAt: new Date(Date.now() + 60_000),
      user: userWithMfa,
    });

    const result = await service.completeMfaLogin('mfa-token', '123456', {});

    expect(result).toBe(tokens);
    expect(prisma.emailVerification.updateMany).toHaveBeenCalled();
  });

  it('exchangeOAuthCode does not burn code when mfaCode is invalid', async () => {
    const { service, prisma } = makeService({
      user: userWithMfa,
      verifyMfaOk: false,
    });

    await expect(
      service.exchangeOAuthCode('oauth-code', {}, '000000'),
    ).rejects.toThrow();

    expect(prisma.emailVerification.update).not.toHaveBeenCalled();
    expect((service as any).createTokens).not.toHaveBeenCalled();
  });

  it('exchangeOAuthCode returns mfaSetupRequired for mandatory-role users without MFA', async () => {
    const { service } = makeService({
      user: userNoMfa,
      mfaConfig: { required: false, requiredForRoles: ['user'] },
    });

    const result: any = await service.exchangeOAuthCode('oauth-code', {});

    expect(result.mfaSetupRequired).toBe(true);
    expect(result.setupToken).toEqual(expect.any(String));
    expect((service as any).createTokens).not.toHaveBeenCalled();
  });

  it('completeMfaLogin rejects already-claimed tokens (race)', async () => {
    const { service, prisma } = makeService({ user: userWithMfa });
    prisma.emailVerification.findUnique.mockResolvedValue({
      id: 'ev-mfa',
      purpose: 'mfa_login',
      usedAt: null,
      expiresAt: new Date(Date.now() + 60_000),
      user: userWithMfa,
    });
    prisma.emailVerification.updateMany.mockResolvedValue({ count: 0 });

    await expect(
      service.completeMfaLogin('mfa-token', '123456', {}),
    ).rejects.toThrow(/already used|expired/i);
    expect((service as any).createTokens).not.toHaveBeenCalled();
  });
});
