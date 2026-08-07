import { UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';

describe('JwtAuthGuard', () => {
  const makeGuard = (opts: {
    payload?: any;
    blacklist?: boolean;
    user?: any;
    session?: any;
  }) => {
    const reflector = {
      getAllAndOverride: jest.fn().mockReturnValue(false),
    };
    const jwtService = {
      verifyAsync: jest.fn().mockResolvedValue(
        opts.payload ?? {
          sub: 'user-123',
          email: 'a@b.com',
          roleId: 'role-1',
          roleName: 'admin',
          sessionId: 'sess-1',
        },
      ),
    };
    const tokenBlacklist = {
      isBlacklisted: jest.fn().mockResolvedValue(opts.blacklist ?? false),
    };
    const config = {
      get: jest.fn().mockReturnValue({
        jwt: {
          algorithm: 'HS256',
          issuer: 'authkit',
          audience: 'authkit-clients',
        },
      }),
      isStrategyEnabled: jest.fn().mockReturnValue(true),
      isFeatureEnabled: jest.fn().mockReturnValue(true),
    };
    const prisma = {
      user: {
        findUnique: jest.fn().mockResolvedValue(
          opts.user === undefined
            ? {
                id: 'user-123',
                email: 'a@b.com',
                roleId: 'role-1',
                isLocked: false,
                deletedAt: null,
              }
            : opts.user,
        ),
      },
      session: {
        findUnique: jest.fn().mockResolvedValue(
          opts.session === undefined
            ? {
                id: 'sess-1',
                userId: 'user-123',
                isRevoked: false,
                expiresAt: new Date(Date.now() + 60_000),
                lastActiveAt: new Date(),
              }
            : opts.session,
        ),
        update: jest.fn().mockResolvedValue({}),
      },
      apiKey: {
        findUnique: jest.fn(),
        update: jest.fn().mockResolvedValue({}),
      },
    };

    return new JwtAuthGuard(
      reflector as any,
      jwtService as any,
      tokenBlacklist as any,
      config as any,
      prisma as any,
    );
  };

  const makeContext = (authHeader?: string) => {
    const request: any = {
      headers: authHeader ? { authorization: authHeader } : {},
      cookies: {},
    };
    return {
      switchToHttp: () => ({ getRequest: () => request }),
      getHandler: () => ({}),
      getClass: () => ({}),
      __request: request,
    } as any;
  };

  it('maps JWT sub to user.id for controllers', async () => {
    const guard = makeGuard({});
    const ctx = makeContext('Bearer tok');
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    expect(ctx.__request.user).toMatchObject({
      id: 'user-123',
      email: 'a@b.com',
      roleName: 'admin',
      sessionId: 'sess-1',
    });
  });

  it('rejects locked users', async () => {
    const guard = makeGuard({
      user: {
        id: 'user-123',
        email: 'a@b.com',
        roleId: 'role-1',
        isLocked: true,
        deletedAt: null,
      },
    });
    const ctx = makeContext('Bearer tok');
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('rejects revoked sessions', async () => {
    const guard = makeGuard({
      session: {
        id: 'sess-1',
        userId: 'user-123',
        isRevoked: true,
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    const ctx = makeContext('Bearer tok');
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('rejects tokens without sub', async () => {
    const guard = makeGuard({ payload: { email: 'a@b.com' } });
    const ctx = makeContext('Bearer tok');
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('rejects missing bearer token', async () => {
    const guard = makeGuard({});
    const ctx = makeContext();
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('does not accept cookies as JWT (BFF owns cookies) (#51)', async () => {
    const guard = makeGuard({});
    const request: any = {
      headers: {},
      cookies: { access_token: 'cookie-tok' },
    };
    const ctx = {
      switchToHttp: () => ({ getRequest: () => request }),
      getHandler: () => ({}),
      getClass: () => ({}),
    } as any;
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('rejects session owned by a different user (IDOR regression)', async () => {
    const guard = makeGuard({
      session: {
        id: 'sess-1',
        userId: 'other-user',
        isRevoked: false,
        expiresAt: new Date(Date.now() + 60_000),
        lastActiveAt: new Date(),
      },
    });
    const ctx = makeContext('Bearer tok');
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  describe('mfa_setup token path allowlist (#124, #133)', () => {
    const mfaSetupPayload = {
      sub: 'user-123',
      email: 'a@b.com',
      roleId: 'role-1',
      roleName: 'user',
      type: 'mfa_setup',
      // setup tokens are not session-bound
    };

    const makeMfaCtx = (urlFields: {
      path?: string;
      url?: string;
      originalUrl?: string;
    }) => {
      const request: any = {
        headers: { authorization: 'Bearer tok' },
        cookies: {},
        ...urlFields,
      };
      return {
        switchToHttp: () => ({ getRequest: () => request }),
        getHandler: () => ({}),
        getClass: () => ({}),
        __request: request,
      } as any;
    };

    it.each([
      '/auth/mfa/totp/setup',
      '/api/auth/mfa/totp/setup',
      '/v1/auth/mfa/totp/setup',
      '/api/v1/auth/mfa/totp/setup',
      '/api/v1/auth/mfa/totp/enable',
      '/api/v1/auth/mfa/email/send',
      '/api/v1/auth/mfa/email/verify',
      '/api/v1/auth/me',
      '/api/v1/auth/me/',
    ])('allows live Nest pathname %s', async (path) => {
      const guard = makeGuard({ payload: mfaSetupPayload, session: null });
      const ctx = makeMfaCtx({ path });
      await expect(guard.canActivate(ctx)).resolves.toBe(true);
    });

    it('rejects query-string bypass (/users?x=/auth/mfa/)', async () => {
      const guard = makeGuard({ payload: mfaSetupPayload, session: null });
      const ctx = makeMfaCtx({
        path: '/users',
        url: '/users?x=/auth/mfa/',
        originalUrl: '/users?x=/auth/mfa/',
      });
      await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
        ForbiddenException,
      );
    });

    it('rejects when only url carries MFA substring in query (no path)', async () => {
      const guard = makeGuard({ payload: mfaSetupPayload, session: null });
      const ctx = makeMfaCtx({
        url: '/api/v1/users?redirect=/auth/mfa/totp/setup',
      });
      await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
        ForbiddenException,
      );
    });

    it('rejects unrelated auth routes (e.g. change-password)', async () => {
      const guard = makeGuard({ payload: mfaSetupPayload, session: null });
      const ctx = makeMfaCtx({ path: '/api/v1/auth/change-password' });
      await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
        ForbiddenException,
      );
    });

    it('rejects prefix smuggling (/api/v1/evil/auth/mfa/totp/setup)', async () => {
      const guard = makeGuard({ payload: mfaSetupPayload, session: null });
      const ctx = makeMfaCtx({ path: '/api/v1/evil/auth/mfa/totp/setup' });
      await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
        ForbiddenException,
      );
    });
  });
});
