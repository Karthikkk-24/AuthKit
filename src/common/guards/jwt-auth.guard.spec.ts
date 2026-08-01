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
});
