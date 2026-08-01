import { UnauthorizedException } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';

describe('JwtAuthGuard', () => {
  const makeGuard = (payload: any, blacklist = false) => {
    const reflector = {
      getAllAndOverride: jest.fn().mockReturnValue(false),
    };
    const jwtService = {
      verifyAsync: jest.fn().mockResolvedValue(payload),
    };
    const tokenBlacklist = {
      isBlacklisted: jest.fn().mockResolvedValue(blacklist),
    };
    const config = {
      get: jest.fn().mockReturnValue({
        algorithm: 'HS256',
        issuer: 'authkit',
        audience: 'authkit-clients',
      }),
    };

    return new JwtAuthGuard(
      reflector as any,
      jwtService as any,
      tokenBlacklist as any,
      config as any,
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
    const guard = makeGuard({
      sub: 'user-123',
      email: 'a@b.com',
      roleId: 'role-1',
      roleName: 'admin',
      sessionId: 'sess-1',
    });
    const ctx = makeContext('Bearer tok');
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    expect(ctx.__request.user).toMatchObject({
      id: 'user-123',
      sub: 'user-123',
      email: 'a@b.com',
      roleName: 'admin',
      sessionId: 'sess-1',
    });
  });

  it('rejects tokens without sub', async () => {
    const guard = makeGuard({ email: 'a@b.com' });
    const ctx = makeContext('Bearer tok');
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });

  it('rejects missing bearer token', async () => {
    const guard = makeGuard({ sub: 'user-123' });
    const ctx = makeContext();
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
