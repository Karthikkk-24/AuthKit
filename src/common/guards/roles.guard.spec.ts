import { ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolesGuard } from './roles.guard';

describe('RolesGuard hierarchy (#39)', () => {
  const reflector = {
    getAllAndOverride: jest.fn(),
  } as unknown as Reflector;
  const guard = new RolesGuard(reflector);

  function ctx(user: any) {
    return {
      getHandler: () => ({}),
      getClass: () => ({}),
      switchToHttp: () => ({
        getRequest: () => ({ user }),
      }),
    } as any;
  }

  it('allows higher roles to satisfy lower requirements', () => {
    (reflector.getAllAndOverride as jest.Mock).mockReturnValue(['user']);
    expect(guard.canActivate(ctx({ roleName: 'admin' }))).toBe(true);
    expect(guard.canActivate(ctx({ roleName: 'superadmin' }))).toBe(true);
  });

  it('rejects lower roles for higher requirements', () => {
    (reflector.getAllAndOverride as jest.Mock).mockReturnValue(['admin']);
    expect(() => guard.canActivate(ctx({ roleName: 'user' }))).toThrow(
      ForbiddenException,
    );
  });

  it('passes when no roles are required', () => {
    (reflector.getAllAndOverride as jest.Mock).mockReturnValue(undefined);
    expect(guard.canActivate(ctx({ roleName: 'guest' }))).toBe(true);
  });
});
