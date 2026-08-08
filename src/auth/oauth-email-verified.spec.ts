import { ForbiddenException } from '@nestjs/common';
import { AuthService } from './auth.service';

describe('findOrCreateOAuthUser email verification (#149)', () => {
  function makeService() {
    const prisma = {
      user: {
        findFirst: jest.fn().mockResolvedValue(null),
        findUnique: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue({ id: 'u1' }),
      },
      role: {
        findUnique: jest.fn().mockResolvedValue({ id: 'role-user', name: 'user' }),
      },
    };
    const config = {
      get: jest.fn().mockReturnValue({
        registration: { enabled: true, defaultRole: 'user' },
      }),
      isFeatureEnabled: jest.fn().mockReturnValue(true),
    };
    const service = new AuthService(
      prisma as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      config as any,
      {} as any,
    );
    return { service, prisma };
  }

  it('rejects new OAuth users without a provider-verified email', async () => {
    const { service, prisma } = makeService();
    await expect(
      service.findOrCreateOAuthUser({
        provider: 'google',
        providerId: 'g1',
        email: 'a@x.com',
        emailVerified: false,
        name: 'A',
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(prisma.user.create).not.toHaveBeenCalled();
  });

  it('creates when email is provider-verified', async () => {
    const { service, prisma } = makeService();
    await service.findOrCreateOAuthUser({
      provider: 'google',
      providerId: 'g1',
      email: 'a@x.com',
      emailVerified: true,
      name: 'A',
    });
    expect(prisma.user.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          email: 'a@x.com',
          emailVerifiedAt: expect.any(Date),
        }),
      }),
    );
  });

  it('still returns existing linked users without re-checking emailVerified', async () => {
    const { service, prisma } = makeService();
    prisma.user.findFirst.mockResolvedValue({ id: 'existing' });
    const user = await service.findOrCreateOAuthUser({
      provider: 'github',
      providerId: 'gh1',
      email: 'a@x.com',
      emailVerified: false,
      name: 'A',
    });
    expect(user).toEqual({ id: 'existing' });
    expect(prisma.user.create).not.toHaveBeenCalled();
  });
});
