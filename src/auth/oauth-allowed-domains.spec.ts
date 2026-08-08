import { ForbiddenException } from '@nestjs/common';
import { AuthService } from './auth.service';

describe('findOrCreateOAuthUser allowedDomains (#155)', () => {
  function makeService(allowedDomains: string[] | undefined) {
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
        registration: {
          enabled: true,
          defaultRole: 'user',
          allowedDomains,
        },
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

  it('blocks OAuth provisioning outside the allowlist', async () => {
    const { service, prisma } = makeService(['company.com']);
    await expect(
      service.findOrCreateOAuthUser({
        provider: 'google',
        providerId: 'g1',
        email: 'attacker@gmail.com',
        emailVerified: true,
        name: 'A',
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(prisma.user.create).not.toHaveBeenCalled();
  });

  it('allows OAuth provisioning on an allowlisted domain', async () => {
    const { service, prisma } = makeService(['company.com']);
    await service.findOrCreateOAuthUser({
      provider: 'google',
      providerId: 'g1',
      email: 'alice@company.com',
      emailVerified: true,
      name: 'Alice',
    });
    expect(prisma.user.create).toHaveBeenCalled();
  });

  it('does not re-check domains for already-linked OAuth users', async () => {
    const { service, prisma } = makeService(['company.com']);
    prisma.user.findFirst.mockResolvedValue({ id: 'existing' });
    const user = await service.findOrCreateOAuthUser({
      provider: 'github',
      providerId: 'gh1',
      email: 'outsider@gmail.com',
      emailVerified: true,
      name: 'A',
    });
    expect(user).toEqual({ id: 'existing' });
  });
});
