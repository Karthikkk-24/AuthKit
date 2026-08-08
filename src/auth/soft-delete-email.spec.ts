import { AuthService } from './auth.service';

describe('register frees soft-deleted email (#114)', () => {
  function makeService(existing: any) {
    const prisma = {
      user: {
        findUnique: jest
          .fn()
          .mockResolvedValueOnce(existing) // email check
          .mockResolvedValue(null),
        update: jest.fn().mockResolvedValue({}),
        create: jest.fn().mockResolvedValue({
          id: 'new',
          email: 'a@x.com',
          name: 'A',
          role: { name: 'user' },
        }),
      },
      role: {
        findUnique: jest.fn().mockResolvedValue({ id: 'r1', name: 'user' }),
      },
    };
    const passwords = {
      validateStrength: jest.fn().mockReturnValue({ valid: true, errors: [] }),
      hash: jest.fn().mockResolvedValue('hash'),
      isPwned: jest.fn(),
    };
    const email = {
      sendAccountAlreadyRegistered: jest.fn().mockResolvedValue(undefined),
    };
    const config = {
      get: jest.fn((key: string) => {
        if (key === 'auth') {
          return { registration: { enabled: true, defaultRole: 'user' } };
        }
        if (key === 'email') return { enabled: false };
        return {};
      }),
      isFeatureEnabled: jest.fn((f: string) => f === 'registration'),
    };
    const audit = { log: jest.fn().mockResolvedValue(undefined) };
    const webhooks = { dispatch: jest.fn().mockResolvedValue(undefined) };
    const service = new AuthService(
      prisma as any,
      {} as any,
      passwords as any,
      {} as any,
      {} as any,
      email as any,
      audit as any,
      config as any,
      webhooks as any,
    );
    return { service, prisma, email, audit };
  }

  it('renames soft-deleted email then creates a new user', async () => {
    const { service, prisma } = makeService({
      id: 'old',
      email: 'a@x.com',
      deletedAt: new Date(),
    });
    await service.register(
      { email: 'a@x.com', password: 'Password1!', name: 'A' } as any,
      {},
    );
    expect(prisma.user.update).toHaveBeenCalledWith({
      where: { id: 'old' },
      data: {
        email: 'deleted+old@deleted.invalid',
        googleId: null,
        githubId: null,
      },
    });
    expect(prisma.user.create).toHaveBeenCalled();
  });

  it('returns generic success for active emails without creating (#116)', async () => {
    const { service, prisma, email, audit } = makeService({
      id: 'live',
      email: 'a@x.com',
      name: 'Live',
      deletedAt: null,
    });
    const result = await service.register(
      { email: 'a@x.com', password: 'Password1!', name: 'A' } as any,
      {},
    );
    expect(result.message).toMatch(/Registration successful/);
    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(email.sendAccountAlreadyRegistered).toHaveBeenCalled();
    expect(audit.log).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        metadata: { reason: 'email_exists' },
      }),
    );
  });
});
