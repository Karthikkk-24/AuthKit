import { UserService } from './user.service';

describe('UserService.updateProfile (#104)', () => {
  const prisma = {
    user: {
      update: jest.fn(),
    },
  };

  const service = new UserService(
    prisma as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
  );

  beforeEach(() => {
    jest.clearAllMocks();
    prisma.user.update.mockResolvedValue({
      id: 'u1',
      email: 'a@b.com',
      name: 'Ada',
      avatarUrl: null,
      roleId: 'r1',
      passwordHash: 'secret',
      googleId: null,
      githubId: null,
      role: { name: 'user' },
    });
  });

  it('passes only name and avatarUrl into Prisma', async () => {
    await service.updateProfile('u1', {
      name: 'Ada Lovelace',
      avatarUrl: 'https://cdn.example.com/a.png',
      // @ts-expect-error — privileged fields must be ignored even if smuggled
      roleId: 'superadmin-role',
      isMfaEnabled: false,
      passwordHash: 'pwned',
      emailVerifiedAt: new Date().toISOString(),
    } as any);

    expect(prisma.user.update).toHaveBeenCalledWith({
      where: { id: 'u1' },
      data: {
        name: 'Ada Lovelace',
        avatarUrl: 'https://cdn.example.com/a.png',
      },
      include: { role: true },
    });
  });

  it('omits undefined fields so partial patches do not clear values', async () => {
    await service.updateProfile('u1', { name: 'Only Name' });

    expect(prisma.user.update).toHaveBeenCalledWith({
      where: { id: 'u1' },
      data: { name: 'Only Name' },
      include: { role: true },
    });
  });

  it('strips passwordHash from the returned profile', async () => {
    const result = await service.updateProfile('u1', { name: 'Ada' });
    expect(result).not.toHaveProperty('passwordHash');
    expect(result.name).toBe('Ada');
  });
});
