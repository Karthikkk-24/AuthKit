import { AuthService } from './auth.service';

describe('validateLocalUser lockout disclosure (#115)', () => {
  it('returns null for locked accounts (no lockReason/expiry in response)', async () => {
    const prisma = {
      user: {
        findUnique: jest.fn().mockResolvedValue({
          id: 'u1',
          email: 'a@x.com',
          deletedAt: null,
          passwordHash: 'hash',
          isLocked: true,
          lockedAt: new Date(),
          lockReason: 'Too many failed attempts',
          role: { permissions: [] },
        }),
      },
    };
    const audit = { log: jest.fn().mockResolvedValue(undefined) };
    const config = {
      get: jest.fn((key: string) => {
        if (key === 'security') {
          return { accountLockout: { lockDurationMinutes: 30 } };
        }
        if (key === 'audit') {
          return { logFailedLogins: true };
        }
        return {};
      }),
    };
    const service = new AuthService(
      prisma as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      audit as any,
      config as any,
      {} as any,
    );

    const result = await service.validateLocalUser('a@x.com', 'pw', {});
    expect(result).toBeNull();
    expect(audit.log).toHaveBeenCalledWith(
      expect.objectContaining({
        metadata: expect.objectContaining({ reason: 'account_locked' }),
      }),
    );
  });
});
