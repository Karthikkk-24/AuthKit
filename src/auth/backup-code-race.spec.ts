import { UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

describe('claimBackupCode race (#117)', () => {
  it('rejects when atomic update claims zero rows', async () => {
    const prisma = {
      mfaCredential: {
        findUnique: jest.fn().mockResolvedValue({
          isEnabled: true,
          secret: 'x',
          backupCodes: ['abc'],
        }),
      },
      $executeRaw: jest.fn().mockResolvedValue(0),
    };
    const cryptoService = {
      hmacSha256: jest.fn().mockReturnValue('hmac-hash'),
      decrypt: jest.fn(),
    };
    const service = new AuthService(
      prisma as any,
      {} as any,
      {} as any,
      cryptoService as any,
      {} as any,
      {} as any,
      {} as any,
      { get: jest.fn(), isFeatureEnabled: jest.fn() } as any,
      {} as any,
    );

    await expect(service.verifyMfa('u1', 'code', true)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect(prisma.$executeRaw).toHaveBeenCalled();
  });

  it('accepts when atomic update claims the code', async () => {
    const prisma = {
      mfaCredential: {
        findUnique: jest.fn().mockResolvedValue({
          isEnabled: true,
          secret: 'x',
          backupCodes: ['hmac-hash'],
        }),
      },
      $executeRaw: jest.fn().mockResolvedValueOnce(1),
    };
    const cryptoService = {
      hmacSha256: jest.fn().mockReturnValue('hmac-hash'),
    };
    const service = new AuthService(
      prisma as any,
      {} as any,
      {} as any,
      cryptoService as any,
      {} as any,
      {} as any,
      {} as any,
      { get: jest.fn(), isFeatureEnabled: jest.fn() } as any,
      {} as any,
    );

    await expect(service.verifyMfa('u1', 'code', true)).resolves.toBe(true);
  });
});
