import { CryptoService } from './crypto.service';
import { AuthService } from './auth.service';

describe('MFA backup code hashing (#148)', () => {
  it('stores HMAC digests of 64-bit codes, not unsalted SHA-256 of 32-bit codes', async () => {
    const cryptoService = new CryptoService();
    const hmacSpy = jest.spyOn(cryptoService, 'hmacSha256');

    const prisma = {
      mfaCredential: {
        findUnique: jest.fn().mockResolvedValue({
          secret: 'PLAINTEXTSECRET',
          isEnabled: false,
        }),
        update: jest.fn().mockResolvedValue({}),
      },
      user: { update: jest.fn().mockResolvedValue({}) },
      $transaction: jest.fn(async (ops: any[]) => {
        for (const op of ops) await op;
      }),
    };
    const config = {
      get: jest.fn().mockReturnValue({
        enabled: true,
        methods: ['totp'],
        backupCodesCount: 2,
      }),
      isFeatureEnabled: jest.fn().mockReturnValue(true),
    };
    const webhooks = { dispatch: jest.fn().mockResolvedValue(undefined) };
    const service = new AuthService(
      prisma as any,
      {} as any,
      {} as any,
      cryptoService,
      {} as any,
      {} as any,
      {} as any,
      config as any,
      webhooks as any,
    );

    // Bypass TOTP verify
    jest.spyOn(require('speakeasy').totp, 'verify').mockReturnValue(true);

    const result = await service.enableTotp('u1', '123456');
    expect(result.backupCodes).toHaveLength(2);
    for (const c of result.backupCodes) {
      expect(c).toMatch(/^[a-f0-9]{16}$/); // 8 bytes hex
    }
    expect(hmacSpy).toHaveBeenCalled();
    expect(prisma.mfaCredential.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          backupCodes: expect.arrayContaining([expect.any(String)]),
        }),
      }),
    );
    const stored: string[] =
      prisma.mfaCredential.update.mock.calls[0][0].data.backupCodes;
    // Must not equal unsalted sha256 of the plaintext code
    const crypto = require('crypto');
    for (let i = 0; i < result.backupCodes.length; i++) {
      const unsalted = crypto
        .createHash('sha256')
        .update(result.backupCodes[i])
        .digest('hex');
      expect(stored[i]).not.toBe(unsalted);
      expect(stored[i]).toBe(cryptoService.hmacSha256(result.backupCodes[i]));
    }
  });
});
