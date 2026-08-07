import { BadRequestException } from '@nestjs/common';
import { AuthService } from './auth.service';

describe('setupTotp step-up (#125)', () => {
  function makeService(opts: {
    user?: any;
    existingTotp?: any;
    verifyOk?: boolean;
  }) {
    const prisma = {
      user: {
        findUnique: jest.fn().mockResolvedValue(
          opts.user ?? {
            id: 'u1',
            email: 'a@b.com',
            isMfaEnabled: true,
          },
        ),
      },
      mfaCredential: {
        findUnique: jest.fn().mockResolvedValue(
          opts.existingTotp === undefined
            ? { isEnabled: true }
            : opts.existingTotp,
        ),
        upsert: jest.fn().mockResolvedValue({}),
      },
    };
    const config = {
      get: jest.fn((key: string) => {
        if (key === 'mfa') {
          return { enabled: true, methods: ['totp', 'email'], totpIssuer: 'AuthKit' };
        }
        if (key === 'redis') return { prefix: 'authkit:' };
        return {};
      }),
      isFeatureEnabled: jest.fn().mockReturnValue(true),
      isStrategyEnabled: jest.fn().mockReturnValue(true),
    };
    const cryptoSvc = {
      encrypt: jest.fn().mockReturnValue('iv.tag.data'),
    };
    const service = new AuthService(
      prisma as any,
      {} as any,
      {} as any,
      cryptoSvc as any,
      { redis: null } as any,
      {} as any,
      {} as any,
      config as any,
      {} as any,
    );

    jest.spyOn(service as any, 'verifyMfaWithFallback').mockImplementation(async () => {
      if (opts.verifyOk === false) {
        throw new BadRequestException('Invalid MFA code');
      }
      return true;
    });

    return { service, prisma, cryptoSvc };
  }

  it('rejects re-enrollment without currentMfaCode when MFA is enabled', async () => {
    const { service, prisma } = makeService({});
    await expect(service.setupTotp('u1')).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(prisma.mfaCredential.upsert).not.toHaveBeenCalled();
  });

  it('rotates secret after valid currentMfaCode', async () => {
    const { service, prisma } = makeService({ verifyOk: true });
    // qrcode is required dynamically — mock to avoid real canvas work if needed
    jest.isolateModules(() => {
      jest.doMock('qrcode', () => ({
        toDataURL: jest.fn().mockResolvedValue('data:image/png;base64,xx'),
      }));
    });
    // Ensure speakeasy path works; QRCode require inside method
    const qrcode = require('qrcode');
    if (!qrcode.toDataURL.mock) {
      jest.spyOn(qrcode, 'toDataURL').mockResolvedValue('data:image/png;base64,xx');
    }

    const result = await service.setupTotp('u1', '123456');
    expect(result.secret).toEqual(expect.any(String));
    expect(prisma.mfaCredential.upsert).toHaveBeenCalled();
    expect((service as any).verifyMfaWithFallback).toHaveBeenCalledWith(
      'u1',
      '123456',
    );
  });

  it('allows first-time enrollment without currentMfaCode', async () => {
    const { service, prisma } = makeService({
      user: { id: 'u1', email: 'a@b.com', isMfaEnabled: false },
      existingTotp: null,
    });
    const qrcode = require('qrcode');
    jest.spyOn(qrcode, 'toDataURL').mockResolvedValue('data:image/png;base64,xx');

    await service.setupTotp('u1');
    expect(prisma.mfaCredential.upsert).toHaveBeenCalled();
    expect((service as any).verifyMfaWithFallback).not.toHaveBeenCalled();
  });
});
