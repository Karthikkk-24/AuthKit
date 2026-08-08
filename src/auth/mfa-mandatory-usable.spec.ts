import { AuthService } from './auth.service';

describe('applyMfaGate mandatory vs usable MFA (#144)', () => {
  function makeService(mfaConfig: any, featureMfa = true) {
    const config = {
      get: jest.fn((key: string) => {
        if (key === 'mfa') return mfaConfig;
        return {};
      }),
      isFeatureEnabled: jest.fn((f: string) =>
        f === 'mfa' ? featureMfa : true,
      ),
    };
    const jwt = {
      signAsync: jest.fn().mockResolvedValue('setup-token'),
    };
    return new AuthService(
      {} as any,
      jwt as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      config as any,
      {} as any,
    );
  }

  it('does not block when MFA is required but feature/methods are disabled', async () => {
    const service = makeService(
      { enabled: false, required: true, methods: ['totp'], requiredForRoles: ['admin'] },
      false,
    );
    const user = {
      id: 'u1',
      email: 'a@x.com',
      name: 'A',
      roleId: 'r1',
      isMfaEnabled: false,
      role: { name: 'admin' },
    };
    const result = await (service as any).applyMfaGate(user, undefined, {
      challengeStyle: 'password',
    });
    expect(result).toEqual({ kind: 'ok' });
  });

  it('blocks with setup when MFA is required and enrollment is possible', async () => {
    const service = makeService({
      enabled: true,
      required: true,
      methods: ['totp'],
      requiredForRoles: ['admin'],
    });
    const user = {
      id: 'u1',
      email: 'a@x.com',
      name: 'A',
      roleId: 'r1',
      isMfaEnabled: false,
      role: { name: 'admin' },
    };
    const result = await (service as any).applyMfaGate(user, undefined, {
      challengeStyle: 'password',
    });
    expect(result.kind).toBe('blocked');
    expect(result.response.mfaSetupRequired).toBe(true);
  });
});
