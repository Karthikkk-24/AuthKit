import { AuthService } from './auth.service';

describe('AuthService.isEmailVerificationEnforced (#112)', () => {
  function makeService(opts: {
    requireEmailVerification?: boolean;
    featureEnabled?: boolean;
    emailEnabled?: boolean;
  }) {
    const config = {
      get: jest.fn((key: string) => {
        if (key === 'auth') {
          return {
            registration: {
              requireEmailVerification: opts.requireEmailVerification ?? true,
            },
          };
        }
        if (key === 'email') {
          return { enabled: opts.emailEnabled ?? false };
        }
        return {};
      }),
      isFeatureEnabled: jest.fn().mockReturnValue(opts.featureEnabled ?? true),
    };
    return new AuthService(
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      config as any,
      {} as any,
    );
  }

  it('is false when mailer is disabled even if verification flags are on', () => {
    const service = makeService({
      requireEmailVerification: true,
      featureEnabled: true,
      emailEnabled: false,
    });
    expect((service as any).isEmailVerificationEnforced()).toBe(false);
  });

  it('is true when requirement, feature, and mailer are all enabled', () => {
    const service = makeService({
      requireEmailVerification: true,
      featureEnabled: true,
      emailEnabled: true,
    });
    expect((service as any).isEmailVerificationEnforced()).toBe(true);
  });

  it('is false when feature flag is off', () => {
    const service = makeService({
      requireEmailVerification: true,
      featureEnabled: false,
      emailEnabled: true,
    });
    expect((service as any).isEmailVerificationEnforced()).toBe(false);
  });
});
