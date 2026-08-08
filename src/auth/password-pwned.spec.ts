import { ServiceUnavailableException } from '@nestjs/common';
import { PasswordService } from './password.service';

describe('PasswordService.isPwned fail-closed (#159)', () => {
  const originalFetch = global.fetch;
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    global.fetch = originalFetch;
    process.env.NODE_ENV = originalEnv;
    jest.restoreAllMocks();
  });

  function makeService(failClosed?: boolean) {
    const config = {
      get: jest.fn((key: string) => {
        if (key === 'features') {
          return {
            pwnedPasswordCheck: true,
            ...(typeof failClosed === 'boolean'
              ? { pwnedPasswordFailClosed: failClosed }
              : {}),
          };
        }
        if (key === 'auth') {
          return { password: { minLength: 8, maxLength: 128 } };
        }
        return undefined;
      }),
    };
    return new PasswordService(config as any);
  }

  it('throws ServiceUnavailable when HIBP returns non-OK and fail-closed', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 503,
      text: async () => '',
    }) as any;

    const service = makeService(true);
    await expect(service.isPwned('SomePassw0rd!')).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('throws when fetch rejects and fail-closed is enabled', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('network down')) as any;
    const service = makeService(true);
    await expect(service.isPwned('SomePassw0rd!')).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('returns false (fail-open) when fail-closed is disabled', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => '',
    }) as any;

    const service = makeService(false);
    await expect(service.isPwned('SomePassw0rd!')).resolves.toBe(false);
  });

  it('defaults to fail-closed in production when config unset', async () => {
    process.env.NODE_ENV = 'production';
    global.fetch = jest.fn().mockRejectedValue(new Error('timeout')) as any;
    const service = makeService(undefined);
    await expect(service.isPwned('SomePassw0rd!')).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });
});
