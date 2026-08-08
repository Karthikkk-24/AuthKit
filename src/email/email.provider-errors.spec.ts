import { EmailService } from './email.service';
import { requestContext } from '../common/request-context';

describe('EmailService provider HTTP errors (#157)', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  function makeService(provider: 'sendgrid' | 'resend') {
    const config = {
      get: jest.fn((key: string) => {
        if (key === 'email') {
          return {
            enabled: true,
            provider,
            from: 'noreply@example.com',
            fromName: 'AuthKit',
            sendgrid: { apiKey: 'sg-test' },
            resend: { apiKey: 're-test' },
            templates: { branding: { companyName: 'AuthKit' } },
          };
        }
        return undefined;
      }),
    };
    return new EmailService(config as any);
  }

  it('throws when SendGrid returns non-2xx', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => '{"errors":[{"message":"unauthorized"}]}',
    }) as any;

    const service = makeService('sendgrid');
    const errorSpy = jest.spyOn((service as any).logger, 'error').mockImplementation();

    await requestContext.run({ requestId: 'req-157' }, async () => {
      await expect(
        service.sendEmailVerification('a@b.com', 'Ada', 'tok'),
      ).rejects.toThrow(/sendgrid failed with HTTP 401/);
    });

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('requestId=req-157'),
    );
  });

  it('throws when Resend returns non-2xx', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => 'internal',
    }) as any;

    const service = makeService('resend');
    jest.spyOn((service as any).logger, 'error').mockImplementation();

    await expect(
      service.sendMagicLink('a@b.com', 'Ada', 'tok'),
    ).rejects.toThrow(/resend failed with HTTP 500/);
  });

  it('resolves when provider returns 2xx', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 202,
      text: async () => '',
    }) as any;

    const service = makeService('sendgrid');
    await expect(
      service.sendPasswordReset('a@b.com', 'Ada', 'tok'),
    ).resolves.toBeUndefined();
  });
});
