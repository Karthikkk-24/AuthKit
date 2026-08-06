import { WebhookService } from './webhook.service';

describe('WebhookService.dispatch tenant isolation (#61)', () => {
  function makeService() {
    const prisma = {
      webhook: {
        findMany: jest.fn().mockResolvedValue([]),
      },
      webhookDelivery: {
        create: jest.fn(),
      },
    };
    const config = {
      get: jest.fn().mockReturnValue({ enabled: true }),
      isFeatureEnabled: jest.fn().mockReturnValue(false),
    };
    const service = new WebhookService(prisma as any, config as any);
    return { service, prisma };
  }

  it('filters endpoints by payload.userId (event subject)', async () => {
    const { service, prisma } = makeService();

    await service.dispatch('user.login', { userId: 'user-a', email: 'a@x.com' });

    expect(prisma.webhook.findMany).toHaveBeenCalledWith({
      where: {
        isActive: true,
        events: { has: 'user.login' },
        userId: 'user-a',
      },
    });
  });

  it('skips dispatch when payload has no userId', async () => {
    const { service, prisma } = makeService();

    await service.dispatch('user.login', { email: 'orphan@x.com' } as any);

    expect(prisma.webhook.findMany).not.toHaveBeenCalled();
  });

  it('does not query endpoints when webhooks are disabled', async () => {
    const { service, prisma } = makeService();
    (service as any).config.get.mockReturnValue({ enabled: false });

    await service.dispatch('user.login', { userId: 'user-a' });

    expect(prisma.webhook.findMany).not.toHaveBeenCalled();
  });
});

describe('WebhookService.isPrivateIp IPv6 coverage (#81)', () => {
  function service() {
    return new WebhookService({} as any, {
      get: jest.fn(),
      isFeatureEnabled: jest.fn(),
    } as any);
  }

  it('blocks IPv4-mapped private addresses', () => {
    const s = service() as any;
    expect(s.isPrivateIp('::ffff:10.0.0.1')).toBe(true);
    expect(s.isPrivateIp('::ffff:127.0.0.1')).toBe(true);
    expect(s.isPrivateIp('::ffff:192.168.1.1')).toBe(true);
    expect(s.isPrivateIp('::ffff:8.8.8.8')).toBe(false);
  });

  it('blocks ULA and link-local IPv6', () => {
    const s = service() as any;
    expect(s.isPrivateIp('fc00::1')).toBe(true);
    expect(s.isPrivateIp('fd12:3456:789a::1')).toBe(true);
    expect(s.isPrivateIp('fe80::1')).toBe(true);
    expect(s.isPrivateIp('::1')).toBe(true);
  });

  it('allows global unicast IPv6', () => {
    const s = service() as any;
    expect(s.isPrivateIp('2001:4860:4860::8888')).toBe(false);
  });
});
