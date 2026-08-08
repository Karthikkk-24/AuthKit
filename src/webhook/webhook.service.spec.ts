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

describe('WebhookService DNS pin agent (#111)', () => {
  function service() {
    return new WebhookService({} as any, {
      get: jest.fn(),
      isFeatureEnabled: jest.fn(),
    } as any);
  }

  it('pinned lookup returns the pre-validated address, not a rebind', () => {
    const s = service() as any;
    const agent = s.createPinnedAgent('https:', '203.0.113.10', 4);
    const lookup = (agent as any).options.lookup as Function;

    let resolved: any;
    lookup('evil.example', {}, (err: Error | null, addr: string, family: number) => {
      resolved = { err, addr, family };
    });

    expect(resolved.err).toBeNull();
    expect(resolved.addr).toBe('203.0.113.10');
    expect(resolved.family).toBe(4);
  });

  it('pinned lookup refuses if pinned address is private', () => {
    const s = service() as any;
    const agent = s.createPinnedAgent('http:', '10.0.0.1', 4);
    const lookup = (agent as any).options.lookup as Function;

    let resolved: any;
    lookup('evil.example', {}, (err: Error | null) => {
      resolved = { err };
    });

    expect(resolved.err).toBeInstanceOf(Error);
    expect(String(resolved.err.message)).toMatch(/private/i);
  });

  it('resolveSafeWebhookTarget pins literal public IPs', async () => {
    const s = service() as any;
    const prev = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';
    try {
      const target = await s.resolveSafeWebhookTarget('http://203.0.113.50/hook');
      expect(target.address).toBe('203.0.113.50');
      expect(target.family).toBe(4);
    } finally {
      process.env.NODE_ENV = prev;
    }
  });

  it('resolveSafeWebhookTarget rejects literal private IPs', async () => {
    const s = service() as any;
    await expect(
      s.resolveSafeWebhookTarget('https://10.0.0.5/hook'),
    ).rejects.toThrow(/private/i);
  });
});
