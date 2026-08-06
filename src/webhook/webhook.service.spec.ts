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
