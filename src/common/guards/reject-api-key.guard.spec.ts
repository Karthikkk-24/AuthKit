import { ForbiddenException } from '@nestjs/common';
import { RejectApiKeyGuard } from './reject-api-key.guard';

describe('RejectApiKeyGuard (#147)', () => {
  const guard = new RejectApiKeyGuard();

  const ctx = (user: any) =>
    ({
      switchToHttp: () => ({
        getRequest: () => ({ user }),
      }),
    }) as any;

  it('allows interactive JWT sessions', () => {
    expect(guard.canActivate(ctx({ id: 'u1', isApiKeyAuth: false }))).toBe(
      true,
    );
  });

  it('allows missing isApiKeyAuth (JWT default)', () => {
    expect(guard.canActivate(ctx({ id: 'u1' }))).toBe(true);
  });

  it('rejects API key principals', () => {
    expect(() =>
      guard.canActivate(ctx({ id: 'u1', isApiKeyAuth: true, apiKeyId: 'k1' })),
    ).toThrow(ForbiddenException);
  });
});
