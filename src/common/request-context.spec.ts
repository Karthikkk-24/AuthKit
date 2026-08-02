import { requestContext, getRequestId } from './request-context';

describe('requestContext (#54)', () => {
  it('exposes requestId within AsyncLocalStorage scope', () => {
    expect(getRequestId()).toBeUndefined();
    requestContext.run({ requestId: 'req-123' }, () => {
      expect(getRequestId()).toBe('req-123');
    });
    expect(getRequestId()).toBeUndefined();
  });
});
