import { SignedCookieOAuthStateStore } from './oauth-state.store';

describe('SignedCookieOAuthStateStore (#127)', () => {
  const secret = 'a'.repeat(32);

  function mockReq() {
    const cookies: string[] = [];
    const res = {
      append: jest.fn((name: string, value: string) => {
        if (name === 'Set-Cookie') cookies.push(value);
      }),
      getHeader: jest.fn(),
      setHeader: jest.fn(),
    };
    const req: any = {
      res,
      headers: {},
      _cookies: cookies,
    };
    return req;
  }

  it('round-trips state via signed cookie', (done) => {
    const store = new SignedCookieOAuthStateStore(secret);
    const req = mockReq();

    store.store(req, (err: Error | null, state: string) => {
      expect(err).toBeNull();
      expect(state).toMatch(/^[a-f0-9]+$/);
      expect(req.res.append).toHaveBeenCalled();

      const setCookie: string = req.res.append.mock.calls[0][1];
      const match = setCookie.match(/authkit_oauth_state=([^;]+)/);
      expect(match).toBeTruthy();
      req.headers.cookie = `authkit_oauth_state=${match![1]}`;

      store.verify(req, state, (verr, ok, verified) => {
        expect(verr).toBeNull();
        expect(ok).toBe(true);
        expect(verified).toBe(state);
        done();
      });
    });
  });

  it('rejects mismatched state (CSRF)', (done) => {
    const store = new SignedCookieOAuthStateStore(secret);
    const req = mockReq();

    store.store(req, (_err: Error | null, state: string) => {
      const setCookie: string = req.res.append.mock.calls[0][1];
      const match = setCookie.match(/authkit_oauth_state=([^;]+)/);
      req.headers.cookie = `authkit_oauth_state=${match![1]}`;

      store.verify(req, 'attacker-forged-state', (verr, ok) => {
        expect(verr).toBeNull();
        expect(ok).toBe(false);
        expect(state).toBeTruthy();
        done();
      });
    });
  });

  it('rejects missing cookie', (done) => {
    const store = new SignedCookieOAuthStateStore(secret);
    const req = mockReq();
    store.verify(req, 'anything', (verr, ok) => {
      expect(verr).toBeNull();
      expect(ok).toBe(false);
      done();
    });
  });
});
