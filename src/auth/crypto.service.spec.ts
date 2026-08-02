import { CryptoService } from './crypto.service';

describe('CryptoService (#18/#23)', () => {
  const PREV = process.env.AUTHKIT_SECRET_KEY;

  beforeAll(() => {
    process.env.AUTHKIT_SECRET_KEY = 'a'.repeat(64);
  });

  afterAll(() => {
    if (PREV === undefined) delete process.env.AUTHKIT_SECRET_KEY;
    else process.env.AUTHKIT_SECRET_KEY = PREV;
  });

  it('round-trips plaintext through AES-256-GCM', () => {
    const svc = new CryptoService();
    const secret = 'JBSWY3DPEHPK3PXP';
    const enc = svc.encrypt(secret);
    expect(enc).not.toEqual(secret);
    expect(enc.split('.')).toHaveLength(3);
    expect(svc.decrypt(enc)).toEqual(secret);
  });

  it('rejects malformed payloads', () => {
    const svc = new CryptoService();
    expect(() => svc.decrypt('not-encrypted')).toThrow(/Malformed/);
  });
});
