import * as crypto from 'crypto';

describe('timingSafeEqualHex (#152)', () => {
  function timingSafeEqualHex(a: string, b: string): boolean {
    const left = Buffer.from(a);
    const right = Buffer.from(b);
    if (left.length !== right.length) return false;
    return crypto.timingSafeEqual(left, right);
  }

  it('returns true for identical digests', () => {
    const h = crypto.createHash('sha256').update('123456').digest('hex');
    expect(timingSafeEqualHex(h, h)).toBe(true);
  });

  it('returns false for different equal-length digests', () => {
    const a = crypto.createHash('sha256').update('123456').digest('hex');
    const b = crypto.createHash('sha256').update('654321').digest('hex');
    expect(timingSafeEqualHex(a, b)).toBe(false);
  });

  it('fails closed on length mismatch', () => {
    expect(timingSafeEqualHex('aa', 'aabb')).toBe(false);
  });
});
