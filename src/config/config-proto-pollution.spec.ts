describe('config merge prototype pollution (#151)', () => {
  const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
  const SECRET_KEY_RE =
    /^(password|passwd|secret|apiKey|api_key|token|clientSecret|privateKey)$/i;

  function deepMergePreserveSecrets(target: any, source: any): any {
    if (source === null || source === undefined) return target;
    if (typeof source !== 'object' || Array.isArray(source)) return source;
    const base =
      target && typeof target === 'object' && !Array.isArray(target)
        ? { ...target }
        : Object.create(null);
    for (const key of Object.keys(source)) {
      if (DANGEROUS_KEYS.has(key)) continue;
      if (SECRET_KEY_RE.test(key)) continue;
      const next = source[key];
      if (next && typeof next === 'object' && !Array.isArray(next)) {
        base[key] = deepMergePreserveSecrets(base[key], next);
      } else {
        base[key] = next;
      }
    }
    return base;
  }

  it('does not pollute Object.prototype via __proto__', () => {
    const polluted = JSON.parse('{"__proto__":{"polluted":true},"features":{"mfa":true}}');
    const merged = deepMergePreserveSecrets({ features: { registration: false } }, polluted);
    expect(({} as any).polluted).toBeUndefined();
    expect(merged.features.mfa).toBe(true);
    expect(merged.features.registration).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(merged, '__proto__')).toBe(false);
  });
});
