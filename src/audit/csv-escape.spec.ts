import { escapeCsvField } from './csv-escape';

describe('escapeCsvField (#156)', () => {
  it('neutralizes formula-like leading characters', () => {
    expect(escapeCsvField('=1+1')).toBe(`"'=1+1"`);
    expect(escapeCsvField('+cmd')).toBe(`"'+cmd"`);
    expect(escapeCsvField('-2+3')).toBe(`"'-2+3"`);
    expect(escapeCsvField('@SUM(A1)')).toBe(`"'@SUM(A1)"`);
    expect(escapeCsvField('\tHYPERLINK')).toBe(`"'\tHYPERLINK"`);
    expect(escapeCsvField('\r=1')).toBe(`"'\r=1"`);
  });

  it('still RFC-escapes quotes', () => {
    expect(escapeCsvField('say "hi"')).toBe(`"say ""hi"""`);
  });

  it('leaves safe values unchanged aside from quoting', () => {
    expect(escapeCsvField('login.success')).toBe(`"login.success"`);
    expect(escapeCsvField(null)).toBe('""');
  });

  it('does not treat JSON objects as formulas (leading brace is safe)', () => {
    expect(escapeCsvField({ note: '=cmd' })).toBe(`"{\"note\":\"=cmd\"}"`);
  });
});
