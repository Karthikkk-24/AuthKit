/** Leading chars that spreadsheet apps treat as formulas (#156). */
const FORMULA_PREFIX = /^[=+\-@\t\r]/;

/**
 * RFC 4180 CSV field escaping with formula-injection neutralization.
 * Prefixes a leading apostrophe when the cell would otherwise be executable.
 */
export function escapeCsvField(value: unknown): string {
  if (value === null || value === undefined) return '""';
  let str =
    typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (FORMULA_PREFIX.test(str)) {
    str = `'${str}`;
  }
  return `"${str.replace(/"/g, '""')}"`;
}
