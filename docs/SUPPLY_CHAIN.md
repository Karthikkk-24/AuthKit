## Supply-chain triage (#82)

Snapshot after P4 bumps (Next 16.3.0 + pnpm overrides for `qs`, `body-parser`, `nanoid`, `diff`, `postcss`).

### Process
1. `pnpm audit --prod` (CI hard-fails on **critical**)
2. `snyk test --all-projects` when authenticated (`snyk auth` or `SNYK_TOKEN`)
3. `snyk code test` once Snyk Code is enabled for the org

### Overrides (`package.json` → `pnpm.overrides`)
| Package | Floor | Reason |
|---|---|---|
| `qs` | `>=6.14.2` | DoS via arrayLimit |
| `body-parser` | `>=2.3.0` | invalid limit disables size cap |
| `nanoid` | `>=5.1.16 <6` | infinite loop (Next/postcss path) |
| `diff` | `>=4.0.4` | DoS in parsePatch |
| `postcss` | `>=8.5.18` | prior Next transitive advisories |

### Direct bumps
- `admin`: `next` / `eslint-config-next` → `16.3.0`

### Remaining (accepted / blocked)
- `sharp` advisories under Next (no safe override without Next-compatible sharp)
- `@nestjs/terminus` optional `typeorm` peer advisories (Prisma-only; TypeORM unused)
- `@babel/core` via Next styled-jsx (await upstream)

Re-run audits after each Nest/Next major upgrade; prefer direct bumps over long-lived overrides.
