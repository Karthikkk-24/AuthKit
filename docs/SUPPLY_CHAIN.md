## Supply-chain triage (#121)

Snapshot after deleting stale `admin/package-lock.json` (pnpm is the source of
truth), bumping Nest/axios/nodemailer, and extending `pnpm.overrides`.

### Process
1. `pnpm audit --prod` (CI hard-fails on **critical**)
2. `snyk test --all-projects` when authenticated (`snyk auth` or `SNYK_TOKEN`)
3. `snyk code test` once Snyk Code is enabled for the org (`SNYK-CODE-0005` until then)

### Overrides (`package.json` → `pnpm.overrides`)
| Package | Floor | Reason |
|---|---|---|
| `qs` | `>=6.14.2` | DoS via arrayLimit |
| `body-parser` | `>=2.3.0` | invalid limit disables size cap |
| `nanoid` | `>=5.1.16 <6` | infinite loop (Next/postcss path) |
| `diff` | `>=4.0.4` | DoS in parsePatch |
| `postcss` | `>=8.5.18` | prior Next transitive advisories |
| `brace-expansion` | `>=2.1.3` | ReDoS floor |
| `@isaacs/brace-expansion` | `>=5.0.1` | critical DoS |
| `path-to-regexp` | `>=8.4.0` | ReDoS |
| `multer` | `>=2.2.0` | Nest platform-express path |
| `file-type` | `>=21.3.2` | resource exhaustion |
| `js-yaml` | `>=4.2.0` | via `@nestjs/swagger` |

### Direct bumps (#121)
- Root: `@nestjs/common|core|platform-express|testing` → `11.1.28`
- Root / admin: `axios` → `1.19.0`
- Root: `nodemailer` → `9.0.5`
- Removed `admin/package-lock.json` (was pinning Next **16.2.6** while `package.json` declared **16.3.0**)

### Remaining (accepted / blocked)
- `sharp` advisories under Next (no safe override without Next-compatible sharp)
- `@nestjs/terminus` optional `typeorm` peer advisories (Prisma-only; TypeORM unused)
- `@babel/core` via Next styled-jsx (await upstream)
- **Snyk Code**: still blocked for org `kkshettigar24` (`SNYK-CODE-0005`) — enable in Snyk UI

Re-run audits after each Nest/Next major upgrade; prefer direct bumps over long-lived overrides.

### Rescan #5 verification (#140)

Re-checked after #121 / PR #204:

- `admin/package-lock.json` absent; pnpm resolves `next@16.3.0`
- `pnpm audit --prod`: no criticals; remaining highs are accepted (typeorm peer via terminus, Next/babel/sharp paths) — see above
- Snyk Code still blocked (`SNYK-CODE-0005`) until enabled in org UI
