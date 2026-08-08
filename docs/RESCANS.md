## Security rescan history

Index of post-P4 full rescans. Child findings live as separate issues; this file
records tooling status so meta tickets can close without re-filing the backlog.

### Rescan #3 (#123)

- **Commit / context:** after merge of #99–#103
- **Snyk OSS:** authenticated; highs across root + stale admin lockfile (addressed in #121 / PR #204)
- **Snyk Code:** blocked `SNYK-CODE-0005` for org `kkshettigar24` (enable in Snyk UI)
- **pnpm audit --prod:** findings triaged via overrides + direct bumps (`docs/SUPPLY_CHAIN.md`)
- **Manual + AI OWASP/flow:** net-new children filed in that wave (not re-opened here)

Closed findings from earlier waves (#60–#98) remain fixed and were not re-opened.

### Rescan #4 (#131)

- **Commit / context:** second full pass after filing #104–#123 (`main` @ `f26ca26`)
- **Snyk OSS:** highs still driven by stale `admin/package-lock.json` (fixed in #121 / PR #204)
- **Snyk Code:** still `SNYK-CODE-0005`
- **Net-new children:** filed separately in that wave; prior #104–#123 not re-filed

### Rescan #5 (#141)

- **Commit / context:** after PR #132 (#124 MFA path bypass fix), `main` @ `b0e5834`
- **Snyk OSS / pnpm:** stale admin lockfile + highs — remediated in #121 / PR #204; verified in #140
- **Snyk Code:** still `SNYK-CODE-0005`
- **Net-new children:** #133–#140 (actionable work tracked separately)

### Rescan #6 (#154)

- **Commit / context:** full rescan of `main` @ `b0e5834` (after #124/#132)
- **Tooling:** Snyk OSS highs + stale admin lockfile (fixed #121); Snyk Code blocked; pnpm audit triaged
- **Net-new children:** email OTP MFA, API key session equivalence, backup-code entropy, OAuth email trust, GitHub missing-email, config `__proto__`, non-constant-time OTP (#152), supply-chain (#153)

### Rescan #7 (#161)

- **Commit / context:** `main` after prior P3 wave; prior open backlog #104–#154 re-verified (not re-filed)
- **Tooling:** Snyk OSS / pnpm — see #160 + `docs/SUPPLY_CHAIN.md`; Snyk Code still `SNYK-CODE-0005`
- **Net-new children this pass:** #155–#160 (P2–P4); actionable P3s #156–#159 fixed separately
