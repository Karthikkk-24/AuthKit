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
