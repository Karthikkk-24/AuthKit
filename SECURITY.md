# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Older tags / forks | ❌ — please upgrade |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

1. Email **security@authkit.dev** (or the repository owner’s security contact) with:
   - A short description of the issue and impact
   - Steps to reproduce / proof of concept
   - Affected commit / version if known
2. Allow **up to 90 days** for an initial fix or mitigation before public disclosure.
3. We will acknowledge receipt within **5 business days** and keep you updated.

We appreciate coordinated disclosure and will credit reporters who wish to be named.

## Threat model (summary)

AuthKit is an authentication & authorization platform. The highest-value assets are:

| Asset | Why it matters |
|---|---|
| User credentials & MFA secrets | Account takeover |
| JWT signing keys / session store | Forge sessions, bypass logout |
| Admin console session (BFF cookies) | Full tenant administration |
| API keys | Machine-to-machine access |
| Webhook signing secrets | Spoof outbound events |
| Audit logs | Tamper evidence / compliance |

### Trust boundaries

```
[Browser / Admin UI :3001] --BFF httpOnly cookies--> [Next.js BFF]
        |                                                |
        |          Bearer JWT / ApiKey                    v
[Client apps] ------------------------------------> [Nest API :3000]
                                                         |
                              +-----------+--------------+-----------+
                              v           v              v           v
                          PostgreSQL    Redis      SMTP/OAuth    Webhook URLs
```

- **Unauthenticated attackers** can hit public auth endpoints (register/login/OAuth/magic-link when enabled). Rate limits, lockout, and feature flags apply.
- **Authenticated users** are scoped by JWT `sub` + session checks; role-grained RBAC via `PermissionsGuard` and hierarchical `RolesGuard`.
- **Admins** use the BFF; only `admin` / `superadmin` roles receive console cookies.
- **Webhook consumers** must verify `X-AuthKit-Signature` (`sha256=` HMAC of raw body).
- **Infrastructure**: prefer binding Postgres/Redis to localhost in compose; never ship default seed passwords to production.

### Notable controls already in place

- Argon2id password hashing; optional HIBP pwned-password check
- JWT blacklist (Redis) + session revoke on lock/logout/password change
- Refresh-token rotation with family reuse detection
- SSRF protections on webhook URLs; owner-scoped webhook mutations
- Config edits whitelisted and deep-merged to preserve `${ENV}` secrets
- Audit logging for auth successes/failures when flags are enabled
- API keys accepted only via `X-API-Key` / `Authorization: ApiKey` (not query strings)
- API key scopes intersect RBAC permissions when scopes are non-empty

### Prometheus metrics (#68)

`GET /api/v1/metrics/prometheus` is **public in non-production** for local scrapers.

In **production** it returns 401 unless you explicitly opt in:

| Mode | How |
|---|---|
| Network ACL scraper (no JWT) | Set `PROMETHEUS_PUBLIC=true` and restrict the path at the reverse proxy / firewall |
| Authenticated scrape | `GET /api/v1/metrics/prometheus/secure` with an admin/superadmin Bearer token |

Do not expose process metrics to the public internet.

### Request ID correlation (#54, #84)

Every API response includes `X-Request-Id` (incoming header honored when present, else a new UUID).

| Surface | How to correlate |
|---|---|
| HTTP response | `X-Request-Id` response header |
| Nest logs / handlers | `getRequestId()` from AsyncLocalStorage (`src/common/request-context.ts`) |
| Audit rows | `metadata.requestId` when the audit write runs inside a request context |

**Ops tip:** when investigating a failed login or admin action, grab `X-Request-Id` from the client/network panel and search audit logs for `metadata.requestId` (or filter exports). Propagate the same header across BFF → API hops when debugging multi-service traces.

### Admin BFF cookies (#24, #81, #84)

| Setting | Default | Notes |
|---|---|---|
| `httpOnly` | on | JWT never readable by JS |
| `SameSite` | `Lax` | Safe for OAuth/magic-link top-level redirects |
| `COOKIE_SAMESITE=strict` | opt-in | Stronger CSRF posture; may break cross-site top-level cookie send on first navigation |
| Origin check | on (mutating BFF routes) | `admin/src/lib/csrf.ts` rejects cross-site POSTs |

Prefer `Lax` + Origin checks unless you fully control all auth entry URLs on the admin origin.

### Out of scope / known non-goals

- SMS MFA (enum reserved; not implemented)
- Multi-ORM switching (Prisma only)
- Full OpenTelemetry distributed tracing (request IDs + optional Prometheus are available)

## Supply chain (#82)

- CI (`security.yml`) hard-fails on **critical** `pnpm audit --prod` findings
- High findings are reported (soft gate) and triaged via `pnpm.overrides` + direct bumps
- Run locally: `pnpm audit --prod` / `pnpm audit:deps`
- Snyk OSS: `snyk test --all-projects` (requires `snyk auth` or `SNYK_TOKEN`)
- Snyk Code: enable for org `kkshettigar24` in the Snyk UI, then `snyk code test`

## Safe defaults for deployers

1. Set unique `SEED_ADMIN_PASSWORD` (required in production; local seed generates a one-time password if unset)
2. Run `npm run keys:generate` and keep `./keys` out of git
3. Enable email verification and review `authkit.config.json` feature flags
4. Restrict CORS origins; keep Redis authenticated
5. Rotate webhook secrets periodically
6. Keep Prometheus private (`PROMETHEUS_PUBLIC` unset in production unless firewalled)
7. Set `AUTHKIT_SECRET_KEY` (64-char hex) for TOTP encryption at rest
8. Set `TRUST_PROXY=1` only when behind a real reverse proxy
9. Prefer fail-closed Redis blacklist in staging via `AUTHKIT_STRICT_REDIS=true`
10. Optionally set `COOKIE_SAMESITE=strict` for the admin BFF when OAuth redirects are same-site only
