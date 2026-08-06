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

### Out of scope / known non-goals

- SMS MFA (enum reserved; not implemented)
- Multi-ORM switching (Prisma only)
- Full OpenTelemetry distributed tracing (request IDs + optional Prometheus are available)

## Safe defaults for deployers

1. Set unique `SEED_ADMIN_PASSWORD` before production seed
2. Run `npm run keys:generate` and keep `./keys` out of git
3. Enable email verification and review `authkit.config.json` feature flags
4. Restrict CORS origins; keep Redis authenticated
5. Rotate webhook secrets periodically
6. Keep Prometheus private (`PROMETHEUS_PUBLIC` unset in production unless firewalled)
7. Set `AUTHKIT_SECRET_KEY` (64-char hex) for TOTP encryption at rest
8. Set `TRUST_PROXY=1` only when behind a real reverse proxy
9. Prefer fail-closed Redis blacklist in staging via `AUTHKIT_STRICT_REDIS=true`
