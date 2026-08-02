<p align="center">
  <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/shield-check.svg" width="64" alt="AuthKit Logo">
</p>

<h1 align="center">AuthKit</h1>

<p align="center">
  Enterprise-grade authentication & authorization platform.<br/>
  <strong>Plug-and-play. Fully configurable. Secure by default.</strong>
</p>

<p align="center">
  <img alt="NestJS" src="https://img.shields.io/badge/NestJS-11-E0234E?logo=nestjs&logoColor=white">
  <img alt="Next.js" src="https://img.shields.io/badge/Next.js-16-black?logo=next.js">
  <img alt="PostgreSQL" src="https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white">
  <img alt="Redis" src="https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white">
  <img alt="Prisma" src="https://img.shields.io/badge/Prisma-ORM-2D3748?logo=prisma">
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript&logoColor=white">
</p>

---

## ✨ Features

| Category | Features |
|---|---|
| **Authentication** | Email/Password, Google OAuth, GitHub OAuth, Magic Links |
| **MFA** | TOTP (authenticator apps), Email OTP |
| **RBAC** | Hierarchical roles, granular permissions, wildcard matching, per-user overrides |
| **Security** | Argon2id hashing, Pwned password check (HIBP), JWT blacklisting, rate limiting, Helmet CSP |
| **Sessions** | Multi-device tracking, remote revocation, inactivity auto-revoke (Postgres-backed; Redis used for JWT blacklist / OTP) |
| **API Keys** | SHA-256 hashed, scoped, expiring, revocable |
| **Audit Logs** | Structured event log, metadata, IP/UA capture, CSV export |
| **Webhooks** | HMAC-SHA256 signed delivery, retry backoff, secret rotation |
| **Admin UI** | Dashboard metrics, user management, RBAC editor, audit viewer, webhook config, API key manager, settings |
| **Database** | PostgreSQL via Prisma |
| **Observability** | `/health` endpoint, `/metrics/dashboard`, Swagger docs |

---

## 📁 Project Structure

```
AuthKit/
├── src/                     # NestJS API
│   ├── auth/                # Login, register, OAuth, MFA, password reset
│   ├── user/                # User CRUD, profile, sessions, GDPR export
│   ├── rbac/                # Roles, permissions, per-user overrides
│   ├── api-key/             # API key lifecycle
│   ├── audit/               # Audit log service & controller
│   ├── webhook/             # Endpoint registration & HMAC dispatch
│   ├── metrics/             # Growth & event timeline metrics
│   ├── redis/               # Redis module (ioredis)
│   ├── database/prisma/     # PrismaService
│   ├── email/               # Email service (SMTP/SendGrid/Resend)
│   └── common/              # Guards, decorators, interceptors
├── admin/                   # Next.js 16 Admin Dashboard
│   └── src/app/dashboard/
│       ├── page.tsx         # Metrics overview
│       ├── users/           # User management
│       ├── roles/           # RBAC editor
│       ├── api-keys/        # API key manager
│       ├── audit/           # Audit log viewer
│       ├── webhooks/        # Webhook config
│       └── settings/        # Platform settings
├── prisma/
│   ├── schema.prisma        # 15-model schema
│   └── seed.ts              # System roles, permissions & superadmin
├── authkit.config.json      # ✳️ Master feature configuration
├── docker-compose.yml       # PostgreSQL + Redis + API + Admin
├── Dockerfile               # Multi-stage production build
└── .env.example             # All environment variables documented
```

---

## 🚀 Quick Start

### Prerequisites

- Node.js 20+
- pnpm 9+
- Docker & Docker Compose (or local Postgres 16 + Redis 7)

### 1. Clone & install

```bash
git clone https://github.com/yourorg/authkit.git
cd authkit
pnpm install
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in required values
```

### 3. Start infrastructure

```bash
docker compose up postgres redis -d
```

### 4. Run database migrations & seed

```bash
npm run db:migrate     # Run Prisma migrations
npm run db:seed        # Creates system roles, permissions & superadmin
```

### 5. Generate RSA keys (production recommended)

```bash
npm run keys:generate  # Writes RSA-4096 keys to ./keys/
```

### 6. Start development servers

```bash
# Terminal 1 — API
npm run start:dev

# Terminal 2 — Admin dashboard
cd admin && pnpm dev
```

- **API:** http://localhost:3000
- **Swagger:** http://localhost:3000/docs
- **Admin:** http://localhost:3001
- **Default admin login:** `admin@authkit.dev` / `Admin@AuthKit2025!`

---

## 🐳 Docker (Production)

```bash
# Build and start everything
docker compose up --build

# First-time migrations & seed
docker compose exec api npx prisma migrate deploy
docker compose exec api node -e "require('./prisma/seed')"
```

Add `--profile dev` to also start MailHog (SMTP catch-all on port 8025).

---

## ⚙️ Configuration

All features are controlled via `authkit.config.json`:

```json
{
  "auth": {
    "localAuth": true,
    "google": true,
    "github": true
  },
  "mfa": {
    "enabled": true,
    "totp": true,
    "emailOtp": true,
    "required": false
  },
  "security": {
    "maxLoginAttempts": 5,
    "lockoutDurationMinutes": 30,
    "pwnedPasswordCheck": true,
    "requireEmailVerification": true
  },
  "database": {
    "orm": "prisma"
  },
  "webhooks": {
    "enabled": true
  }
}
```

---

## 🔑 Authentication Flows

### Email / Password
```
POST /api/v1/auth/register   → { email, password, name }
POST /api/v1/auth/login      → { email, password }  → { accessToken, refreshToken }
POST /api/v1/auth/refresh    → { refreshToken }
POST /api/v1/auth/logout
```

### OAuth
```
GET /api/v1/auth/google
GET /api/v1/auth/github
```

### MFA
```
POST /api/v1/auth/mfa/totp/setup    → { qrCode, secret }
POST /api/v1/auth/mfa/totp/verify   → { code }
POST /api/v1/auth/mfa/email/send
POST /api/v1/auth/mfa/email/verify  → { code }
```

### Password Reset
```
POST /api/v1/auth/forgot-password  → { email }
POST /api/v1/auth/reset-password    → { token, newPassword }
```

---

## 🛡️ RBAC System

### Built-in Role Hierarchy (lowest → highest)

```
guest → user → moderator → admin → superadmin
```

Higher roles satisfy lower `@Roles(...)` checks at enforcement time (e.g. `admin` passes `@Roles('user')`). Permission rows also inherit via `Role.parentId` in `PermissionsGuard`. Permissions are `resource:action` pairs with wildcard support:

| Expression | Meaning |
|---|---|
| `users:read` | Can read users |
| `users:*` | Full access to users resource |
| `*:*` | Superadmin — all resources & actions |

### Using decorators in your code

```typescript
@Roles('admin')
@Permissions('users:delete')
@Delete(':id')
deleteUser(@Param('id') id: string) { … }
```

### Per-user permission overrides

```
PATCH /api/v1/rbac/users/:userId/permissions
{ "grant": ["reports:read"], "deny": ["admin:access"] }
```

---

## 🔐 API Key Authentication

```
POST /api/v1/api-keys         → { name, scopes, expiresIn }
                              ← { key: "ak_...", id }  (shown once!)
GET  /api/v1/api-keys
DELETE /api/v1/api-keys/:id
```

Use in requests:
```
Authorization: ApiKey ak_your_key_here
```

---

## 📊 Admin Dashboard Pages

| Page | Path | Description |
|---|---|---|
| Overview | `/dashboard` | Stat cards + user growth + auth events chart |
| Users | `/dashboard/users` | Search, lock, unlock, delete, role badge |
| Roles & Perms | `/dashboard/roles` | Create roles, assign permissions grid |
| API Keys | `/dashboard/api-keys` | Create scoped keys, one-time reveal, revoke |
| Audit Logs | `/dashboard/audit` | Expandable events, action filter, CSV export |
| Webhooks | `/dashboard/webhooks` | Register endpoints, HMAC secrets, toggle |
| Settings | `/dashboard/settings` | Edit authkit.config.json via UI |

---

## 📡 Webhooks

Register an HTTPS endpoint and receive signed payloads for any auth event:

**Supported events:** `user.created`, `user.login`, `user.locked`, `session.revoked`, `password.changed`, `mfa.enrolled`, `api_key.created`

**Verifying webhook signatures:**

```javascript
const crypto = require('crypto');
const isValid = crypto.timingSafeEqual(
  Buffer.from(req.headers['x-authkit-signature']),
  Buffer.from(crypto.createHmac('sha256', SECRET).update(rawBody).digest('hex'))
);
```

---

## 🗄️ Database

AuthKit uses **Prisma** against PostgreSQL. Multi-ORM switching was removed (#35).

| Command | When to use |
|---|---|
| `pnpm db:migrate` / `prisma migrate dev` | Local development — creates/applies migrations |
| `pnpm db:deploy` / `prisma migrate deploy` | CI/production — applies committed migrations |
| `npx prisma db push` | Prototyping only — syncs schema without migration history |

A baseline migration lives under `prisma/migrations/` (#40).

---

## 🧪 Testing

```bash
npm run test          # Unit tests
npm run test:cov      # Coverage report
npm run test:e2e      # End-to-end tests
```

---

## 📝 Scripts Reference

| Command | Description |
|---|---|
| `npm run start:dev` | Start API in watch mode |
| `npm run db:migrate` | Run pending Prisma migrations |
| `npm run db:seed` | Seed system roles, permissions & admin |
| `npm run db:reset` | Reset DB and re-seed |
| `npm run db:studio` | Open Prisma Studio |
| `npm run keys:generate` | Generate RSA-4096 key pair |
| `cd admin && pnpm dev` | Start admin dashboard |

---

## 🔒 Security Best Practices

1. **Change the default admin password** immediately after first seed
2. **Use RS256 JWT** in production (`npm run keys:generate`)
3. Enable `pwnedPasswordCheck` to reject known-breached passwords
4. Set `requireEmailVerification: true` to prevent spam accounts
5. Keep `MAX_LOGIN_ATTEMPTS` at 5 or lower
6. Never commit `.env` — only `.env.example` belongs in git
7. Rotate webhook secrets periodically via the admin UI

---

## 📄 License

MIT — see [LICENSE](./LICENSE) for details.
