# ── Stage 1: Builder ──────────────────────────────────────────────────
# NestJS API lives at the repo root; admin is the Next.js workspace package.
FROM node:20-alpine AS builder

RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

# Copy workspace manifests first for layer caching
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY admin/package.json ./admin/

RUN pnpm install --frozen-lockfile

# Copy all source
COPY . .

# Build the NestJS API (root package)
RUN pnpm build

# Generate Prisma client for the runtime image
RUN npx prisma generate

# Build the Next.js admin (standalone output expected via next.config)
WORKDIR /app/admin
RUN pnpm build

# ── Stage 2: API Runtime ──────────────────────────────────────────────
FROM node:20-alpine AS api

RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app

COPY --from=builder /app/package.json /app/pnpm-workspace.yaml /app/pnpm-lock.yaml ./
COPY --from=builder /app/admin/package.json ./admin/
RUN pnpm install --prod --frozen-lockfile

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/node_modules/@prisma ./node_modules/@prisma
COPY --from=builder /app/authkit.config.json ./authkit.config.json

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "dist/main.js"]

# ── Stage 3: Admin Runtime ────────────────────────────────────────────
# Next standalone in a workspace nests under the package directory name.
FROM node:20-alpine AS admin

WORKDIR /app

COPY --from=builder /app/admin/.next/standalone ./
COPY --from=builder /app/admin/.next/static ./admin/.next/static
COPY --from=builder /app/admin/public ./admin/public

ENV NODE_ENV=production
ENV PORT=3001
ENV HOSTNAME=0.0.0.0
EXPOSE 3001

CMD ["node", "admin/server.js"]
