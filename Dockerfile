# ── Stage 1: Builder ──────────────────────────────────────────────────
FROM node:20-alpine AS builder

RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

# Copy workspace manifests first for layer caching
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY api/package.json ./api/
COPY admin/package.json ./admin/

RUN pnpm install --frozen-lockfile

# Copy all source
COPY . .

# Build the NestJS API
WORKDIR /app/api
RUN pnpm build

# Build the Next.js admin
WORKDIR /app/admin
RUN pnpm build

# ── Stage 2: API Runtime ──────────────────────────────────────────────
FROM node:20-alpine AS api

RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app

COPY --from=builder /app/package.json /app/pnpm-workspace.yaml /app/pnpm-lock.yaml ./
COPY --from=builder /app/api/package.json ./api/
RUN pnpm install --prod --frozen-lockfile

COPY --from=builder /app/api/dist ./api/dist
COPY --from=builder /app/prisma ./prisma

# Generate Prisma client
RUN cd api && npx prisma generate

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "api/dist/main.js"]

# ── Stage 3: Admin Runtime ────────────────────────────────────────────
FROM node:20-alpine AS admin

WORKDIR /app/admin

COPY --from=builder /app/admin/.next/standalone ./
COPY --from=builder /app/admin/.next/static ./.next/static
COPY --from=builder /app/admin/public ./public

ENV NODE_ENV=production
EXPOSE 3001

CMD ["node", "server.js"]
