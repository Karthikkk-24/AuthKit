import { Module } from '@nestjs/common';
import { APP_GUARD, APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { AppConfigModule } from './config/config.module';
import { PrismaModule } from './database/prisma/prisma.module';
import { RedisModule } from './redis/redis.module';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { RbacModule } from './rbac/rbac.module';
import { ApiKeyModule } from './api-key/api-key.module';
import { AuditModule } from './audit/audit.module';
import { WebhookModule } from './webhook/webhook.module';
import { EmailModule } from './email/email.module';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
import { RolesGuard } from './common/guards/roles.guard';
import { PermissionsGuard } from './common/guards/permissions.guard';
import { HealthModule } from './health/health.module';
import { MetricsModule } from './metrics/metrics.module';

@Module({
  imports: [
    // ── Core configuration ──────────────────────────────────────────
    AppConfigModule,

    // ── Database & Cache ────────────────────────────────────────────
    PrismaModule,
    RedisModule,

    // ── Rate Limiting ───────────────────────────────────────────────
    ThrottlerModule.forRoot([
      { name: 'short', ttl: 1_000, limit: 10 },
      { name: 'medium', ttl: 60_000, limit: 200 },
      { name: 'long', ttl: 3_600_000, limit: 2_000 },
    ]),

    // ── Feature Modules ─────────────────────────────────────────────
    AuthModule,
    UserModule,
    RbacModule,
    ApiKeyModule,
    AuditModule,
    WebhookModule,
    EmailModule,

    // ── Observability ───────────────────────────────────────────────
    HealthModule,
    MetricsModule,
  ],
  providers: [
    // Global JWT guard — all routes protected by default
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    // Global rate limiting
    { provide: APP_GUARD, useClass: ThrottlerGuard },
  ],
})
export class AppModule {}
