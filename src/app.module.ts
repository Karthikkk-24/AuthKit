import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
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
import { PermissionsGuard } from './common/guards/permissions.guard';
import { IpListGuard } from './common/guards/ip-list.guard';
import { RequestIdMiddleware } from './common/middleware/request-id.middleware';
import { HealthModule } from './health/health.module';
import { MetricsModule } from './metrics/metrics.module';
import { ConfigLoaderService } from './config/config-loader.service';

@Module({
  imports: [
    AppConfigModule,
    PrismaModule,
    RedisModule,
    ThrottlerModule.forRootAsync({
      imports: [AppConfigModule],
      inject: [ConfigLoaderService],
      useFactory: (config: ConfigLoaderService) => {
        const rl = config.get<any>('security')?.rateLimit ?? {};
        const global = rl.global ?? {};
        // Named throttlers used by @Throttle({ short|medium|long }).
        // Route decorators still override ttl/limit per endpoint (#79, #87).
        return [
          { name: 'short', ttl: 1_000, limit: 10 },
          {
            name: 'medium',
            ttl: Number(global.windowMs) > 0 ? Number(global.windowMs) : 60_000,
            limit: Number(global.max) > 0 ? Number(global.max) : 200,
          },
          { name: 'long', ttl: 3_600_000, limit: 2_000 },
        ];
      },
    }),
    AuthModule,
    UserModule,
    RbacModule,
    ApiKeyModule,
    AuditModule,
    WebhookModule,
    EmailModule,
    HealthModule,
    MetricsModule,
  ],
  providers: [
    { provide: APP_GUARD, useClass: IpListGuard },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
    { provide: APP_GUARD, useClass: ThrottlerGuard },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(RequestIdMiddleware).forRoutes('*');
  }
}
