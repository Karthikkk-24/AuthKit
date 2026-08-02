import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { MetricsController } from './metrics.controller';
import { PrometheusController } from './prometheus.controller';
import { MetricsService } from './metrics.service';
import { PrometheusService } from './prometheus.service';
import { PrometheusInterceptor } from './prometheus.interceptor';
import { PrismaModule } from '../database/prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [MetricsController, PrometheusController],
  providers: [
    MetricsService,
    PrometheusService,
    { provide: APP_INTERCEPTOR, useClass: PrometheusInterceptor },
  ],
  exports: [MetricsService, PrometheusService],
})
export class MetricsModule {}
