import { Controller, Get, UseGuards } from '@nestjs/common';
import {
  HealthCheck,
  HealthCheckService,
  PrismaHealthIndicator,
  MemoryHealthIndicator,
  DiskHealthIndicator,
  HealthIndicatorResult,
} from '@nestjs/terminus';
import { Public } from '../common/decorators/public.decorator';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { PrismaService } from '../database/prisma/prisma.service';
import { TokenBlacklistService } from '../auth/token-blacklist.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private prismaHealth: PrismaHealthIndicator,
    private memory: MemoryHealthIndicator,
    private disk: DiskHealthIndicator,
    private prisma: PrismaService,
    private blacklist: TokenBlacklistService,
  ) {}

  /** Public liveness — no infra detail (#77). */
  @Get()
  @Public()
  @ApiOperation({ summary: 'Liveness probe (no infra detail)' })
  live() {
    return { status: 'ok' };
  }

  /** Authenticated readiness with DB/Redis/heap/disk detail (#77). */
  @Get('ready')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('superadmin', 'admin')
  @HealthCheck()
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Readiness / diagnostics (admin)' })
  check() {
    return this.health.check([
      () => this.prismaHealth.pingCheck('database', this.prisma),
      async (): Promise<HealthIndicatorResult> => {
        try {
          const ok = await this.blacklist.ping();
          return { redis: { status: ok ? 'up' : 'down' } };
        } catch {
          return { redis: { status: 'down' } };
        }
      },
      () => this.memory.checkHeap('memory_heap', 512 * 1024 * 1024),
      () =>
        this.disk.checkStorage('disk', {
          path: '/',
          thresholdPercent: 0.9,
        }),
    ]);
  }
}
