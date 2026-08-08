import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { MetricsService } from './metrics.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { PermissionsGuard } from '../common/guards/permissions.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { RequirePermissions } from '../common/decorators/permissions.decorator';

@ApiTags('Metrics')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard, PermissionsGuard)
@Roles('superadmin', 'admin')
@RequirePermissions({ action: 'read', resource: 'metrics' })
@Controller('metrics')
export class MetricsController {
  constructor(private readonly metricsService: MetricsService) {}

  @Get('dashboard')
  @ApiOperation({ summary: 'Get dashboard statistics' })
  dashboard() {
    return this.metricsService.getDashboardStats();
  }

  @Get('user-growth')
  @ApiOperation({ summary: 'User growth over last N days' })
  userGrowth(@Query('days') days?: string) {
    return this.metricsService.getUserGrowth(days ? parseInt(days, 10) : 30);
  }

  @Get('event-timeline')
  @ApiOperation({ summary: 'Audit event timeline (success vs failure)' })
  eventTimeline(@Query('days') days?: string) {
    return this.metricsService.getEventTimeline(days ? parseInt(days, 10) : 7);
  }
}
