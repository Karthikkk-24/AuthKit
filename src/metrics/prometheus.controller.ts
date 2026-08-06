import { Controller, Get, Res, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import type { Response } from 'express';
import { Public } from '../common/decorators/public.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { PrometheusService } from './prometheus.service';

/**
 * Prometheus scrape endpoint (#54, #68).
 * Public only when PROMETHEUS_PUBLIC=true or outside production.
 * Otherwise requires admin/superadmin JWT.
 */
@ApiTags('Metrics')
@Controller('metrics')
export class PrometheusController {
  constructor(private readonly prometheus: PrometheusService) {}

  private isPublicScrapeAllowed(): boolean {
    if (process.env.PROMETHEUS_PUBLIC === 'true') return true;
    return process.env.NODE_ENV !== 'production';
  }

  @Public()
  @Get('prometheus')
  @ApiOperation({
    summary:
      'Prometheus exposition format (public in non-prod or when PROMETHEUS_PUBLIC=true)',
  })
  async scrapePublic(@Res() res: Response) {
    if (!this.isPublicScrapeAllowed()) {
      res.status(401).json({
        message:
          'Prometheus scrape requires authentication in production. Set PROMETHEUS_PUBLIC=true for network-ACL scrapers, or use GET /metrics/prometheus/secure with an admin token.',
      });
      return;
    }
    const body = await this.prometheus.metrics();
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(body);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('superadmin', 'admin')
  @Get('prometheus/secure')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Authenticated Prometheus scrape (#68)' })
  async scrapeSecure(@Res() res: Response) {
    const body = await this.prometheus.metrics();
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(body);
  }
}
