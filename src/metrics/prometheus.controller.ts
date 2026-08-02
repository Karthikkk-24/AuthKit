import { Controller, Get, Res } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import type { Response } from 'express';
import { Public } from '../common/decorators/public.decorator';
import { PrometheusService } from './prometheus.service';

/**
 * Public Prometheus scrape endpoint (#54). Kept outside the admin-guarded
 * MetricsController so RolesGuard does not block scrapers.
 */
@ApiTags('Metrics')
@Controller('metrics')
export class PrometheusController {
  constructor(private readonly prometheus: PrometheusService) {}

  @Public()
  @Get('prometheus')
  @ApiOperation({ summary: 'Prometheus exposition format (#54)' })
  async scrape(@Res() res: Response) {
    const body = await this.prometheus.metrics();
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(body);
  }
}
