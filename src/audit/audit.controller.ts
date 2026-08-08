import {
  Controller,
  Get,
  Query,
  UseGuards,
  Res,
  Header,
  ForbiddenException,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import type { Response } from 'express';
import { AuditService } from './audit.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { PermissionsGuard } from '../common/guards/permissions.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { RequirePermissions } from '../common/decorators/permissions.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { escapeCsvField } from './csv-escape';

@ApiTags('Audit Logs')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get()
  @UseGuards(RolesGuard, PermissionsGuard)
  @Roles('superadmin', 'admin')
  @RequirePermissions({ action: 'read', resource: 'audit' })
  @ApiOperation({ summary: 'Query audit logs (admin)' })
  query(
    @Query('userId') userId?: string,
    @Query('action') action?: string,
    @Query('resource') resource?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('success') success?: string,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    return this.auditService.query({
      userId,
      action,
      resource,
      from: from ? new Date(from) : undefined,
      to: to ? new Date(to) : undefined,
      success: success !== undefined ? success === 'true' : undefined,
      page: page ? parseInt(page, 10) : 1,
      limit: limit ? parseInt(limit, 10) : 50,
    });
  }

  @Get('export')
  @UseGuards(RolesGuard, PermissionsGuard)
  @Roles('superadmin', 'admin')
  @RequirePermissions({ action: 'export', resource: 'audit' })
  @Header('Content-Type', 'text/csv; charset=utf-8')
  @Header('Content-Disposition', 'attachment; filename="audit-logs.csv"')
  @ApiOperation({ summary: 'Export audit logs as CSV (admin)' })
  async exportCsv(
    @Res() res: Response,
    @Query('userId') userId?: string,
    @Query('action') action?: string,
    @Query('resource') resource?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('success') success?: string,
    @Query('limit') limit?: string,
  ) {
    const rows = await this.auditService.query({
      userId,
      action,
      resource,
      from: from ? new Date(from) : undefined,
      to: to ? new Date(to) : undefined,
      success: success !== undefined ? success === 'true' : undefined,
      page: 1,
      // Safety ceiling so an export cannot exhaust memory (#27)
      limit: Math.min(limit ? parseInt(limit, 10) : 10_000, 50_000),
    });

    res.write(this.toCsvHeader());
    for (const log of rows.data) {
      res.write(this.toCsvRow(log));
    }
    res.end();
  }

  // RFC 4180 + formula-injection neutralization (#156).
  private csvField(value: unknown): string {
    return escapeCsvField(value);
  }

  private toCsvHeader(): string {
    return (
      [
        'id',
        'timestamp',
        'action',
        'userId',
        'resourceId',
        'resourceType',
        'ip',
        'userAgent',
        'success',
        'metadata',
      ]
        .map((h) => this.csvField(h))
        .join(',') + '\r\n'
    );
  }

  private toCsvRow(log: any): string {
    return (
      [
        log.id,
        log.timestamp instanceof Date ? log.timestamp.toISOString() : log.timestamp,
        log.action,
        log.userId,
        log.resourceId,
        log.resourceType,
        log.ip,
        log.userAgent,
        log.success,
        log.metadata,
      ]
        .map((v) => this.csvField(v))
        .join(',') + '\r\n'
    );
  }

  @Get('me')
  @ApiOperation({ summary: 'Get own audit history' })
  myLogs(
    @CurrentUser() user: any,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    return this.auditService.query({
      userId: user.id,
      page: page ? parseInt(page, 10) : 1,
      limit: limit ? parseInt(limit, 10) : 20,
    });
  }
}
