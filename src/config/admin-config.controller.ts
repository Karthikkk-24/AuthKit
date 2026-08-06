import {
  Controller,
  Get,
  Patch,
  Body,
  UseGuards,
  Req,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { ConfigLoaderService } from './config-loader.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { PermissionsGuard } from '../common/guards/permissions.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { RequirePermissions } from '../common/decorators/permissions.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { AuditService } from '../audit/audit.service';
import type { Request } from 'express';

/**
 * Exposes authkit.config.json to the admin console (#29). The persisted
 * file stores `${ENV_VAR}` placeholders. GET returns a redacted view so
 * interpolated secrets never leave the API (#62). Writes always go through
 * a whitelist so credentials cannot be edited via the API.
 */
@ApiTags('Config')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard, PermissionsGuard)
@Roles('superadmin', 'admin')
@Controller('admin/config')
export class AdminConfigController {
  constructor(
    private readonly config: ConfigLoaderService,
    private readonly audit: AuditService,
  ) {}

  @Get()
  @RequirePermissions({ action: 'read', resource: 'settings' })
  @ApiOperation({ summary: 'Get the live authkit configuration (secrets redacted)' })
  getConfig() {
    return this.config.getAllRedacted();
  }

  @Patch()
  @RequirePermissions({ action: 'update', resource: 'settings' })
  @ApiOperation({
    summary: 'Update editable config sections (ui, features, mfa, session, security, audit, webhooks, email)',
  })
  async updateConfig(
    @Body() body: Record<string, unknown>,
    @CurrentUser() admin: any,
    @Req() req: Request,
  ) {
    const before = Object.keys(body ?? {}).filter((k) =>
      ConfigLoaderService.EDITABLE_FIELDS.has(k),
    );

    this.config.updateEditable(body);

    await this.audit.log({
      action: 'config.updated',
      userId: admin.id,
      resourceType: 'config',
      metadata: { sections: before },
      ip: req?.ip,
      success: true,
    });

    // Never return interpolated secrets in the PATCH response either (#62).
    return {
      message: 'Config updated',
      editable: before,
      config: this.config.getAllRedacted(),
    };
  }
}
