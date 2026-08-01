import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { WebhookService, WebhookEventType } from './webhook.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { PermissionsGuard } from '../common/guards/permissions.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { RequirePermissions } from '../common/decorators/permissions.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';

@ApiTags('Webhooks')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard, PermissionsGuard)
@Roles('superadmin', 'admin')
@Controller('webhooks')
export class WebhookController {
  constructor(private readonly webhookService: WebhookService) {}

  @Post('endpoints')
  @RequirePermissions({ action: 'create', resource: 'webhooks' })
  @ApiOperation({ summary: 'Register a webhook endpoint' })
  register(
    @Body()
    body: {
      url: string;
      events: WebhookEventType[];
      description?: string;
    },
    @CurrentUser() admin: any,
  ) {
    return this.webhookService.registerEndpoint(admin.id, body);
  }

  @Get('endpoints')
  @RequirePermissions({ action: 'read', resource: 'webhooks' })
  @ApiOperation({ summary: 'List all webhook endpoints' })
  list(@CurrentUser() admin: any) {
    return this.webhookService.listEndpoints(admin.id);
  }

  @Patch('endpoints/:id/toggle')
  @RequirePermissions({ action: 'update', resource: 'webhooks' })
  @ApiOperation({ summary: 'Enable or disable a webhook endpoint' })
  toggle(
    @Param('id') id: string,
    @Body() body: { isActive: boolean },
    @CurrentUser() admin: any,
  ) {
    return this.webhookService.toggleEndpoint(id, admin.id, body.isActive);
  }

  @Post('endpoints/:id/rotate-secret')
  @RequirePermissions({ action: 'update', resource: 'webhooks' })
  @ApiOperation({ summary: 'Rotate HMAC signing secret' })
  rotateSecret(@Param('id') id: string, @CurrentUser() admin: any) {
    return this.webhookService.rotateSecret(id, admin.id);
  }

  @Delete('endpoints/:id')
  @Roles('superadmin')
  @RequirePermissions({ action: 'delete', resource: 'webhooks' })
  @ApiOperation({ summary: 'Delete a webhook endpoint' })
  delete(@Param('id') id: string, @CurrentUser() admin: any) {
    return this.webhookService.deleteEndpoint(id, admin.id);
  }
}
