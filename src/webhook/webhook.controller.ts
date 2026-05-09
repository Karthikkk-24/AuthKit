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
import { Roles } from '../common/decorators/roles.decorator';

@ApiTags('Webhooks')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('superadmin', 'admin')
@Controller('webhooks')
export class WebhookController {
  constructor(private readonly webhookService: WebhookService) {}

  @Post('endpoints')
  @ApiOperation({ summary: 'Register a webhook endpoint' })
  register(
    @Body()
    body: {
      url: string;
      events: WebhookEventType[];
      description?: string;
    },
  ) {
    return this.webhookService.registerEndpoint(body);
  }

  @Get('endpoints')
  @ApiOperation({ summary: 'List all webhook endpoints' })
  list() {
    return this.webhookService.listEndpoints();
  }

  @Patch('endpoints/:id/toggle')
  @ApiOperation({ summary: 'Enable or disable a webhook endpoint' })
  toggle(@Param('id') id: string, @Body() body: { isActive: boolean }) {
    return this.webhookService.toggleEndpoint(id, body.isActive);
  }

  @Post('endpoints/:id/rotate-secret')
  @ApiOperation({ summary: 'Rotate HMAC signing secret' })
  rotateSecret(@Param('id') id: string) {
    return this.webhookService.rotateSecret(id);
  }

  @Delete('endpoints/:id')
  @Roles('superadmin')
  @ApiOperation({ summary: 'Delete a webhook endpoint' })
  delete(@Param('id') id: string) {
    return this.webhookService.deleteEndpoint(id);
  }
}
