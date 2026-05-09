import { Controller, Get, Post, Delete, Param, Body, UseGuards, Req } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { ApiKeyService } from './api-key.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Request } from 'express';

@ApiTags('API Keys')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('api-keys')
export class ApiKeyController {
  constructor(private readonly apiKeyService: ApiKeyService) {}

  @Post()
  @ApiOperation({ summary: 'Create an API key (raw key shown only once)' })
  create(
    @CurrentUser() user: any,
    @Body() body: { name: string; scopes?: string[]; expiresIn?: number },
    @Req() req: Request,
  ) {
    return this.apiKeyService.create(user.id, body, req);
  }

  @Get()
  @ApiOperation({ summary: 'List own API keys' })
  list(@CurrentUser() user: any) {
    return this.apiKeyService.list(user.id);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Revoke an API key' })
  revoke(
    @CurrentUser() user: any,
    @Param('id') id: string,
    @Req() req: Request,
  ) {
    return this.apiKeyService.revoke(user.id, id, req);
  }
}
