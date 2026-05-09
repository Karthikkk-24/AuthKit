import {
  Controller,
  Get,
  Patch,
  Delete,
  Post,
  Param,
  Body,
  Query,
  UseGuards,
  Req,
  ParseIntPipe,
  DefaultValuePipe,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Request } from 'express';

@ApiTags('Users')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  // ─── SELF ──────────────────────────────────────────────────────────
  @Get('me')
  @ApiOperation({ summary: 'Get own profile' })
  getMe(@CurrentUser() user: any) {
    return this.userService.findById(user.id);
  }

  @Patch('me')
  @ApiOperation({ summary: 'Update own profile' })
  updateMe(
    @CurrentUser() user: any,
    @Body() body: { name?: string; avatarUrl?: string },
  ) {
    return this.userService.updateProfile(user.id, body);
  }

  @Get('me/sessions')
  @ApiOperation({ summary: 'List own active sessions' })
  getMySessions(@CurrentUser() user: any) {
    return this.userService.getSessions(user.id);
  }

  @Delete('me/sessions/:sessionId')
  @ApiOperation({ summary: 'Revoke a specific session' })
  revokeSession(
    @CurrentUser() user: any,
    @Param('sessionId') sessionId: string,
    @Req() req: Request,
  ) {
    return this.userService.revokeSession(user.id, sessionId, req);
  }

  @Get('me/export')
  @ApiOperation({ summary: 'Export own data (GDPR)' })
  exportData(@CurrentUser() user: any) {
    return this.userService.exportData(user.id);
  }

  // ─── ADMIN ─────────────────────────────────────────────────────────
  @Get()
  @UseGuards(RolesGuard)
  @Roles('superadmin', 'admin')
  @ApiOperation({ summary: 'List all users (admin)' })
  findAll(
    @Query('search') search?: string,
    @Query('roleId') roleId?: string,
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page?: number,
    @Query('limit', new DefaultValuePipe(20), ParseIntPipe) limit?: number,
  ) {
    return this.userService.findAll({ search, roleId, page, limit });
  }

  @Get(':id')
  @UseGuards(RolesGuard)
  @Roles('superadmin', 'admin')
  @ApiOperation({ summary: 'Get user by ID (admin)' })
  findOne(@Param('id') id: string) {
    return this.userService.findById(id);
  }

  @Patch(':id/role')
  @UseGuards(RolesGuard)
  @Roles('superadmin', 'admin')
  @ApiOperation({ summary: 'Assign role to user (admin)' })
  assignRole(
    @Param('id') id: string,
    @Body() body: { roleId: string },
    @CurrentUser() admin: any,
    @Req() req: Request,
  ) {
    return this.userService.assignRole(id, body.roleId, admin.id, req);
  }

  @Post(':id/lock')
  @UseGuards(RolesGuard)
  @Roles('superadmin', 'admin')
  @ApiOperation({ summary: 'Lock a user account (admin)' })
  lockUser(
    @Param('id') id: string,
    @Body() body: { reason: string },
    @CurrentUser() admin: any,
    @Req() req: Request,
  ) {
    return this.userService.lockUser(id, body.reason, admin.id, req);
  }

  @Post(':id/unlock')
  @UseGuards(RolesGuard)
  @Roles('superadmin', 'admin')
  @ApiOperation({ summary: 'Unlock a user account (admin)' })
  unlockUser(
    @Param('id') id: string,
    @CurrentUser() admin: any,
    @Req() req: Request,
  ) {
    return this.userService.unlockUser(id, admin.id, req);
  }

  @Delete(':id')
  @UseGuards(RolesGuard)
  @Roles('superadmin', 'admin')
  @ApiOperation({ summary: 'Soft-delete a user (admin)' })
  deleteUser(
    @Param('id') id: string,
    @CurrentUser() admin: any,
    @Req() req: Request,
  ) {
    return this.userService.softDelete(id, admin.id, req);
  }
}
