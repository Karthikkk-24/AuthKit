import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Req,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { RbacService, CreateRoleDto, CreatePermissionDto } from './rbac.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { PermissionsGuard } from '../common/guards/permissions.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { RequirePermissions } from '../common/decorators/permissions.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import type { Request } from 'express';

@ApiTags('RBAC')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard, PermissionsGuard)
@Roles('superadmin', 'admin')
@Controller('rbac')
export class RbacController {
  constructor(private readonly rbacService: RbacService) {}

  // ─── ROLES ─────────────────────────────────────────────────────────
  @Post('roles')
  @RequirePermissions({ action: 'update', resource: 'roles' })
  @ApiOperation({ summary: 'Create a role' })
  createRole(
    @Body() body: CreateRoleDto,
    @CurrentUser() admin: any,
    @Req() req: Request,
  ) {
    return this.rbacService.createRole(body, admin.id, req);
  }

  @Get('roles')
  @RequirePermissions({ action: 'read', resource: 'roles' })
  @ApiOperation({ summary: 'List all roles' })
  getRoles() {
    return this.rbacService.getRoles();
  }

  @Get('roles/:id')
  @RequirePermissions({ action: 'read', resource: 'roles' })
  @ApiOperation({ summary: 'Get a role with permissions' })
  getRole(@Param('id') id: string) {
    return this.rbacService.getRole(id);
  }

  @Patch('roles/:id')
  @RequirePermissions({ action: 'update', resource: 'roles' })
  @ApiOperation({ summary: 'Update a role' })
  updateRole(
    @Param('id') id: string,
    @Body() body: Partial<CreateRoleDto>,
    @CurrentUser() admin: any,
    @Req() req: Request,
  ) {
    return this.rbacService.updateRole(id, body, admin.id, req);
  }

  @Delete('roles/:id')
  @Roles('superadmin')
  @RequirePermissions({ action: 'delete', resource: 'roles' })
  @ApiOperation({ summary: 'Delete a role (superadmin only)' })
  deleteRole(
    @Param('id') id: string,
    @CurrentUser() admin: any,
    @Req() req: Request,
  ) {
    return this.rbacService.deleteRole(id, admin.id, req);
  }

  @Patch('roles/:id/permissions')
  @RequirePermissions({ action: 'update', resource: 'roles' })
  @ApiOperation({
    summary: 'Replace a role\'s permissions (action/resource pairs)',
  })
  assignPermissions(
    @Param('id') id: string,
    @Body() body: { permissions: Array<{ action: string; resource: string }> },
    @CurrentUser() admin: any,
    @Req() req: Request,
  ) {
    return this.rbacService.assignPermissionsToRole(id, body.permissions ?? [], admin.id, req);
  }

  // ─── PERMISSIONS ───────────────────────────────────────────────────
  @Post('permissions')
  @ApiOperation({ summary: 'Create a permission' })
  createPermission(@Body() body: CreatePermissionDto) {
    return this.rbacService.createPermission(body);
  }

  @Get('permissions')
  @RequirePermissions({ action: 'read', resource: 'permissions' })
  @ApiOperation({ summary: 'List permissions (optionally filter by resource)' })
  getPermissions(@Query('resource') resource?: string) {
    return this.rbacService.getPermissions(resource);
  }

  @Delete('permissions/:id')
  @Roles('superadmin')
  @RequirePermissions({ action: 'delete', resource: 'permissions' })
  @ApiOperation({ summary: 'Delete a permission (superadmin only)' })
  deletePermission(@Param('id') id: string) {
    return this.rbacService.deletePermission(id);
  }

}
