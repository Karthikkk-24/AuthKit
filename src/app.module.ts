import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { RoleController } from './role/role.controller';
import { RoleService } from './role/role.service';
import { RoleModule } from './role/role.module';
import { PermissionController } from './permission/permission.controller';
import { PermissionService } from './permission/permission.service';
import { PermissionModule } from './permission/permission.module';
import { ResourceModule } from './resource/resource.module';
import { AccessControlController } from './access_control/access_control.controller';
import { AccessControlService } from './access_control/access_control.service';
import { AccessControlModule } from './access_control/access_control.module';

@Module({
  imports: [AuthModule, UserModule, RoleModule, PermissionModule, ResourceModule, AccessControlModule],
  controllers: [AppController, RoleController, PermissionController, AccessControlController],
  providers: [AppService, RoleService, PermissionService, AccessControlService],
})
export class AppModule {}
