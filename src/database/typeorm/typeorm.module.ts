import { Module, Global } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigLoaderService } from '../../config/config-loader.service';
import { UserEntity } from './entities/user.entity';
import { RoleEntity } from './entities/role.entity';
import { PermissionEntity } from './entities/permission.entity';
import { SessionEntity } from './entities/session.entity';
import { ApiKeyEntity } from './entities/api-key.entity';
import { MfaCredentialEntity } from './entities/mfa-credential.entity';
import { ResourceEntity } from './entities/resource.entity';
import { ResourceAccessEntity } from './entities/resource-access.entity';
import { AuditLogEntity } from './entities/audit-log.entity';
import { EmailVerificationEntity } from './entities/email-verification.entity';
import { PasswordResetEntity } from './entities/password-reset.entity';
import { WebhookEntity } from './entities/webhook.entity';
import { WebhookDeliveryEntity } from './entities/webhook-delivery.entity';
import { IpBlockEntity } from './entities/ip-block.entity';

@Global()
@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [ConfigLoaderService],
      useFactory: (config: ConfigLoaderService) => ({
        type: 'postgres',
        url: config.get('database').url,
        entities: [
          UserEntity, RoleEntity, PermissionEntity, SessionEntity, ApiKeyEntity,
          MfaCredentialEntity, ResourceEntity, ResourceAccessEntity, AuditLogEntity,
          EmailVerificationEntity, PasswordResetEntity, WebhookEntity,
          WebhookDeliveryEntity, IpBlockEntity,
        ],
        synchronize: config.get('app').environment === 'development',
        logging: config.get('app').environment === 'development',
      }),
    }),
  ],
  exports: [TypeOrmModule],
})
export class TypeOrmDatabaseModule {}
