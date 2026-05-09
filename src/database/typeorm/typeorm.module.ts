import { Module, Global } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigLoaderService } from '../config/config-loader.service';
import { UserEntity } from './typeorm/entities/user.entity';
import { RoleEntity } from './typeorm/entities/role.entity';
import { PermissionEntity } from './typeorm/entities/permission.entity';
import { SessionEntity } from './typeorm/entities/session.entity';
import { ApiKeyEntity } from './typeorm/entities/api-key.entity';
import { MfaCredentialEntity } from './typeorm/entities/mfa-credential.entity';
import { ResourceEntity } from './typeorm/entities/resource.entity';
import { ResourceAccessEntity } from './typeorm/entities/resource-access.entity';
import { AuditLogEntity } from './typeorm/entities/audit-log.entity';
import { EmailVerificationEntity } from './typeorm/entities/email-verification.entity';
import { PasswordResetEntity } from './typeorm/entities/password-reset.entity';
import { WebhookEntity } from './typeorm/entities/webhook.entity';
import { WebhookDeliveryEntity } from './typeorm/entities/webhook-delivery.entity';
import { IpBlockEntity } from './typeorm/entities/ip-block.entity';

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
