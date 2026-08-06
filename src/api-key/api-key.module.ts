import { Module } from '@nestjs/common';
import { ApiKeyController } from './api-key.controller';
import { ApiKeyService } from './api-key.service';
import { PrismaModule } from '../database/prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';
import { WebhookModule } from '../webhook/webhook.module';
import { AppConfigModule } from '../config/config.module';

@Module({
  imports: [PrismaModule, AuditModule, WebhookModule, AppConfigModule],
  controllers: [ApiKeyController],
  providers: [ApiKeyService],
  exports: [ApiKeyService],
})
export class ApiKeyModule {}
