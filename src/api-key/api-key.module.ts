import { Module } from '@nestjs/common';
import { ApiKeyController } from './api-key.controller';
import { ApiKeyService } from './api-key.service';
import { PrismaModule } from '../database/prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';
import { WebhookModule } from '../webhook/webhook.module';

@Module({
  imports: [PrismaModule, AuditModule, WebhookModule],
  controllers: [ApiKeyController],
  providers: [ApiKeyService],
  exports: [ApiKeyService],
})
export class ApiKeyModule {}
