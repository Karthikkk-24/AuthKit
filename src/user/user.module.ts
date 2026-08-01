import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { PrismaModule } from '../database/prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';
import { WebhookModule } from '../webhook/webhook.module';

@Module({
  imports: [PrismaModule, AuditModule, WebhookModule],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
