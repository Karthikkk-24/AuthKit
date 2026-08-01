import { Module } from '@nestjs/common';
import { WebhookController } from './webhook.controller';
import { WebhookService } from './webhook.service';
import { PrismaModule } from '../database/prisma/prisma.module';
import { AppConfigModule } from '../config/config.module';

@Module({
  imports: [PrismaModule, AppConfigModule],
  controllers: [WebhookController],
  providers: [WebhookService],
  exports: [WebhookService],
})
export class WebhookModule {}
