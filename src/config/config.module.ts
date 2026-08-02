import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ConfigLoaderService } from './config-loader.service';
import { AdminConfigController } from './admin-config.controller';
import { PrismaModule } from '../database/prisma/prisma.module';
import { AuditModule } from '../audit/audit.module';

@Global()
@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true }), PrismaModule, AuditModule],
  controllers: [AdminConfigController],
  providers: [ConfigLoaderService],
  exports: [ConfigLoaderService],
})
export class AppConfigModule {}
