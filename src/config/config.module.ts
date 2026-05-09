import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ConfigLoaderService } from './config-loader.service';

@Global()
@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true })],
  providers: [ConfigLoaderService],
  exports: [ConfigLoaderService],
})
export class AppConfigModule {}
