import { Module, Global } from '@nestjs/common';
import { InjectRedis, RedisModule as NestRedisModule } from '@nestjs-modules/ioredis';
import { ConfigModule } from '../config/config.module';
import { ConfigLoaderService } from '../config/config-loader.service';

@Global()
@Module({
  imports: [
    NestRedisModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigLoaderService],
      useFactory: (config: ConfigLoaderService) => ({
        type: 'single',
        url: config.get<any>('redis').url,
      }),
    }),
  ],
  exports: [NestRedisModule],
})
export class RedisModule {}
