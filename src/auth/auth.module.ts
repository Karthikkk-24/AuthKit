import { Module, Global } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PasswordService } from './password.service';
import { CryptoService } from './crypto.service';
import { TokenBlacklistService } from './token-blacklist.service';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { GitHubStrategy } from './strategies/github.strategy';
import { PrismaModule } from '../database/prisma/prisma.module';
import { AppConfigModule } from '../config/config.module';
import { EmailModule } from '../email/email.module';
import { AuditModule } from '../audit/audit.module';
import { RedisModule } from '../redis/redis.module';
import { WebhookModule } from '../webhook/webhook.module';
import { ConfigLoaderService } from '../config/config-loader.service';
import { resolveJwtKeys } from './jwt-keys.util';

@Global()
@Module({
  imports: [
    PrismaModule,
    AppConfigModule,
    EmailModule,
    AuditModule,
    RedisModule,
    WebhookModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [AppConfigModule],
      inject: [ConfigLoaderService],
      useFactory: (config: ConfigLoaderService) => {
        const jwtConfig = config.get<any>('auth').jwt;
        const keys = resolveJwtKeys(jwtConfig.algorithm);

        return {
          privateKey: keys.secret,
          publicKey: keys.publicKey,
          // Nest JwtModule also accepts `secret` for HS*; keep dual for compatibility
          secret: keys.secret,
          signOptions: {
            algorithm: jwtConfig.algorithm,
            issuer: jwtConfig.issuer,
            audience: jwtConfig.audience,
            expiresIn: jwtConfig.accessTokenExpiry,
          },
          verifyOptions: {
            algorithms: [jwtConfig.algorithm],
            issuer: jwtConfig.issuer,
            audience: jwtConfig.audience,
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PasswordService,
    CryptoService,
    TokenBlacklistService,
    LocalStrategy,
    JwtStrategy,
    GoogleStrategy,
    GitHubStrategy,
  ],
  exports: [AuthService, PasswordService, CryptoService, TokenBlacklistService, JwtModule],
})
export class AuthModule {}
