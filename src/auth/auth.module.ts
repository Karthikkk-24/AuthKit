import { Module, Global } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import * as fs from 'fs';
import * as path from 'path';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PasswordService } from './password.service';
import { CryptoService } from './crypto.service';
import { TokenBlacklistService } from './token-blacklist.service';
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

/** Sync peek at config so disabled OAuth strategies are never registered (#79). */
function oauthProvidersEnabled(): { google: boolean; github: boolean } {
  try {
    const raw = JSON.parse(
      fs.readFileSync(path.resolve(process.cwd(), 'authkit.config.json'), 'utf-8'),
    );
    const google = raw?.auth?.strategies?.google;
    const github = raw?.auth?.strategies?.github;
    const interpolate = (v: unknown) => {
      if (typeof v !== 'string') return '';
      return v.replace(/\$\{([^}]+)\}/g, (_, key) => process.env[key] || '');
    };
    return {
      google: Boolean(
        google?.enabled &&
          interpolate(google.clientId) &&
          interpolate(google.clientSecret),
      ),
      github: Boolean(
        github?.enabled &&
          interpolate(github.clientId) &&
          interpolate(github.clientSecret),
      ),
    };
  } catch {
    return { google: false, github: false };
  }
}

const oauth = oauthProvidersEnabled();

@Global()
@Module({
  imports: [
    PrismaModule,
    AppConfigModule,
    EmailModule,
    AuditModule,
    RedisModule,
    WebhookModule,
    PassportModule.register({}),
    JwtModule.registerAsync({
      imports: [AppConfigModule],
      inject: [ConfigLoaderService],
      useFactory: (config: ConfigLoaderService) => {
        const jwtConfig = config.get<any>('auth').jwt;
        const keys = resolveJwtKeys(jwtConfig.algorithm);

        return {
          privateKey: keys.secret,
          publicKey: keys.publicKey,
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
    ...(oauth.google ? [GoogleStrategy] : []),
    ...(oauth.github ? [GitHubStrategy] : []),
  ],
  exports: [AuthService, PasswordService, CryptoService, TokenBlacklistService, JwtModule],
})
export class AuthModule {}
