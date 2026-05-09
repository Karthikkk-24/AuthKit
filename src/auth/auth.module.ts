import { Module, Global } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PasswordService } from './password.service';
import { TokenBlacklistService } from './token-blacklist.service';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { GitHubStrategy } from './strategies/github.strategy';
import { PrismaModule } from '../database/prisma/prisma.module';
import { ConfigModule } from '../config/config.module';
import { EmailModule } from '../email/email.module';
import { AuditModule } from '../audit/audit.module';
import { RedisModule } from '../redis/redis.module';
import { ConfigLoaderService } from '../config/config-loader.service';
import * as fs from 'fs';
import * as path from 'path';

@Global()
@Module({
  imports: [
    PrismaModule,
    ConfigModule,
    EmailModule,
    AuditModule,
    RedisModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigLoaderService],
      useFactory: (config: ConfigLoaderService) => {
        const jwtConfig = config.get<any>('auth').jwt;

        // Try RSA private key for RS256
        const privKeyPath = path.resolve(process.cwd(), 'keys', 'private.pem');
        let secret: string | Buffer;
        if (fs.existsSync(privKeyPath)) {
          secret = fs.readFileSync(privKeyPath);
        } else {
          secret = process.env.JWT_SECRET || 'dev-secret-change-in-production';
        }

        return {
          secret,
          signOptions: {
            algorithm: jwtConfig.algorithm,
            issuer: jwtConfig.issuer,
            audience: jwtConfig.audience,
            expiresIn: jwtConfig.accessTokenExpiry,
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PasswordService,
    TokenBlacklistService,
    LocalStrategy,
    JwtStrategy,
    GoogleStrategy,
    GitHubStrategy,
  ],
  exports: [AuthService, PasswordService, TokenBlacklistService, JwtModule],
})
export class AuthModule {}
