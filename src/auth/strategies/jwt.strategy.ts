import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigLoaderService } from '../../config/config-loader.service';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly config: ConfigLoaderService) {
    const jwtConfig = config.get<any>('auth').jwt;

    // Load RSA public key for RS256 verification
    let publicKey: string;
    const pubKeyPath = path.resolve(process.cwd(), 'keys', 'public.pem');
    if (fs.existsSync(pubKeyPath)) {
      publicKey = fs.readFileSync(pubKeyPath, 'utf-8');
    } else {
      // Fallback: symmetric secret for development
      publicKey = process.env.JWT_SECRET || 'dev-secret-change-in-production';
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: publicKey,
      algorithms: [jwtConfig.algorithm],
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience,
    });
  }

  async validate(payload: any) {
    return {
      id: payload.sub,
      email: payload.email,
      roleId: payload.roleId,
      roleName: payload.roleName,
      sessionId: payload.sessionId,
      isApiKeyAuth: false,
    };
  }
}
