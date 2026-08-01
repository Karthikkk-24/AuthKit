import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigLoaderService } from '../../config/config-loader.service';
import { resolveJwtKeys } from '../jwt-keys.util';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly config: ConfigLoaderService) {
    const jwtConfig = config.get<any>('auth').jwt;
    const keys = resolveJwtKeys(jwtConfig.algorithm);

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: keys.publicKey,
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
