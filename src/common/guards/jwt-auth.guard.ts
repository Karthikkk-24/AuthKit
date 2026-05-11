import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { TokenBlacklistService } from '../../auth/token-blacklist.service';
import { ConfigLoaderService } from '../../config/config-loader.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwtService: JwtService,
    private readonly tokenBlacklist: TokenBlacklistService,
    private readonly config: ConfigLoaderService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check @Public() decorator
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest();
    const token = this.extractToken(request);

    if (!token) {
      throw new UnauthorizedException('No authentication token provided');
    }

    // Check blacklist
    const isBlacklisted = await this.tokenBlacklist.isBlacklisted(token);
    if (isBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    try {
      const jwtConfig = this.config.get<any>('auth').jwt;
      const payload = await this.jwtService.verifyAsync(token, {
        algorithms: [jwtConfig.algorithm],
        issuer: jwtConfig.issuer,
        audience: jwtConfig.audience,
      });
      request['user'] = payload;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    return true;
  }

  private extractToken(request: any): string | null {
    // Authorization: Bearer <token>
    const authHeader = request.headers?.['authorization'];
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    // Cookie: access_token=<token>
    if (request.cookies?.access_token) {
      return request.cookies.access_token;
    }
    return null;
  }
}
