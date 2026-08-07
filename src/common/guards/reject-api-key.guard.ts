import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';

/**
 * Blocks API-key principals from interactive / account-lifecycle routes (#147).
 * Machine credentials must not mint MFA, change passwords, self-delete, or
 * create additional API keys — those require an interactive user session JWT.
 */
@Injectable()
export class RejectApiKeyGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const user = context.switchToHttp().getRequest()?.user;
    if (user?.isApiKeyAuth) {
      throw new ForbiddenException(
        'This endpoint requires an interactive user session (API keys are not allowed)',
      );
    }
    return true;
  }
}
