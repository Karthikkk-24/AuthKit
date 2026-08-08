import { Injectable, ForbiddenException, ConflictException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigLoaderService } from '../../config/config-loader.service';
import { AuthService } from '../auth.service';
import {
  SignedCookieOAuthStateStore,
  resolveOAuthStateSecret,
} from '../oauth-state.store';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly config: ConfigLoaderService,
    private readonly authService: AuthService,
  ) {
    const googleConfig = config.get<any>('auth').strategies.google;
    super({
      clientID: googleConfig.clientId,
      clientSecret: googleConfig.clientSecret,
      callbackURL: googleConfig.callbackUrl,
      scope: ['email', 'profile'],
      // CSRF: signed cookie state store — never Passport NullStore (#127)
      state: true,
      store: new SignedCookieOAuthStateStore(resolveOAuthStateSecret()),
    } as any);
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, emails, displayName, photos } = profile;
    const email = emails?.[0]?.value;
    const avatarUrl = photos?.[0]?.value;

    try {
      const user = await this.authService.findOrCreateOAuthUser({
        provider: 'google',
        providerId: id,
        email,
        name: displayName,
        avatarUrl,
      });
      done(null, user);
    } catch (err) {
      // Surface policy failures to the callback as a stable redirect reason (#88)
      if (err instanceof ForbiddenException) {
        done(null, { oauthError: 'registration_disabled' });
        return;
      }
      if (err instanceof ConflictException) {
        done(null, { oauthError: 'account_exists' });
        return;
      }
      done(err as Error, false);
    }
  }
}
