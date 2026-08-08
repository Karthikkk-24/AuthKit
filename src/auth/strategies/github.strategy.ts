import { Injectable, ForbiddenException, ConflictException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-github2';
import { ConfigLoaderService } from '../../config/config-loader.service';
import { AuthService } from '../auth.service';
import {
  SignedCookieOAuthStateStore,
  resolveOAuthStateSecret,
} from '../oauth-state.store';

@Injectable()
export class GitHubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(
    private readonly config: ConfigLoaderService,
    private readonly authService: AuthService,
  ) {
    const githubConfig = config.get<any>('auth').strategies.github;
    // passport-github2 types omit `store`; runtime passport-oauth2 supports it (#127)
    super({
      clientID: githubConfig.clientId,
      clientSecret: githubConfig.clientSecret,
      callbackURL: githubConfig.callbackUrl,
      scope: ['user:email'],
      state: true,
      store: new SignedCookieOAuthStateStore(resolveOAuthStateSecret()),
    } as any);
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: (err: any, user?: any) => void,
  ): Promise<any> {
    const emails: any[] = Array.isArray(profile.emails) ? profile.emails : [];
    // Prefer primary verified, then any verified (#149)
    const verified =
      emails.find((e) => e?.primary && e?.verified) ??
      emails.find((e) => e?.verified) ??
      null;
    const email = verified?.value ?? emails.find((e) => e?.primary)?.value ?? emails[0]?.value;
    const emailVerified = Boolean(verified?.value);

    if (!email || typeof email !== 'string') {
      // Stable redirect — GitHub apps need user:email + a visible address (#150).
      done(null, { oauthError: 'email_required' });
      return;
    }

    try {
      const user = await this.authService.findOrCreateOAuthUser({
        provider: 'github',
        providerId: String(profile.id),
        email,
        emailVerified,
        name: profile.displayName || profile.username,
        avatarUrl: profile.photos?.[0]?.value,
      });
      done(null, user);
    } catch (err) {
      // Surface policy failures to the callback as a stable redirect reason (#88)
      if (err instanceof ForbiddenException) {
        const msg = String((err as any).message ?? '');
        let oauthError = 'registration_disabled';
        if (msg.includes('verified')) oauthError = 'email_unverified';
        else if (msg.includes('email')) oauthError = 'email_required';
        done(null, { oauthError });
        return;
      }
      if (err instanceof ConflictException) {
        done(null, { oauthError: 'account_exists' });
        return;
      }
      done(err, false);
    }
  }
}
