import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-github2';
import { ConfigLoaderService } from '../../config/config-loader.service';
import { AuthService } from '../auth.service';

@Injectable()
export class GitHubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(
    private readonly config: ConfigLoaderService,
    private readonly authService: AuthService,
  ) {
    const githubConfig = config.get<any>('auth').strategies.github;
    super({
      clientID: githubConfig.clientId,
      clientSecret: githubConfig.clientSecret,
      callbackURL: githubConfig.callbackUrl,
      scope: ['user:email'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: Function,
  ): Promise<any> {
    const email =
      profile.emails?.find((e: any) => e.primary)?.value ??
      profile.emails?.[0]?.value;

    try {
      const user = await this.authService.findOrCreateOAuthUser({
        provider: 'github',
        providerId: String(profile.id),
        email,
        name: profile.displayName || profile.username,
        avatarUrl: profile.photos?.[0]?.value,
      });
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }
}
