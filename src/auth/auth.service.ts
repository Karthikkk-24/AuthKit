import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  ForbiddenException,
  ConflictException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../database/prisma/prisma.service';
import { PasswordService } from './password.service';
import { TokenBlacklistService } from './token-blacklist.service';
import { EmailService } from '../email/email.service';
import { AuditService } from '../audit/audit.service';
import { ConfigLoaderService } from '../config/config-loader.service';
import { WebhookService, WebhookEventType } from '../webhook/webhook.service';
import { RegisterDto, LoginDto, ResetPasswordDto, ChangePasswordDto } from './dto/auth.dto';
import { CryptoService } from './crypto.service';
import * as crypto from 'crypto';
// speakeasy remains for TOTP (#48). otplib was evaluated as a replacement but
// deferred to avoid a risky mid-release MFA format migration; revisit when adding new MFA factors.
import * as speakeasy from 'speakeasy';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly passwordService: PasswordService,
    private readonly cryptoService: CryptoService,
    private readonly blacklist: TokenBlacklistService,
    private readonly email: EmailService,
    private readonly audit: AuditService,
    private readonly config: ConfigLoaderService,
    private readonly webhooks: WebhookService,
  ) {}

  /** True when MFA features are enabled globally and the given method is allowed. */
  private isMfaMethodAllowed(method: 'totp' | 'email'): boolean {
    const mfaConfig = this.config.get<any>('mfa');
    if (!mfaConfig?.enabled || !this.config.isFeatureEnabled('mfa')) return false;
    const methods: string[] = Array.isArray(mfaConfig.methods) ? mfaConfig.methods : ['totp'];
    return methods.includes(method);
  }

  private emitWebhook(event: WebhookEventType, payload: Record<string, any>) {
    void this.webhooks.dispatch(event, payload).catch((err) => {
      this.logger.warn(`Webhook dispatch failed for ${event}: ${err?.message}`);
    });
  }

  // ─────────────────────────────────────────────────────────────────────
  // REGISTRATION
  // ─────────────────────────────────────────────────────────────────────
  async register(dto: RegisterDto, req: any) {
    const regConfig = this.config.get<any>('auth').registration;
    if (!regConfig.enabled) {
      throw new ForbiddenException('Registration is currently disabled');
    }

    // Domain allowlist check
    if (regConfig.allowedDomains?.length > 0) {
      const domain = dto.email.split('@')[1];
      if (!regConfig.allowedDomains.includes(domain)) {
        throw new ForbiddenException(`Email domain @${domain} is not allowed`);
      }
    }

    // Check existing user
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (existing) {
      throw new ConflictException('Email is already registered');
    }

    // Validate password strength
    const { valid, errors } = this.passwordService.validateStrength(dto.password);
    if (!valid) {
      throw new BadRequestException(errors.join('; '));
    }

    // Check HaveIBeenPwned
    if (this.config.isFeatureEnabled('pwnedPasswordCheck')) {
      const pwned = await this.passwordService.isPwned(dto.password);
      if (pwned) {
        throw new BadRequestException(
          'This password has been found in data breaches. Please choose a different password.',
        );
      }
    }

    // Get or create default role
    const defaultRole = await this.prisma.role.findUnique({
      where: { name: regConfig.defaultRole || 'user' },
    });
    if (!defaultRole) {
      throw new BadRequestException('Default role not configured');
    }

    const passwordHash = await this.passwordService.hash(dto.password);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        name: dto.name,
        passwordHash,
        roleId: defaultRole.id,
      },
      include: { role: true },
    });

    // Send email verification
    if (regConfig.requireEmailVerification && this.config.isFeatureEnabled('emailVerification')) {
      await this.sendEmailVerification(user.id);
    }

    await this.audit.log({
      action: 'auth.register',
      userId: user.id,
      ip: req?.ip,
      userAgent: req?.headers?.['user-agent'],
      success: true,
    });

    this.emitWebhook('user.registered', {
      userId: user.id,
      email: user.email,
      name: user.name,
    });

    return { message: 'Registration successful. Please check your email to verify your account.' };
  }

  // ─────────────────────────────────────────────────────────────────────
  // EMAIL VERIFICATION
  // ─────────────────────────────────────────────────────────────────────
  async sendEmailVerification(userId: string) {
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    await this.prisma.emailVerification.create({
      data: {
        userId,
        tokenHash,
        purpose: 'email_verification',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      },
    });

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) return;

    await this.email.sendEmailVerification(user.email, user.name, token);
  }

  async verifyEmail(token: string) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const record = await this.prisma.emailVerification.findUnique({
      where: { tokenHash },
    });

    if (!record || record.purpose !== 'email_verification') {
      throw new BadRequestException('Invalid verification token');
    }
    if (record.usedAt) throw new BadRequestException('Token already used');
    if (record.expiresAt < new Date()) throw new BadRequestException('Token expired');

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: record.userId },
        data: { emailVerifiedAt: new Date() },
      }),
      this.prisma.emailVerification.update({
        where: { id: record.id },
        data: { usedAt: new Date() },
      }),
    ]);

    return { message: 'Email verified successfully' };
  }

  // ─────────────────────────────────────────────────────────────────────
  // LOGIN
  // ─────────────────────────────────────────────────────────────────────
  async validateLocalUser(email: string, password: string, req?: any) {
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: { role: { include: { permissions: true } } },
    });

    if (!user || user.deletedAt) {
      await this.auditFailedLogin({ email, reason: 'unknown_user', req });
      return null;
    }
    if (!user.passwordHash) {
      await this.auditFailedLogin({
        email,
        userId: user.id,
        reason: 'oauth_only',
        req,
      });
      return null; // OAuth-only account
    }

    // Check account lock
    if (user.isLocked) {
      const lockConfig = this.config.get<any>('security').accountLockout;
      const lockExpiry = user.lockedAt
        ? new Date(user.lockedAt.getTime() + lockConfig.lockDurationMinutes * 60 * 1000)
        : null;

      if (!lockExpiry || lockExpiry > new Date()) {
        await this.auditFailedLogin({
          email,
          userId: user.id,
          reason: 'account_locked',
          req,
        });
        throw new ForbiddenException(
          `Account is locked${lockExpiry ? ` until ${lockExpiry.toISOString()}` : ''}. Reason: ${user.lockReason || 'Too many failed attempts'}`,
        );
      }

      // Auto-unlock after duration
      await this.prisma.user.update({
        where: { id: user.id },
        data: { isLocked: false, lockedAt: null, failedLoginAttempts: 0 },
      });
    }

    const valid = await this.passwordService.verify(user.passwordHash, password);
    if (!valid) {
      await this.handleFailedLogin(user, req);
      return null;
    }

    // Reset failed attempts on successful verification
    await this.prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0 },
    });

    return user;
  }

  /** Honor audit.logFailedLogins; never store passwords or tokens (#38). */
  private async auditFailedLogin(input: {
    email: string;
    userId?: string;
    reason: string;
    req?: any;
  }) {
    const auditCfg = this.config.get<any>('audit') ?? {};
    if (!auditCfg.logFailedLogins) return;
    await this.audit.log({
      action: 'auth.login',
      userId: input.userId,
      ip: input.req?.ip,
      userAgent: input.req?.headers?.['user-agent'],
      success: false,
      metadata: {
        reason: input.reason,
        // Redact to domain-safe identifier only when configured
        email: this.redactEmail(input.email, auditCfg),
      },
    });
  }

  private redactEmail(email: string, auditCfg: any): string {
    const sensitive: string[] = auditCfg.sensitiveFieldsToRedact ?? [];
    if (sensitive.includes('email') || sensitive.includes('password')) {
      const [local, domain] = email.split('@');
      if (!domain) return '[redacted]';
      return `${local.slice(0, 1)}***@${domain}`;
    }
    return email;
  }

  private async handleFailedLogin(user: any, req?: any) {
    const lockConfig = this.config.get<any>('security').accountLockout;
    if (!lockConfig.enabled) {
      await this.auditFailedLogin({
        email: user.email,
        userId: user.id,
        reason: 'invalid_password',
        req,
      });
      return;
    }

    const newAttempts = user.failedLoginAttempts + 1;
    const shouldLock = newAttempts >= lockConfig.maxAttempts;

    // Progressive delay: slow down successive failures to blunt brute force (#22)
    if (lockConfig.progressiveDelay && !shouldLock) {
      const delayMs = Math.min(2 ** (newAttempts - 1) * 500, 10_000);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: newAttempts,
        isLocked: shouldLock,
        lockedAt: shouldLock ? new Date() : undefined,
        lockReason: shouldLock ? 'Too many failed login attempts' : undefined,
      },
    });

    await this.auditFailedLogin({
      email: user.email,
      userId: user.id,
      reason: shouldLock ? 'locked_after_failures' : 'invalid_password',
      req,
    });

    if (shouldLock) {
      await this.email.sendAccountLocked(user.email, user.name).catch(() => {});
    }
  }

  async login(user: any, dto: LoginDto, req: any) {
    const authConfig = this.config.get<any>('auth');
    const regConfig = authConfig.registration;
    const mfaConfig = this.config.get<any>('mfa');

    // Email verification check
    if (regConfig.requireEmailVerification && !user.emailVerifiedAt) {
      throw new ForbiddenException(
        'Please verify your email before logging in',
      );
    }

    // MFA check — enforced for opted-in users, and required for configured
    // roles (#23). When a required-role user hasn't enrolled yet they are
    // told to enroll before a session is created.
    const roleName = user.role?.name;
    const mfaMandatory =
      mfaConfig?.required === true ||
      (Array.isArray(mfaConfig?.requiredForRoles) &&
        roleName != null &&
        mfaConfig.requiredForRoles.includes(roleName));

    if (user.isMfaEnabled || mfaMandatory) {
      if (!user.isMfaEnabled && mfaMandatory) {
        // Enrollment flow: issue a short-lived, scope-limited token that only
        // permits calling the MFA setup endpoints.
        const setupToken = await this.jwt.signAsync(
          {
            sub: user.id,
            email: user.email,
            roleId: user.roleId,
            roleName: user.role?.name,
            type: 'mfa_setup',
          },
          { expiresIn: '10m' },
        );
        return {
          mfaSetupRequired: true,
          setupToken,
          tokenType: 'Bearer',
          expiresIn: '10m',
          message: `MFA is required for the "${roleName}" role. Use the setup token to configure an authenticator via /auth/mfa/totp/*, then sign in again.`,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role?.name,
          },
        };
      }
      if (!dto.mfaCode) {
        return { requiresMfa: true, userId: user.id };
      }
      // Backup codes are accepted in the mfaCode field so the client does not
      // need to know which factor the user typed (#23).
      await this.verifyMfaWithFallback(user.id, dto.mfaCode);
    }

    return this.createTokens(user, req);
  }

  async createTokens(
    user: any,
    req: any,
    opts: { auditAction?: 'auth.login' | 'auth.refresh' | null } = {
      auditAction: 'auth.login',
    },
  ) {
    const jwtConfig = this.config.get<any>('auth').jwt;
    const sessionConfig = this.config.get<any>('session');

    // Enforce max concurrent sessions
    if (sessionConfig.maxConcurrentSessions > 0) {
      const activeSessions = await this.prisma.session.count({
        where: { userId: user.id, isRevoked: false, expiresAt: { gt: new Date() } },
      });
      if (activeSessions >= sessionConfig.maxConcurrentSessions) {
        // Revoke oldest session
        const oldest = await this.prisma.session.findFirst({
          where: { userId: user.id, isRevoked: false },
          orderBy: { createdAt: 'asc' },
        });
        if (oldest) {
          await this.prisma.session.update({
            where: { id: oldest.id },
            data: { isRevoked: true, revokedAt: new Date() },
          });
        }
      }
    }

    // Parse device info from UA
    const uaParser = require('ua-parser-js');
    const ua = req?.headers?.['user-agent'] || '';
    const parsed = uaParser(ua);

    const refreshToken = crypto.randomBytes(40).toString('hex');
    const refreshTokenHash = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const refreshExpiry = this.parseExpiry(jwtConfig.refreshTokenExpiry);

    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshTokenHash,
        ip: req?.ip,
        userAgent: ua,
        deviceName: parsed.device.model || 'Unknown',
        deviceType: parsed.device.type || 'desktop',
        browser: `${parsed.browser.name || ''} ${parsed.browser.version || ''}`.trim(),
        os: `${parsed.os.name || ''} ${parsed.os.version || ''}`.trim(),
        expiresAt: new Date(Date.now() + refreshExpiry),
        lastActiveAt: new Date(),
      },
    });

    const payload = {
      sub: user.id,
      email: user.email,
      roleId: user.roleId,
      roleName: user.role?.name,
      sessionId: session.id,
      type: 'access',
    };

    const accessToken = await this.jwt.signAsync(payload, {
      expiresIn: jwtConfig.accessTokenExpiry,
    });

    // Update last login
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date(), lastLoginIp: req?.ip },
    });

    const auditCfg = this.config.get<any>('audit') ?? {};
    const action = opts.auditAction ?? null;
    if (action === 'auth.login' && auditCfg.logSuccessfulLogins !== false) {
      await this.audit.log({
        action: 'auth.login',
        userId: user.id,
        ip: req?.ip,
        userAgent: ua,
        success: true,
      });
    } else if (action === 'auth.refresh' && auditCfg.logTokenRefresh) {
      await this.audit.log({
        action: 'auth.refresh',
        userId: user.id,
        ip: req?.ip,
        userAgent: ua,
        success: true,
      });
    }

    if (action === 'auth.login') {
      this.emitWebhook('user.login', {
        userId: user.id,
        email: user.email,
        sessionId: session.id,
      });
    }

    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: jwtConfig.accessTokenExpiry,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role?.name,
        avatarUrl: user.avatarUrl,
        emailVerifiedAt: user.emailVerifiedAt,
        isMfaEnabled: user.isMfaEnabled,
      },
    };
  }

  // ─────────────────────────────────────────────────────────────────────
  // REFRESH TOKEN
  // ─────────────────────────────────────────────────────────────────────
  async refreshTokens(refreshToken: string, req: any) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const session = await this.prisma.session.findFirst({
      where: { refreshTokenHash: tokenHash, isRevoked: false },
      include: { user: { include: { role: { include: { permissions: true } } } } },
    });

    if (!session) {
      const auditCfg = this.config.get<any>('audit') ?? {};
      if (auditCfg.logTokenRefresh) {
        await this.audit.log({
          action: 'auth.refresh',
          ip: req?.ip,
          userAgent: req?.headers?.['user-agent'],
          success: false,
          metadata: { reason: 'invalid_refresh_token' },
        });
      }
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    if (session.expiresAt < new Date()) {
      await this.prisma.session.update({
        where: { id: session.id },
        data: { isRevoked: true, revokedAt: new Date() },
      });
      const auditCfg = this.config.get<any>('audit') ?? {};
      if (auditCfg.logTokenRefresh) {
        await this.audit.log({
          action: 'auth.refresh',
          userId: session.userId,
          ip: req?.ip,
          userAgent: req?.headers?.['user-agent'],
          success: false,
          metadata: { reason: 'refresh_expired' },
        });
      }
      throw new UnauthorizedException('Refresh token expired');
    }

    if (!session.user || session.user.deletedAt || session.user.isLocked) {
      throw new UnauthorizedException('User account is not accessible');
    }

    // Rotate: revoke old session, create new tokens
    await this.prisma.session.update({
      where: { id: session.id },
      data: { isRevoked: true, revokedAt: new Date() },
    });

    return this.createTokens(session.user, req, { auditAction: 'auth.refresh' });
  }

  // ─────────────────────────────────────────────────────────────────────
  // LOGOUT
  // ─────────────────────────────────────────────────────────────────────
  async logout(userId: string, sessionId: string, accessToken: string, req: any) {
    const jwtConfig = this.config.get<any>('auth').jwt;
    const ttl = this.parseExpiry(jwtConfig.accessTokenExpiry);

    // Blacklist the access token
    await this.blacklist.blacklist(accessToken, Math.ceil(ttl / 1000));

    // Revoke session
    if (sessionId) {
      await this.prisma.session.updateMany({
        where: { id: sessionId, userId },
        data: { isRevoked: true, revokedAt: new Date() },
      });
    }

    await this.audit.log({
      action: 'auth.logout',
      userId,
      ip: req?.ip,
      userAgent: req?.headers?.['user-agent'],
      success: true,
    });

    this.emitWebhook('user.logout', { userId, sessionId });

    return { message: 'Logged out successfully' };
  }

  async logoutAll(userId: string, currentAccessToken: string, req: any) {
    const jwtConfig = this.config.get<any>('auth').jwt;
    const ttl = this.parseExpiry(jwtConfig.accessTokenExpiry);

    await this.blacklist.blacklist(currentAccessToken, Math.ceil(ttl / 1000));

    await this.prisma.session.updateMany({
      where: { userId, isRevoked: false },
      data: { isRevoked: true, revokedAt: new Date() },
    });

    await this.audit.log({
      action: 'auth.logout_all',
      userId,
      ip: req?.ip,
      userAgent: req?.headers?.['user-agent'],
      success: true,
    });

    return { message: 'Logged out from all devices' };
  }

  // ─────────────────────────────────────────────────────────────────────
  // PASSWORD RESET
  // ─────────────────────────────────────────────────────────────────────
  async forgotPassword(email: string, req: any) {
    const user = await this.prisma.user.findUnique({ where: { email } });

    // Always return success to prevent user enumeration
    if (!user || user.deletedAt || !user.passwordHash) {
      return { message: 'If that email exists, a reset link has been sent' };
    }

    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    await this.prisma.passwordReset.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      },
    });

    await this.email.sendPasswordReset(user.email, user.name, token);

    await this.audit.log({
      action: 'auth.forgot_password',
      userId: user.id,
      ip: req?.ip,
      success: true,
    });

    return { message: 'If that email exists, a reset link has been sent' };
  }

  async resetPassword(dto: ResetPasswordDto, req: any) {
    const tokenHash = crypto.createHash('sha256').update(dto.token).digest('hex');
    const record = await this.prisma.passwordReset.findUnique({ where: { tokenHash } });

    if (!record) throw new BadRequestException('Invalid reset token');
    if (record.usedAt) throw new BadRequestException('Token already used');
    if (record.expiresAt < new Date()) throw new BadRequestException('Token expired');

    const { valid, errors } = this.passwordService.validateStrength(dto.newPassword);
    if (!valid) throw new BadRequestException(errors.join('; '));

    if (this.config.isFeatureEnabled('pwnedPasswordCheck')) {
      const pwned = await this.passwordService.isPwned(dto.newPassword);
      if (pwned) throw new BadRequestException('Password found in data breaches');
    }

    const newHash = await this.passwordService.hash(dto.newPassword);

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: record.userId },
        data: { passwordHash: newHash },
      }),
      this.prisma.passwordReset.update({
        where: { id: record.id },
        data: { usedAt: new Date() },
      }),
      // Revoke all sessions (force re-login everywhere)
      this.prisma.session.updateMany({
        where: { userId: record.userId },
        data: { isRevoked: true, revokedAt: new Date() },
      }),
    ]);

    await this.audit.log({
      action: 'auth.password_reset',
      userId: record.userId,
      ip: req?.ip,
      success: true,
    });

    return { message: 'Password reset successfully. Please log in with your new password.' };
  }

  async changePassword(userId: string, dto: ChangePasswordDto, req: any, currentSessionId?: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.passwordHash) {
      throw new BadRequestException('Cannot change password for OAuth-only accounts');
    }

    const valid = await this.passwordService.verify(user.passwordHash, dto.currentPassword);
    if (!valid) throw new UnauthorizedException('Current password is incorrect');

    const { valid: strongEnough, errors } = this.passwordService.validateStrength(dto.newPassword);
    if (!strongEnough) throw new BadRequestException(errors.join('; '));

    if (this.config.isFeatureEnabled('pwnedPasswordCheck')) {
      const pwned = await this.passwordService.isPwned(dto.newPassword);
      if (pwned) throw new BadRequestException('Password found in data breaches');
    }

    const newHash = await this.passwordService.hash(dto.newPassword);

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: userId },
        data: { passwordHash: newHash },
      }),
      // Revoke every *other* session so a stolen session dies on password change (#21).
      // The session performing the change stays valid (conventional UX).
      this.prisma.session.updateMany({
        where: {
          userId,
          isRevoked: false,
          ...(currentSessionId ? { id: { not: currentSessionId } } : {}),
        },
        data: { isRevoked: true, revokedAt: new Date() },
      }),
    ]);

    await this.audit.log({
      action: 'auth.password_changed',
      userId,
      ip: req?.ip,
      metadata: { revokedOtherSessions: true },
      success: true,
    });

    this.emitWebhook('user.password_changed', { userId });

    return { message: 'Password changed successfully. Other sessions have been signed out.' };
  }

  // ─────────────────────────────────────────────────────────────────────
  // OAUTH
  // ─────────────────────────────────────────────────────────────────────
  async findOrCreateOAuthUser(profile: {
    provider: 'google' | 'github';
    providerId: string;
    email: string;
    name: string;
    avatarUrl?: string;
  }) {
    const providerField = profile.provider === 'google' ? 'googleId' : 'githubId';

    // Try to find by provider ID (already-linked account)
    let user = await this.prisma.user.findFirst({
      where: { [providerField]: profile.providerId },
      include: { role: { include: { permissions: true } } },
    });

    if (user) {
      return user;
    }

    if (profile.email) {
      const existingByEmail = await this.prisma.user.findUnique({
        where: { email: profile.email },
        include: { role: { include: { permissions: true } } },
      });

      if (existingByEmail) {
        // Do NOT silently link OAuth to an existing password/email account.
        // Silent email-based linking enables account takeover if an attacker
        // controls an OAuth identity for the victim's email address.
        throw new ConflictException(
          `An account with this email already exists. Sign in with your existing credentials instead of linking via ${profile.provider} automatically.`,
        );
      }
    }

    // Create new OAuth-only user
    const defaultRole = await this.prisma.role.findUnique({
      where: { name: 'user' },
    });

    user = await this.prisma.user.create({
      data: {
        email: profile.email,
        name: profile.name,
        avatarUrl: profile.avatarUrl,
        emailVerifiedAt: new Date(), // OAuth emails are pre-verified by the provider
        roleId: defaultRole!.id,
        [providerField]: profile.providerId,
      },
      include: { role: { include: { permissions: true } } },
    });

    return user;
  }

  // ─────────────────────────────────────────────────────────────────────
  // MFA
  // ─────────────────────────────────────────────────────────────────────
  /** Decrypt a stored TOTP secret, tolerating legacy plaintext values. */
  private decryptTotpSecret(stored: string): string {
    // Encrypted payloads have the iv.tag.data dot-separated shape.
    if (stored.includes('.')) {
      try {
        return this.cryptoService.decrypt(stored);
      } catch (err) {
        this.logger.error('Failed to decrypt TOTP secret', err);
        throw new UnauthorizedException('MFA credential is corrupted');
      }
    }
    return stored; // legacy plaintext
  }

  async setupTotp(userId: string) {
    if (!this.isMfaMethodAllowed('totp')) {
      throw new BadRequestException('TOTP MFA is disabled');
    }
    const mfaConfig = this.config.get<any>('mfa');
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    const secret = speakeasy.generateSecret({
      name: `${mfaConfig.totpIssuer}:${user.email}`,
      issuer: mfaConfig.totpIssuer,
    });

    // Encrypt the shared secret at rest (#23); decrypt via decryptTotpSecret.
    const encryptedSecret = this.cryptoService.encrypt(secret.base32);

    // Store (not yet enabled — user must verify first)
    await this.prisma.mfaCredential.upsert({
      where: { userId_type: { userId, type: 'TOTP' } },
      create: {
        userId,
        type: 'TOTP',
        secret: encryptedSecret,
        isEnabled: false,
      },
      update: {
        secret: encryptedSecret,
        isEnabled: false,
      },
    });

    const QRCode = require('qrcode');
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url!);

    return { secret: secret.base32, qrCode: qrCodeUrl };
  }

  async enableTotp(userId: string, code: string) {
    if (!this.isMfaMethodAllowed('totp')) {
      throw new BadRequestException('TOTP MFA is disabled');
    }
    const cred = await this.prisma.mfaCredential.findUnique({
      where: { userId_type: { userId, type: 'TOTP' } },
    });
    if (!cred || !cred.secret) throw new BadRequestException('TOTP not set up');

    const valid = speakeasy.totp.verify({
      secret: this.decryptTotpSecret(cred.secret),
      encoding: 'base32',
      token: code,
      window: 1,
    });
    if (!valid) throw new BadRequestException('Invalid TOTP code');

    // Generate backup codes
    const mfaConfig = this.config.get<any>('mfa');
    const backupCodes: string[] = [];
    const hashedBackupCodes: string[] = [];

    for (let i = 0; i < (mfaConfig.backupCodesCount || 10); i++) {
      const code = crypto.randomBytes(4).toString('hex');
      backupCodes.push(code);
      hashedBackupCodes.push(
        crypto.createHash('sha256').update(code).digest('hex'),
      );
    }

    await this.prisma.$transaction([
      this.prisma.mfaCredential.update({
        where: { userId_type: { userId, type: 'TOTP' } },
        data: { isEnabled: true, verifiedAt: new Date(), backupCodes: hashedBackupCodes },
      }),
      this.prisma.user.update({
        where: { id: userId },
        data: { isMfaEnabled: true },
      }),
    ]);

    this.emitWebhook('mfa.enabled', { userId, method: 'totp' });

    return { message: 'TOTP MFA enabled', backupCodes };
  }

  async verifyMfa(userId: string, code: string, isBackupCode: boolean) {
    const cred = await this.prisma.mfaCredential.findUnique({
      where: { userId_type: { userId, type: 'TOTP' } },
    });
    if (!cred || !cred.isEnabled) {
      throw new BadRequestException('MFA not configured');
    }

    if (isBackupCode) {
      const hash = crypto.createHash('sha256').update(code).digest('hex');
      const idx = cred.backupCodes.indexOf(hash);
      if (idx === -1) throw new UnauthorizedException('Invalid backup code');

      // Single-use: remove the code
      const remaining = [...cred.backupCodes];
      remaining.splice(idx, 1);
      await this.prisma.mfaCredential.update({
        where: { userId_type: { userId, type: 'TOTP' } },
        data: { backupCodes: remaining },
      });
      return true;
    }

    const valid = speakeasy.totp.verify({
      secret: this.decryptTotpSecret(cred.secret!),
      encoding: 'base32',
      token: code,
      window: 1,
    });
    if (!valid) throw new UnauthorizedException('Invalid MFA code');
    return true;
  }

  /**
   * During login, accept whichever enabled factor the user provided —
   * TOTP, an EMAIL OTP, or a backup code — without the client having to
   * declare the factor type (#18, #23).
   */
  private async verifyMfaWithFallback(userId: string, code: string) {
    if (!code) throw new UnauthorizedException('MFA code is required');

    // 1) TOTP against the enrolled credential.
    try {
      await this.verifyMfa(userId, code, false);
      return true;
    } catch {
      // not a valid TOTP (or TOTP not enrolled) — keep trying
    }

    // 2) Single-use backup code on the TOTP credential.
    try {
      await this.verifyMfa(userId, code, true);
      return true;
    } catch {
      // not a backup code either — keep trying
    }

    // 3) Pending EMAIL OTP.
    await this.verifyEmailOtpCodeOnly(userId, code);
    return true;
  }

  /**
   * Validate a pending EMAIL OTP without enabling the factor
   * (login-time proof). Consumes the code on success.
   */
  private async verifyEmailOtpCodeOnly(userId: string, code: string) {
    const redis = this.redisClient;
    if (!redis) throw new UnauthorizedException('Invalid MFA code');
    const key = `${this.config.get<any>('redis')?.prefix ?? 'authkit:'}mfa:email:${userId}`;
    const storedHash = await redis.get(key);
    if (!storedHash) throw new UnauthorizedException('Invalid MFA code');
    const hash = crypto.createHash('sha256').update(code).digest('hex');
    if (hash !== storedHash) throw new UnauthorizedException('Invalid MFA code');
    await redis.del(key);
    return true;
  }

  async disableMfa(userId: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user?.passwordHash) throw new BadRequestException('Cannot verify identity');

    const valid = await this.passwordService.verify(user.passwordHash, password);
    if (!valid) throw new UnauthorizedException('Incorrect password');

    await this.prisma.$transaction([
      this.prisma.mfaCredential.deleteMany({ where: { userId } }),
      this.prisma.user.update({
        where: { id: userId },
        data: { isMfaEnabled: false },
      }),
    ]);

    this.emitWebhook('mfa.disabled', { userId });

    return { message: 'MFA disabled' };
  }

  // ─── EMAIL OTP MFA (#18) ────────────────────────────────────────────
  private get redisClient(): import('ioredis').Redis | null {
    // Lazy: token-blacklist service owns the Redis connection.
    return (this.blacklist as any).redis ?? null;
  }

  async sendEmailOtp(userId: string) {
    if (!this.isMfaMethodAllowed('email')) {
      throw new BadRequestException('Email MFA is disabled');
    }
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    const otp = crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
    const key = `${this.config.get<any>('redis')?.prefix ?? 'authkit:'}mfa:email:${userId}`;
    const redis = this.redisClient;
    if (!redis) throw new BadRequestException('Email MFA is temporarily unavailable');

    await redis.set(key, crypto.createHash('sha256').update(otp).digest('hex'), 'EX', 600);

    await this.email.sendEmailOtp(user.email, user.name, otp);
    return { message: 'Verification code sent' };
  }

  async verifyEmailOtp(userId: string, code: string) {
    if (!this.isMfaMethodAllowed('email')) {
      throw new BadRequestException('Email MFA is disabled');
    }
    if (!/^\d{6}$/.test(code)) throw new BadRequestException('Invalid code format');

    const redis = this.redisClient;
    if (!redis) throw new BadRequestException('Email MFA is temporarily unavailable');

    const key = `${this.config.get<any>('redis')?.prefix ?? 'authkit:'}mfa:email:${userId}`;
    const storedHash = await redis.get(key);
    if (!storedHash) throw new UnauthorizedException('Code expired or not requested');

    const hash = crypto.createHash('sha256').update(code).digest('hex');
    if (hash !== storedHash) throw new UnauthorizedException('Invalid code');

    await redis.del(key);

    // Mark EMAIL MFA as verified/enabled as a side effect of proving control.
    await this.prisma.$transaction([
      this.prisma.mfaCredential.upsert({
        where: { userId_type: { userId, type: 'EMAIL' } },
        create: { userId, type: 'EMAIL', isEnabled: true, verifiedAt: new Date() },
        update: { isEnabled: true, verifiedAt: new Date() },
      }),
      this.prisma.user.update({ where: { id: userId }, data: { isMfaEnabled: true } }),
    ]);

    return { message: 'Email MFA verified' };
  }

  // ─────────────────────────────────────────────────────────────────────
  // MAGIC LINK
  // ─────────────────────────────────────────────────────────────────────
  async sendMagicLink(email: string, req: any) {
    if (
      !this.config.isStrategyEnabled('magicLink') &&
      !this.config.isFeatureEnabled('magicLink')
    ) {
      throw new BadRequestException('Magic link authentication is disabled');
    }

    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user || user.deletedAt) {
      return { message: 'If that email exists, a magic link has been sent' };
    }

    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    await this.prisma.emailVerification.create({
      data: {
        userId: user.id,
        tokenHash,
        purpose: 'magic_link',
        expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      },
    });

    await this.email.sendMagicLink(user.email, user.name, token);
    return { message: 'If that email exists, a magic link has been sent' };
  }

  async verifyMagicLink(token: string, req: any) {
    if (
      !this.config.isStrategyEnabled('magicLink') &&
      !this.config.isFeatureEnabled('magicLink')
    ) {
      throw new BadRequestException('Magic link authentication is disabled');
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const record = await this.prisma.emailVerification.findUnique({
      where: { tokenHash },
      include: { user: { include: { role: { include: { permissions: true } } } } },
    });

    // Reject email-verification (and other) tokens — only magic_link may mint sessions.
    if (!record || record.purpose !== 'magic_link') {
      throw new BadRequestException('Invalid magic link');
    }
    if (record.usedAt) throw new BadRequestException('Magic link already used');
    if (record.expiresAt < new Date()) throw new BadRequestException('Magic link expired');
    if (record.user.deletedAt || record.user.isLocked) {
      throw new UnauthorizedException('Account is not allowed to sign in');
    }

    await this.prisma.emailVerification.update({
      where: { id: record.id },
      data: { usedAt: new Date() },
    });

    return this.createTokens(record.user, req);
  }

  // ─────────────────────────────────────────────────────────────────────
  // OAUTH ONE-TIME CODE EXCHANGE (no tokens in redirect URLs)
  // ─────────────────────────────────────────────────────────────────────
  /**
   * After OAuth callback, store a short-lived one-time code instead of
   * putting access/refresh tokens in the redirect query string.
   */
  async createOAuthExchangeCode(userId: string): Promise<string> {
    const code = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(code).digest('hex');

    await this.prisma.emailVerification.create({
      data: {
        userId,
        tokenHash,
        purpose: 'oauth_exchange',
        expiresAt: new Date(Date.now() + 60 * 1000), // 60 seconds
      },
    });

    return code;
  }

  async exchangeOAuthCode(code: string, req: any) {
    if (!code || typeof code !== 'string') {
      throw new BadRequestException('Invalid OAuth exchange code');
    }

    const tokenHash = crypto.createHash('sha256').update(code).digest('hex');
    const record = await this.prisma.emailVerification.findUnique({
      where: { tokenHash },
      include: { user: { include: { role: { include: { permissions: true } } } } },
    });

    if (!record || record.purpose !== 'oauth_exchange') {
      throw new BadRequestException('Invalid or expired OAuth exchange code');
    }
    if (record.usedAt) throw new BadRequestException('OAuth exchange code already used');
    if (record.expiresAt < new Date()) {
      throw new BadRequestException('OAuth exchange code expired');
    }
    if (record.user.deletedAt || record.user.isLocked) {
      throw new UnauthorizedException('Account is not allowed to sign in');
    }

    await this.prisma.emailVerification.update({
      where: { id: record.id },
      data: { usedAt: new Date() },
    });

    return this.createTokens(record.user, req);
  }

  // ─────────────────────────────────────────────────────────────────────
  // HELPERS
  // ─────────────────────────────────────────────────────────────────────
  private parseExpiry(expiry: string): number {
    const unit = expiry.slice(-1);
    const value = parseInt(expiry.slice(0, -1), 10);
    const multipliers: Record<string, number> = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
    };
    return value * (multipliers[unit] || 1000);
  }
}
