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

  /**
   * Mandatory MFA must not lock roles out when enrollment is impossible (#144).
   * Same flags as `isMfaMethodAllowed` — at least one method must be usable.
   */
  private isMfaEnrollmentPossible(): boolean {
    return this.isMfaMethodAllowed('totp') || this.isMfaMethodAllowed('email');
  }

  /** Sanitized DB profile for GET /auth/me (#78). */
  async getProfile(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { role: true },
    });
    if (!user || user.deletedAt) throw new NotFoundException('User not found');
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      avatarUrl: user.avatarUrl,
      role: user.role?.name,
      roleId: user.roleId,
      emailVerifiedAt: user.emailVerifiedAt,
      isMfaEnabled: user.isMfaEnabled,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
    };
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
    if (!regConfig.enabled || !this.config.isFeatureEnabled('registration')) {
      throw new ForbiddenException('Registration is currently disabled');
    }

    // Domain allowlist check
    if (regConfig.allowedDomains?.length > 0) {
      const domain = dto.email.split('@')[1];
      if (!regConfig.allowedDomains.includes(domain)) {
        throw new ForbiddenException(`Email domain @${domain} is not allowed`);
      }
    }

    // Check existing user — soft-deleted rows must not block re-registration (#114).
    // Active emails must not return 409 (enumeration) (#116).
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (existing?.deletedAt) {
      await this.prisma.user.update({
        where: { id: existing.id },
        data: {
          email: `deleted+${existing.id}@deleted.invalid`,
          googleId: null,
          githubId: null,
        },
      });
    }

    // Validate password strength (same checks whether or not email exists)
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

    const successMessage = this.isEmailVerificationEnforced()
      ? 'Registration successful. Please check your email to verify your account.'
      : 'Registration successful.';

    if (existing && !existing.deletedAt) {
      // Match create-path work roughly; do not disclose that the email exists (#116).
      await this.passwordService.hash(dto.password);
      void this.email
        .sendAccountAlreadyRegistered(existing.email, existing.name)
        .catch((err) => {
          this.logger.warn(
            `Failed to send already-registered notice: ${err?.message ?? err}`,
          );
        });
      await this.audit.log({
        action: 'auth.register',
        userId: existing.id,
        ip: req?.ip,
        userAgent: req?.headers?.['user-agent'],
        success: false,
        metadata: { reason: 'email_exists' },
      });
      return { message: successMessage };
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

    // Send email verification (#93 — same predicate as login enforcement)
    if (this.isEmailVerificationEnforced()) {
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

    return { message: successMessage };
  }

  // ─────────────────────────────────────────────────────────────────────
  // EMAIL VERIFICATION
  // ─────────────────────────────────────────────────────────────────────
  async sendEmailVerification(userId: string) {
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Invalidate prior unused verification tokens for this user (#129).
    await this.prisma.emailVerification.updateMany({
      where: {
        userId,
        purpose: 'email_verification',
        usedAt: null,
      },
      data: { usedAt: new Date() },
    });

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
      await this.passwordService.verifyDummy(password);
      await this.auditFailedLogin({ email, reason: 'unknown_user', req });
      return null;
    }
    if (!user.passwordHash) {
      await this.passwordService.verifyDummy(password);
      await this.auditFailedLogin({
        email,
        userId: user.id,
        reason: 'oauth_only',
        req,
      });
      return null; // OAuth-only account
    }

    // Check account lock — do not disclose lock state/reason/expiry (#115).
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
        // Same client-visible outcome as unknown user / bad password.
        return null;
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

    // Progressive in-request sleep was removed (#122): holding the socket amplifies
    // DoS. Prefer HTTP 429 via @Throttle on login + account lockout instead.
    if (lockConfig.progressiveDelay) {
      this.logger.debug(
        'accountLockout.progressiveDelay is ignored; use security.rateLimit.login throttling',
      );
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
      await this.email
        .sendAccountLocked(user.email, user.name)
        .catch((err) => {
          this.logger.warn(
            `Failed to send account-locked email to ${user.email}: ${err?.message ?? err}`,
          );
        });
    }
  }

  /**
   * Email verification is enforced only when the auth requirement, feature flag,
   * and mailer are all on (#93, #112). Enforcing while `email.enabled` is false
   * locks users out (verification mail never sends).
   */
  private isEmailVerificationEnforced(): boolean {
    const reg = this.config.get<any>('auth')?.registration ?? {};
    const emailEnabled = Boolean(this.config.get<any>('email')?.enabled);
    return (
      Boolean(reg.requireEmailVerification) &&
      this.config.isFeatureEnabled('emailVerification') &&
      emailEnabled
    );
  }

  /** Shared gate for password / magic-link session mint (#89, #93). */
  private assertEmailVerifiedForLogin(user: { emailVerifiedAt?: Date | null }) {
    if (this.isEmailVerificationEnforced() && !user.emailVerifiedAt) {
      throw new ForbiddenException(
        'Please verify your email before logging in',
      );
    }
  }

  async login(user: any, dto: LoginDto, req: any) {
    this.assertEmailVerifiedForLogin(user);

    // Shared MFA gate (#23, #60). Password login re-submits credentials with
    // mfaCode; OAuth/magic-link use opaque mfaToken (#76, #136).
    const mfa = await this.applyMfaGate(user, dto.mfaCode, {
      challengeStyle: 'password',
    });
    if (mfa.kind !== 'ok') return mfa.response;

    return this.createTokens(user, req);
  }

  /**
   * Single MFA gate for every session-minting path (#60).
   * Password login uses challengeStyle `password` (client resubmits email+password).
   * OAuth / magic-link use `token` (one-time mfaToken completed via /auth/mfa/complete).
   */
  private async applyMfaGate(
    user: any,
    mfaCode: string | undefined,
    opts: { challengeStyle: 'password' | 'token' },
  ): Promise<
    | { kind: 'ok' }
    | { kind: 'blocked'; response: Record<string, any> }
  > {
    const mfaConfig = this.config.get<any>('mfa');
    const roleName = user.role?.name;
    const policyRequiresMfa =
      mfaConfig?.required === true ||
      (Array.isArray(mfaConfig?.requiredForRoles) &&
        roleName != null &&
        mfaConfig.requiredForRoles.includes(roleName));
    // Do not enforce mandatory MFA when enrollment/verification is disabled (#144).
    const mfaMandatory = policyRequiresMfa && this.isMfaEnrollmentPossible();

    if (!user.isMfaEnabled && !mfaMandatory) {
      return { kind: 'ok' };
    }

    if (!user.isMfaEnabled && mfaMandatory) {
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
        kind: 'blocked',
        response: {
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
        },
      };
    }

    if (!mfaCode) {
      if (opts.challengeStyle === 'password') {
        // Opaque challenge token — do not leak internal userId (#76).
        // Legacy clients may still re-submit email+password+mfaCode on /login.
        const mfaToken = await this.createMfaLoginToken(user.id);
        void this.maybeAutoSendEmailOtpForChallenge(user.id).catch((err) => {
          this.logger.warn(
            `Auto email OTP for login challenge failed: ${err?.message ?? err}`,
          );
        });
        return {
          kind: 'blocked',
          response: {
            requiresMfa: true,
            mfaToken,
            message:
              'MFA code required. Resubmit login with mfaCode, or complete via POST /auth/mfa/complete with mfaToken and mfaCode. For email MFA, request a code via POST /auth/mfa/email/challenge.',
          },
        };
      }
      const mfaToken = await this.createMfaLoginToken(user.id);
      void this.maybeAutoSendEmailOtpForChallenge(user.id).catch((err) => {
        this.logger.warn(
          `Auto email OTP for login challenge failed: ${err?.message ?? err}`,
        );
      });
      return {
        kind: 'blocked',
        response: {
          requiresMfa: true,
          mfaToken,
          message:
            'MFA code required. Complete sign-in via POST /auth/mfa/complete with mfaToken and mfaCode. For email MFA, request a code via POST /auth/mfa/email/challenge.',
        },
      };
    }

    // Backup codes are accepted in the mfaCode field so the client does not
    // need to know which factor the user typed (#23).
    await this.verifyMfaWithFallback(user.id, mfaCode);
    return { kind: 'ok' };
  }

  /** Short-lived one-time token proving first-factor auth succeeded; used for MFA (#60). */
  private async createMfaLoginToken(userId: string): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await this.prisma.emailVerification.create({
      data: {
        userId,
        tokenHash,
        purpose: 'mfa_login',
        expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
      },
    });
    return token;
  }

  /**
   * Complete an OAuth / magic-link MFA challenge (#60).
   * Consumes the mfa_login token and mints a full session.
   */
  async completeMfaLogin(mfaToken: string, mfaCode: string, req: any) {
    if (!mfaToken || typeof mfaToken !== 'string') {
      throw new BadRequestException('Invalid MFA token');
    }
    if (!mfaCode || typeof mfaCode !== 'string') {
      throw new BadRequestException('MFA code is required');
    }

    const tokenHash = crypto.createHash('sha256').update(mfaToken).digest('hex');
    const record = await this.prisma.emailVerification.findUnique({
      where: { tokenHash },
      include: {
        user: { include: { role: { include: { permissions: true } } } },
      },
    });

    if (!record || record.purpose !== 'mfa_login') {
      throw new BadRequestException('Invalid or expired MFA token');
    }
    if (record.usedAt) throw new BadRequestException('MFA token already used');
    if (record.expiresAt < new Date()) {
      throw new BadRequestException('MFA token expired');
    }
    if (record.user.deletedAt || record.user.isLocked) {
      throw new UnauthorizedException('Account is not allowed to sign in');
    }

    // Verify MFA before burning the token so a typo does not force full
    // OAuth/magic-link restart (#138). Concurrent success is still single-shot
    // via the atomic claim below; /auth/mfa/complete remains throttled.
    await this.verifyMfaWithFallback(record.user.id, mfaCode);

    const claimed = await this.prisma.emailVerification.updateMany({
      where: {
        id: record.id,
        purpose: 'mfa_login',
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      data: { usedAt: new Date() },
    });
    if (claimed.count !== 1) {
      throw new BadRequestException('MFA token already used or expired');
    }

    return this.createTokens(record.user, req);
  }

  async createTokens(
    user: any,
    req: any,
    opts: {
      auditAction?: 'auth.login' | 'auth.refresh' | null;
      /** Preserve refresh-token family across rotation (#67). */
      familyId?: string;
    } = {
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
    const familyId = opts.familyId || crypto.randomUUID();

    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshTokenHash,
        familyId,
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

    // Look up by hash including revoked rows so we can detect reuse (#67)
    const session = await this.prisma.session.findFirst({
      where: { refreshTokenHash: tokenHash },
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

    // Reuse of a rotated (revoked) refresh token → kill the whole family
    if (session.isRevoked) {
      await this.prisma.session.updateMany({
        where: { familyId: session.familyId, isRevoked: false },
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
          metadata: { reason: 'refresh_token_reuse' },
        });
      }
      throw new UnauthorizedException('Refresh token reuse detected');
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

    // Atomic claim: only one concurrent refresh may rotate this session
    const claimed = await this.prisma.session.updateMany({
      where: { id: session.id, isRevoked: false, refreshTokenHash: tokenHash },
      data: { isRevoked: true, revokedAt: new Date() },
    });

    if (claimed.count === 0) {
      await this.prisma.session.updateMany({
        where: { familyId: session.familyId, isRevoked: false },
        data: { isRevoked: true, revokedAt: new Date() },
      });
      throw new UnauthorizedException('Refresh token reuse detected');
    }

    return this.createTokens(session.user, req, {
      auditAction: 'auth.refresh',
      familyId: session.familyId,
    });
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

    await this.revokeUserApiKeys(userId);

    await this.audit.log({
      action: 'auth.logout_all',
      userId,
      ip: req?.ip,
      userAgent: req?.headers?.['user-agent'],
      success: true,
    });

    return { message: 'Logged out from all devices' };
  }

  /** Revoke all active API keys for a user (#143). */
  private async revokeUserApiKeys(userId: string): Promise<void> {
    await this.prisma.apiKey.updateMany({
      where: { userId, isRevoked: false },
      data: { isRevoked: true, revokedAt: new Date() },
    });
  }

  // ─────────────────────────────────────────────────────────────────────
  // PASSWORD RESET
  // ─────────────────────────────────────────────────────────────────────
  async forgotPassword(email: string, req: any) {
    // Controller also gates features.passwordReset; keep service consistent (#90)
    if (!this.config.isFeatureEnabled('passwordReset')) {
      return { message: 'If that email exists, a reset link has been sent' };
    }

    const user = await this.prisma.user.findUnique({ where: { email } });

    // Always return success to prevent user enumeration
    if (!user || user.deletedAt || !user.passwordHash) {
      return { message: 'If that email exists, a reset link has been sent' };
    }

    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Invalidate prior unused reset tokens (#129).
    await this.prisma.passwordReset.updateMany({
      where: { userId: user.id, usedAt: null },
      data: { usedAt: new Date() },
    });

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

    // Claim the reset token atomically before mutating credentials (#108).
    await this.prisma.$transaction(async (tx) => {
      const claimed = await tx.passwordReset.updateMany({
        where: {
          id: record.id,
          usedAt: null,
          expiresAt: { gt: new Date() },
        },
        data: { usedAt: new Date() },
      });
      if (claimed.count !== 1) {
        throw new BadRequestException('Token already used or expired');
      }

      await tx.user.update({
        where: { id: record.userId },
        data: { passwordHash: newHash },
      });
      await tx.session.updateMany({
        where: { userId: record.userId },
        data: { isRevoked: true, revokedAt: new Date() },
      });
      // Password recovery must kill API-key footholds too (#143).
      await tx.apiKey.updateMany({
        where: { userId: record.userId, isRevoked: false },
        data: { isRevoked: true, revokedAt: new Date() },
      });
    });

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
      // API keys are long-lived credentials — revoke on password change (#143).
      this.prisma.apiKey.updateMany({
        where: { userId, isRevoked: false },
        data: { isRevoked: true, revokedAt: new Date() },
      }),
    ]);

    await this.audit.log({
      action: 'auth.password_changed',
      userId,
      ip: req?.ip,
      metadata: { revokedOtherSessions: true, revokedApiKeys: true },
      success: true,
    });

    this.emitWebhook('user.password_changed', { userId });

    return {
      message:
        'Password changed successfully. Other sessions and API keys have been revoked.',
    };
  }

  // ─────────────────────────────────────────────────────────────────────
  // OAUTH
  // ─────────────────────────────────────────────────────────────────────
  async findOrCreateOAuthUser(profile: {
    provider: 'google' | 'github';
    providerId: string;
    email: string;
    emailVerified?: boolean;
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

    if (!profile.email || typeof profile.email !== 'string') {
      throw new ForbiddenException(
        'OAuth provider did not return an email address',
      );
    }

    // New accounts require a provider-verified email (#149).
    if (!profile.emailVerified) {
      throw new ForbiddenException(
        'OAuth email is not verified with the identity provider. Verify the email with Google/GitHub, then try again.',
      );
    }

    if (profile.email) {
      const existingByEmail = await this.prisma.user.findUnique({
        where: { email: profile.email },
        include: { role: { include: { permissions: true } } },
      });

      if (existingByEmail) {
        if (existingByEmail.deletedAt) {
          // Soft-deleted rows must not block OAuth re-provisioning (#114).
          await this.prisma.user.update({
            where: { id: existingByEmail.id },
            data: {
              email: `deleted+${existingByEmail.id}@deleted.invalid`,
              googleId: null,
              githubId: null,
            },
          });
        } else {
          // Do NOT silently link OAuth to an existing password/email account.
          // Silent email-based linking enables account takeover if an attacker
          // controls an OAuth identity for the victim's email address.
          throw new ConflictException(
            `An account with this email already exists. Sign in with your existing credentials instead of linking via ${profile.provider} automatically.`,
          );
        }
      }
    }

    // Closed registration must block OAuth provisioning of new users (#88).
    // Existing linked OAuth users already returned above.
    const regConfig = this.config.get<any>('auth')?.registration ?? {};
    if (
      regConfig.enabled === false ||
      !this.config.isFeatureEnabled('registration')
    ) {
      throw new ForbiddenException(
        'Registration is currently disabled. Contact an administrator to create an account.',
      );
    }

    // Same domain allowlist as local registration (#155).
    if (Array.isArray(regConfig.allowedDomains) && regConfig.allowedDomains.length > 0) {
      const domain = profile.email.split('@')[1]?.toLowerCase();
      const allowed = regConfig.allowedDomains.map((d: string) =>
        String(d).toLowerCase(),
      );
      if (!domain || !allowed.includes(domain)) {
        throw new ForbiddenException(
          `Email domain @${domain ?? 'unknown'} is not allowed`,
        );
      }
    }

    // Create new OAuth-only user
    const defaultRole = await this.prisma.role.findUnique({
      where: { name: regConfig.defaultRole || 'user' },
    });

    if (!defaultRole) {
      throw new BadRequestException('Default role not configured');
    }

    user = await this.prisma.user.create({
      data: {
        email: profile.email,
        name: profile.name,
        avatarUrl: profile.avatarUrl,
        // Only set after provider-verified check above (#149)
        emailVerifiedAt: new Date(),
        roleId: defaultRole.id,
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

  /** HMAC-SHA256 digest for MFA backup codes (#148). */
  private hashBackupCode(code: string): string {
    return this.cryptoService.hmacSha256(code.trim().toLowerCase());
  }

  /** Constant-time index lookup for stored backup-code digests (#148). */
  private findBackupCodeIndex(stored: string[], candidateHash: string): number {
    let found = -1;
    const cand = Buffer.from(candidateHash);
    for (let i = 0; i < stored.length; i++) {
      const row = Buffer.from(stored[i] ?? '');
      if (row.length === cand.length && crypto.timingSafeEqual(row, cand)) {
        found = i;
      }
    }
    return found;
  }

  /**
   * Atomically remove one backup-code digest if present (#117).
   * Returns true when this caller won the claim.
   */
  private async claimBackupCode(userId: string, hash: string): Promise<boolean> {
    const updated = await this.prisma.$executeRaw`
      UPDATE "MfaCredential"
      SET "backupCodes" = array_remove("backupCodes", ${hash}),
          "updatedAt" = NOW()
      WHERE "userId" = ${userId}
        AND type = CAST('TOTP' AS "MfaType")
        AND ${hash} = ANY("backupCodes")
    `;
    return Number(updated) === 1;
  }

  async setupTotp(userId: string, currentMfaCode?: string) {
    if (!this.isMfaMethodAllowed('totp')) {
      throw new BadRequestException('TOTP MFA is disabled');
    }
    const mfaConfig = this.config.get<any>('mfa');
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    // Re-enrollment must prove the current factor before rotating the secret (#125).
    const existingTotp = await this.prisma.mfaCredential.findUnique({
      where: { userId_type: { userId, type: 'TOTP' } },
      select: { isEnabled: true },
    });
    if (user.isMfaEnabled || existingTotp?.isEnabled) {
      if (!currentMfaCode || typeof currentMfaCode !== 'string') {
        throw new BadRequestException(
          'Current MFA code is required to re-enroll TOTP. Disable MFA first, or pass currentMfaCode.',
        );
      }
      await this.verifyMfaWithFallback(userId, currentMfaCode);
    }

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

    // Generate backup codes — ≥64 bits entropy + HMAC-SHA256 (not unsalted SHA-256) (#148)
    const mfaConfig = this.config.get<any>('mfa');
    const backupCodes: string[] = [];
    const hashedBackupCodes: string[] = [];

    for (let i = 0; i < (mfaConfig.backupCodesCount || 10); i++) {
      const backup = crypto.randomBytes(8).toString('hex'); // 64 bits
      backupCodes.push(backup);
      hashedBackupCodes.push(this.hashBackupCode(backup));
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
      const hash = this.hashBackupCode(code);
      // Legacy unsalted SHA-256 digests from before #148
      const legacyHash = crypto.createHash('sha256').update(code).digest('hex');
      // Atomic claim so two parallel logins cannot both accept the same code (#117).
      if (
        !(await this.claimBackupCode(userId, hash)) &&
        !(await this.claimBackupCode(userId, legacyHash))
      ) {
        throw new UnauthorizedException('Invalid backup code');
      }
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

    // 3) Pending EMAIL OTP — only if EMAIL MFA is enrolled (#146).
    // Enrollment OTPs must complete via POST /auth/mfa/email/verify, not login.
    if (!this.isMfaMethodAllowed('email')) {
      throw new UnauthorizedException('Invalid MFA code');
    }
    const emailCred = await this.prisma.mfaCredential.findUnique({
      where: { userId_type: { userId, type: 'EMAIL' } },
      select: { isEnabled: true },
    });
    if (!emailCred?.isEnabled) {
      throw new UnauthorizedException('Invalid MFA code');
    }
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

  async disableMfa(
    userId: string,
    password?: string,
    mfaCode?: string,
  ) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    if (user.passwordHash) {
      if (!password) {
        throw new BadRequestException('Password confirmation is required');
      }
      const valid = await this.passwordService.verify(user.passwordHash, password);
      if (!valid) throw new UnauthorizedException('Incorrect password');
    }

    // Always require a current MFA factor when MFA is enabled (#109).
    // Password alone must not drop MFA; OAuth-only accounts only have this step (#92).
    if (user.isMfaEnabled) {
      if (!mfaCode) {
        throw new BadRequestException(
          'MFA code (TOTP, email OTP, or backup code) is required to disable MFA',
        );
      }
      await this.verifyMfaWithFallback(userId, mfaCode);
    } else if (!user.passwordHash) {
      // Passwordless with MFA already off — nothing to disable; still require a code
      // was the old path when MFA was on. If MFA is off, allow no-op style reject.
      throw new BadRequestException('MFA is not enabled');
    }

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

  
  /** SMS MFA is schema-reserved but not implemented (#43). */
  private assertMfaMethodEnabled(method: string) {
    if (method === 'sms' || method === 'SMS') {
      throw new BadRequestException(
        'SMS MFA is not available yet. Use TOTP or email OTP.',
      );
    }
    const mfa = this.config.get<any>('mfa') ?? {};
    const methods: string[] = mfa.methods ?? [];
    if (!mfa.enabled || !methods.map((m) => m.toLowerCase()).includes(method.toLowerCase())) {
      throw new BadRequestException(`MFA method "${method}" is disabled`);
    }
  }

  async sendEmailOtp(userId: string) {
    this.assertMfaMethodEnabled('email');
    if (!this.isMfaMethodAllowed('email')) {
      throw new BadRequestException('Email MFA is disabled');
    }
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');
    return this.issueEmailOtp(user);
  }

  /**
   * Send an email OTP during an unauthenticated MFA login challenge (#106).
   * The opaque `mfaToken` proves first-factor success; requires an enrolled EMAIL factor.
   */
  async sendEmailOtpForLoginChallenge(mfaToken: string) {
    if (!mfaToken || typeof mfaToken !== 'string') {
      throw new BadRequestException('Invalid MFA token');
    }
    this.assertMfaMethodEnabled('email');
    if (!this.isMfaMethodAllowed('email')) {
      throw new BadRequestException('Email MFA is disabled');
    }

    const user = await this.resolveMfaChallengeUser(mfaToken);
    await this.assertEmailMfaEnrolled(user.id);
    return this.issueEmailOtp(user);
  }

  /**
   * Best-effort auto-send when a login MFA challenge is issued and EMAIL MFA
   * is enrolled (#106). Failures must not block the challenge response.
   */
  private async maybeAutoSendEmailOtpForChallenge(userId: string) {
    if (!this.isMfaMethodAllowed('email')) return;
    const enrolled = await this.prisma.mfaCredential.findUnique({
      where: { userId_type: { userId, type: 'EMAIL' } },
      select: { isEnabled: true },
    });
    if (!enrolled?.isEnabled) return;
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.deletedAt || user.isLocked) return;
    await this.issueEmailOtp(user);
  }

  private async resolveMfaChallengeUser(mfaToken: string) {
    const tokenHash = crypto.createHash('sha256').update(mfaToken).digest('hex');
    const record = await this.prisma.emailVerification.findUnique({
      where: { tokenHash },
      include: { user: true },
    });
    if (!record || record.purpose !== 'mfa_login') {
      throw new BadRequestException('Invalid or expired MFA token');
    }
    if (record.usedAt) throw new BadRequestException('MFA token already used');
    if (record.expiresAt < new Date()) {
      throw new BadRequestException('MFA token expired');
    }
    if (!record.user || record.user.deletedAt || record.user.isLocked) {
      throw new UnauthorizedException('Account is not allowed to sign in');
    }
    return record.user;
  }

  private async assertEmailMfaEnrolled(userId: string) {
    const cred = await this.prisma.mfaCredential.findUnique({
      where: { userId_type: { userId, type: 'EMAIL' } },
      select: { isEnabled: true },
    });
    if (!cred?.isEnabled) {
      throw new BadRequestException('Email MFA is not enrolled for this account');
    }
  }

  private async issueEmailOtp(user: { id: string; email: string; name: string }) {
    const otp = crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
    const key = `${this.config.get<any>('redis')?.prefix ?? 'authkit:'}mfa:email:${user.id}`;
    const redis = this.redisClient;
    if (!redis) throw new BadRequestException('Email MFA is temporarily unavailable');

    await redis.set(
      key,
      crypto.createHash('sha256').update(otp).digest('hex'),
      'EX',
      600,
    );

    await this.email.sendEmailOtp(user.email, user.name, otp);
    return { message: 'Verification code sent' };
  }

  async verifyEmailOtp(userId: string, code: string) {
    if (!this.isMfaMethodAllowed('email')) {
      throw new BadRequestException('Email MFA is disabled');
    }
    if (!/^\d{6}$/.test(code)) throw new BadRequestException('Invalid code format');

    await this.verifyEmailOtpCodeOnly(userId, code);

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

  /**
   * Step-up for OAuth-only self-delete (#130): MFA code when enrolled, else
   * a one-shot email OTP (does not enable EMAIL MFA).
   */
  async assertAccountDeletionStepUp(
    userId: string,
    opts: { password?: string; confirmationCode?: string },
  ): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.deletedAt) throw new NotFoundException('User not found');

    if (user.passwordHash) {
      if (!opts.password) {
        throw new UnauthorizedException('Password is required to delete the account');
      }
      const valid = await this.passwordService.verify(user.passwordHash, opts.password);
      if (!valid) throw new UnauthorizedException('Incorrect password');
      return;
    }

    if (!opts.confirmationCode) {
      throw new UnauthorizedException(
        'Confirmation code is required to delete an OAuth account. Request one via POST /auth/account/delete/challenge, or use your MFA code if enrolled.',
      );
    }

    if (user.isMfaEnabled) {
      await this.verifyMfaWithFallback(userId, opts.confirmationCode);
      return;
    }

    await this.verifyEmailOtpCodeOnly(userId, opts.confirmationCode);
  }

  /** Issue email OTP used as OAuth account-deletion step-up (#130). */
  async sendAccountDeletionChallenge(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.deletedAt) throw new NotFoundException('User not found');
    if (user.passwordHash) {
      throw new BadRequestException(
        'Password accounts confirm deletion with their password, not an email challenge',
      );
    }
    if (user.isMfaEnabled) {
      throw new BadRequestException(
        'MFA is enabled — pass confirmationCode with your authenticator or backup code',
      );
    }
    return this.issueEmailOtp(user);
  }

  // ─────────────────────────────────────────────────────────────────────
  // MAGIC LINK
  // ─────────────────────────────────────────────────────────────────────
  async sendMagicLink(email: string, req: any) {
    if (
      !this.config.isStrategyEnabled('magicLink') ||
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

    // Invalidate prior unused magic-link tokens (#129).
    await this.prisma.emailVerification.updateMany({
      where: {
        userId: user.id,
        purpose: 'magic_link',
        usedAt: null,
      },
      data: { usedAt: new Date() },
    });

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

  /**
   * Validate + consume a magic-link token; returns the user without minting a session.
   * Used by GET click-through (exchange code) and POST verify (MFA gate + tokens).
   */
  async consumeMagicLinkToken(token: string) {
    if (
      !this.config.isStrategyEnabled('magicLink') ||
      !this.config.isFeatureEnabled('magicLink')
    ) {
      throw new BadRequestException('Magic link authentication is disabled');
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const record = await this.prisma.emailVerification.findUnique({
      where: { tokenHash },
      include: {
        user: { include: { role: { include: { permissions: true } } } },
      },
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

    this.assertEmailVerifiedForLogin(record.user);

    const claimed = await this.prisma.emailVerification.updateMany({
      where: {
        id: record.id,
        purpose: 'magic_link',
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      data: { usedAt: new Date() },
    });
    if (claimed.count !== 1) {
      throw new BadRequestException('Magic link already used or expired');
    }

    return record.user;
  }

  async verifyMagicLink(token: string, req: any, mfaCode?: string) {
    // Peek first so a wrong mfaCode does not burn the magic-link token when the
    // client attempted a one-shot verify+MFA (#60 review).
    const user = await this.peekMagicLinkUser(token);

    this.assertEmailVerifiedForLogin(user);

    if (mfaCode) {
      await this.verifyMfaWithFallback(user.id, mfaCode);
      // MFA ok — consume and mint
      await this.consumeMagicLinkToken(token);
      return this.createTokens(user, req);
    }

    const mfa = await this.applyMfaGate(user, undefined, {
      challengeStyle: 'token',
    });
    if (mfa.kind !== 'ok') {
      // Challenge / setup: consume magic link so it cannot be replayed, then
      // hand the client an mfaToken or setupToken.
      await this.consumeMagicLinkToken(token);
      return mfa.response;
    }

    await this.consumeMagicLinkToken(token);
    return this.createTokens(user, req);
  }

  /** Load magic-link user without marking the token used. */
  private async peekMagicLinkUser(token: string) {
    if (
      !this.config.isStrategyEnabled('magicLink') ||
      !this.config.isFeatureEnabled('magicLink')
    ) {
      throw new BadRequestException('Magic link authentication is disabled');
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const record = await this.prisma.emailVerification.findUnique({
      where: { tokenHash },
      include: {
        user: { include: { role: { include: { permissions: true } } } },
      },
    });

    if (!record || record.purpose !== 'magic_link') {
      throw new BadRequestException('Invalid magic link');
    }
    if (record.usedAt) throw new BadRequestException('Magic link already used');
    if (record.expiresAt < new Date()) throw new BadRequestException('Magic link expired');
    if (record.user.deletedAt || record.user.isLocked) {
      throw new UnauthorizedException('Account is not allowed to sign in');
    }

    this.assertEmailVerifiedForLogin(record.user);

    return record.user;
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

  async exchangeOAuthCode(code: string, req: any, mfaCode?: string) {
    if (!code || typeof code !== 'string') {
      throw new BadRequestException('Invalid OAuth exchange code');
    }

    const tokenHash = crypto.createHash('sha256').update(code).digest('hex');
    const record = await this.prisma.emailVerification.findUnique({
      where: { tokenHash },
      include: {
        user: { include: { role: { include: { permissions: true } } } },
      },
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

    const user = record.user;

    // When the client already sent mfaCode, verify MFA *before* burning the
    // exchange code so a typo does not force a full OAuth restart (#60 review).
    if (mfaCode) {
      await this.verifyMfaWithFallback(user.id, mfaCode);
      await this.claimOneTimeEmailToken(record.id, 'oauth_exchange');
      return this.createTokens(user, req);
    }

    const mfa = await this.applyMfaGate(user, undefined, {
      challengeStyle: 'token',
    });

    // Always consume the one-time exchange code once we know the outcome path
    // (tokens, MFA challenge, or setup). Prevents replay of the oauth code.
    await this.claimOneTimeEmailToken(record.id, 'oauth_exchange');

    if (mfa.kind !== 'ok') return mfa.response;
    return this.createTokens(user, req);
  }

  /** Atomically mark an EmailVerification one-time token used (#108). */
  private async claimOneTimeEmailToken(
    id: string,
    purpose: string,
  ): Promise<void> {
    const claimed = await this.prisma.emailVerification.updateMany({
      where: {
        id,
        purpose,
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      data: { usedAt: new Date() },
    });
    if (claimed.count !== 1) {
      throw new BadRequestException('Token already used or expired');
    }
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
