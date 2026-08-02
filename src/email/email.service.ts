import { Injectable, Logger } from '@nestjs/common';
import { ConfigLoaderService } from '../config/config-loader.service';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter | null = null;

  constructor(private readonly config: ConfigLoaderService) {
    this.initTransporter();
  }

  /** Escape user-controlled strings before interpolating into HTML (XSS/HTML injection). */
  private escapeHtml(value: string): string {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /**
   * Validate a hex color (#rgb/#rrggbb) used in inline styles.
   * Falls back to the default when the config value is malformed.
   */
  private safeColor(value: string, fallback = '#6366f1'): string {
    return /^#[0-9a-fA-F]{6}$/.test(value) || /^#[0-9a-fA-F]{3}$/.test(value)
      ? value
      : fallback;
  }

  /** Only allow http(s) image URLs for the branding logo. */
  private safeUrl(value: string): string {
    if (!value) return '';
    try {
      const url = new URL(value);
      return url.protocol === 'https:' || url.protocol === 'http:' ? value : '';
    } catch {
      return '';
    }
  }

  private initTransporter() {
    const emailConfig = this.config.get<any>('email');
    if (!emailConfig.enabled) {
      this.logger.warn('Email service is disabled in config');
      return;
    }

    if (emailConfig.provider === 'smtp') {
      this.transporter = nodemailer.createTransport({
        host: emailConfig.smtp.host,
        port: emailConfig.smtp.port,
        secure: emailConfig.smtp.secure,
        auth: {
          user: emailConfig.smtp.user,
          pass: emailConfig.smtp.password,
        },
      });
    }
    // For SendGrid/Resend, use their APIs via fetch
  }

  private async send(to: string, subject: string, html: string): Promise<void> {
    const emailConfig = this.config.get<any>('email');
    if (!emailConfig.enabled) {
      this.logger.debug(`[DEV] Email to ${to}: ${subject}`);
      return;
    }

    const from = `"${emailConfig.fromName}" <${emailConfig.from}>`;

    if (emailConfig.provider === 'smtp' && this.transporter) {
      await this.transporter.sendMail({ from, to, subject, html });
    } else if (emailConfig.provider === 'sendgrid') {
      await fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${emailConfig.sendgrid.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          personalizations: [{ to: [{ email: to }] }],
          from: { email: emailConfig.from, name: emailConfig.fromName },
          subject,
          content: [{ type: 'text/html', value: html }],
        }),
      });
    } else if (emailConfig.provider === 'resend') {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${emailConfig.resend.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ from, to, subject, html }),
      });
    }
  }

  private getBaseTemplate(content: string, title: string): string {
    const branding = this.config.get<any>('email').templates?.branding || {};
    const companyName = this.escapeHtml(branding.companyName || 'AuthKit');
    const primaryColor = this.safeColor(branding.primaryColor || '#6366f1');
    const logo = this.safeUrl(branding.logo || '');
    const safeTitle = this.escapeHtml(title);

    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${safeTitle}</title>
</head>
<body style="margin:0;padding:0;background:#0f0f23;font-family:'Inter',system-ui,sans-serif;">
  <div style="max-width:600px;margin:40px auto;background:linear-gradient(135deg,#1a1a3e 0%,#0d0d1a 100%);border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.5);">
    <!-- Header -->
    <div style="background:linear-gradient(135deg,${primaryColor} 0%,#4f46e5 100%);padding:40px;text-align:center;">
      ${logo ? `<img src="${logo}" alt="${companyName}" height="48" style="margin-bottom:16px">` : ''}
      <h1 style="color:#fff;margin:0;font-size:28px;font-weight:800;letter-spacing:-0.5px;">${companyName}</h1>
    </div>
    <!-- Content -->
    <div style="padding:48px 40px;">
      ${content}
    </div>
    <!-- Footer -->
    <div style="padding:24px 40px;border-top:1px solid rgba(255,255,255,0.08);text-align:center;">
      <p style="color:#6b7280;font-size:12px;margin:0;">
        &copy; ${new Date().getFullYear()} ${companyName}. This is an automated message — please do not reply.
      </p>
    </div>
  </div>
</body>
</html>`;
  }

  /** URL of the admin/frontend console that consumes emailed tokens. */
  private getFrontendUrl(): string {
    return process.env.FRONTEND_URL || 'http://localhost:3001';
  }

  /** Base URL of this API (used for GET click-through handlers). */
  private getApiUrl(): string {
    return process.env.APP_URL || 'http://localhost:3000';
  }

  async sendEmailVerification(to: string, name: string, token: string): Promise<void> {
    // Click-through hits a GET handler on the API which verifies then
    // redirects to the frontend (#20). Versioned /v1 path matches main.ts.
    const verifyUrl = `${this.getApiUrl()}/api/v1/auth/verify-email?token=${encodeURIComponent(token)}`;
    const html = this.getBaseTemplate(
      `
      <h2 style="color:#fff;font-size:24px;font-weight:700;margin:0 0 16px;">Verify your email</h2>
      <p style="color:#a1a1aa;font-size:16px;line-height:1.6;margin:0 0 32px;">
        Hi ${this.escapeHtml(name)}, thanks for signing up! Click the button below to verify your email address.
      </p>
      <a href="${verifyUrl}" style="display:inline-block;background:linear-gradient(135deg,#6366f1,#4f46e5);color:#fff;text-decoration:none;padding:16px 40px;border-radius:12px;font-size:16px;font-weight:700;letter-spacing:0.5px;">
        Verify Email
      </a>
      <p style="color:#6b7280;font-size:14px;margin:32px 0 0;">
        This link expires in <strong style="color:#a1a1aa;">24 hours</strong>.
        If you didn't create an account, you can ignore this email.
      </p>
      `,
      'Verify your email',
    );
    await this.send(to, 'Verify your email address', html);
  }

  async sendPasswordReset(to: string, name: string, token: string): Promise<void> {
    const resetUrl = `${this.getFrontendUrl()}/reset-password?token=${encodeURIComponent(token)}`;
    const html = this.getBaseTemplate(
      `
      <h2 style="color:#fff;font-size:24px;font-weight:700;margin:0 0 16px;">Reset your password</h2>
      <p style="color:#a1a1aa;font-size:16px;line-height:1.6;margin:0 0 32px;">
        Hi ${this.escapeHtml(name)}, we received a request to reset your password. Click below to proceed.
      </p>
      <a href="${resetUrl}" style="display:inline-block;background:linear-gradient(135deg,#f59e0b,#d97706);color:#fff;text-decoration:none;padding:16px 40px;border-radius:12px;font-size:16px;font-weight:700;">
        Reset Password
      </a>
      <p style="color:#6b7280;font-size:14px;margin:32px 0 0;">
        This link expires in <strong style="color:#a1a1aa;">1 hour</strong>.
        If you didn't request this, your account is safe — you can ignore this email.
      </p>
      `,
      'Reset your password',
    );
    await this.send(to, 'Reset your password', html);
  }

  async sendMagicLink(to: string, name: string, token: string): Promise<void> {
    // Click-through hits a GET handler on the API which verifies the token,
    // then redirects to the frontend OAuth-success page with a one-time code (#20).
    const magicUrl = `${this.getApiUrl()}/api/v1/auth/magic-link/verify?token=${encodeURIComponent(token)}`;
    const html = this.getBaseTemplate(
      `
      <h2 style="color:#fff;font-size:24px;font-weight:700;margin:0 0 16px;">Your magic login link</h2>
      <p style="color:#a1a1aa;font-size:16px;line-height:1.6;margin:0 0 32px;">
        Hi ${this.escapeHtml(name)}, click the button below to log in instantly — no password needed.
      </p>
      <a href="${magicUrl}" style="display:inline-block;background:linear-gradient(135deg,#06b6d4,#0891b2);color:#fff;text-decoration:none;padding:16px 40px;border-radius:12px;font-size:16px;font-weight:700;">
        Log In Now
      </a>
      <p style="color:#6b7280;font-size:14px;margin:32px 0 0;">
        This link expires in <strong style="color:#a1a1aa;">15 minutes</strong> and can only be used once.
      </p>
      `,
      'Magic login link',
    );
    await this.send(to, 'Your magic login link', html);
  }

  async sendAccountLocked(to: string, name: string): Promise<void> {
    const html = this.getBaseTemplate(
      `
      <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:12px;padding:24px;margin-bottom:24px;">
        <h2 style="color:#ef4444;font-size:20px;font-weight:700;margin:0 0 8px;">⚠️ Account Locked</h2>
        <p style="color:#fca5a5;font-size:14px;margin:0;">Suspicious activity detected</p>
      </div>
      <p style="color:#a1a1aa;font-size:16px;line-height:1.6;margin:0 0 16px;">
        Hi ${this.escapeHtml(name)}, your account has been temporarily locked due to too many failed login attempts.
      </p>
      <p style="color:#a1a1aa;font-size:16px;line-height:1.6;margin:0;">
        If this wasn't you, please reset your password immediately or contact support.
      </p>
      `,
      'Account locked',
    );
    await this.send(to, '⚠️ Your account has been locked', html);
  }

  async sendEmailOtp(to: string, name: string, otp: string): Promise<void> {
    const html = this.getBaseTemplate(
      `
      <h2 style="color:#fff;font-size:24px;font-weight:700;margin:0 0 16px;">Your verification code</h2>
      <p style="color:#a1a1aa;font-size:16px;line-height:1.6;margin:0 0 32px;">
        Hi ${this.escapeHtml(name)}, enter this code to complete your login.
      </p>
      <div style="background:rgba(99,102,241,0.1);border:2px solid rgba(99,102,241,0.3);border-radius:16px;padding:32px;text-align:center;margin:0 0 32px;">
        <span style="color:#6366f1;font-size:48px;font-weight:800;letter-spacing:12px;font-family:monospace;">${this.escapeHtml(otp)}</span>
      </div>
      <p style="color:#6b7280;font-size:14px;">
        This code expires in <strong style="color:#a1a1aa;">10 minutes</strong>.
        Never share this code with anyone.
      </p>
      `,
      'Verification code',
    );
    await this.send(to, `Your verification code: ${otp}`, html);
  }
}
