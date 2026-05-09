import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';

export interface AuthKitConfig {
  app: {
    name: string;
    port: number;
    environment: string;
    apiPrefix: string;
    adminPath: string;
  };
  database: {
    orm: 'prisma' | 'typeorm' | 'drizzle';
    url: string;
  };
  auth: {
    strategies: {
      local: { enabled: boolean };
      google: { enabled: boolean; clientId: string; clientSecret: string; callbackUrl: string };
      github: { enabled: boolean; clientId: string; clientSecret: string; callbackUrl: string };
      magicLink: { enabled: boolean };
      apiKey: { enabled: boolean };
    };
    jwt: {
      algorithm: string;
      accessTokenExpiry: string;
      refreshTokenExpiry: string;
      issuer: string;
      audience: string;
    };
    password: {
      hashingAlgorithm: 'argon2id' | 'bcrypt';
      minLength: number;
      maxLength: number;
      requireUppercase: boolean;
      requireLowercase: boolean;
      requireNumbers: boolean;
      requireSpecialChars: boolean;
      checkPwnedPasswords: boolean;
    };
    registration: {
      enabled: boolean;
      requireEmailVerification: boolean;
      defaultRole: string;
      allowedDomains: string[];
    };
  };
  mfa: {
    enabled: boolean;
    required: boolean;
    requiredForRoles: string[];
    methods: string[];
    backupCodesCount: number;
    totpIssuer: string;
  };
  security: {
    rateLimit: {
      enabled: boolean;
      global: { windowMs: number; max: number };
      login: { windowMs: number; max: number };
      register: { windowMs: number; max: number };
      passwordReset: { windowMs: number; max: number };
    };
    accountLockout: {
      enabled: boolean;
      maxAttempts: number;
      lockDurationMinutes: number;
      progressiveDelay: boolean;
    };
    cors: { enabled: boolean; origins: string[]; credentials: boolean };
    helmet: { enabled: boolean };
    ipAllowlist: string[];
    ipBlocklist: string[];
  };
  session: {
    maxConcurrentSessions: number;
    trackDevices: boolean;
    autoRevokeInactiveSessions: boolean;
    inactivityTimeoutDays: number;
  };
  email: {
    enabled: boolean;
    provider: 'smtp' | 'sendgrid' | 'resend';
    from: string;
    fromName: string;
    smtp: { host: string; port: number; secure: boolean; user: string; password: string };
    sendgrid: { apiKey: string };
    resend: { apiKey: string };
    templates: { branding: { logo: string; primaryColor: string; companyName: string } };
  };
  redis: { url: string; prefix: string };
  audit: {
    enabled: boolean;
    logSuccessfulLogins: boolean;
    logFailedLogins: boolean;
    logTokenRefresh: boolean;
    retentionDays: number;
    sensitiveFieldsToRedact: string[];
  };
  webhooks: { enabled: boolean; timeout: number; retries: number };
  ui: {
    enabled: boolean;
    theme: string;
    availableThemes: string[];
    showSwaggerDocs: boolean;
  };
  features: {
    registration: boolean;
    emailVerification: boolean;
    passwordReset: boolean;
    magicLink: boolean;
    mfa: boolean;
    apiKeys: boolean;
    webhooks: boolean;
    adminImpersonation: boolean;
    gdprTools: boolean;
    pwnedPasswordCheck: boolean;
  };
}

@Injectable()
export class ConfigLoaderService {
  private readonly config: AuthKitConfig;

  constructor(private readonly nestConfig: ConfigService) {
    this.config = this.loadConfig();
  }

  private interpolateEnv(value: string): string {
    return value.replace(/\$\{([^}]+)\}/g, (_, key) => process.env[key] || '');
  }

  private interpolateObject(obj: any): any {
    if (typeof obj === 'string') return this.interpolateEnv(obj);
    if (Array.isArray(obj)) return obj.map((v) => this.interpolateObject(v));
    if (obj && typeof obj === 'object') {
      const result: any = {};
      for (const key of Object.keys(obj)) {
        result[key] = this.interpolateObject(obj[key]);
      }
      return result;
    }
    return obj;
  }

  private loadConfig(): AuthKitConfig {
    const configPath = path.resolve(process.cwd(), 'authkit.config.json');
    if (!fs.existsSync(configPath)) {
      throw new Error(`authkit.config.json not found at ${configPath}`);
    }
    const raw = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    return this.interpolateObject(raw) as AuthKitConfig;
  }

  get<T = any>(key: keyof AuthKitConfig): T {
    return this.config[key] as unknown as T;
  }

  getAll(): AuthKitConfig {
    return this.config;
  }

  isFeatureEnabled(feature: keyof AuthKitConfig['features']): boolean {
    return this.config.features[feature] ?? false;
  }

  isStrategyEnabled(strategy: keyof AuthKitConfig['auth']['strategies']): boolean {
    const s = this.config.auth.strategies[strategy] as any;
    return s?.enabled ?? false;
  }
}
