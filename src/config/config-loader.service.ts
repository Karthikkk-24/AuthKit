import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';

const CONFIG_PATH = () => path.resolve(process.cwd(), 'authkit.config.json');

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

// Top-level sections an admin may PATCH via /admin/config (#29).
const EDITABLE_FIELDS = new Set([
  'ui',
  'features',
  'mfa',
  'session',
  'security',
  'audit',
  'webhooks',
  'email',
]);

@Injectable()
export class ConfigLoaderService {
  private config: AuthKitConfig;

  /** Paths the admin UI is permitted to edit. */
  static readonly EDITABLE_FIELDS = EDITABLE_FIELDS;

  constructor(private readonly nestConfig: ConfigService) {
    this.config = this.loadConfig();
  }

  /** Re-read and re-interpolate authkit.config.json from disk. */
  reload(): AuthKitConfig {
    this.config = this.loadConfig();
    return this.config;
  }

  /**
   * Apply a whitelisted set of changes to authkit.config.json, persist it,
   * and hot-reload. Only top-level sections listed in EDITABLE_FIELDS may be
   * rewritten; everything else is ignored.
   */
  updateEditable(patch: Record<string, unknown>): AuthKitConfig {
    const allowed: Record<string, unknown> = {};
    for (const key of Object.keys(patch ?? {})) {
      if (EDITABLE_FIELDS.has(key)) allowed[key] = (patch as any)[key];
    }
    if (Object.keys(allowed).length === 0) {
      return this.config; // nothing editable requested
    }

    const configPath = CONFIG_PATH();
    const raw = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    const next = { ...raw, ...allowed };
    fs.writeFileSync(configPath, JSON.stringify(next, null, 2) + '\n', 'utf-8');
    return this.reload();
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
    const configPath = CONFIG_PATH();
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
