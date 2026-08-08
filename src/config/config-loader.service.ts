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
    orm: 'prisma'; // TypeORM/Drizzle adapters were removed (#35)
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

const SECRET_KEY_RE =
  /^(password|passwd|secret|apiKey|api_key|token|clientSecret|privateKey)$/i;

/** Keys that must never be copied during merge/interpolate (#151). */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Deep-merge objects; never overwrite credential keys from API patches. */
function deepMergePreserveSecrets(target: any, source: any): any {
  if (source === null || source === undefined) return target;
  if (typeof source !== 'object' || Array.isArray(source)) return source;
  const base =
    target && typeof target === 'object' && !Array.isArray(target)
      ? { ...target }
      : Object.create(null);
  for (const key of Object.keys(source)) {
    if (DANGEROUS_KEYS.has(key)) continue;
    if (SECRET_KEY_RE.test(key)) continue;
    const next = source[key];
    if (next && typeof next === 'object' && !Array.isArray(next)) {
      base[key] = deepMergePreserveSecrets(base[key], next);
    } else if (
      typeof base[key] === 'string' &&
      /\$\{[^}]+\}/.test(base[key]) &&
      (next === '' || next == null)
    ) {
      // Keep ${ENV_VAR} placeholders when the admin GET returned an empty interpolation
      continue;
    } else {
      base[key] = next;
    }
  }
  return base;
}

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
   *
   * Deep-merges into existing sections so nested credential placeholders
   * (e.g. `${SMTP_PASSWORD}`) are never clobbered by interpolated empties
   * that the admin GET returns (#29).
   */
  updateEditable(patch: Record<string, unknown>): AuthKitConfig {
    const configPath = CONFIG_PATH();
    const raw = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    let changed = false;

    for (const key of Object.keys(patch ?? {})) {
      if (DANGEROUS_KEYS.has(key)) continue;
      if (!EDITABLE_FIELDS.has(key)) continue;
      raw[key] = deepMergePreserveSecrets(raw[key] ?? {}, (patch as any)[key]);
      changed = true;
    }
    if (!changed) return this.config;

    fs.writeFileSync(configPath, JSON.stringify(raw, null, 2) + '\n', 'utf-8');
    return this.reload();
  }

  private interpolateEnv(value: string): string {
    return value.replace(/\$\{([^}]+)\}/g, (_, key) => {
      if (process.env[key]) return process.env[key] as string;
      // Canonical SMTP_PASSWORD; accept legacy SMTP_PASS (#71)
      if (key === 'SMTP_PASSWORD' && process.env.SMTP_PASS) {
        return process.env.SMTP_PASS;
      }
      return '';
    });
  }

  private interpolateObject(obj: any): any {
    if (typeof obj === 'string') return this.interpolateEnv(obj);
    if (Array.isArray(obj)) return obj.map((v) => this.interpolateObject(v));
    if (obj && typeof obj === 'object') {
      const result: any = Object.create(null);
      for (const key of Object.keys(obj)) {
        if (DANGEROUS_KEYS.has(key)) continue;
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

  /**
   * Admin-facing config snapshot with credential fields redacted (#62).
   * Live secrets from env interpolation must never reach the admin UI or logs.
   */
  getAllRedacted(): AuthKitConfig {
    return redactSecrets(structuredClone(this.config)) as AuthKitConfig;
  }

  isFeatureEnabled(feature: keyof AuthKitConfig['features']): boolean {
    return this.config.features[feature] ?? false;
  }

  isStrategyEnabled(strategy: keyof AuthKitConfig['auth']['strategies']): boolean {
    const s = this.config.auth.strategies[strategy] as any;
    return s?.enabled ?? false;
  }
}

/** Replace secret-shaped leaf values so GET/PATCH responses never leak credentials. */
export function redactSecrets(obj: any, path: string[] = []): any {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map((v, i) => redactSecrets(v, [...path, String(i)]));
  if (typeof obj !== 'object') return obj;

  const out: any = {};
  for (const key of Object.keys(obj)) {
    const nextPath = [...path, key];
    const pathKey = nextPath.join('.');
    // Also redact connection URLs that often embed credentials (#62 review).
    const isSecretUrl =
      key === 'url' &&
      (pathKey === 'database.url' ||
        pathKey === 'redis.url' ||
        path.includes('database') ||
        path.includes('redis'));

    if (SECRET_KEY_RE.test(key) || isSecretUrl) {
      const val = obj[key];
      if (typeof val === 'string' && val.length > 0) {
        out[key] = '[REDACTED]';
      } else if (val && typeof val === 'object' && !Array.isArray(val)) {
        // e.g. auth.password policy object — recurse but don't blank the object
        out[key] = redactSecrets(val, nextPath);
      } else {
        out[key] = val;
      }
    } else if (obj[key] && typeof obj[key] === 'object') {
      out[key] = redactSecrets(obj[key], nextPath);
    } else {
      out[key] = obj[key];
    }
  }
  return out;
}
