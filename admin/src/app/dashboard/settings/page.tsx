'use client';
import React, { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Shield, Mail, Database, Zap, Check, Save, Webhook, Activity } from 'lucide-react';
import { configApi } from '@/lib/api';

interface ConfigSection {
  key: string;
  label: string;
  icon: React.ElementType;
  /** Dot-path into the live authkit config (top-level editable section). */
  section: string;
  fields: Array<{
    key: string;
    label: string;
    type: 'toggle' | 'number' | 'text' | 'select';
    options?: string[];
    description?: string;
    /** Nested path under the section, e.g. ['accountLockout','maxAttempts'] */
    path: string[];
  }>;
}

const CONFIG_SECTIONS: ConfigSection[] = [
  {
    key: 'security',
    label: 'Security',
    icon: Shield,
    section: 'security',
    fields: [
      {
        key: 'maxLoginAttempts',
        label: 'Max Login Attempts',
        type: 'number',
        description: 'Attempts before account lockout',
        path: ['accountLockout', 'maxAttempts'],
      },
      {
        key: 'lockoutDurationMinutes',
        label: 'Lockout Duration (mins)',
        type: 'number',
        path: ['accountLockout', 'lockDurationMinutes'],
      },
      {
        key: 'progressiveDelay',
        label: 'Progressive Delay',
        type: 'toggle',
        description: 'Increase wait after each failed login',
        path: ['accountLockout', 'progressiveDelay'],
      },
    ],
  },
  {
    key: 'features',
    label: 'Features',
    icon: Zap,
    section: 'features',
    fields: [
      { key: 'registration', label: 'Registration', type: 'toggle', path: ['registration'] },
      { key: 'emailVerification', label: 'Email Verification', type: 'toggle', path: ['emailVerification'] },
      { key: 'passwordReset', label: 'Password Reset', type: 'toggle', path: ['passwordReset'] },
      { key: 'magicLink', label: 'Magic Link', type: 'toggle', path: ['magicLink'] },
      { key: 'mfa', label: 'MFA Feature Flag', type: 'toggle', path: ['mfa'] },
      { key: 'apiKeys', label: 'API Keys', type: 'toggle', path: ['apiKeys'] },
      { key: 'webhooks', label: 'Webhooks', type: 'toggle', path: ['webhooks'] },
      { key: 'gdprTools', label: 'GDPR Tools', type: 'toggle', path: ['gdprTools'] },
      { key: 'pwnedPasswordCheck', label: 'Pwned Password Check', type: 'toggle', path: ['pwnedPasswordCheck'] },
    ],
  },
  {
    key: 'mfa',
    label: 'Multi-Factor Auth',
    icon: Shield,
    section: 'mfa',
    fields: [
      { key: 'enabled', label: 'Enable MFA', type: 'toggle', path: ['enabled'] },
      { key: 'required', label: 'Require MFA for All Users', type: 'toggle', path: ['required'] },
      { key: 'backupCodesCount', label: 'Backup Codes Count', type: 'number', path: ['backupCodesCount'] },
      { key: 'totpIssuer', label: 'TOTP Issuer', type: 'text', path: ['totpIssuer'] },
    ],
  },
  {
    key: 'session',
    label: 'Sessions',
    icon: Activity,
    section: 'session',
    fields: [
      { key: 'maxConcurrentSessions', label: 'Max Concurrent Sessions', type: 'number', path: ['maxConcurrentSessions'] },
      { key: 'trackDevices', label: 'Track Devices', type: 'toggle', path: ['trackDevices'] },
      {
        key: 'autoRevokeInactiveSessions',
        label: 'Auto-revoke Inactive Sessions',
        type: 'toggle',
        path: ['autoRevokeInactiveSessions'],
      },
      {
        key: 'inactivityTimeoutDays',
        label: 'Inactivity Timeout (days)',
        type: 'number',
        path: ['inactivityTimeoutDays'],
      },
    ],
  },
  {
    key: 'email',
    label: 'Email',
    icon: Mail,
    section: 'email',
    fields: [
      { key: 'enabled', label: 'Email Enabled', type: 'toggle', path: ['enabled'] },
      {
        key: 'provider',
        label: 'Email Provider',
        type: 'select',
        options: ['smtp', 'sendgrid', 'resend'],
        path: ['provider'],
      },
      { key: 'from', label: 'From Address', type: 'text', path: ['from'] },
      { key: 'fromName', label: 'From Name', type: 'text', path: ['fromName'] },
    ],
  },
  {
    key: 'webhooks',
    label: 'Webhooks',
    icon: Webhook,
    section: 'webhooks',
    fields: [
      { key: 'enabled', label: 'Webhooks Enabled', type: 'toggle', path: ['enabled'] },
      { key: 'timeout', label: 'Timeout (ms)', type: 'number', path: ['timeout'] },
      { key: 'retries', label: 'Retries', type: 'number', path: ['retries'] },
    ],
  },
  {
    key: 'ui',
    label: 'UI',
    icon: Database,
    section: 'ui',
    fields: [
      { key: 'enabled', label: 'Admin UI Enabled', type: 'toggle', path: ['enabled'] },
      {
        key: 'theme',
        label: 'Theme',
        type: 'select',
        options: ['midnight', 'aurora', 'slate', 'ember', 'arctic'],
        path: ['theme'],
      },
      { key: 'showSwaggerDocs', label: 'Show Swagger Docs', type: 'toggle', path: ['showSwaggerDocs'] },
    ],
  },
];

function getAt(obj: any, path: string[]): unknown {
  return path.reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

function setAt(obj: any, path: string[], value: unknown): any {
  if (path.length === 0) return value;
  const [head, ...rest] = path;
  return { ...obj, [head]: setAt(obj?.[head] ?? {}, rest, value) };
}

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!value)}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${value ? 'bg-violet-600' : 'bg-slate-700'}`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${value ? 'translate-x-6' : 'translate-x-1'}`}
      />
    </button>
  );
}

export default function SettingsPage() {
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Record<string, any> | null>(null);
  const [activeSection, setActiveSection] = useState('security');
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');

  const { data, isLoading, isError } = useQuery({
    queryKey: ['admin-config'],
    queryFn: () => configApi.get(),
  });

  useEffect(() => {
    if (data) setDraft(structuredClone(data) as Record<string, any>);
  }, [data]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (!draft) return;
      // Only send editable top-level sections (#29 whitelist)
      const patch: Record<string, unknown> = {};
      for (const section of CONFIG_SECTIONS) {
        if (draft[section.section] !== undefined) {
          patch[section.section] = draft[section.section];
        }
      }
      // Also persist audit section if present in draft
      if (draft.audit) patch.audit = draft.audit;
      return configApi.update(patch);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-config'] });
      setSaved(true);
      setError('');
      setTimeout(() => setSaved(false), 2000);
    },
    onError: (err: Error) => setError(err.message),
  });

  const currentSection = CONFIG_SECTIONS.find((s) => s.key === activeSection)!;
  const sectionData = draft?.[currentSection.section] ?? {};

  const updateField = (path: string[], value: unknown) => {
    setDraft((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        [currentSection.section]: setAt(prev[currentSection.section] ?? {}, path, value),
      };
    });
  };

  if (isLoading || !draft) {
    return (
      <div className="space-y-4">
        <div className="h-8 w-48 bg-slate-800 rounded animate-pulse" />
        <div className="h-64 bg-slate-800/40 rounded-2xl animate-pulse" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-6 text-red-300 text-sm">
        Failed to load configuration. Ensure you are signed in as an admin with settings:read.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <p className="text-slate-400 text-sm mt-1">
            Persist changes to <code className="font-mono text-xs">authkit.config.json</code> with hot reload
          </p>
        </div>
        <button
          onClick={() => saveMutation.mutate()}
          disabled={saveMutation.isPending}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all ${
            saved ? 'bg-emerald-600 text-white' : 'bg-violet-600 hover:bg-violet-500 text-white'
          }`}
        >
          {saved ? (
            <>
              <Check className="h-4 w-4" /> Saved!
            </>
          ) : (
            <>
              <Save className="h-4 w-4" /> Save Changes
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      <div className="flex gap-6">
        <nav className="w-48 space-y-1 flex-shrink-0">
          {CONFIG_SECTIONS.map((section) => {
            const Icon = section.icon;
            const active = section.key === activeSection;
            return (
              <button
                key={section.key}
                onClick={() => setActiveSection(section.key)}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium text-left transition-all ${
                  active
                    ? 'bg-violet-500/10 text-violet-400 border border-violet-500/20'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                <Icon className="h-4 w-4" />
                {section.label}
              </button>
            );
          })}
        </nav>

        <div className="flex-1 space-y-3">
          <div className="rounded-2xl bg-slate-800/40 border border-slate-700/50 overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-700/50 flex items-center gap-3">
              {React.createElement(currentSection.icon, { className: 'h-5 w-5 text-violet-400' })}
              <h2 className="font-semibold text-white">{currentSection.label}</h2>
            </div>
            <div className="divide-y divide-slate-700/30">
              {currentSection.fields.map((field) => {
                const value = getAt(sectionData, field.path);
                return (
                  <div key={field.key} className="px-6 py-4 flex items-center justify-between gap-6">
                    <div>
                      <p className="text-sm font-medium text-white">{field.label}</p>
                      {field.description && (
                        <p className="text-xs text-slate-500 mt-0.5">{field.description}</p>
                      )}
                    </div>
                    {field.type === 'toggle' && (
                      <Toggle
                        value={Boolean(value)}
                        onChange={(v) => updateField(field.path, v)}
                      />
                    )}
                    {field.type === 'number' && (
                      <input
                        type="number"
                        value={typeof value === 'number' ? value : 0}
                        onChange={(e) => updateField(field.path, parseInt(e.target.value, 10) || 0)}
                        className="w-24 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm text-right focus:outline-none focus:border-violet-500 transition-colors"
                      />
                    )}
                    {field.type === 'text' && (
                      <input
                        type="text"
                        value={typeof value === 'string' ? value : ''}
                        onChange={(e) => updateField(field.path, e.target.value)}
                        className="w-64 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm focus:outline-none focus:border-violet-500 transition-colors"
                      />
                    )}
                    {field.type === 'select' && (
                      <select
                        value={typeof value === 'string' ? value : (field.options?.[0] ?? '')}
                        onChange={(e) => updateField(field.path, e.target.value)}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm focus:outline-none focus:border-violet-500 appearance-none cursor-pointer"
                      >
                        {field.options?.map((o) => (
                          <option key={o} value={o}>
                            {o}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          <p className="text-xs text-slate-500 text-right">
            Changes are written to <code className="font-mono">authkit.config.json</code> and hot-reloaded
            without a restart.
          </p>
        </div>
      </div>
    </div>
  );
}
