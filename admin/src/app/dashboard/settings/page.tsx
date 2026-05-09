'use client';
import React, { useState } from 'react';
import { Settings, Shield, Mail, Database, Zap, Check, Save, RefreshCw } from 'lucide-react';

interface ConfigSection {
  key: string;
  label: string;
  icon: React.ElementType;
  fields: Array<{ key: string; label: string; type: 'toggle' | 'number' | 'text' | 'select'; options?: string[]; description?: string; }>;
}

const CONFIG_SECTIONS: ConfigSection[] = [
  {
    key: 'security', label: 'Security', icon: Shield,
    fields: [
      { key: 'maxLoginAttempts', label: 'Max Login Attempts', type: 'number', description: 'Attempts before account lockout' },
      { key: 'lockoutDurationMinutes', label: 'Lockout Duration (mins)', type: 'number' },
      { key: 'requireEmailVerification', label: 'Require Email Verification', type: 'toggle' },
      { key: 'pwnedPasswordCheck', label: 'Pwned Password Check (HIBP)', type: 'toggle', description: 'Reject known breached passwords' },
    ],
  },
  {
    key: 'auth', label: 'Authentication', icon: Zap,
    fields: [
      { key: 'allowLocalAuth', label: 'Allow Password Login', type: 'toggle' },
      { key: 'allowGoogleOAuth', label: 'Allow Google OAuth', type: 'toggle' },
      { key: 'allowGithubOAuth', label: 'Allow GitHub OAuth', type: 'toggle' },
      { key: 'accessTokenExpiry', label: 'Access Token Expiry', type: 'select', options: ['5m','15m','30m','1h','6h','12h'], description: 'JWT access token lifetime' },
      { key: 'refreshTokenExpiry', label: 'Refresh Token Expiry', type: 'select', options: ['1d','7d','14d','30d','90d'] },
    ],
  },
  {
    key: 'mfa', label: 'Multi-Factor Auth', icon: Shield,
    fields: [
      { key: 'mfaEnabled', label: 'Enable MFA', type: 'toggle' },
      { key: 'mfaTotpEnabled', label: 'TOTP (Authenticator App)', type: 'toggle' },
      { key: 'mfaEmailOtpEnabled', label: 'Email OTP', type: 'toggle' },
      { key: 'mfaRequired', label: 'Require MFA for All Users', type: 'toggle', description: 'Force all accounts to enroll MFA' },
    ],
  },
  {
    key: 'email', label: 'Email', icon: Mail,
    fields: [
      { key: 'emailProvider', label: 'Email Provider', type: 'select', options: ['smtp','sendgrid','resend'] },
      { key: 'emailFrom', label: 'From Address', type: 'text' },
    ],
  },
  {
    key: 'database', label: 'Database', icon: Database,
    fields: [
      { key: 'orm', label: 'Default ORM', type: 'select', options: ['prisma','typeorm','drizzle'] },
      { key: 'sessionCacheTtl', label: 'Session Cache TTL (secs)', type: 'number', description: 'Redis cache duration for sessions' },
    ],
  },
];

// Simulated default config state
const DEFAULT_CONFIG: Record<string, Record<string, unknown>> = {
  security: { maxLoginAttempts: 5, lockoutDurationMinutes: 30, requireEmailVerification: true, pwnedPasswordCheck: true },
  auth: { allowLocalAuth: true, allowGoogleOAuth: true, allowGithubOAuth: true, accessTokenExpiry: '15m', refreshTokenExpiry: '7d' },
  mfa: { mfaEnabled: true, mfaTotpEnabled: true, mfaEmailOtpEnabled: true, mfaRequired: false },
  email: { emailProvider: 'smtp', emailFrom: 'AuthKit <noreply@authkit.dev>' },
  database: { orm: 'prisma', sessionCacheTtl: 3600 },
};

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button onClick={() => onChange(!value)} className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${value ? 'bg-violet-600' : 'bg-slate-700'}`}>
      <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${value ? 'translate-x-6' : 'translate-x-1'}`} />
    </button>
  );
}

export default function SettingsPage() {
  const [config, setConfig] = useState(DEFAULT_CONFIG);
  const [saved, setSaved] = useState(false);
  const [activeSection, setActiveSection] = useState('security');

  const currentSection = CONFIG_SECTIONS.find(s => s.key === activeSection)!;

  const updateField = (sectionKey: string, fieldKey: string, value: unknown) => {
    setConfig(prev => ({ ...prev, [sectionKey]: { ...prev[sectionKey], [fieldKey]: value } }));
  };

  const handleSave = () => {
    // In production this would POST to /admin/config
    console.log('Saving config:', config);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <p className="text-slate-400 text-sm mt-1">Configure AuthKit behaviour via authkit.config.json</p>
        </div>
        <button onClick={handleSave} className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all ${saved ? 'bg-emerald-600 text-white' : 'bg-violet-600 hover:bg-violet-500 text-white'}`}>
          {saved ? <><Check className="h-4 w-4" /> Saved!</> : <><Save className="h-4 w-4" /> Save Changes</>}
        </button>
      </div>

      <div className="flex gap-6">
        {/* Section Nav */}
        <nav className="w-48 space-y-1 flex-shrink-0">
          {CONFIG_SECTIONS.map(section => {
            const Icon = section.icon;
            const active = section.key === activeSection;
            return (
              <button key={section.key} onClick={() => setActiveSection(section.key)} className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium text-left transition-all ${active ? 'bg-violet-500/10 text-violet-400 border border-violet-500/20' : 'text-slate-400 hover:text-white hover:bg-slate-800'}`}>
                <Icon className="h-4 w-4" />
                {section.label}
              </button>
            );
          })}
        </nav>

        {/* Fields */}
        <div className="flex-1 space-y-3">
          <div className="rounded-2xl bg-slate-800/40 border border-slate-700/50 overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-700/50 flex items-center gap-3">
              {React.createElement(currentSection.icon, { className: 'h-5 w-5 text-violet-400' })}
              <h2 className="font-semibold text-white">{currentSection.label}</h2>
            </div>
            <div className="divide-y divide-slate-700/30">
              {currentSection.fields.map(field => {
                const sectionConfig = config[activeSection] ?? {};
                const value = sectionConfig[field.key];
                return (
                  <div key={field.key} className="px-6 py-4 flex items-center justify-between gap-6">
                    <div>
                      <p className="text-sm font-medium text-white">{field.label}</p>
                      {field.description && <p className="text-xs text-slate-500 mt-0.5">{field.description}</p>}
                    </div>
                    {field.type === 'toggle' && <Toggle value={value as boolean} onChange={v => updateField(activeSection, field.key, v)} />}
                    {field.type === 'number' && (
                      <input type="number" value={value as number} onChange={e => updateField(activeSection, field.key, parseInt(e.target.value))}
                        className="w-24 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm text-right focus:outline-none focus:border-violet-500 transition-colors" />
                    )}
                    {field.type === 'text' && (
                      <input type="text" value={value as string} onChange={e => updateField(activeSection, field.key, e.target.value)}
                        className="w-64 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm focus:outline-none focus:border-violet-500 transition-colors" />
                    )}
                    {field.type === 'select' && (
                      <select value={value as string} onChange={e => updateField(activeSection, field.key, e.target.value)}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm focus:outline-none focus:border-violet-500 appearance-none cursor-pointer">
                        {field.options?.map(o => <option key={o} value={o}>{o}</option>)}
                      </select>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          <p className="text-xs text-slate-500 text-right">Changes are written to <code className="font-mono">authkit.config.json</code> and require an API restart to take effect.</p>
        </div>
      </div>
    </div>
  );
}
