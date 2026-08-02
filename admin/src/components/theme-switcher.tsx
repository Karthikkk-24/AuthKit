'use client';

import { useEffect, useState } from 'react';
import { Palette } from 'lucide-react';
import { configApi } from '@/lib/api';

const STORAGE_KEY = 'ak_admin_theme';

const THEME_VARS: Record<string, Record<string, string>> = {
  midnight: {
    '--bg-primary': '#09090b',
    '--bg-surface': '#18181b',
    '--bg-elevated': '#27272a',
    '--border': '#3f3f46',
    '--accent-violet': '#8b5cf6',
  },
  aurora: {
    '--bg-primary': '#0a1628',
    '--bg-surface': '#12233d',
    '--bg-elevated': '#1a3258',
    '--border': '#2a4a73',
    '--accent-violet': '#22d3ee',
  },
  slate: {
    '--bg-primary': '#0f172a',
    '--bg-surface': '#1e293b',
    '--bg-elevated': '#334155',
    '--border': '#475569',
    '--accent-violet': '#64748b',
  },
  ember: {
    '--bg-primary': '#1a0f0a',
    '--bg-surface': '#2a1810',
    '--bg-elevated': '#3d2418',
    '--border': '#5c3a28',
    '--accent-violet': '#f97316',
  },
  arctic: {
    '--bg-primary': '#0c1222',
    '--bg-surface': '#152238',
    '--bg-elevated': '#1e3352',
    '--border': '#2d4a6f',
    '--accent-violet': '#38bdf8',
  },
};

function applyTheme(name: string) {
  const vars = THEME_VARS[name] ?? THEME_VARS.midnight;
  const root = document.documentElement;
  for (const [k, v] of Object.entries(vars)) {
    root.style.setProperty(k, v);
  }
  root.dataset.theme = name;
}

export function ThemeSwitcher() {
  const [themes, setThemes] = useState<string[]>(Object.keys(THEME_VARS));
  const [theme, setTheme] = useState('midnight');

  useEffect(() => {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && THEME_VARS[saved]) {
      setTheme(saved);
      applyTheme(saved);
    } else {
      applyTheme('midnight');
    }

    configApi
      .get()
      .then((cfg: any) => {
        const available: string[] = cfg?.ui?.availableThemes ?? [];
        const filtered = available.filter((t) => THEME_VARS[t]);
        if (filtered.length) setThemes(filtered);
        const configured = cfg?.ui?.theme;
        if (!saved && configured && THEME_VARS[configured]) {
          setTheme(configured);
          applyTheme(configured);
        }
      })
      .catch(() => {
        /* config optional for theme UX */
      });
  }, []);

  const onChange = (next: string) => {
    setTheme(next);
    localStorage.setItem(STORAGE_KEY, next);
    applyTheme(next);
  };

  return (
    <div className="px-3 pb-2">
      <label className="flex items-center gap-2 px-3 py-2 text-xs text-zinc-500 uppercase tracking-wider">
        <Palette className="w-3.5 h-3.5" />
        Theme
      </label>
      <select
        value={theme}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-sm text-zinc-200"
        aria-label="Admin theme"
      >
        {themes.map((t) => (
          <option key={t} value={t}>
            {t}
          </option>
        ))}
      </select>
    </div>
  );
}
