'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  Users,
  Shield,
  Key,
  Activity,
  Webhook,
  Settings,
  LogOut,
  Lock,
  ChevronRight,
} from 'lucide-react';
import { clsx } from 'clsx';
import { ThemeSwitcher } from '@/components/theme-switcher';

const navLinks = [
  { href: '/dashboard',         label: 'Dashboard',    icon: LayoutDashboard },
  { href: '/dashboard/users',   label: 'Users',        icon: Users },
  { href: '/dashboard/roles',   label: 'Roles & Perms',icon: Shield },
  { href: '/dashboard/api-keys',label: 'API Keys',     icon: Key },
  { href: '/dashboard/audit',   label: 'Audit Logs',   icon: Activity },
  { href: '/dashboard/webhooks',label: 'Webhooks',     icon: Webhook },
  { href: '/dashboard/settings',label: 'Settings',     icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 shrink-0 h-screen sticky top-0 flex flex-col border-r border-zinc-800 bg-zinc-950">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-zinc-800">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-violet-500 to-blue-500 flex items-center justify-center glow-violet">
          <Lock className="w-4 h-4 text-white" />
        </div>
        <div>
          <p className="font-bold text-sm tracking-tight text-white">AuthKit</p>
          <p className="text-[10px] text-zinc-500 uppercase tracking-widest">Admin Console</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        {navLinks.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + '/');
          return (
            <Link
              key={href}
              href={href}
              className={clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group',
                active
                  ? 'bg-violet-500/10 text-violet-400 border border-violet-500/20'
                  : 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60',
              )}
            >
              <Icon className={clsx('w-4 h-4 shrink-0', active ? 'text-violet-400' : 'text-zinc-500 group-hover:text-zinc-300')} />
              <span className="flex-1">{label}</span>
              {active && <ChevronRight className="w-3 h-3 text-violet-400/60" />}
            </Link>
          );
        })}
      </nav>

      {/* Theme (#44) */}
      <ThemeSwitcher />

      {/* Footer */}
      <div className="px-3 py-4 border-t border-zinc-800">
        <button
          className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400
                     hover:text-rose-400 hover:bg-rose-500/10 transition-all w-full"
          onClick={async () => {
            try {
              const { authApi } = await import('@/lib/api');
              await authApi.logout();
            } catch {
              /* still clear local session via redirect */
            }
            window.location.href = '/login';
          }}
        >
          <LogOut className="w-4 h-4" />
          Sign out
        </button>
      </div>
    </aside>
  );
}
