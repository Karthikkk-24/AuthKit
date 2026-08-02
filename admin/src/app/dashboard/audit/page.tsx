'use client';
import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Download, ShieldAlert, Clock, User, Filter } from 'lucide-react';
import { apiClient } from '@/lib/api';

/** Matches AuditService.query / AuditLog Prisma model (#28) */
interface AuditLog {
  id: string;
  action: string;
  userId: string | null;
  resourceType: string | null;
  resourceId: string | null;
  metadata: Record<string, unknown> | null;
  ip: string | null;
  userAgent: string | null;
  timestamp: string;
  success: boolean;
}
interface AuditResponse {
  data: AuditLog[];
  total: number;
  page: number;
  limit: number;
  pages: number;
}

const ACTION_COLORS: Record<string, string> = {
  login: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  logout: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
  register: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  'password.changed': 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  'password.reset': 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  'user.locked': 'text-red-400 bg-red-500/10 border-red-500/20',
  'user.unlocked': 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  'user.deleted': 'text-red-400 bg-red-500/10 border-red-500/20',
  'mfa.enabled': 'text-violet-400 bg-violet-500/10 border-violet-500/20',
  'mfa.disabled': 'text-violet-400 bg-violet-500/10 border-violet-500/20',
  'apikey.created': 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
  'apikey.revoked': 'text-red-400 bg-red-500/10 border-red-500/20',
  'config.updated': 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  'role.permissions_updated': 'text-violet-400 bg-violet-500/10 border-violet-500/20',
};

function getActionClass(action: string) {
  return ACTION_COLORS[action] ?? 'text-slate-400 bg-slate-500/10 border-slate-500/20';
}
function formatAction(action: string) {
  return action.replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function AuditLogsPage() {
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data, isLoading } = useQuery<AuditResponse>({
    queryKey: ['audit', page, actionFilter],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), limit: '25' });
      if (actionFilter) params.set('action', actionFilter);
      return apiClient(`/audit?${params}`);
    },
    placeholderData: (p) => p,
  });

  const logs = data?.data ?? [];
  const total = data?.total ?? 0;
  const totalPages = data?.pages ?? (Math.ceil(total / (data?.limit ?? 25)) || 1);

  const handleExport = async () => {
    const params = new URLSearchParams();
    if (actionFilter) params.set('action', actionFilter);
    const qs = params.toString();
    const res = await apiClient<string>(`/audit/export${qs ? `?${qs}` : ''}`);
    const blob = new Blob([res], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const ACTIONS = [
    'login',
    'logout',
    'register',
    'password.changed',
    'password.reset',
    'user.locked',
    'user.unlocked',
    'user.deleted',
    'mfa.enabled',
    'mfa.disabled',
    'apikey.created',
    'apikey.revoked',
    'config.updated',
    'role.permissions_updated',
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Audit Logs</h1>
          <p className="text-slate-400 text-sm mt-1">{total.toLocaleString()} events recorded</p>
        </div>
        <button
          onClick={handleExport}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-violet-600 hover:bg-violet-500 text-white text-sm font-medium transition-colors"
        >
          <Download className="h-4 w-4" /> Export CSV
        </button>
      </div>

      <div className="flex gap-3">
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <select
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              setPage(1);
            }}
            className="pl-9 pr-8 py-3 rounded-xl bg-slate-800/60 border border-slate-700 text-white text-sm focus:outline-none focus:border-violet-500 appearance-none cursor-pointer"
          >
            <option value="">All actions</option>
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {formatAction(a)}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="space-y-2">
        {isLoading ? (
          Array.from({ length: 10 }).map((_, i) => (
            <div key={i} className="h-16 rounded-xl bg-slate-800/40 border border-slate-700/30 animate-pulse" />
          ))
        ) : logs.length === 0 ? (
          <div className="py-20 text-center text-slate-500">
            <ShieldAlert className="h-12 w-12 mx-auto mb-3 opacity-30" />
            <p>No audit events found</p>
          </div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="rounded-xl bg-slate-800/40 border border-slate-700/30 overflow-hidden">
              <button
                onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                className="w-full px-4 py-3.5 flex items-center gap-4 text-left hover:bg-slate-700/20 transition-colors"
              >
                <div
                  className={`flex-shrink-0 px-2.5 py-0.5 rounded-full text-xs font-medium border ${getActionClass(log.action)} ${log.success ? '' : 'opacity-60'}`}
                >
                  {formatAction(log.action)}
                </div>
                <div className="flex-1 min-w-0 flex items-center gap-3">
                  <div className="flex items-center gap-1.5 text-sm text-slate-300 truncate">
                    <User className="h-3.5 w-3.5 text-slate-500 flex-shrink-0" />
                    <span className="truncate font-mono text-xs">{log.userId ?? 'System'}</span>
                  </div>
                  {log.resourceType && (
                    <span className="text-slate-500 text-xs truncate">
                      {log.resourceType}
                      {log.resourceId ? `:${log.resourceId.slice(0, 8)}` : ''}
                    </span>
                  )}
                </div>
                {!log.success && (
                  <span className="flex-shrink-0 px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 text-xs border border-red-500/20">
                    Failed
                  </span>
                )}
                <div className="flex items-center gap-1.5 text-xs text-slate-500 flex-shrink-0">
                  <Clock className="h-3 w-3" />
                  {new Date(log.timestamp).toLocaleString()}
                </div>
              </button>
              {expanded === log.id && (
                <div className="px-4 pb-4 border-t border-slate-700/30 pt-3 grid grid-cols-2 gap-3">
                  {[
                    ['Event ID', log.id],
                    ['Resource', log.resourceType ?? '—'],
                    ['Resource ID', log.resourceId ?? '—'],
                    ['IP Address', log.ip ?? '—'],
                    ['User ID', log.userId ?? '—'],
                    ['User Agent', log.userAgent ?? '—'],
                  ].map(([label, value]) => (
                    <div key={label}>
                      <p className="text-xs text-slate-500">{label}</p>
                      <p className="text-sm text-slate-300 font-mono break-all">{value}</p>
                    </div>
                  ))}
                  {log.metadata && Object.keys(log.metadata).length > 0 && (
                    <div className="col-span-2">
                      <p className="text-xs text-slate-500 mb-1">Metadata</p>
                      <pre className="text-xs text-slate-300 bg-slate-900/60 rounded-lg p-3 overflow-auto max-h-32">
                        {JSON.stringify(log.metadata, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm">
          <p className="text-slate-400">
            Page {page} of {totalPages}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-xs transition-colors"
            >
              ← Prev
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-xs transition-colors"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
