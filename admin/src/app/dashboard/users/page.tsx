'use client';
import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Search, Lock, Unlock, Trash2, RefreshCw, Shield, User as UserIcon, MoreVertical, X, Check, AlertTriangle, ChevronLeft, ChevronRight } from 'lucide-react';
import { apiClient } from '@/lib/api';

interface User { id: string; email: string; name: string | null; isLocked: boolean; isDeleted: boolean; emailVerified: boolean; createdAt: string; lastLoginAt: string | null; role: { name: string; displayName: string } | null; _count: { sessions: number }; }
interface UsersResponse { data: User[]; meta: { total: number; page: number; limit: number }; }

const ROLE_COLORS: Record<string, string> = {
  superadmin: 'bg-violet-500/20 text-violet-300 border border-violet-500/30',
  admin: 'bg-blue-500/20 text-blue-300 border border-blue-500/30',
  moderator: 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30',
  user: 'bg-slate-500/20 text-slate-300 border border-slate-500/30',
  guest: 'bg-zinc-500/20 text-zinc-400 border border-zinc-500/30',
};

function StatusBadge({ user }: { user: User }) {
  if (user.isDeleted) return <span className="px-2 py-0.5 text-xs rounded-full bg-red-500/20 text-red-400 border border-red-500/30">Deleted</span>;
  if (user.isLocked) return <span className="px-2 py-0.5 text-xs rounded-full bg-orange-500/20 text-orange-400 border border-orange-500/30">Locked</span>;
  return <span className="px-2 py-0.5 text-xs rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">Active</span>;
}

function ConfirmDialog({ open, title, message, variant, onConfirm, onCancel }: { open: boolean; title: string; message: string; variant: 'danger' | 'warning'; onConfirm: () => void; onCancel: () => void; }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onCancel} />
      <div className="relative z-10 w-full max-w-sm rounded-2xl bg-slate-900 border border-slate-700 p-6 shadow-2xl">
        <div className={`inline-flex p-3 rounded-xl mb-4 ${variant === 'danger' ? 'bg-red-500/20' : 'bg-orange-500/20'}`}>
          <AlertTriangle className={`h-6 w-6 ${variant === 'danger' ? 'text-red-400' : 'text-orange-400'}`} />
        </div>
        <h3 className="text-lg font-semibold text-white mb-2">{title}</h3>
        <p className="text-sm text-slate-400 mb-6">{message}</p>
        <div className="flex gap-3">
          <button onClick={onCancel} className="flex-1 px-4 py-2 rounded-lg bg-slate-800 text-slate-300 text-sm hover:bg-slate-700 transition-colors">Cancel</button>
          <button onClick={onConfirm} className={`flex-1 px-4 py-2 rounded-lg text-white text-sm font-medium transition-colors ${variant === 'danger' ? 'bg-red-600 hover:bg-red-500' : 'bg-orange-600 hover:bg-orange-500'}`}>Confirm</button>
        </div>
      </div>
    </div>
  );
}

function UserActions({ user, onAction }: { user: User; onAction: (a: string, u: User) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button onClick={() => setOpen(!open)} className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 transition-colors"><MoreVertical className="h-4 w-4" /></button>
      {open && (<>
        <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
        <div className="absolute right-0 top-8 z-20 w-44 rounded-xl bg-slate-800 border border-slate-700 shadow-xl overflow-hidden">
          {!user.isLocked
            ? <button onClick={() => { setOpen(false); onAction('lock', user); }} className="flex items-center gap-2.5 w-full px-4 py-2.5 text-sm text-orange-400 hover:bg-slate-700 transition-colors"><Lock className="h-3.5 w-3.5" /> Lock account</button>
            : <button onClick={() => { setOpen(false); onAction('unlock', user); }} className="flex items-center gap-2.5 w-full px-4 py-2.5 text-sm text-emerald-400 hover:bg-slate-700 transition-colors"><Unlock className="h-3.5 w-3.5" /> Unlock account</button>
          }
          <button onClick={() => { setOpen(false); onAction('delete', user); }} disabled={user.isDeleted} className="flex items-center gap-2.5 w-full px-4 py-2.5 text-sm text-red-400 hover:bg-slate-700 transition-colors disabled:opacity-40"><Trash2 className="h-3.5 w-3.5" /> Delete user</button>
        </div>
      </>)}
    </div>
  );
}

export default function UsersPage() {
  const qc = useQueryClient();
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [confirm, setConfirm] = useState<{ open: boolean; action: string; user: User | null }>({ open: false, action: '', user: null });

  const { data, isLoading, isFetching } = useQuery<UsersResponse>({
    queryKey: ['users', search, page],
    queryFn: () => apiClient(`/users?search=${encodeURIComponent(search)}&page=${page}&limit=20`),
    placeholderData: (prev) => prev,
  });

  const lockMutation = useMutation({ mutationFn: ({ id, lock }: { id: string; lock: boolean }) => apiClient(`/users/${id}/${lock ? 'lock' : 'unlock'}`, { method: 'PATCH' }), onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }) });
  const deleteMutation = useMutation({ mutationFn: (id: string) => apiClient(`/users/${id}`, { method: 'DELETE' }), onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }) });

  const handleAction = (action: string, user: User) => setConfirm({ open: true, action, user });
  const handleConfirm = () => {
    if (!confirm.user) return;
    if (confirm.action === 'lock') lockMutation.mutate({ id: confirm.user.id, lock: true });
    if (confirm.action === 'unlock') lockMutation.mutate({ id: confirm.user.id, lock: false });
    if (confirm.action === 'delete') deleteMutation.mutate(confirm.user.id);
    setConfirm({ open: false, action: '', user: null });
  };

  const users = data?.data ?? [];
  const meta = data?.meta ?? { total: 0, page: 1, limit: 20 };
  const totalPages = Math.ceil(meta.total / meta.limit);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">User Management</h1>
          <p className="text-slate-400 text-sm mt-1">{meta.total.toLocaleString()} total users</p>
        </div>
        <button onClick={() => qc.invalidateQueries({ queryKey: ['users'] })} className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-sm hover:bg-slate-700 transition-colors border border-slate-700">
          <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      <div className="relative">
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
        <input type="text" placeholder="Search by name or email…" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} className="w-full pl-11 pr-4 py-3 rounded-xl bg-slate-800/60 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-violet-500 transition-colors" />
        {search && <button onClick={() => setSearch('')} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white"><X className="h-4 w-4" /></button>}
      </div>

      <div className="rounded-2xl bg-slate-800/40 border border-slate-700/50 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-slate-700/50">
              {['User','Role','Status','Sessions','Joined','Last Login','Actions'].map(h => (
                <th key={h} className={`px-6 py-4 text-xs font-medium text-slate-400 uppercase tracking-wider ${h === 'Actions' ? 'text-right' : 'text-left'}`}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/30">
            {isLoading ? Array.from({ length: 8 }).map((_, i) => (
              <tr key={i}>{Array.from({ length: 7 }).map((_, j) => <td key={j} className="px-6 py-4"><div className="h-4 bg-slate-700/50 rounded animate-pulse" /></td>)}</tr>
            )) : users.length === 0 ? (
              <tr><td colSpan={7} className="px-6 py-16 text-center text-slate-500"><UserIcon className="h-12 w-12 mx-auto mb-3 opacity-30" /><p>No users found</p></td></tr>
            ) : users.map(user => (
              <tr key={user.id} className="hover:bg-slate-700/20 transition-colors">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <div className="h-9 w-9 rounded-full bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center text-white text-sm font-semibold flex-shrink-0">{(user.name ?? user.email)[0].toUpperCase()}</div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate">{user.name ?? '—'}</p>
                      <p className="text-xs text-slate-400 truncate">{user.email}</p>
                    </div>
                    {user.emailVerified && <Check className="h-3.5 w-3.5 text-emerald-400 flex-shrink-0" title="Email verified" />}
                  </div>
                </td>
                <td className="px-6 py-4">
                  {user.role ? <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium ${ROLE_COLORS[user.role.name] ?? ROLE_COLORS.guest}`}><Shield className="h-3 w-3" />{user.role.displayName}</span> : <span className="text-slate-500 text-xs">No role</span>}
                </td>
                <td className="px-6 py-4"><StatusBadge user={user} /></td>
                <td className="px-6 py-4 text-sm text-slate-300">{user._count.sessions}</td>
                <td className="px-6 py-4 text-sm text-slate-400">{new Date(user.createdAt).toLocaleDateString()}</td>
                <td className="px-6 py-4 text-sm text-slate-400">{user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleDateString() : '—'}</td>
                <td className="px-6 py-4 text-right"><UserActions user={user} onAction={handleAction} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm">
          <p className="text-slate-400">Showing {(meta.page - 1) * meta.limit + 1}–{Math.min(meta.page * meta.limit, meta.total)} of {meta.total}</p>
          <div className="flex items-center gap-2">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"><ChevronLeft className="h-4 w-4" /></button>
            <span className="px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-white">{page} / {totalPages}</span>
            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages} className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"><ChevronRight className="h-4 w-4" /></button>
          </div>
        </div>
      )}

      <ConfirmDialog open={confirm.open} title={confirm.action === 'delete' ? 'Delete User' : confirm.action === 'lock' ? 'Lock Account' : 'Unlock Account'} message={confirm.action === 'delete' ? `Permanently delete ${confirm.user?.email}? This cannot be undone.` : confirm.action === 'lock' ? `Lock ${confirm.user?.email}? They cannot sign in.` : `Restore access for ${confirm.user?.email}?`} variant={confirm.action === 'delete' ? 'danger' : 'warning'} onConfirm={handleConfirm} onCancel={() => setConfirm({ open: false, action: '', user: null })} />
    </div>
  );
}
