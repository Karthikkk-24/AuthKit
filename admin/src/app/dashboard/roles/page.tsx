'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { rbacApi } from '@/lib/api';
import { Plus, Pencil, Trash2, Check } from 'lucide-react';
import { clsx } from 'clsx';

export default function RolesPage() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<any>(null);
  const [creating, setCreating] = useState(false);
  const [newRoleName, setNewRoleName] = useState('');

  const { data: roles = [] } = useQuery({
    queryKey: ['roles'],
    queryFn: () => rbacApi.getRoles(),
  });

  const { data: permissions = [] } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => rbacApi.getPermissions(),
  });

  const createRole = useMutation({
    mutationFn: (data: any) => rbacApi.createRole(data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['roles'] }); setCreating(false); setNewRoleName(''); },
  });

  const assignPerms = useMutation({
    mutationFn: ({ roleId, permissionIds }: { roleId: string; permissionIds: string[] }) =>
      rbacApi.assignPermissions(roleId, permissionIds),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['roles'] }),
  });

  const selectedPerms: string[] = selected?.permissions?.map((p: any) => p.id) ?? [];

  const togglePerm = (permId: string) => {
    if (!selected) return;
    const next = selectedPerms.includes(permId)
      ? selectedPerms.filter((id) => id !== permId)
      : [...selectedPerms, permId];
    assignPerms.mutate({ roleId: selected.id, permissionIds: next });
  };

  // Group permissions by resource
  const grouped = (permissions as any[]).reduce<Record<string, any[]>>((acc, p) => {
    (acc[p.resource] ??= []).push(p);
    return acc;
  }, {});

  return (
    <div className="space-y-6 animate-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Roles & Permissions</h1>
          <p className="text-sm text-zinc-500 mt-1">Define roles and assign granular permissions</p>
        </div>
        <button className="btn-primary flex items-center gap-2" onClick={() => setCreating(true)}>
          <Plus className="w-4 h-4" /> New Role
        </button>
      </div>

      {creating && (
        <div className="card border-violet-500/30 space-y-3 animate-in">
          <input
            className="input"
            placeholder="Role name (e.g. editor)"
            value={newRoleName}
            onChange={(e) => setNewRoleName(e.target.value)}
          />
          <div className="flex gap-3">
            <button
              className="btn-primary"
              onClick={() => createRole.mutate({ name: newRoleName })}
              disabled={!newRoleName}
            >
              Create
            </button>
            <button className="btn-secondary" onClick={() => setCreating(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Role list */}
        <div className="space-y-2">
          {(roles as any[]).map((role) => (
            <button
              key={role.id}
              onClick={() => setSelected(role)}
              className={clsx(
                'w-full text-left px-4 py-3 rounded-xl border transition-all',
                selected?.id === role.id
                  ? 'border-violet-500/40 bg-violet-500/10 text-violet-300'
                  : 'border-zinc-800 bg-zinc-900 text-zinc-300 hover:border-zinc-700',
              )}
            >
              <div className="flex items-center justify-between">
                <span className="font-medium">{role.displayName ?? role.name}</span>
                {role.isSystem && (
                  <span className="badge-gray text-[10px]">system</span>
                )}
              </div>
              <p className="text-xs text-zinc-500 mt-0.5">
                {role._count?.users ?? 0} users · {role.permissions?.length ?? 0} perms
              </p>
            </button>
          ))}
        </div>

        {/* Permissions panel */}
        <div className="lg:col-span-2">
          {selected ? (
            <div className="card space-y-4">
              <h2 className="font-semibold text-zinc-200">
                Permissions for <span className="text-violet-400">{selected.displayName ?? selected.name}</span>
              </h2>
              <div className="space-y-4">
                {Object.entries(grouped).map(([resource, perms]) => (
                  <div key={resource}>
                    <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">
                      {resource}
                    </p>
                    <div className="grid grid-cols-2 gap-2">
                      {perms.map((p: any) => {
                        const active = selectedPerms.includes(p.id);
                        return (
                          <button
                            key={p.id}
                            onClick={() => togglePerm(p.id)}
                            className={clsx(
                              'flex items-center gap-2 px-3 py-2 rounded-lg text-sm border transition-all',
                              active
                                ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                                : 'border-zinc-800 bg-zinc-800/60 text-zinc-400 hover:border-zinc-600',
                            )}
                          >
                            <div className={clsx(
                              'w-4 h-4 rounded flex items-center justify-center border',
                              active ? 'border-emerald-400 bg-emerald-400' : 'border-zinc-600',
                            )}>
                              {active && <Check className="w-2.5 h-2.5 text-zinc-900" />}
                            </div>
                            <span className="font-mono text-xs">{p.action}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="card h-40 flex items-center justify-center text-zinc-500 text-sm">
              Select a role to manage its permissions
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
