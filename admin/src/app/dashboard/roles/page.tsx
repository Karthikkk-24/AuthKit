'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { rbacApi } from '@/lib/api';
import { Plus, Check, Trash2 } from 'lucide-react';
import { clsx } from 'clsx';

// Mirrors the shapes returned by /rbac/roles and /rbac/permissions (#28, #33)
interface Permission { id: string; resource: string; action: string; roleId: string; }
interface Role {
  id: string;
  name: string;
  description: string | null;
  isSystem: boolean;
  createdAt: string;
  permissions: Permission[];
  _count?: { users: number };
}

// The shared catalog of permission combinations an admin can assign.
// The API has no global catalog, so we derive one from the union of all
// role-owned permission rows plus sensible primitives.
const FALLBACK_RESOURCES = ['users', 'roles', 'permissions', 'audit', 'webhooks', 'apikeys', 'settings', 'sessions', 'resources', 'mfa'];
const FALLBACK_ACTIONS = ['read', 'write', 'update', 'delete', 'create', 'export', 'lock', '*'];

export default function RolesPage() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<Role | null>(null);
  const [creating, setCreating] = useState(false);
  const [newRoleName, setNewRoleName] = useState('');

  const { data: roles = [] } = useQuery<Role[]>({
    queryKey: ['roles'],
    queryFn: () => rbacApi.getRoles(),
  });

  const createRole = useMutation({
    mutationFn: (data: { name: string }) => rbacApi.createRole(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['roles'] });
      setCreating(false);
      setNewRoleName('');
    },
  });

  const deleteRole = useMutation({
    mutationFn: (id: string) => rbacApi.deleteRole(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['roles'] });
      setSelected(null);
    },
  });

  const assignPerms = useMutation({
    mutationFn: ({ roleId, permissions }: { roleId: string; permissions: Array<{ action: string; resource: string }> }) =>
      rbacApi.assignPermissions(roleId, permissions),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['roles'] }),
  });

  // Selected role's current permission pairs ("resource:action")
  const selectedKeys = new Set((selected?.permissions ?? []).map((p) => `${p.resource}:${p.action}`));

  const togglePerm = (resource: string, action: string) => {
    if (!selected) return;
    const key = `${resource}:${action}`;
    const current = (selected.permissions ?? []).map((p) => ({ action: p.action, resource: p.resource }));
    const next = selectedKeys.has(key)
      ? current.filter((p) => !(p.resource === resource && p.action === action))
      : [...current, { action, resource }];
    assignPerms.mutate({ roleId: selected.id, permissions: next });
    // Reflect the change locally so the UI stays responsive
    setSelected({ ...selected, permissions: next.map((p, i) => ({ id: `pending-${i}`, roleId: selected.id, ...p })) });
  };

  const grouped = FALLBACK_RESOURCES.map((resource) => ({
    resource,
    actions: FALLBACK_ACTIONS,
  }));

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
          {roles.map((role) => (
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
                <span className="font-medium">{role.name}</span>
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
              <div className="flex items-center justify-between">
                <h2 className="font-semibold text-zinc-200">
                  Permissions for <span className="text-violet-400">{selected.name}</span>
                </h2>
                {!selected.isSystem && (
                  <button
                    onClick={() => deleteRole.mutate(selected.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-red-400 hover:bg-red-500/10 border border-red-500/20"
                  >
                    <Trash2 className="w-3.5 h-3.5" /> Delete role
                  </button>
                )}
              </div>
              <div className="space-y-4">
                {grouped.map(({ resource, actions }) => (
                  <div key={resource}>
                    <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">
                      {resource}
                    </p>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                      {actions.map((action) => {
                        const active = selectedKeys.has(`${resource}:${action}`);
                        return (
                          <button
                            key={action}
                            onClick={() => togglePerm(resource, action)}
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
                            <span className="font-mono text-xs">{action}</span>
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
