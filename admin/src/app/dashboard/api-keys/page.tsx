'use client';
import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Key, Plus, Trash2, Copy, Eye, EyeOff, Check, RefreshCw, X } from 'lucide-react';
import { apiClient } from '@/lib/api';

interface ApiKey { id: string; name: string; prefix: string; scopes: string[]; lastUsedAt: string | null; expiresAt: string | null; createdAt: string; isRevoked: boolean; }
interface NewKeyResponse extends ApiKey { key: string; }

const AVAILABLE_SCOPES = ['read', 'write', 'admin', 'users:read', 'users:write', 'audit:read', 'webhooks:manage', 'apikeys:manage'];

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); };
  return (
    <button onClick={copy} className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 transition-colors" title="Copy">
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

function CreateKeyModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<string[]>(['read']);
  const [expiry, setExpiry] = useState('90');
  const [newKey, setNewKey] = useState<string | null>(null);
  const [visible, setVisible] = useState(false);

  const mutation = useMutation({
    mutationFn: () => apiClient<NewKeyResponse>('/api-keys', { method: 'POST', body: JSON.stringify({ name, scopes, expiresIn: parseInt(expiry) || undefined }) }),
    onSuccess: (data: NewKeyResponse) => { setNewKey(data.key); qc.invalidateQueries({ queryKey: ['api-keys'] }); },
  });

  const toggleScope = (s: string) => setScopes(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={!newKey ? onClose : undefined} />
      <div className="relative z-10 w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-700 p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-white">{newKey ? '🔑 Save Your Key' : 'Create API Key'}</h2>
          {!newKey && <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400"><X className="h-4 w-4" /></button>}
        </div>

        {newKey ? (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-sm">
              ⚠️ This key is shown only once. Copy it now — you won't be able to see it again.
            </div>
            <div className="flex items-center gap-2 p-3 rounded-xl bg-slate-800 border border-slate-700">
              <code className="flex-1 text-sm text-emerald-400 font-mono break-all">{visible ? newKey : newKey.replace(/./g, '•')}</code>
              <button onClick={() => setVisible(v => !v)} className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400"><EyeOff className="h-4 w-4" /></button>
              <CopyButton text={newKey} />
            </div>
            <button onClick={onClose} className="w-full py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 text-white text-sm font-medium transition-colors">Done</button>
          </div>
        ) : (
          <div className="space-y-5">
            <div>
              <label className="block text-sm text-slate-400 mb-2">Key Name</label>
              <input type="text" placeholder="e.g. CI/CD Pipeline" value={name} onChange={e => setName(e.target.value)} className="w-full px-4 py-2.5 rounded-xl bg-slate-800 border border-slate-700 text-white text-sm focus:outline-none focus:border-violet-500 transition-colors" />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-2">Scopes</label>
              <div className="flex flex-wrap gap-2">
                {AVAILABLE_SCOPES.map(s => (
                  <button key={s} onClick={() => toggleScope(s)} className={`px-3 py-1 rounded-lg text-xs font-medium border transition-colors ${scopes.includes(s) ? 'bg-violet-600 border-violet-500 text-white' : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'}`}>{s}</button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-2">Expires In</label>
              <select value={expiry} onChange={e => setExpiry(e.target.value)} className="w-full px-4 py-2.5 rounded-xl bg-slate-800 border border-slate-700 text-white text-sm focus:outline-none focus:border-violet-500 appearance-none">
                <option value="30">30 days</option>
                <option value="90">90 days</option>
                <option value="365">1 year</option>
                <option value="0">Never</option>
              </select>
            </div>
            <div className="flex gap-3 pt-2">
              <button onClick={onClose} className="flex-1 py-2.5 rounded-xl bg-slate-800 text-slate-300 text-sm hover:bg-slate-700 transition-colors">Cancel</button>
              <button onClick={() => mutation.mutate()} disabled={!name || mutation.isPending} className="flex-1 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 text-white text-sm font-medium transition-colors disabled:opacity-50">
                {mutation.isPending ? 'Creating…' : 'Create Key'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function ApiKeysPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data: keys = [], isLoading } = useQuery<ApiKey[]>({
    queryKey: ['api-keys'],
    queryFn: () => apiClient('/api-keys'),
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => apiClient(`/api-keys/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">API Keys</h1>
          <p className="text-slate-400 text-sm mt-1">{keys.length} active key{keys.length !== 1 ? 's' : ''}</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 px-4 py-2 rounded-xl bg-violet-600 hover:bg-violet-500 text-white text-sm font-medium transition-colors">
          <Plus className="h-4 w-4" /> New Key
        </button>
      </div>

      <div className="space-y-3">
        {isLoading ? Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-20 rounded-xl bg-slate-800/40 border border-slate-700/30 animate-pulse" />) :
        keys.length === 0 ? (
          <div className="py-20 text-center text-slate-500 rounded-2xl bg-slate-800/40 border border-slate-700/30">
            <Key className="h-12 w-12 mx-auto mb-3 opacity-30" />
            <p>No API keys yet. Create your first key to get started.</p>
          </div>
        ) : keys.map(key => (
          <div key={key.id} className={`flex items-center gap-4 px-5 py-4 rounded-xl border transition-colors ${!key.isRevoked ? 'bg-slate-800/40 border-slate-700/50' : 'bg-slate-800/20 border-slate-700/20 opacity-60'}`}>
            <div className="h-10 w-10 rounded-xl bg-violet-500/20 flex items-center justify-center flex-shrink-0">
              <Key className="h-5 w-5 text-violet-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <p className="font-medium text-white text-sm">{key.name}</p>
                {key.isRevoked && <span className="px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 text-xs border border-red-500/20">Revoked</span>}
              </div>
              <div className="flex items-center gap-3 mt-1">
                <code className="text-xs text-slate-400 font-mono">{key.prefix}••••••••</code>
                <span className="text-xs text-slate-500">·</span>
                <span className="text-xs text-slate-500">{key.scopes.join(', ')}</span>
              </div>
            </div>
            <div className="text-right text-xs text-slate-500 flex-shrink-0">
              <p>{key.lastUsedAt ? `Last used ${new Date(key.lastUsedAt).toLocaleDateString()}` : 'Never used'}</p>
              <p className="mt-0.5">{key.expiresAt ? `Expires ${new Date(key.expiresAt).toLocaleDateString()}` : 'No expiry'}</p>
            </div>
            {!key.isRevoked && (
              <button onClick={() => revokeMutation.mutate(key.id)} className="flex-shrink-0 p-2 rounded-lg hover:bg-red-500/20 text-slate-400 hover:text-red-400 transition-colors" title="Revoke">
                <Trash2 className="h-4 w-4" />
              </button>
            )}
          </div>
        ))}
      </div>

      {showCreate && <CreateKeyModal onClose={() => setShowCreate(false)} />}
    </div>
  );
}
