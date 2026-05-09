'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { webhooksApi } from '@/lib/api';
import { Plus, Trash2, ToggleLeft, ToggleRight, RefreshCw, Copy, CheckCheck } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { clsx } from 'clsx';

const AVAILABLE_EVENTS = [
  'user.registered', 'user.login', 'user.logout', 'user.password_changed',
  'user.email_verified', 'user.locked', 'user.unlocked', 'user.deleted',
  'mfa.enabled', 'mfa.disabled', 'session.revoked', 'apikey.created',
  'apikey.revoked', 'role.assigned',
];

export default function WebhooksPage() {
  const qc = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [url, setUrl] = useState('');
  const [events, setEvents] = useState<string[]>([]);
  const [copiedSecret, setCopiedSecret] = useState<string | null>(null);

  const { data: endpoints = [], isLoading } = useQuery({
    queryKey: ['webhooks'],
    queryFn: () => webhooksApi.list(),
  });

  const create = useMutation({
    mutationFn: () => webhooksApi.create({ url, events }),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['webhooks'] });
      setAdding(false);
      setUrl('');
      setEvents([]);
      if (data.secret) {
        navigator.clipboard.writeText(data.secret);
        alert(`Endpoint created! Secret copied to clipboard:\n${data.secret}`);
      }
    },
  });

  const toggle = useMutation({
    mutationFn: ({ id, isActive }: { id: string; isActive: boolean }) =>
      webhooksApi.toggle(id, isActive),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  });

  const rotate = useMutation({
    mutationFn: (id: string) => webhooksApi.rotateSecret(id),
    onSuccess: (data) => {
      navigator.clipboard.writeText(data.secret);
      setCopiedSecret(data.secret);
      setTimeout(() => setCopiedSecret(null), 3000);
    },
  });

  const del = useMutation({
    mutationFn: (id: string) => webhooksApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  });

  const toggleEvent = (e: string) =>
    setEvents((prev) => (prev.includes(e) ? prev.filter((x) => x !== e) : [...prev, e]));

  return (
    <div className="space-y-6 animate-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Webhooks</h1>
          <p className="text-sm text-zinc-500 mt-1">HMAC-signed event delivery</p>
        </div>
        <button className="btn-primary flex items-center gap-2" onClick={() => setAdding(true)}>
          <Plus className="w-4 h-4" />
          Add Endpoint
        </button>
      </div>

      {/* Add form */}
      {adding && (
        <div className="card space-y-4 border-violet-500/30 animate-in">
          <h2 className="font-semibold text-zinc-200">New Endpoint</h2>
          <input
            className="input"
            placeholder="https://yourapp.com/webhook"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <div>
            <p className="text-xs text-zinc-500 mb-2">Select events to subscribe to:</p>
            <div className="flex flex-wrap gap-2">
              {AVAILABLE_EVENTS.map((ev) => (
                <button
                  key={ev}
                  onClick={() => toggleEvent(ev)}
                  className={clsx(
                    'text-xs px-2.5 py-1 rounded-full border transition-all',
                    events.includes(ev)
                      ? 'bg-violet-500/20 border-violet-500/40 text-violet-300'
                      : 'bg-zinc-800 border-zinc-700 text-zinc-400 hover:border-zinc-500',
                  )}
                >
                  {ev}
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-3">
            <button
              className="btn-primary"
              onClick={() => create.mutate()}
              disabled={!url || events.length === 0}
            >
              Create
            </button>
            <button className="btn-secondary" onClick={() => setAdding(false)}>Cancel</button>
          </div>
        </div>
      )}

      {/* Endpoint list */}
      <div className="space-y-3">
        {isLoading
          ? Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="card h-20 animate-pulse bg-zinc-900" />
            ))
          : (endpoints as any[]).map((ep) => (
              <div key={ep.id} className="card space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="font-mono text-sm text-zinc-200">{ep.url}</p>
                    <p className="text-xs text-zinc-500 mt-0.5">
                      {ep.failureCount > 0 && (
                        <span className="text-rose-400 mr-2">{ep.failureCount} failures</span>
                      )}
                      {ep.lastDeliveredAt
                        ? `Last delivery ${formatDistanceToNow(new Date(ep.lastDeliveredAt), { addSuffix: true })}`
                        : 'No deliveries yet'}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => rotate.mutate(ep.id)}
                      className="p-1.5 rounded-lg hover:bg-zinc-700 text-zinc-400 hover:text-zinc-100 transition-colors"
                      title="Rotate secret"
                    >
                      <RefreshCw className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => toggle.mutate({ id: ep.id, isActive: !ep.isActive })}
                      className="p-1.5 rounded-lg hover:bg-zinc-700 text-zinc-400 hover:text-zinc-100 transition-colors"
                    >
                      {ep.isActive
                        ? <ToggleRight className="w-5 h-5 text-emerald-400" />
                        : <ToggleLeft className="w-5 h-5" />}
                    </button>
                    <button
                      onClick={() => { if (confirm('Delete endpoint?')) del.mutate(ep.id); }}
                      className="p-1.5 rounded-lg hover:bg-rose-500/10 text-zinc-400 hover:text-rose-400 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {ep.events.map((ev: string) => (
                    <span key={ev} className="badge-blue text-[10px]">{ev}</span>
                  ))}
                </div>
              </div>
            ))}
      </div>
    </div>
  );
}
