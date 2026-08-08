'use client';

import { FormEvent, Suspense, useEffect, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { Loader2, CheckCircle2, AlertCircle, Shield } from 'lucide-react';

/**
 * Landing page for OAuth / magic-link redirects (#71).
 * Exchanges the one-time `code` via the BFF and establishes an admin session.
 * When MFA is required, collects mfaCode and completes via mfaToken (#110).
 */
function OAuthSuccessInner() {
  const params = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<'working' | 'mfa' | 'ok' | 'error'>('working');
  const [message, setMessage] = useState('Completing sign-in…');
  const [mfaToken, setMfaToken] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const code = params.get('code');
    if (!code) {
      setStatus('error');
      setMessage('Missing exchange code');
      return;
    }

    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/api/auth/oauth-exchange', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ code }),
        });
        const data = await res.json().catch(() => ({}));
        if (cancelled) return;

        if (!res.ok) {
          setStatus('error');
          setMessage(
            Array.isArray(data.message) ? data.message.join(', ') : (data.message ?? 'Exchange failed'),
          );
          return;
        }

        if (data.requiresMfa) {
          if (!data.mfaToken || typeof data.mfaToken !== 'string') {
            setStatus('error');
            setMessage('MFA is required but no mfaToken was returned. Restart sign-in.');
            return;
          }
          setMfaToken(data.mfaToken);
          setStatus('mfa');
          setMessage(data.message ?? 'Enter your MFA code to finish signing in.');
          return;
        }

        if (data.mfaSetupRequired) {
          setStatus('error');
          setMessage(data.message ?? 'MFA enrollment is required before continuing.');
          return;
        }

        if (data.nonAdmin) {
          setStatus('ok');
          setMessage(data.message ?? 'Signed in (non-admin). You can close this window.');
          return;
        }

        setStatus('ok');
        setMessage('Signed in. Redirecting…');
        router.replace('/dashboard');
      } catch (err: any) {
        if (!cancelled) {
          setStatus('error');
          setMessage(err?.message ?? 'Exchange failed');
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [params, router]);

  const handleMfaSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!mfaToken || !mfaCode.trim()) return;

    setSubmitting(true);
    setMessage('');
    try {
      const res = await fetch('/api/auth/mfa-complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ mfaToken, mfaCode: mfaCode.trim() }),
      });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        setStatus('error');
        setMessage(
          Array.isArray(data.message)
            ? data.message.join(', ')
            : (data.message ?? 'MFA verification failed. Restart sign-in.'),
        );
        return;
      }

      if (data.nonAdmin) {
        setStatus('ok');
        setMessage(data.message ?? 'Signed in (non-admin). You can close this window.');
        return;
      }

      setStatus('ok');
      setMessage('Signed in. Redirecting…');
      router.replace('/dashboard');
    } catch (err: any) {
      setStatus('error');
      setMessage(err?.message ?? 'MFA verification failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
      <div className="glass rounded-2xl p-8 max-w-sm w-full text-center space-y-4">
        {status === 'working' && (
          <Loader2 className="w-8 h-8 text-violet-400 animate-spin mx-auto" />
        )}
        {status === 'ok' && (
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
        )}
        {status === 'error' && (
          <AlertCircle className="w-8 h-8 text-rose-400 mx-auto" />
        )}
        {status === 'mfa' && (
          <Shield className="w-8 h-8 text-violet-400 mx-auto" />
        )}

        {message && <p className="text-sm text-zinc-300">{message}</p>}

        {status === 'mfa' && (
          <form onSubmit={handleMfaSubmit} className="space-y-4 text-left">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-zinc-400">MFA code</label>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                className="input tracking-widest w-full"
                placeholder="123456"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                required
                autoFocus
              />
            </div>
            <button
              type="submit"
              disabled={submitting || !mfaCode.trim()}
              className="btn-primary w-full flex items-center justify-center gap-2 py-2.5"
            >
              {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
              {submitting ? 'Verifying…' : 'Verify MFA'}
            </button>
          </form>
        )}

        {status === 'error' && (
          <a href="/login" className="text-sm text-violet-400 hover:underline inline-block">
            Back to login
          </a>
        )}
      </div>
    </div>
  );
}

export default function OAuthSuccessPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-zinc-950 flex items-center justify-center text-zinc-400 text-sm">
          Loading…
        </div>
      }
    >
      <OAuthSuccessInner />
    </Suspense>
  );
}
