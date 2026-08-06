'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { Loader2, CheckCircle2, AlertCircle } from 'lucide-react';

/**
 * Landing page for OAuth / magic-link redirects (#71).
 * Exchanges the one-time `code` via the BFF and establishes an admin session.
 */
function OAuthSuccessInner() {
  const params = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<'working' | 'ok' | 'error'>('working');
  const [message, setMessage] = useState('Completing sign-in…');

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
          setStatus('error');
          setMessage(
            data.message ??
              'MFA is required. Complete sign-in via the API with mfaToken + mfaCode.',
          );
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
        <p className="text-sm text-zinc-300">{message}</p>
        {status === 'error' && (
          <a href="/login" className="text-sm text-violet-400 hover:underline">
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
