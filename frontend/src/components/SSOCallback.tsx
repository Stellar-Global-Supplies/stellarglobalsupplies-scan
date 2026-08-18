import { useEffect, useState } from 'react';
import { supabase } from '../lib/supabase';

const EXCHANGE_FN = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/sso-exchange`;
const LANDING_URL = (import.meta.env.VITE_LANDING_URL as string) || 'https://apps.stellarglobalsupplies.com';
const MAX_AGE_MS  = 5 * 60 * 1000;

// ── Open-redirect guard ───────────────────────────────────────
// Only allow paths on the same origin.
// Anything with a different host (e.g. https://evil.com) falls back to /dashboard.
function safeRedirect(redirect: string, fallback = '/dashboard'): string {
  try {
    const url = new URL(redirect, window.location.origin);
    if (url.origin !== window.location.origin) return fallback;
    return url.pathname + url.search + url.hash;
  } catch {
    return redirect.startsWith('/') ? redirect : fallback;
  }
}

export default function SSOCallback() {
  const [status, setStatus] = useState('Verifying your session…');
  const [error,  setError]  = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token  = params.get('token');
    const ts     = Number(params.get('ts') || 0);

    // ✅ Sanitise redirect — never follow an external URL
    const redirect = safeRedirect(params.get('redirect') || '/dashboard');

    if (ts && Date.now() - ts > MAX_AGE_MS) {
      setError('This sign-in link has expired. Please return to the portal.');
      return;
    }

    if (!token) {
      // ✅ Only pass origin + sanitised path as callback — not the raw param
      const callback = encodeURIComponent(window.location.origin + redirect);
      window.location.replace(`${LANDING_URL}/login?callback=${callback}`);
      return;
    }

    setStatus('Exchanging credentials…');

    fetch(EXCHANGE_FN, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token }),
    })
      .then(async res => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Exchange failed (${res.status})`);
        return data;
      })
      .then(async ({ access_token, refresh_token }: { access_token: string; refresh_token: string }) => {
        setStatus('Setting up your workspace…');
        const { error: authErr } = await supabase.auth.setSession({ access_token, refresh_token });
        if (authErr) throw new Error(authErr.message);
        // ✅ redirect is already sanitised above — safe to use
        window.location.replace(redirect);
      })
      .catch((err: Error) => {
        setError(err.message || 'Sign-in failed. Please return to the portal.');
      });
  }, []);

  if (error) {
    return (
      <div style={s.page}>
        <div style={s.card}>
          <div style={{ fontSize:32, marginBottom:12 }}>🛡️</div>
          <p style={s.errorTitle}>Sign-in error</p>
          <p style={s.errorMsg}>{error}</p>
          <a href={LANDING_URL} style={s.btn}>Return to Portal</a>
        </div>
      </div>
    );
  }

  return (
    <div style={s.page}>
      <div style={s.card}>
        <div style={{ fontSize:32, marginBottom:12 }}>🛡️</div>
        <p style={{ fontWeight:600, color:'#1a1a18', marginBottom:6 }}>Security Scanner</p>
        <p style={{ color:'#888', fontSize:13 }}>{status}</p>
      </div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  page:       { minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center', background:'#f5f5f0' },
  card:       { background:'#fff', borderRadius:16, border:'0.5px solid #e0e0d8', padding:'2.5rem 2rem', textAlign:'center', width:360, boxShadow:'0 4px 24px rgba(0,0,0,0.06)' },
  errorTitle: { fontWeight:600, color:'#1a1a18', fontSize:16, marginBottom:8 },
  errorMsg:   { color:'#888', fontSize:13, marginBottom:20 },
  btn:        { display:'inline-block', padding:'10px 24px', background:'#1a1a18', color:'#fff', borderRadius:8, fontSize:14, fontWeight:500, textDecoration:'none' },
};
