import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Session } from '@supabase/supabase-js';
import { supabase } from './lib/supabase';
import Dashboard    from './pages/Dashboard';
import Login        from './pages/Login';
import AuthCallback from './pages/AuthCallback';
import SSOCallback  from './components/SSOCallback';

const LANDING_URL = (import.meta.env.VITE_LANDING_URL as string) || 'https://apps.stellarglobalsupplies.com';

function ProtectedRoute({ session, children }: { session: Session | null; children: React.ReactNode }) {
  if (!session) {
    const callback = encodeURIComponent(window.location.href);
    window.location.replace(`${LANDING_URL}/login?callback=${callback}`);
    return (
      <div style={{ minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center', background:'#f5f5f0' }}>
        <div style={{ textAlign:'center' }}>
          <div style={{ fontSize:32, marginBottom:12 }}>🛡️</div>
          <p style={{ color:'#888', fontSize:14 }}>Redirecting to portal…</p>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setLoading(false);
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, s) => {
      setSession(s);
    });

    return () => subscription.unsubscribe();
  }, []);

  if (loading) {
    return (
      <div style={{ minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center', background:'#f5f5f0' }}>
        <div style={{ textAlign:'center' }}>
          <div style={{ fontSize:32, marginBottom:12 }}>🛡️</div>
          <p style={{ color:'#888', fontSize:14 }}>Loading Stellar Global Supplies Security Scanner…</p>
        </div>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        {/* ✅ SSO entry point — landing page redirects here */}
        <Route path="/sso-callback"  element={<SSOCallback />} />

        {/* Existing GitHub OAuth callback — untouched */}
        <Route path="/auth/callback" element={<AuthCallback />} />

        <Route path="/" element={session ? <Navigate to="/dashboard" replace /> : <Login />} />

        <Route path="/dashboard" element={
          <ProtectedRoute session={session}>
            <Dashboard />
          </ProtectedRoute>
        } />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
